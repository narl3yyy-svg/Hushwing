"""Hushwing DNS guard: every name lookup Hushwing needs goes through the VPN, never through Windows.

Normally the torrent engine asks Windows to look up tracker names (tracker.example.org). Windows may
send that question to your router / ISP instead of through the VPN: a "DNS leak". With the guard on,
the engine never sees a hostname at all:

  * UDP trackers  : Hushwing looks the name up itself, asking the VPN's own DNS server from a socket
                    bound to the VPN adapter, and gives the engine the IP address instead.
  * HTTP(S) trackers: the engine talks to a tiny relay on 127.0.0.1. The relay looks the name up the
                    same way, connects from the VPN address and checks the HTTPS certificate against
                    the real name.
  * DHT bootstrap : the start-up DHT routers are looked up the same way.
  * Web seeds and DHT nodes embedded as names are dropped (they would need Windows DNS).

If the VPN is down, nothing is looked up and nothing is sent: there is no fallback to Windows DNS.
"""
from __future__ import annotations

import hashlib
import ipaddress
import queue
import secrets
import socket
import ssl
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

QUAD9 = "9.9.9.9"  # only if the VPN adapter reports no DNS server; still sent through the VPN
DEFAULT_BOOTSTRAP = ["dht.libtorrent.org:25401", "router.bittorrent.com:6881", "router.utorrent.com:6881",
                     "dht.transmissionbt.com:6881"]


# --------------------------------------------------------------------------- DNS over the VPN
def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna")
        if not 0 < len(raw) < 64:
            raise ValueError("bad hostname")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _skip_name(buf: bytes, i: int) -> int:
    while True:
        n = buf[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += n + 1


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def resolve(host: str, dns_server: str, bind_ip: str, timeout: float = 3.0) -> list[str]:
    """IPv4 addresses for `host`, asked from `dns_server` through a socket bound to `bind_ip`."""
    if is_ip(host):
        return [host.strip("[]")]
    if not bind_ip:
        raise OSError("VPN not connected")
    qid = secrets.randbits(16)
    query = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + _encode_name(host) + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((bind_ip, 0))
        s.settimeout(timeout)
        for _ in range(2):
            s.sendto(query, (dns_server, 53))
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    data, src = s.recvfrom(4096)
                except socket.timeout:
                    break
                if src[0] != dns_server or len(data) < 12 or struct.unpack(">H", data[:2])[0] != qid:
                    continue  # not our answer
                _id, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
                if flags & 0x000F:
                    return []
                i = 12
                for _ in range(qd):
                    i = _skip_name(data, i) + 4
                ips = []
                for _ in range(an):
                    i = _skip_name(data, i)
                    rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[i:i + 10])
                    i += 10
                    if rtype == 1 and rdlen == 4:
                        ips.append(socket.inet_ntoa(data[i:i + 4]))
                    i += rdlen
                return ips
        return []
    finally:
        s.close()


# --------------------------------------------------------------------------- the guard
class DnsGuard:
    def __init__(self):
        self.bind_ip: str | None = None
        self.dns_server: str = QUAD9
        self.lookups = 0
        self.failures = 0
        self.relayed = 0
        self.last_error = ""
        self._cache: dict[str, tuple[float, list[str]]] = {}
        self._lock = threading.Lock()
        self.routes: dict[str, str] = {}  # relay id -> original http(s) announce URL
        self.server = None
        self.port = 0
        self.relay_ip = None  # the relay listens on the VPN address: the engine's sockets are bound to it

    def _start_relay(self, ip: str):
        self.close()
        guard = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.client_address[0] != guard.relay_ip:  # only this PC (the engine) may use it
                    self.send_error(403)
                    return
                guard._relay(self)

        try:
            self.server = ThreadingHTTPServer((ip, 0), Handler)
        except OSError as e:
            self.last_error = f"relay: {e}"
            self.server, self.relay_ip = None, None
            return
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.relay_ip = ip
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass
        self.server = None

    # -- configuration
    def configure(self, bind_ip: str | None, dns_server: str | None) -> bool:
        """Returns True if the relay address changed (tracker URLs must then be rewritten again)."""
        if bind_ip != self.bind_ip or (dns_server or QUAD9) != self.dns_server:
            with self._lock:
                self._cache.clear()
        self.bind_ip = bind_ip
        self.dns_server = dns_server or QUAD9
        if bind_ip and bind_ip != self.relay_ip:
            self._start_relay(bind_ip)
            return True
        return False

    @property
    def ready(self) -> bool:
        return bool(self.bind_ip) and self.relay_ip == self.bind_ip

    def lookup(self, host: str) -> str:
        if is_ip(host):
            return host.strip("[]")
        now = time.time()
        with self._lock:
            hit = self._cache.get(host.lower())
        if hit and hit[0] > now:
            return hit[1][secrets.randbelow(len(hit[1]))]
        bind = self.bind_ip
        if not bind:
            raise OSError("VPN not connected: lookup refused")
        self.lookups += 1
        try:
            ips = resolve(host, self.dns_server, bind)
        except OSError as e:
            self.failures += 1
            raise OSError(f"lookup of {host} failed: {e}")
        if not ips:
            self.failures += 1
            raise OSError(f"{host} not found")
        with self._lock:
            self._cache[host.lower()] = (now + 600, ips)
        return ips[0]

    # -- rewriting what the engine sees
    def relay_url(self, url: str) -> str:
        rid = hashlib.sha256(url.encode()).hexdigest()[:20]
        self.routes[rid] = url
        if not self.relay_ip:
            raise OSError("VPN not connected")
        return f"http://{self.relay_ip}:{self.port}/announce?hwr={rid}"

    def rewrite_tracker(self, url: str) -> str | None:
        """Engine-safe version of a tracker URL, or None if it can't be used without Windows DNS.
        Raises OSError when a UDP tracker can't be looked up right now (retry later)."""
        parts = urlsplit(url)
        scheme, host = parts.scheme.lower(), parts.hostname or ""
        if scheme in ("http", "https"):
            return url if host in ("127.0.0.1", "localhost") else self.relay_url(url)
        if scheme == "udp":
            if is_ip(host):
                return url
            ip = self.lookup(host)
            port = f":{parts.port}" if parts.port else ""
            return f"udp://{ip}{port}{parts.path or '/announce'}" + (f"?{parts.query}" if parts.query else "")
        return None  # wss:// etc.

    def bootstrap_nodes(self, nodes=None) -> str:
        out = []
        for hp in nodes or DEFAULT_BOOTSTRAP:
            host, _, port = hp.rpartition(":")
            try:
                out.append(f"{self.lookup(host)}:{port}")
            except OSError:
                continue
        return ",".join(out)

    # -- HTTP(S) tracker relay
    def _relay(self, req: BaseHTTPRequestHandler):
        try:
            path, _, query = req.path.partition("?")
            action = path.strip("/")
            params = query.split("&")
            rid = next((x[4:] for x in params if x.startswith("hwr=")), "")
            query = "&".join(x for x in params if not x.startswith("hwr=") and x)
            target = self.routes.get(rid)
            if not target or action not in ("announce", "scrape"):
                req.send_error(404)
                return
            if action == "scrape":
                head, sep, tail = target.rpartition("announce")
                if not sep:
                    req.send_error(404)
                    return
                target = head + "scrape" + tail
            if query:
                target += ("&" if "?" in target else "?") + query
            status, headers, body = self._fetch(target, req.headers.get("User-Agent", ""))
            self.relayed += 1
            req.send_response(status)
            for k, v in headers:
                if k.lower() in ("content-type", "content-encoding"):
                    req.send_header(k, v)
            req.send_header("Content-Length", str(len(body)))
            req.end_headers()
            req.wfile.write(body)
        except Exception as e:
            self.last_error = str(e)
            try:
                req.send_error(502, "tracker unreachable through the VPN")
            except Exception:
                pass

    def _fetch(self, url: str, user_agent: str, hops: int = 0):
        parts = urlsplit(url)
        host = parts.hostname or ""
        https = parts.scheme.lower() == "https"
        port = parts.port or (443 if https else 80)
        bind = self.bind_ip
        if not bind:
            raise OSError("VPN not connected")
        ip = self.lookup(host)
        sock = socket.create_connection((ip, port), timeout=20, source_address=(bind, 0))
        try:
            if https:
                ctx = ssl.create_default_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)  # verifies the certificate for `host`
            path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
            host_hdr = host if parts.port in (None, 80, 443) else f"{host}:{parts.port}"
            req = (f"GET {path} HTTP/1.0\r\nHost: {host_hdr}\r\nAccept-Encoding: gzip\r\nConnection: close\r\n"
                   + (f"User-Agent: {user_agent}\r\n" if user_agent else "") + "\r\n")
            sock.sendall(req.encode("latin-1"))
            data = b""
            while len(data) < 8 * 1024 * 1024:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
        finally:
            sock.close()
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        status = int(lines[0].split()[1])
        headers = [tuple(x.split(":", 1)) for x in lines[1:] if ":" in x]
        headers = [(k.strip(), v.strip()) for k, v in headers]
        if status in (301, 302, 303, 307, 308) and hops < 3:
            loc = dict((k.lower(), v) for k, v in headers).get("location", "")
            if loc.lower().startswith(("http://", "https://")):
                return self._fetch(loc, user_agent, hops + 1)
        if any(k.lower() == "transfer-encoding" and "chunked" in v.lower() for k, v in headers):
            body = _unchunk(body)
        return status, headers, body


def _unchunk(b: bytes) -> bytes:
    out, i = b"", 0
    while True:
        j = b.find(b"\r\n", i)
        if j < 0:
            return out
        size = int(b[i:j].split(b";")[0] or b"0", 16)
        if size == 0:
            return out
        out += b[j + 2:j + 2 + size]
        i = j + 2 + size + 2


class Resolver(threading.Thread):
    """Background worker: turns a torrent's original trackers into engine-safe ones."""

    def __init__(self, guard: DnsGuard):
        super().__init__(daemon=True)
        self.guard = guard
        self.jobs: queue.Queue = queue.Queue()
        self.results: queue.Queue = queue.Queue()
        self.start()

    def submit(self, key: str, trackers: list[tuple[str, int]]):
        self.jobs.put((key, trackers))

    def run(self):
        while True:
            key, trackers = self.jobs.get()
            if not self.guard.ready:
                time.sleep(2)
                self.jobs.put((key, trackers))  # wait for the VPN
                continue
            safe, missing = [], []
            for url, tier in trackers:
                try:
                    new = self.guard.rewrite_tracker(url)
                    if new:
                        safe.append((new, tier))
                except (OSError, ValueError):
                    missing.append((url, tier))
            self.results.put((key, safe))
            if missing:  # retry unresolved UDP trackers later, without ever using Windows DNS
                threading.Timer(90, lambda k=key, t=trackers: self.jobs.put((k, t))).start()
