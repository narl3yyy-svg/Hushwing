"""Hushwing privacy check: proves where torrent traffic goes, using only local checks.

  * Socket audit: every network socket Hushwing has open must sit on the VPN address (or loopback).
  * Swarm view: the public IP that trackers and peers report back to us (libtorrent external_ip_alert).
  * DNS leak test: can a DNS question still escape through a non-VPN adapter? We send a harmless
    query for "invalid." (a reserved name that never exists) from each non-VPN adapter to its DNS
    server. An answer means Windows could leak tracker lookups that way; silence means the VPN
    app's leak protection is blocking it.

Nothing here talks to a third-party service.
"""
from __future__ import annotations

import ipaddress
import json
import os
import secrets
import socket
import struct
import subprocess
import sys

try:
    import psutil
except ImportError:
    psutil = None

NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0
OK, WARN, FAIL, INFO = "ok", "warn", "fail", "info"


def dns_servers() -> dict[str, list[str]]:
    """{adapter alias: [IPv4 DNS servers]} for adapters that have any."""
    if sys.platform != "win32":
        return {}
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | "
             "Select-Object InterfaceAlias, ServerAddresses | ConvertTo-Json -Compress"],
            capture_output=True, text=True, timeout=15, creationflags=NO_WINDOW).stdout.strip()
        data = json.loads(out) if out else []
        if isinstance(data, dict):
            data = [data]
        return {d["InterfaceAlias"]: list(d["ServerAddresses"] or []) for d in data}
    except Exception:
        return {}


def dns_answers(server: str, bind_ip: str | None, timeout: float = 2.0) -> bool:
    """True if `server` answers a DNS query sent from `bind_ip`."""
    qid = secrets.randbits(16)
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + b"\x07invalid\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if bind_ip:
            s.bind((bind_ip, 0))
        s.settimeout(timeout)
        s.sendto(q, (server, 53))
        while True:
            data, src = s.recvfrom(2048)
            if src[0] == server and data[:2] == struct.pack(">H", qid):
                return True
    except OSError:
        return False
    finally:
        s.close()


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.split("%")[0]).is_loopback
    except ValueError:
        return False


def socket_audit(allowed_ip: str | None):
    """(good, bad) socket descriptions for this process. Sockets must be on allowed_ip or loopback."""
    good, bad = [], []
    if not psutil:
        return good, bad
    try:
        conns = psutil.Process(os.getpid()).net_connections(kind="inet")
    except Exception:
        return good, bad
    for c in conns:
        lip = c.laddr.ip if c.laddr else ""
        proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
        desc = f"{proto} {lip}:{c.laddr.port if c.laddr else ''}" + (f" → {c.raddr.ip}:{c.raddr.port}" if c.raddr else "")
        if _is_loopback(lip):
            continue  # Hushwing's own single-instance channel etc.
        if allowed_ip and lip == allowed_ip:
            good.append(desc)
        else:
            bad.append(desc)
    return good, bad


def run(bound_name: str | None, bound_ip: str | None, locked: bool, external_ip: str | None,
        external_seen: bool, proxy: bool, vpn_names: set[str], guard: dict | None = None) -> list[tuple[str, str, str]]:
    """Returns [(status, title, detail)] for the dialog."""
    res = []
    # 1. binding
    if locked:
        res.append((OK, "Traffic is stopped",
                    "The kill switch / strict mode has stopped all torrent traffic, so nothing can leak right now."))
    elif bound_ip:
        res.append((OK, f"Bound to VPN adapter '{bound_name}'",
                    f"Hushwing only sends and receives through {bound_ip}. If the VPN drops, traffic stops."))
    elif proxy:
        res.append((INFO, "Using a proxy", "Peer and tracker traffic goes through your proxy."))
    else:
        res.append((FAIL, "Not bound to a VPN",
                    "Torrent traffic can use any network adapter, so peers may see your real IP. "
                    "Turn on Settings → Network → 'Any VPN adapter — automatic'."))

    # 2. socket audit
    good, bad = socket_audit(None if locked else bound_ip)
    if locked:
        if bad:
            res.append((FAIL, f"{len(bad)} socket(s) open while blocked", "\n".join(bad[:8])))
        else:
            res.append((OK, "No open network sockets", "Only Hushwing's private loopback channel is open."))
    elif bound_ip:
        if bad:
            res.append((FAIL, f"{len(bad)} socket(s) outside the VPN", "\n".join(bad[:8])))
        else:
            res.append((OK, f"All {len(good)} sockets are on the VPN address",
                        f"Every connection and listening port uses {bound_ip}."))
    else:
        res.append((INFO, f"{len(good) + len(bad)} open sockets", "Not checked: no VPN binding to compare against."))

    # 3. what the swarm sees
    if external_ip:
        res.append((INFO, f"Peers and trackers see you as {external_ip}",
                    "This should be your VPN's address, not your home one. Compare it with the IP shown in "
                    "your VPN app."))
    elif not locked:
        res.append((INFO, "Public IP not reported yet",
                    "Trackers report your public address after the first announce. Add or resume a torrent and "
                    "run the check again." if not external_seen else ""))

    # 4. Hushwing's own lookups (DNS guard)
    if guard:
        if guard["ready"]:
            res.append((OK, "DNS guard on: Hushwing never asks Windows for addresses",
                        f"Tracker and DHT names are looked up through the VPN's DNS server ({guard['server']}) "
                        f"from inside the tunnel: {guard['lookups']} lookups and {guard['relayed']} HTTP(S) "
                        "tracker requests so far. The test below is about other apps on this PC."))
        else:
            res.append((OK, "DNS guard on, waiting for the VPN",
                        "No lookups are made until the VPN is connected; there is no fallback to Windows DNS."))
    elif not proxy and bound_ip:
        res.append((WARN, "DNS guard is off",
                    "Hushwing asks Windows to look up tracker names. Turn on Settings → Privacy → DNS guard."))

    # 5. Windows DNS leak test
    servers = dns_servers()
    if not servers:
        res.append((WARN, "Couldn't read DNS settings", "Windows didn't report any DNS servers."))
        return res
    ifaces = {}
    if psutil:
        for name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and not a.address.startswith(("127.", "169.254.")):
                    ifaces[name] = a.address
    vpn_dns = [s for n, lst in servers.items() if n in vpn_names for s in lst]
    leaks, blocked = [], []
    for alias, lst in servers.items():
        if alias in vpn_names or alias not in ifaces:
            continue
        for srv in lst:
            (leaks if dns_answers(srv, ifaces[alias]) else blocked).append(f"{srv} on {alias}")
    if not (bound_ip or vpn_names):
        res.append((INFO, "DNS leak test skipped", "Connect your VPN first; there's nothing to leak around yet."))
    elif leaks:
        res.append((WARN, "Possible DNS leak",
                    "These DNS servers outside the VPN still answer: " + ", ".join(leaks) + ". Windows may send "
                    "tracker name lookups there, which shows your ISP that you use BitTorrent (not what you "
                    "download; your IP stays hidden from peers). Fix: turn on DNS leak protection / the kill "
                    "switch in your VPN app, then run this check again."))
    else:
        res.append((OK, "No DNS leak path",
                    ("Your VPN's DNS (" + ", ".join(vpn_dns) + ") is in use and " if vpn_dns else "")
                    + ("DNS servers outside the VPN don't answer (" + ", ".join(blocked) + ")."
                       if blocked else "no other adapter has a DNS server.")))
    return res
