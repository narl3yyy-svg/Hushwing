"""
Hushwing - a privacy-first desktop BitTorrent client (libtorrent + tkinter).

Privacy
  * Strict mode: refuses all traffic unless bound to a VPN adapter (or a proxy is set)
  * VPN kill switch: traffic stops instantly if the bound adapter disappears
  * Forced protocol encryption, anonymous mode (no fingerprint / user agent / local IP)
  * Random listening port every launch
  * Incognito mode (nothing saved; history wiped on exit) + one-click "clear history"
  * SOCKS5 / HTTP proxy (password encrypted with Windows DPAPI), IP blocklists
  * UPnP / NAT-PMP / LSD off by default; HTTPS tracker validation + SSRF mitigation
  * Stop seeding automatically at a ratio or time limit

Safety
  * Built-in offline inspector (inspector.py): catches disguised programs, double extensions, fake
    "codec" files, password-protected archives, DRM-licence scams; no signatures, no network
  * Dangerous files are skipped before they even download
  * Completed downloads are also virus-scanned when an antivirus is present (Defender or your own command)
  * Infected torrents are paused immediately so you stop sharing them
  * Mark-of-the-Web on downloaded files, so Windows SmartScreen checks them when opened
  * Warnings for executable / risky files inside torrents

Privacy check
  * One click shows the VPN binding, audits every open socket, shows the IP the swarm sees and tests for
    DNS leaks, all without contacting any third-party service
  * DNS guard (dnsguard.py): tracker and DHT names are looked up only through the VPN's own DNS
    server; the engine never asks Windows, so lookups can't leak outside the VPN
  * Optional I2P support (anonymous network) through a local I2P router

Everything else
  * Runs in the system tray with notifications; drag and drop torrents / magnet links onto the window
  * Download queue (max active downloads / seeds), set-and-forget speed limiter
  * Create your own torrents (no creator tag or creation date embedded), keyboard shortcuts
  * Dark UI, live speed graph, filter + search, per-file priorities, sequential download
  * Peer list with encryption indicator, fast-resume, single-instance with magnet/.torrent hand-off
  * Optional registration as the default app for magnet links and .torrent files

Requires: Python 3.12, pip install libtorrent sv-ttk psutil pillow
"""

import base64
import gzip
import hmac
import json
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
from collections import deque
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import libtorrent as lt

sys.path.insert(0, str(Path(__file__).resolve().parent))
import inspector  # noqa: E402  (offline file inspector, same folder)
import dnsguard  # noqa: E402
import privacy_check  # noqa: E402
import tray as traymod  # noqa: E402

try:
    from tkinterdnd2 import DND_FILES, DND_TEXT, TkinterDnD
except Exception:  # drag and drop is optional
    TkinterDnD = None

try:
    import sv_ttk
except ImportError:
    sv_ttk = None
try:
    import psutil
except ImportError:
    psutil = None
try:
    from PIL import Image, ImageTk
except ImportError:
    Image = ImageTk = None

APP_NAME = "Hushwing"
APP_VERSION = "3.0"
APP_ID = "Hushwing.TorrentClient"
FROZEN = bool(getattr(sys, "frozen", False))  # running as the standalone Hushwing.exe
HERE = Path(__file__).resolve().parent
ASSETS = Path(getattr(sys, "_MEIPASS", HERE)) / "assets"
ICON_ICO = ASSETS / "hushwing.ico"
ICON_PNG = ASSETS / "hushwing_256.png"

STATE_DIR = Path.home() / ".hushwing"
LEGACY_STATE_DIRS = (Path.home() / ".shroud", Path.home() / ".pytorrent")
RESUME_DIR = STATE_DIR / "resume"
CONFIG_FILE = STATE_DIR / "config.json"
SCANS_FILE = STATE_DIR / "scans.json"
IPC_FILE = STATE_DIR / "ipc.json"
NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0

DEFAULT_CONFIG = {
    "download_dir": str(Path.home() / "Downloads"),
    "listen_port": 6881,
    "random_port": True,
    "max_download_kbps": 0,
    "max_upload_kbps": 0,
    "stop_seeding_ratio": 1.0,  # 0 = never stop
    "stop_seeding_minutes": 0,  # 0 = never stop
    "max_active_downloads": 3,  # the rest wait in the queue
    "max_active_seeds": 5,
    "close_to_tray": True,
    "notifications": True,
    # privacy
    "strict_mode": True,
    "incognito": False,
    "force_encryption": True,
    "anonymous_mode": True,
    "bind_interface": "",
    "dns_guard": True,  # look up tracker / DHT names only through the VPN's DNS
    "enable_dht": True,
    "enable_lsd": False,
    "enable_upnp": False,
    "blocklist_path": "",
    "i2p_enabled": False,
    "i2p_host": "127.0.0.1",
    "i2p_port": 7656,
    "i2p_mixed": False,
    "proxy_type": "none",  # none | socks5 | http
    "proxy_host": "",
    "proxy_port": 1080,
    "proxy_user": "",
    "proxy_pass": "",  # DPAPI-encrypted
    # safety
    "scan_on_complete": True,
    "block_suspicious_files": True,  # skip disguised programs etc. before they download
    "scanner_cmd": "",  # custom scanner; {path} is replaced with the download path
    "mark_of_web": True,
}

# palette (matches sv_ttk dark)
BG, PANEL, FG, MUTED = "#1c1c1c", "#202020", "#e8e8e8", "#9a9a9a"
ACCENT, GREEN, RED, YELLOW, BLUE, VIOLET = "#57c8ff", "#6ccb5f", "#ff7070", "#f0c05a", "#7aa7ff", "#a78bfa"

STATE_NAMES = {
    "checking_files": "Checking",
    "downloading_metadata": "Fetching metadata",
    "downloading": "Downloading",
    "finished": "Finished",
    "seeding": "Seeding",
    "checking_resume_data": "Checking resume",
    "allocating": "Allocating",
}

RISKY_EXT = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".msi", ".msp", ".ps1", ".lnk", ".hta", ".jar", ".dll", ".cpl", ".reg", ".iso", ".img",
}
VPN_HINTS = ("wireguard", "wintun", "tap-windows", "openvpn", "nordlynx", "mullvad", "proton", "expressvpn",
             "surfshark", "private internet", "windscribe", "cyberghost", "ipvanish", "vpn", "tunnel")
NOT_VPN = ("tailscale", "zerotier", "hyper-v", "virtualbox", "vmware", "loopback", "bluetooth")


# --------------------------------------------------------------------------- helpers
def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def human_speed(n: float) -> str:
    return "" if n < 1 else human_size(n) + "/s"


def human_eta(seconds: float) -> str:
    if seconds <= 0 or seconds == float("inf"):
        return "∞"
    seconds = int(seconds)
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def progress_bar(p: float, width: int = 10) -> str:
    filled = int(round(p * width))
    return "█" * filled + "░" * (width - filled) + f"  {p * 100:5.1f}%"


def blend(c1: str, c2: str, t: float) -> str:
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{int(x + (y - x) * t):02x}" for x, y in zip(a, b))


def atp_key(atp) -> str:
    """Same key as torrent_key(), from add_torrent_params before the torrent exists."""
    ih = atp.ti.info_hashes() if atp.ti else atp.info_hashes
    return str(ih.get_best())


def torrent_key(handle) -> str:
    try:
        ih = handle.info_hashes()
        best = ih.get_best() if hasattr(ih, "get_best") else (ih.v1 if ih.has_v1() else ih.v2)
        return str(best)
    except AttributeError:
        return str(handle.info_hash())


def is_paused(status) -> bool:
    try:
        return bool(status.flags & lt.torrent_flags.paused)
    except AttributeError:
        return status.paused


def share_ratio(st) -> float:
    return st.all_time_upload / max(st.all_time_download, st.total_wanted_done, 1)


def duration_seconds(v) -> float:
    return v.total_seconds() if hasattr(v, "total_seconds") else float(v or 0)


def is_risky(path: str) -> bool:
    return Path(path).suffix.lower() in RISKY_EXT


PAD_FLAG = getattr(lt.file_storage, "flag_pad_file", 1)


def real_files(fs):
    """[(index, path, size)] without the invisible padding files some torrents contain."""
    return [(i, fs.file_path(i), fs.file_size(i)) for i in range(fs.num_files()) if not fs.file_flags(i) & PAD_FLAG]


def human_rate_limit(kbps: int) -> str:
    if not kbps:
        return "unlimited"
    return f"{kbps / 1024:g} MB/s" if kbps >= 1024 else f"{kbps} KB/s"


def i2p_router_running(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=0.4):
            return True
    except (OSError, ValueError):
        return False


def list_interfaces() -> dict:
    """{adapter name: ipv4} for adapters that are up and have a routable IPv4."""
    if not psutil:
        return {}
    out = {}
    stats = psutil.net_if_stats()
    for name, addrs in psutil.net_if_addrs().items():
        if name in stats and not stats[name].isup:
            continue
        for a in addrs:
            if a.family == 2 and not a.address.startswith(("127.", "169.254.")):
                out[name] = a.address
                break
    return out


def interface_ipv4(name: str):
    return list_interfaces().get(name)


AUTO_VPN = "__auto_vpn__"  # bind_interface value: follow whichever VPN adapter is up
_ADAPTER_DESC = None
_ADAPTER_LOCK = threading.Lock()
_ADAPTER_REFRESHING = False


def adapter_descriptions(refresh: bool = False) -> dict:
    """{adapter name: hardware description}, e.g. 'ProtonVPN' -> 'WireGuard Tunnel'. Cached."""
    global _ADAPTER_DESC
    with _ADAPTER_LOCK:
        if _ADAPTER_DESC is None or refresh:
            descs = {}
            if sys.platform == "win32":
                try:
                    out = subprocess.run(
                        ["powershell", "-NoProfile", "-Command",
                         "Get-NetAdapter | ForEach-Object { $_.Name + '|' + $_.InterfaceDescription }"],
                        capture_output=True, text=True, timeout=10, creationflags=NO_WINDOW).stdout
                    for line in out.splitlines():
                        if "|" in line:
                            n, d = line.split("|", 1)
                            descs[n.strip()] = d.strip()
                except Exception:
                    pass
            _ADAPTER_DESC = descs
        return _ADAPTER_DESC


def refresh_adapter_descriptions_async() -> None:
    global _ADAPTER_REFRESHING
    if _ADAPTER_REFRESHING:
        return
    _ADAPTER_REFRESHING = True

    def work():
        global _ADAPTER_REFRESHING
        try:
            adapter_descriptions(refresh=True)
        finally:
            _ADAPTER_REFRESHING = False

    threading.Thread(target=work, daemon=True).start()


def find_vpn_adapter():
    """(name, ipv4) of a connected VPN adapter, or (None, None).

    VPN apps often create a new adapter name per server/connection, so this is re-checked every
    second. Adapters we haven't identified yet don't count until their description is known."""
    ifaces = list_interfaces()
    descs = _ADAPTER_DESC or {}
    if any(n not in descs for n in ifaces):
        refresh_adapter_descriptions_async()
    for n in sorted(ifaces):
        if n in descs and is_vpn_adapter(n, descs[n]):
            return n, ifaces[n]
    return None, None


def is_vpn_adapter(name: str, desc: str) -> bool:
    text = f"{name} {desc}".lower()
    return any(h in text for h in VPN_HINTS) and not any(n in text for n in NOT_VPN)


def interface_label(name: str, ifaces: dict, descs: dict) -> str:
    desc = descs.get(name, "")
    ip = ifaces.get(name)
    label = f"{name}  ({ip})" if ip else f"{name}  (down)"
    if desc and desc != name:
        label += f" — {desc}"
    if is_vpn_adapter(name, desc):
        label += "   🛡 VPN"
    return label


# ---- Windows DPAPI: encrypt secrets so they're unreadable to other users / machines
def _dpapi(data: bytes, encrypt: bool) -> bytes:
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = BLOB()
    fn = ctypes.windll.crypt32.CryptProtectData if encrypt else ctypes.windll.crypt32.CryptUnprotectData
    if not fn(ctypes.byref(blob_in), None, None, None, None, 0x1, ctypes.byref(blob_out)):
        raise OSError("DPAPI call failed")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(blob_out.pbData, ctypes.c_void_p))


def protect_secret(s: str) -> str:
    if not s:
        return ""
    if sys.platform == "win32":
        return "dpapi:" + base64.b64encode(_dpapi(s.encode(), True)).decode()
    return "b64:" + base64.b64encode(s.encode()).decode()


def unprotect_secret(s: str) -> str:
    try:
        if s.startswith("dpapi:"):
            return _dpapi(base64.b64decode(s[6:]), False).decode()
        if s.startswith("b64:"):
            return base64.b64decode(s[4:]).decode()
    except Exception:
        pass
    return ""


def migrate_legacy_state() -> None:
    for old in LEGACY_STATE_DIRS:
        if old.exists() and not STATE_DIR.exists():
            try:
                old.rename(STATE_DIR)
            except OSError:
                pass


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    try:
        cfg.update(json.loads(CONFIG_FILE.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        pass
    return cfg


def save_config(cfg: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def parse_blocklist(path: str) -> list:
    """Return [(start_ip, end_ip)] from a P2P ('name:a.b.c.d-e.f.g.h') or DAT list."""

    def norm(ip):
        parts = ip.strip().split(".")
        if len(parts) != 4:
            raise ValueError
        nums = [int(p) for p in parts]
        if any(n < 0 or n > 255 for n in nums):
            raise ValueError
        return ".".join(map(str, nums))

    opener = gzip.open if path.lower().endswith(".gz") else open
    ranges = []
    with opener(path, "rt", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(("#", "//")):
                continue
            try:
                if "," in line:  # DAT: start - end , level , desc
                    rng, level = line.split(",")[:2]
                    if int(level) > 127:
                        continue
                    a, b = rng.split("-")
                else:  # P2P: desc:start-end
                    a, b = line.rsplit(":", 1)[1].split("-")
                ranges.append((norm(a), norm(b)))
            except (ValueError, IndexError):
                continue
    return ranges


# ---- malware scanning
def find_defender():
    cands = []
    plat = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft" / "Windows Defender" / "Platform"
    if plat.exists():
        cands += sorted(plat.glob("*/MpCmdRun.exe"), reverse=True)
    cands.append(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Defender" / "MpCmdRun.exe")
    for c in cands:
        if c.exists():
            return str(c)
    return None


def scanner_name(cfg: dict):
    if cfg.get("scanner_cmd", "").strip():
        return "Custom scanner"
    if find_defender():
        return "Microsoft Defender"
    return None


def run_scan(cfg: dict, path: str, root: str = "", rel_files=None):
    """Offline inspector first, then the antivirus if there is one.
    Returns (status, detail, findings). status: clean | warning | threat | error."""
    status, detail, findings = "clean", "", []
    if rel_files is not None:
        try:
            status, detail, findings = inspector.inspect(root, rel_files)
        except Exception as e:
            status, detail = "error", f"Inspector failed: {e}"
    av_status, av_detail = run_av(cfg, path)
    if av_status == "noscanner":
        return status, detail, findings
    if av_status == "threat":
        findings.insert(0, {"file": "", "level": "threat", "reason": av_detail})
        return "threat", av_detail + (f" · {detail}" if detail else ""), findings
    if status == "clean" and av_status == "error":
        return "error", f"{detail} · antivirus: {av_detail}", findings
    return status, (f"{detail} · {av_detail}" if detail else av_detail), findings


def run_av(cfg: dict, path: str):
    """Returns (status, detail). status: clean | threat | noscanner | error."""
    custom = cfg.get("scanner_cmd", "").strip()
    try:
        if custom:
            cmd = custom.replace("{path}", f'"{path}"') if "{path}" in custom else f'{custom} "{path}"'
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=3 * 3600, creationflags=NO_WINDOW)
            if r.returncode == 0:
                return "clean", "Custom scanner: no threats found"
            return "threat", f"Custom scanner reported a problem (exit code {r.returncode})"
        exe = find_defender()
        if not exe:
            return "noscanner", "No antivirus found on this PC"
        r = subprocess.run([exe, "-Scan", "-ScanType", "3", "-File", path], capture_output=True, text=True,
                           timeout=3 * 3600, creationflags=NO_WINDOW)
        if r.returncode == 0:
            return "clean", "Microsoft Defender: no threats found"
        if r.returncode == 2:
            return "threat", "Microsoft Defender found and quarantined malware"
        return "error", f"Defender exit code {r.returncode}"
    except Exception as e:
        return "error", str(e)


def mark_of_the_web(paths) -> None:
    """Tag files as downloaded from the internet so Windows SmartScreen checks them."""
    if sys.platform != "win32":
        return
    for p in paths:
        try:
            if os.path.isfile(p):
                with open(p + ":Zone.Identifier", "w", encoding="utf-8") as f:
                    f.write("[ZoneTransfer]\r\nZoneId=3\r\n")
        except OSError:
            pass


# ---- single instance: hand magnet links / .torrent files to the running window
def forward_to_running_instance(args: list) -> bool:
    try:
        info = json.loads(IPC_FILE.read_text(encoding="utf-8"))
        with socket.create_connection(("127.0.0.1", int(info["port"])), timeout=1.5) as s:
            s.sendall(json.dumps({"token": info["token"], "args": args}).encode())
            s.shutdown(socket.SHUT_WR)
            return s.recv(8) == b"ok"
    except Exception:
        return False


class IPCServer(threading.Thread):
    def __init__(self, on_args):
        super().__init__(daemon=True)
        self.on_args = on_args
        self.token = secrets.token_hex(24)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        IPC_FILE.write_text(json.dumps({"port": self.sock.getsockname()[1], "token": self.token}), encoding="utf-8")

    def run(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                try:
                    conn.settimeout(3)
                    data = b""
                    while len(data) < 1 << 20:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                    msg = json.loads(data)
                    if not hmac.compare_digest(str(msg.get("token", "")), self.token):
                        continue
                    args = [str(a) for a in msg.get("args", [])][:50]
                    conn.sendall(b"ok")
                    self.on_args(args)
                except Exception:
                    continue

    def close(self):
        try:
            self.sock.close()
            IPC_FILE.unlink(missing_ok=True)
        except OSError:
            pass


def register_default_app() -> None:
    """Make Hushwing the handler for magnet: links and .torrent files (current user only)."""
    import winreg

    if FROZEN:
        cmd = f'"{sys.executable}" "%1"'
        icon = f'"{sys.executable}",0'
    else:
        pyw = Path(sys.executable).with_name("pythonw.exe")
        if not pyw.exists():
            pyw = Path(sys.executable)
        cmd = f'"{pyw}" "{Path(__file__).resolve()}" "%1"'
        icon = f'"{ICON_ICO}"'

    def setkey(path, values):
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as k:
            for name, val in values.items():
                winreg.SetValueEx(k, name, 0, winreg.REG_SZ, val)

    c = r"Software\Classes"
    for progid, desc, extra in (("Hushwing.Torrent", "BitTorrent file", {}),
                                ("Hushwing.Magnet", "Magnet link", {"URL Protocol": ""})):
        setkey(rf"{c}\{progid}", {"": desc, **extra})
        setkey(rf"{c}\{progid}\DefaultIcon", {"": icon})
        setkey(rf"{c}\{progid}\shell\open\command", {"": cmd})
    setkey(rf"{c}\.torrent", {"": "Hushwing.Torrent"})
    setkey(rf"{c}\.torrent\OpenWithProgids", {"Hushwing.Torrent": ""})
    setkey(rf"{c}\magnet", {"": "URL:Magnet link", "URL Protocol": ""})
    setkey(rf"{c}\magnet\DefaultIcon", {"": icon})
    setkey(rf"{c}\magnet\shell\open\command", {"": cmd})
    cap = r"Software\Hushwing\Capabilities"
    setkey(cap, {"ApplicationName": APP_NAME, "ApplicationDescription": "Privacy-first BitTorrent client"})
    setkey(cap + r"\FileAssociations", {".torrent": "Hushwing.Torrent"})
    setkey(cap + r"\URLAssociations", {"magnet": "Hushwing.Magnet"})
    setkey(r"Software\RegisteredApplications", {APP_NAME: cap})
    try:
        import ctypes
        ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)
    except Exception:
        pass


# --------------------------------------------------------------------------- engine
class Engine:
    SAVE_FLAGS = getattr(lt.save_resume_flags_t, "save_info_dict", 0) if hasattr(lt, "save_resume_flags_t") else 0

    def __init__(self, cfg: dict):
        self.cfg = cfg
        RESUME_DIR.mkdir(parents=True, exist_ok=True)
        self.pending_saves = 0
        self.on_message = lambda text, level="info": None
        self.on_finished = lambda handle: None
        self.blocked_ranges = 0
        self.seed_override = set()  # torrents the user resumed after the seeding limit
        self._rand_port = None
        self.scans = {}
        self.prechecks = {}  # key -> name-based inspector findings (before download)
        self.external_ip = None  # public IP as reported back by trackers / peers
        # DNS guard
        self.dns = dnsguard.DnsGuard()
        self.resolver = dnsguard.Resolver(self.dns)
        self.orig_trackers = {}  # key -> [(url, tier)] as the torrent really lists them
        self.orig_seeds = {}  # key -> web seed URLs (dropped while guarded)
        self._pending_flags = {}  # key -> (was_paused, was_auto_managed) for torrents added held
        self._vpn_dns = {}  # adapter name -> its DNS server
        self._bootstrap = ""
        self._guarding = False
        if not cfg.get("incognito"):
            try:
                self.scans = json.loads(SCANS_FILE.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                pass

        # decide the network state BEFORE the session exists, so nothing can leak at startup
        self.lock_reason = None  # None | "down" (kill switch) | "nobind" (strict mode)
        self.bound_ip = self.bound_name = None
        if cfg.get("bind_interface"):
            if cfg["bind_interface"] == AUTO_VPN:
                adapter_descriptions()  # identify adapters up front so startup isn't blocked
            self.bound_name, self.bound_ip = self._resolve_binding()
            if self.bound_ip is None:
                self.lock_reason = "down"
        elif cfg.get("strict_mode") and not self._proxy_on():
            self.lock_reason = "nobind"
        if self.guard_active and self.bound_ip:  # ready the guard before the engine exists
            self._configure_dns(self.bound_name, self.bound_ip, blocking=True)
        self._guarding = self.guard_active
        self.session = lt.session(self._settings())
        if self.locked:
            self.session.pause()
        self._load_resume_files()

    @property
    def locked(self) -> bool:
        return self.lock_reason is not None

    @property
    def port(self) -> int:
        if self.cfg.get("random_port"):
            if not self._rand_port:
                self._rand_port = secrets.SystemRandom().randint(20000, 60999)
            return self._rand_port
        return int(self.cfg["listen_port"])

    @property
    def guard_active(self) -> bool:
        """DNS guard applies whenever traffic is meant to go through a VPN adapter."""
        return bool(self.cfg.get("dns_guard", True) and self.cfg.get("bind_interface") and not self._proxy_on())

    def _configure_dns(self, name, ip, blocking=False) -> None:
        server = self._vpn_dns.get(name)
        if server is None:
            if blocking:
                self._vpn_dns[name] = server = (privacy_check.dns_servers().get(name) or [None])[0]
            else:
                self._vpn_dns[name] = None

                def work():
                    srv = (privacy_check.dns_servers().get(name) or [None])[0]
                    self._vpn_dns[name] = srv
                    self.dns.configure(ip, srv)

                threading.Thread(target=work, daemon=True).start()
        changed = self.dns.configure(ip, server)
        if changed:
            for key, trackers in self.orig_trackers.items():  # relay moved: rewrite every torrent again
                self.resolver.submit(key, trackers)
            if blocking:
                self._bootstrap = self.dns.bootstrap_nodes()
            else:
                def boot():
                    self._bootstrap = self.dns.bootstrap_nodes()
                    self._bootstrap_dirty = True
                threading.Thread(target=boot, daemon=True).start()

    def _proxy_on(self) -> bool:
        return self.cfg.get("proxy_type", "none") != "none" and bool(self.cfg.get("proxy_host"))

    def _settings(self) -> dict:
        c = self.cfg
        port = self.port
        s = {
            "user_agent": f"{APP_NAME}/{APP_VERSION}",
            "enable_dht": bool(c["enable_dht"]),
            "enable_lsd": bool(c["enable_lsd"]),
            "enable_upnp": bool(c["enable_upnp"]),
            "enable_natpmp": bool(c["enable_upnp"]),
            "download_rate_limit": int(c["max_download_kbps"]) * 1024,
            "upload_rate_limit": int(c["max_upload_kbps"]) * 1024,
            "anonymous_mode": bool(c["anonymous_mode"]),
            "active_downloads": max(1, int(c.get("max_active_downloads", 3))),
            "active_seeds": max(1, int(c.get("max_active_seeds", 5))),
            "active_limit": max(1, int(c.get("max_active_downloads", 3))) + max(1, int(c.get("max_active_seeds", 5))),
            "validate_https_trackers": True,
            "ssrf_mitigation": True,
            "allow_idna": False,
            "alert_mask": (
                lt.alert.category_t.error_notification
                | lt.alert.category_t.status_notification
                | lt.alert.category_t.storage_notification
            ),
        }
        # encryption: 0 = forced, 1 = enabled; level 2 = rc4 only, 3 = rc4 or plaintext
        if c["force_encryption"]:
            s.update(out_enc_policy=0, in_enc_policy=0, allowed_enc_level=2, prefer_rc4=True)
        else:
            s.update(out_enc_policy=1, in_enc_policy=1, allowed_enc_level=3, prefer_rc4=False)

        if self._proxy_on():
            has_auth = bool(c.get("proxy_user"))
            s.update(
                proxy_type={"socks5": 3 if has_auth else 2, "http": 5 if has_auth else 4}[c["proxy_type"]],
                proxy_hostname=c["proxy_host"],
                proxy_port=int(c["proxy_port"]),
                proxy_username=c.get("proxy_user", ""),
                proxy_password=unprotect_secret(c.get("proxy_pass", "")),
                proxy_peer_connections=True,
                proxy_tracker_connections=True,
                proxy_hostnames=True,
            )
        else:
            s["proxy_type"] = 0

        if c.get("i2p_enabled"):
            s.update(i2p_hostname=c.get("i2p_host") or "127.0.0.1", i2p_port=int(c.get("i2p_port") or 7656),
                     allow_i2p_mixed=bool(c.get("i2p_mixed")))
        else:
            s.update(i2p_hostname="", allow_i2p_mixed=False)

        if self.guard_active:
            s["dht_bootstrap_nodes"] = self._bootstrap  # IPs found through the VPN's DNS ("" until then)

        if self.locked:  # lockdown: loopback only, no discovery of any kind
            s.update(listen_interfaces=f"127.0.0.1:{port}", outgoing_interfaces="127.0.0.1",
                     enable_dht=False, enable_lsd=False, enable_upnp=False, enable_natpmp=False)
        elif self.bound_ip:
            s.update(listen_interfaces=f"{self.bound_ip}:{port}", outgoing_interfaces=self.bound_ip)
        else:
            s.update(listen_interfaces=f"0.0.0.0:{port},[::]:{port}", outgoing_interfaces="")
        return s

    def apply_settings(self) -> None:
        self.session.apply_settings(self._settings())

    # ---- kill switch / strict mode
    def _lock(self, reason: str, message: str) -> None:
        if self.lock_reason != reason:
            self.lock_reason = reason
            self.apply_settings()
            self.session.pause()
            self.on_message(message, "error")

    def _unlock(self, ip) -> None:
        if self.locked or ip != self.bound_ip:
            was = self.lock_reason
            self.lock_reason, self.bound_ip = None, ip
            self.external_ip = None  # new route, new public address
            self.apply_settings()
            self.session.resume()
            if was == "down":
                self.on_message(f"VPN '{self.bound_name}' connected ({ip}) — resumed", "ok")

    def _resolve_binding(self):
        name = self.cfg.get("bind_interface") or ""
        if name == AUTO_VPN:
            return find_vpn_adapter()
        return name, interface_ipv4(name)

    def guard(self) -> str:
        """Enforce kill switch + strict mode. Returns 'up', 'any', 'down' or 'nobind'."""
        name = self.cfg.get("bind_interface") or ""
        if name:
            vname, ip = self._resolve_binding()
            if ip is None:
                what = "No VPN connected" if name == AUTO_VPN else f"'{name}' is down"
                self._lock("down", f"Kill switch: {what} — all traffic stopped")
                return "down"
            self.bound_name = vname
            if self.guard_active:
                self._configure_dns(vname, ip)
            self._unlock(ip)
            return "up"
        if self.cfg.get("strict_mode") and not self._proxy_on():
            self._lock("nobind", "Strict mode: choose your VPN adapter in Settings → Network")
            return "nobind"
        self._unlock(None)
        return "any"

    def set_blocklist(self, ranges: list) -> None:
        f = lt.ip_filter()
        for a, b in ranges:
            try:
                f.add_rule(a, b, 1)
            except Exception:
                pass
        self.session.set_ip_filter(f)
        self.blocked_ranges = len(ranges)

    # ---- adding
    def _add(self, atp) -> None:
        if not atp.save_path:
            atp.save_path = self.cfg["download_dir"]
        Path(atp.save_path).mkdir(parents=True, exist_ok=True)
        if self.guard_active:
            # Add it held (paused, not queued) so the engine can't contact any tracker by name before
            # the guard has swapped the names for VPN-resolved addresses.
            key = atp_key(atp)
            flags = atp.flags
            self._pending_flags[key] = (bool(flags & lt.torrent_flags.paused),
                                        bool(flags & lt.torrent_flags.auto_managed))
            atp.flags = (flags | lt.torrent_flags.paused) & ~lt.torrent_flags.auto_managed
            atp.dht_nodes = []  # "nodes" given as host names would need Windows DNS
            # Web seeds are looked up the moment a torrent is added (even held), so remove them first.
            # (Trackers aren't contacted while held; they're swapped right after the add.)
            seeds = list(atp.url_seeds)
            if atp.ti:
                seeds += [w["url"] for w in atp.ti.web_seeds() if w.get("type", 0) == 0]
                atp.ti.set_web_seeds([])
            atp.url_seeds = []
            atp.http_seeds = []
            self.orig_seeds[key] = list(dict.fromkeys(seeds))
        self.session.async_add_torrent(atp)

    def _guard_new_torrent(self, h) -> None:
        key = torrent_key(h)
        held = self._pending_flags.pop(key, None)
        self._strip(h, key)
        if held:
            was_paused, was_auto = held
            if was_auto:
                h.set_flags(lt.torrent_flags.auto_managed)
            if not was_paused:
                h.resume()

    def _strip(self, h, key) -> None:
        """Take every host name away from the engine; queue the VPN-side rewrite."""
        if key not in self.orig_trackers:
            self.orig_trackers[key] = [(t["url"], t["tier"]) for t in h.trackers()]
            self.orig_seeds[key] = list(dict.fromkeys(self.orig_seeds.get(key, []) + list(h.url_seeds())))
        h.replace_trackers([])
        for u in h.url_seeds():
            h.remove_url_seed(u)
        for u in h.http_seeds():
            h.remove_http_seed(u)
        if self.orig_trackers[key]:
            self.resolver.submit(key, self.orig_trackers[key])

    def _unstrip(self, h, key) -> None:
        trackers = self.orig_trackers.pop(key, [])
        entries = []
        for url, tier in trackers:
            ae = lt.announce_entry(url)
            ae.tier = tier
            entries.append(ae)
        h.replace_trackers(entries)
        for u in self.orig_seeds.pop(key, []):
            h.add_url_seed(u)

    def sync_guard(self) -> None:
        """Turn the guard on/off for torrents already loaded (settings or binding changed)."""
        active = self.guard_active
        if active == self._guarding:
            return
        self._guarding = active
        for h in self.handles():
            key = torrent_key(h)
            if active:
                self._strip(h, key)
            elif key in self.orig_trackers:
                self._unstrip(h, key)
        if not active:
            self._bootstrap = ""
        elif self.dns.ready:
            def boot():
                self._bootstrap = self.dns.bootstrap_nodes()
                self._bootstrap_dirty = True
            threading.Thread(target=boot, daemon=True).start()
        self.apply_settings()
        if not active:
            self.session.apply_settings({"dht_bootstrap_nodes": lt.default_settings()["dht_bootstrap_nodes"]})

    def process_guard_results(self) -> None:
        if getattr(self, "_bootstrap_dirty", False):
            self._bootstrap_dirty = False
            if self.guard_active:
                self.session.apply_settings({"dht_bootstrap_nodes": self._bootstrap})
        while True:
            try:
                key, safe = self.resolver.results.get_nowait()
            except Exception:
                return
            h = self.find(key)
            if not h or key not in self.orig_trackers or not self._guarding:
                continue
            entries = []
            for url, tier in safe:
                ae = lt.announce_entry(url)
                ae.tier = tier
                entries.append(ae)
            h.replace_trackers(entries)

    def original_trackers(self, h) -> list:
        key = torrent_key(h)
        if key in self.orig_trackers:
            return [u for u, _ in self.orig_trackers[key]]
        return [t["url"] for t in h.trackers()]

    def magnet_link(self, h) -> str:
        """Magnet with the torrent's real tracker names (not the guard's internal addresses)."""
        from urllib.parse import quote
        base = lt.make_magnet_uri(h).split("&tr=")[0]
        return base + "".join(f"&tr={quote(u, safe='')}" for u in self.original_trackers(h))

    def add_torrent_file(self, path: str, save_path: str = "") -> None:
        atp = lt.add_torrent_params()
        atp.ti = lt.torrent_info(path)
        if save_path:
            atp.save_path = save_path
        self._add(atp)

    def add_magnet(self, uri: str) -> None:
        self._add(lt.parse_magnet_uri(uri))

    def _load_resume_files(self) -> None:
        for f in RESUME_DIR.glob("*.fastresume"):
            try:
                self._add(lt.read_resume_data(f.read_bytes()))
            except Exception as e:
                print(f"Could not load {f.name}: {e}", file=sys.stderr)

    # ---- control
    def handles(self):
        return [h for h in self.session.get_torrents() if h.is_valid()]

    def find(self, key: str):
        for h in self.handles():
            if torrent_key(h) == key:
                return h
        return None

    def save_resume(self, h) -> None:
        if not self.cfg.get("incognito"):
            h.save_resume_data(self.SAVE_FLAGS)

    def pause(self, h) -> None:
        h.unset_flags(lt.torrent_flags.auto_managed)
        h.pause()
        self.save_resume(h)

    def resume(self, h) -> None:
        if h.status().is_seeding:
            self.seed_override.add(torrent_key(h))
        h.set_flags(lt.torrent_flags.auto_managed)
        h.resume()

    def remove(self, h, delete_files: bool) -> None:
        key = torrent_key(h)
        opts = 0
        if delete_files:
            opts = getattr(lt.options_t, "delete_files", None) if hasattr(lt, "options_t") else None
            opts = opts if opts is not None else lt.session.delete_files
        self.session.remove_torrent(h, opts)
        self.orig_trackers.pop(key, None)
        self.orig_seeds.pop(key, None)
        (RESUME_DIR / f"{key}.fastresume").unlink(missing_ok=True)
        if self.scans.pop(key, None):
            self.save_scans()

    def force_start(self, h) -> None:
        """Start now, ignoring the queue limits."""
        h.unset_flags(lt.torrent_flags.auto_managed)
        h.resume()

    def queue_move(self, h, where: str) -> None:
        if h.status().queue_position < 0:
            return  # seeding torrents aren't queued
        {"top": h.queue_position_top, "up": h.queue_position_up, "down": h.queue_position_down,
         "bottom": h.queue_position_bottom}[where]()

    def toggle_sequential(self, h) -> bool:
        on = not bool(h.status().flags & lt.torrent_flags.sequential_download)
        if on:
            h.set_flags(lt.torrent_flags.sequential_download)
        else:
            h.unset_flags(lt.torrent_flags.sequential_download)
        self.save_resume(h)
        return on

    def enforce_seed_limits(self) -> None:
        ratio_lim = float(self.cfg.get("stop_seeding_ratio") or 0)
        min_lim = float(self.cfg.get("stop_seeding_minutes") or 0)
        if not ratio_lim and not min_lim:
            return
        for h in self.handles():
            st = h.status()
            if not st.is_seeding or is_paused(st) or torrent_key(h) in self.seed_override:
                continue
            ratio_hit = ratio_lim and share_ratio(st) >= ratio_lim
            time_hit = min_lim and duration_seconds(st.seeding_duration) >= min_lim * 60
            if ratio_hit or time_hit:
                self.pause(h)
                self.on_message(f"Stopped seeding '{st.name}' — {'ratio' if ratio_hit else 'time'} limit reached", "ok")

    # ---- history
    def save_scans(self) -> None:
        if not self.cfg.get("incognito"):
            STATE_DIR.mkdir(parents=True, exist_ok=True)
            SCANS_FILE.write_text(json.dumps(self.scans), encoding="utf-8")

    def wipe_history_files(self) -> None:
        for f in RESUME_DIR.glob("*"):
            f.unlink(missing_ok=True)
        SCANS_FILE.unlink(missing_ok=True)

    def clear_history(self) -> None:
        """Forget every torrent (downloaded files are kept) and erase saved history."""
        for h in self.handles():
            self.session.remove_torrent(h)
        self.orig_trackers.clear()
        self.orig_seeds.clear()
        self.scans.clear()
        self.seed_override.clear()
        self.wipe_history_files()

    # ---- persistence / alerts
    def request_save_all(self, only_dirty: bool = True) -> None:
        if self.cfg.get("incognito"):
            return
        for h in self.handles():
            if only_dirty and not h.need_save_resume_data():
                continue
            h.save_resume_data(self.SAVE_FLAGS)
            self.pending_saves += 1

    def _check_risky(self, h, fresh: bool = True) -> None:
        """Name-based inspection as soon as the file list is known. Dangerous files are skipped
        before they download (only for newly added torrents, so the user's own choices stick)."""
        ti = h.torrent_file()
        if not ti:
            return
        fs = ti.files()
        files = [(path, size) for _, path, size in real_files(fs)]
        findings = inspector.check_names(files)
        key = torrent_key(h)
        self.prechecks[key] = findings
        if not findings or not fresh:
            return
        name = h.status().name
        index = {path: i for i, path, _ in real_files(fs)}
        bad = [f for f in findings if f["level"] == inspector.THREAT]
        if bad and self.cfg.get("block_suspicious_files", True):
            prios = list(h.get_file_priorities())
            for f in bad:
                prios[index[f["file"]]] = 0
            h.prioritize_files(prios)
            self.on_message(
                f"🛡 Blocked {len(bad)} dangerous file(s) in '{name}' before download:\n\n"
                + "\n".join(f"• {Path(f['file']).name}: {f['reason']}" for f in bad[:6])
                + ("\n…" if len(bad) > 6 else "")
                + "\n\nThe rest of the torrent downloads normally. This torrent may be fake.", "warn")
        elif bad:
            self.on_message(f"⚠ '{name}' contains dangerous file(s), e.g. {Path(bad[0]['file']).name}: "
                            f"{bad[0]['reason']}", "warn")
        else:
            self.on_message(f"'{name}' contains {len(findings)} program/script file(s) — only run them if you "
                            f"trust the source", "info")

    def process_alerts(self) -> None:
        for a in self.session.pop_alerts():
            if isinstance(a, lt.save_resume_data_alert):
                self.pending_saves = max(0, self.pending_saves - 1)
                if not self.cfg.get("incognito") and a.handle.is_valid():
                    key = torrent_key(a.handle)
                    params = a.params
                    if key in self.orig_trackers:  # store the real tracker names, never the guard's rewrites
                        params.trackers = [u for u, _ in self.orig_trackers[key]]
                        params.tracker_tiers = [t for _, t in self.orig_trackers[key]]
                        params.url_seeds = self.orig_seeds.get(key, [])
                        if key in self._pending_flags:
                            continue
                    (RESUME_DIR / f"{key}.fastresume").write_bytes(lt.write_resume_data_buf(params))
            elif isinstance(a, lt.save_resume_data_failed_alert):
                self.pending_saves = max(0, self.pending_saves - 1)
            elif isinstance(a, lt.add_torrent_alert):
                if a.error.value():
                    self.on_message(f"Could not add torrent: {a.error.message()}", "error")
                else:
                    resumed = (RESUME_DIR / f"{torrent_key(a.handle)}.fastresume").exists()
                    if self.guard_active:
                        self._guard_new_torrent(a.handle)
                    self.save_resume(a.handle)
                    self._check_risky(a.handle, fresh=not resumed)
            elif isinstance(a, lt.metadata_received_alert):
                self.save_resume(a.handle)
                self._check_risky(a.handle)
            elif isinstance(a, lt.torrent_finished_alert):
                self.save_resume(a.handle)
                self.on_finished(a.handle)
            elif isinstance(a, lt.external_ip_alert):
                self.external_ip = str(a.external_address)
            elif isinstance(a, (lt.torrent_error_alert, lt.file_error_alert)):
                self.on_message(a.message(), "error")

    def shutdown(self, timeout: float = 5.0) -> None:
        self.session.pause()
        self.pending_saves = 0
        self.request_save_all(only_dirty=False)
        deadline = time.time() + timeout
        while self.pending_saves > 0 and time.time() < deadline:
            self.session.wait_for_alert(250)
            self.process_alerts()
        if self.cfg.get("incognito"):
            self.wipe_history_files()


# --------------------------------------------------------------------------- UI helpers
def dark_title_bar(win) -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes
        win.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(win.winfo_id())
        val = ctypes.c_int(1)
        for attr in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (new / old builds)
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(val), 4) == 0:
                break
    except Exception:
        pass


class DarkDialog(tk.Toplevel):
    """Modal dialog with themed background and dark title bar."""

    def __init__(self, parent, title):
        super().__init__(parent)
        self.withdraw()
        self.title(title)
        self.transient(parent)
        self.resizable(False, False)
        self.configure(bg=BG)
        self.result = None
        self.body = ttk.Frame(self, padding=18)
        self.body.pack(fill="both", expand=True)
        self.bind("<Escape>", lambda e: self.destroy())

    def show(self):
        dark_title_bar(self)
        self.update_idletasks()
        p = self.master
        x = p.winfo_rootx() + (p.winfo_width() - self.winfo_reqwidth()) // 2
        y = p.winfo_rooty() + (p.winfo_height() - self.winfo_reqheight()) // 3
        x = min(max(x, 0), self.winfo_screenwidth() - self.winfo_reqwidth())
        y = min(max(y, 0), self.winfo_screenheight() - self.winfo_reqheight() - 60)
        self.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        self.deiconify()
        self.grab_set()
        self.wait_window()
        return self.result

    def buttons(self, ok_text="OK", on_ok=None, extra=None):
        row = ttk.Frame(self.body)
        if self.body.grid_slaves():  # dialog body laid out with grid
            row.grid(row=999, column=0, columnspan=10, sticky="ew", pady=(16, 0))
        else:
            row.pack(fill="x", pady=(16, 0), side="bottom")
        ttk.Button(row, text="Cancel", command=self.destroy).pack(side="right")
        ttk.Button(row, text=ok_text, style="Accent.TButton", command=on_ok).pack(side="right", padx=8)
        for text, cmd in extra or []:
            ttk.Button(row, text=text, command=cmd).pack(side="left")
        self.bind("<Return>", lambda e: on_ok())


class Tooltip:
    def __init__(self, widget, text):
        self.widget, self.text, self.tip = widget, text, None
        widget.bind("<Enter>", self.show, add="+")
        widget.bind("<Leave>", self.hide, add="+")
        widget.bind("<ButtonPress>", self.hide, add="+")

    def show(self, _e=None):
        if self.tip:
            return
        x = self.widget.winfo_rootx()
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        tk.Label(self.tip, text=self.text, bg="#2b2b2b", fg=FG, padx=8, pady=4, font=("Segoe UI", 9),
                 relief="solid", borderwidth=1).pack()

    def hide(self, _e=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


def show_shortcuts(parent):
    d = DarkDialog(parent, "Keyboard shortcuts")
    ttk.Label(d.body, text="Keyboard shortcuts", style="Title.TLabel").grid(row=0, column=0, columnspan=2, sticky="w",
                                                                          pady=(0, 10))
    for r, (keys, what) in enumerate(SHORTCUTS, 1):
        ttk.Label(d.body, text=keys, font=("Segoe UI Semibold", 10), foreground=ACCENT).grid(
            row=r, column=0, sticky="w", padx=(0, 18), pady=1)
        ttk.Label(d.body, text=what).grid(row=r, column=1, sticky="w", pady=1)
    row = ttk.Frame(d.body)
    row.grid(row=len(SHORTCUTS) + 1, column=0, columnspan=2, sticky="e", pady=(14, 0))
    ttk.Button(row, text="Close", style="Accent.TButton", command=d.destroy).pack()
    d.bind("<Return>", lambda e: d.destroy())
    d.show()


def ask_string(parent, title, prompt, initial=""):
    d = DarkDialog(parent, title)
    ttk.Label(d.body, text=prompt).pack(anchor="w")
    var = tk.StringVar(value=initial)
    entry = ttk.Entry(d.body, textvariable=var, width=70)
    entry.pack(fill="x", pady=(6, 0))
    entry.focus_set()
    entry.select_range(0, "end")

    def ok():
        d.result = var.get().strip()
        d.destroy()

    d.buttons("Add", ok)
    return d.show()


class SpeedLimitDialog(DarkDialog):
    """Set-and-forget speed limits (saved, applied to everything)."""

    def __init__(self, app):
        super().__init__(app.root, "Speed limits")
        self.app = app
        ttk.Label(self.body, text="Speed limits", style="Title.TLabel").grid(row=0, column=0, columnspan=3, sticky="w")
        ttk.Label(self.body, text="Set them once; Hushwing remembers them. 0 = unlimited.", foreground=MUTED).grid(
            row=1, column=0, columnspan=3, sticky="w", pady=(2, 12))
        self.vars = {}
        for r, (key, label) in enumerate((("max_download_kbps", "↓ Download"), ("max_upload_kbps", "↑ Upload")), 2):
            ttk.Label(self.body, text=label).grid(row=r, column=0, sticky="w", padx=(0, 12), pady=4)
            v = tk.StringVar(value=f"{int(app.cfg[key]) / 1024:g}")
            e = ttk.Entry(self.body, textvariable=v, width=10)
            e.grid(row=r, column=1, sticky="w", pady=4)
            ttk.Label(self.body, text="MB/s", foreground=MUTED).grid(row=r, column=2, sticky="w", padx=6)
            self.vars[key] = v
            if r == 2:
                e.focus_set()
                e.select_range(0, "end")
        presets = ttk.Frame(self.body)
        presets.grid(row=4, column=0, columnspan=3, sticky="w", pady=(10, 0))
        for text, d, u in (("Unlimited", 0, 0), ("1 MB/s", 1, 0.25), ("5 MB/s", 5, 1), ("10 MB/s", 10, 2)):
            ttk.Button(presets, text=text, command=lambda d=d, u=u: (self.vars["max_download_kbps"].set(f"{d:g}"),
                                                                     self.vars["max_upload_kbps"].set(f"{u:g}"))
                       ).pack(side="left", padx=(0, 6))
        self.buttons("Save", self._ok)

    def _ok(self):
        try:
            out = {k: int(round(float(v.get().strip() or 0) * 1024)) for k, v in self.vars.items()}
            if min(out.values()) < 0:
                raise ValueError
        except ValueError:
            messagebox.showerror(APP_NAME, "Enter a number of MB/s (0 = unlimited).", parent=self)
            return
        self.result = out
        self.destroy()


class PrivacyCheckDialog(DarkDialog):
    ICONS = {"ok": ("✓", GREEN), "warn": ("⚠", YELLOW), "fail": ("✕", RED), "info": ("ℹ", BLUE)}

    def __init__(self, app):
        super().__init__(app.root, "Privacy check")
        self.app = app
        top = ttk.Frame(self.body)
        top.pack(fill="x")
        if app.logo_small:
            ttk.Label(top, image=app.logo_small).pack(side="left", padx=(0, 10))
        ttk.Label(top, text="Privacy check", style="Title.TLabel").pack(side="left")
        ttk.Label(self.body, text="Checks run on this PC only. Nothing is sent to any outside service.",
                  foreground=MUTED).pack(anchor="w", pady=(4, 10))
        self.rows = ttk.Frame(self.body, width=620)
        self.rows.pack(fill="both", expand=True)
        self.buttons("Run again", self.run, extra=[])
        self.run()

    def run(self):
        for w in self.rows.winfo_children():
            w.destroy()
        ttk.Label(self.rows, text="Checking… (the DNS test takes a few seconds)", foreground=MUTED).pack(anchor="w")
        e = self.app.engine
        ifaces, descs = list_interfaces(), (adapter_descriptions() or {})
        vpn_names = {n for n in ifaces if is_vpn_adapter(n, descs.get(n, ""))}
        guard = None
        if e.guard_active:
            guard = dict(server=e.dns.dns_server, lookups=e.dns.lookups, relayed=e.dns.relayed,
                         ready=e.dns.ready, torrents=len(e.orig_trackers))
        args = (e.bound_name, e.bound_ip, e.locked, e.external_ip, False, e._proxy_on(), vpn_names, guard)

        def work():
            try:
                res = privacy_check.run(*args)
            except Exception as ex:
                res = [("fail", "Check failed", str(ex))]
            try:
                self.after(0, self.show_results, res)
            except tk.TclError:
                pass

        threading.Thread(target=work, daemon=True).start()

    def show_results(self, res):
        for w in self.rows.winfo_children():
            w.destroy()
        worst = "ok"
        for status, title, detail in res:
            icon, color = self.ICONS.get(status, ("•", FG))
            if status == "fail" or (status == "warn" and worst != "fail"):
                worst = status
            row = ttk.Frame(self.rows)
            row.pack(fill="x", pady=5, anchor="w")
            ttk.Label(row, text=icon, foreground=color, font=("Segoe UI Semibold", 13), width=2).pack(side="left", anchor="n")
            col = ttk.Frame(row)
            col.pack(side="left", fill="x", expand=True)
            ttk.Label(col, text=title, font=("Segoe UI Semibold", 10)).pack(anchor="w")
            if detail:
                ttk.Label(col, text=detail, foreground=MUTED, wraplength=560, justify="left").pack(anchor="w")
        verdict = {"ok": ("Everything checks out.", GREEN), "warn": ("Mostly good, see the warning above.", YELLOW),
                   "fail": ("Your IP may be exposed. Fix the red item above.", RED)}[worst]
        ttk.Label(self.rows, text=verdict[0], foreground=verdict[1], font=("Segoe UI Semibold", 11)).pack(
            anchor="w", pady=(10, 0))
        self.app.last_privacy_verdict = worst


class CreateTorrentDialog(DarkDialog):
    def __init__(self, app):
        super().__init__(app.root, "Create torrent")
        self.app = app
        b = self.body
        ttk.Label(b, text="Create a torrent", style="Title.TLabel").grid(row=0, column=0, columnspan=4, sticky="w")
        ttk.Label(b, text="Share your own files. Hushwing leaves out the creator tag and creation date, so the "
                          "torrent doesn't reveal what made it or when.", foreground=MUTED, wraplength=560).grid(
            row=1, column=0, columnspan=4, sticky="w", pady=(2, 12))
        ttk.Label(b, text="File or folder").grid(row=2, column=0, sticky="w", padx=(0, 12))
        self.src = tk.StringVar()
        ttk.Entry(b, textvariable=self.src, width=46).grid(row=2, column=1, sticky="w")
        ttk.Button(b, text="File…", command=self._pick_file).grid(row=2, column=2, padx=(8, 0))
        ttk.Button(b, text="Folder…", command=self._pick_dir).grid(row=2, column=3, padx=(6, 0))
        ttk.Label(b, text="Trackers").grid(row=3, column=0, sticky="nw", padx=(0, 12), pady=(10, 0))
        self.trackers = tk.Text(b, width=58, height=5, bg=PANEL, fg=FG, insertbackground=FG, relief="flat",
                                font=("Consolas", 9), highlightthickness=1, highlightbackground="#333")
        self.trackers.grid(row=3, column=1, columnspan=3, sticky="w", pady=(10, 0))
        ttk.Label(b, text="One per line. Leave empty for a DHT-only torrent.", foreground=MUTED).grid(
            row=4, column=1, columnspan=3, sticky="w")
        ttk.Label(b, text="Comment").grid(row=5, column=0, sticky="w", padx=(0, 12), pady=(8, 0))
        self.comment = tk.StringVar()
        ttk.Entry(b, textvariable=self.comment, width=46).grid(row=5, column=1, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Label(b, text="Format").grid(row=6, column=0, sticky="w", padx=(0, 12), pady=(8, 0))
        self.fmt = ttk.Combobox(b, state="readonly", width=44, values=[
            "Hybrid v1 + v2 (recommended)", "v1 only (works with very old clients)"])
        self.fmt.current(0)
        self.fmt.grid(row=6, column=1, columnspan=3, sticky="w", pady=(8, 0))
        self.private = tk.BooleanVar(value=False)
        ttk.Checkbutton(b, text="Private torrent (only via its trackers: no DHT or peer exchange)",
                        variable=self.private).grid(row=7, column=1, columnspan=3, sticky="w", pady=(8, 0))
        self.seed = tk.BooleanVar(value=True)
        ttk.Checkbutton(b, text="Start seeding it now", variable=self.seed).grid(
            row=8, column=1, columnspan=3, sticky="w", pady=(4, 0))
        self.progress = ttk.Progressbar(b, length=430, maximum=1.0)
        self.progress.grid(row=9, column=1, columnspan=3, sticky="w", pady=(12, 0))
        self.status = ttk.Label(b, text="", foreground=MUTED)
        self.status.grid(row=10, column=1, columnspan=3, sticky="w")
        self.busy = False
        self.buttons("Create…", self._create)

    def _pick_file(self):
        f = filedialog.askopenfilename(parent=self, title="Choose a file to share")
        if f:
            self.src.set(os.path.normpath(f))

    def _pick_dir(self):
        d = filedialog.askdirectory(parent=self, title="Choose a folder to share")
        if d:
            self.src.set(os.path.normpath(d))

    def _create(self):
        if self.busy:
            return
        src = self.src.get().strip().strip('"')
        if not src or not os.path.exists(src):
            messagebox.showerror(APP_NAME, "Choose a file or folder first.", parent=self)
            return
        name = Path(src).name
        out = filedialog.asksaveasfilename(parent=self, title="Save torrent as", defaultextension=".torrent",
                                           initialfile=f"{name}.torrent", filetypes=[("Torrent", "*.torrent")])
        if not out:
            return
        trackers = [t.strip() for t in self.trackers.get("1.0", "end").splitlines()]
        opts = dict(trackers=trackers, comment=self.comment.get().strip(), private=self.private.get(),
                    v1_only=self.fmt.current() == 1)
        seed = self.seed.get()
        self.busy = True
        self.status.configure(text="Hashing files…", foreground=MUTED)

        def progress(piece, total):
            try:
                self.after(0, lambda: self.progress.configure(value=piece / max(total, 1)))
            except tk.TclError:
                pass

        def work():
            try:
                make_torrent(src, out, progress=progress, **opts)
                self.after(0, self._done, out, src, seed, None)
            except Exception as ex:
                self.after(0, self._done, out, src, seed, str(ex))

        threading.Thread(target=work, daemon=True).start()

    def _done(self, out, src, seed, err):
        self.busy = False
        if err:
            self.status.configure(text=f"Failed: {err}", foreground=RED)
            return
        if seed:
            self.app.engine.add_torrent_file(out, save_path=str(Path(src).parent))
        self.app.flash(f"Created {Path(out).name}" + (" and started seeding" if seed else ""), "ok")
        self.result = out
        self.destroy()


def make_torrent(src: str, out: str, trackers=(), comment="", private=False, v1_only=False, progress=None):
    fs = lt.file_storage()
    src_path = Path(src)
    lt.add_files(fs, str(src_path), lambda p: not Path(p).name.startswith((".", "~$")) and
                 Path(p).name.lower() not in ("thumbs.db", "desktop.ini"))
    if fs.num_files() == 0:
        raise ValueError("There are no files to share in that folder.")
    flags = lt.create_torrent.v1_only if v1_only else 0
    ct = lt.create_torrent(fs, 0, flags)
    tier = 0
    for t in trackers:
        if not t:
            tier += 1
            continue
        if not t.lower().startswith(("http://", "https://", "udp://")):
            raise ValueError(f"Not a tracker URL: {t}")
        ct.add_tracker(t, tier)
    if comment:
        ct.set_comment(comment)
    ct.set_priv(bool(private))
    ct.set_creator("")
    total = ct.num_pieces()
    lt.set_piece_hashes(ct, str(src_path.parent), lambda i: progress and progress(i + 1, total))
    data = ct.generate()
    data.pop(b"creation date", None)
    data.pop(b"created by", None)
    Path(out).write_bytes(lt.bencode(data))


SHORTCUTS = [
    ("Ctrl+O", "Add .torrent file"), ("Ctrl+M", "Add magnet link"), ("Ctrl+V", "Paste magnet link"),
    ("Ctrl+N", "Create a torrent"), ("Drag & drop", "Drop .torrent files or magnet links on the window"),
    ("Ctrl+A", "Select all torrents"), ("Ctrl+R", "Resume selected"), ("Ctrl+P", "Pause selected"),
    ("Ctrl+S", "Force start selected (skip the queue)"), ("Ctrl+↑ / Ctrl+↓", "Move up / down in the queue"),
    ("Delete", "Remove (keep files)"), ("Shift+Delete", "Remove and delete files"),
    ("Enter / Ctrl+E", "Open folder"), ("Ctrl+F", "Search"), ("Ctrl+L", "Speed limits"),
    ("Ctrl+I", "Privacy check"), ("Ctrl+,", "Settings"), ("F1", "This list"), ("Ctrl+Q", "Quit"),
]


class SettingsDialog(DarkDialog):
    def __init__(self, app, cfg):
        super().__init__(app.root, "Settings")
        self.app = app
        self.cfg = dict(cfg)
        self.v = {}
        self.mbs_keys = set()
        nb = ttk.Notebook(self.body)
        nb.pack(fill="both", expand=True)

        def tab(title):
            f = ttk.Frame(nb, padding=16)
            f.columnconfigure(1, weight=1)
            nb.add(f, text=f"  {title}  ")
            return f

        # -- General
        g = tab("General")
        self._entry(g, 0, "Download folder", "download_dir", width=44)
        ttk.Button(g, text="Browse…", command=self._browse_dir).grid(row=0, column=2, padx=(8, 0))
        self._mbs(g, 1, "Max download speed (MB/s, 0 = unlimited)", "max_download_kbps")
        self._mbs(g, 2, "Max upload speed (MB/s, 0 = unlimited)", "max_upload_kbps")
        self._entry(g, 3, "Max active downloads", "max_active_downloads")
        self._entry(g, 4, "Max active seeding torrents", "max_active_seeds")
        self._hint(g, 5, "Extra torrents wait in the queue and start by themselves when a slot frees up.")
        self._entry(g, 6, "Stop seeding at ratio (0 = never)", "stop_seeding_ratio")
        self._entry(g, 7, "Stop seeding after minutes (0 = never)", "stop_seeding_minutes")
        self._hint(g, 8, "Less seeding means your IP sits in a swarm for less time.")
        self._check(g, 9, "Keep running in the system tray when I close the window", "close_to_tray")
        self._check(g, 10, "Show notifications", "notifications",
                    "Download finished, dangerous files blocked, VPN dropped.")
        ttk.Separator(g).grid(row=12, column=0, columnspan=3, sticky="ew", pady=12)
        ttk.Button(g, text="Make Hushwing the default for magnet links and .torrent files",
                   command=self._register_default).grid(row=13, column=0, columnspan=3, sticky="w")
        self._hint(g, 14, "Only changes settings for your Windows account. Windows may ask you to confirm in "
                          "Default Apps.")

        # -- Privacy
        p = tab("Privacy")
        self._check(p, 0, "Strict mode", "strict_mode",
                    "Never connect unless traffic is bound to a VPN adapter (or a proxy is set). "
                    "Prevents leaking your real IP if you forget to turn the VPN on.")
        self._check(p, 2, "Force encryption", "force_encryption",
                    "Only use encrypted peer connections. Hides torrent traffic from basic ISP inspection.")
        self._check(p, 4, "Anonymous mode", "anonymous_mode",
                    "Don't reveal client name/version, fingerprint or your local IP to peers and trackers.")
        self._check(p, 6, "Random port every launch", "random_port",
                    "Makes you harder to recognise across sessions. Takes effect next launch.")
        self._entry(p, 8, "Fixed port (if not random)", "listen_port")
        self._check(p, 9, "Incognito mode", "incognito",
                    "Nothing is saved. When Hushwing closes, your torrent list and history are erased "
                    "(downloaded files stay).")
        ttk.Button(p, text="Clear history now…", command=self._clear_history).grid(
            row=11, column=0, sticky="w", pady=(12, 0))
        self._check(p, 12, "DNS guard: look up tracker names only through the VPN", "dns_guard",
                    "Hushwing asks your VPN's own DNS server from inside the tunnel and never asks Windows, so "
                    "tracker lookups can't leak to your ISP. Web seeds are skipped while it's on.")

        # -- Network
        n = tab("Network")
        ttk.Label(n, text="Bind to adapter (kill switch)").grid(row=0, column=0, sticky="w")
        ifaces, descs = list_interfaces(), adapter_descriptions()
        self.iface_names = ["", AUTO_VPN] + sorted(ifaces, key=lambda k: (not is_vpn_adapter(k, descs.get(k, "")), k))
        if self.cfg["bind_interface"] and self.cfg["bind_interface"] not in self.iface_names:
            self.iface_names.append(self.cfg["bind_interface"])
        labels = ["Any adapter (no kill switch)", "Any VPN adapter — automatic (recommended)"] + [
            interface_label(x, ifaces, descs) for x in self.iface_names[2:]]
        self.iface_combo = ttk.Combobox(n, values=labels, state="readonly", width=58)
        self.iface_combo.current(self.iface_names.index(self.cfg["bind_interface"]))
        self.iface_combo.grid(row=0, column=1, columnspan=2, sticky="w")
        self._hint(n, 1, "All torrent traffic goes only through your VPN and stops instantly if it disconnects. "
                         "'Automatic' follows your VPN even when it reconnects under a new adapter name.")
        self._check(n, 2, "DHT (find peers without trackers)", "enable_dht", "Needed for most magnet links.")
        self._check(n, 4, "Local peer discovery", "enable_lsd", "Broadcasts on your local network.")
        self._check(n, 6, "UPnP / NAT-PMP port forwarding", "enable_upnp",
                    "Opens a port on your router. Off is safer; useless behind most VPNs anyway.")
        ttk.Label(n, text="IP blocklist").grid(row=8, column=0, sticky="w", pady=(12, 0))
        self.v["blocklist_path"] = tk.StringVar(value=self.cfg["blocklist_path"])
        ttk.Entry(n, textvariable=self.v["blocklist_path"], width=40).grid(row=8, column=1, sticky="w", pady=(12, 0))
        ttk.Button(n, text="Browse…", command=self._browse_blocklist).grid(row=8, column=2, padx=(8, 0), pady=(12, 0))
        ttk.Separator(n).grid(row=9, column=0, columnspan=3, sticky="ew", pady=12)
        self._check(n, 10, "I2P anonymous network", "i2p_enabled",
                    "Download I2P torrents through an I2P router running on this PC (for example i2pd). Much "
                    "slower, but nobody — not even your VPN company — can see who you are.")
        self._entry(n, 12, "I2P router (SAM) address", "i2p_host", width=16)
        self._entry(n, 13, "I2P router (SAM) port", "i2p_port")
        self._check(n, 14, "Mixed mode: also use normal peers for I2P torrents", "i2p_mixed",
                    "Faster, but those normal peers see your VPN address instead of only your I2P identity.")
        up = i2p_router_running(self.cfg["i2p_host"], self.cfg["i2p_port"])
        ttk.Label(n, text=("✓ I2P router found" if up else "No I2P router running at that address"),
                  foreground=GREEN if up else MUTED).grid(row=16, column=0, columnspan=3, sticky="w", pady=(6, 0))

        # -- Proxy
        x = tab("Proxy")
        ttk.Label(x, text="Proxy type").grid(row=0, column=0, sticky="w", pady=4)
        self.v["proxy_type"] = tk.StringVar(value=self.cfg["proxy_type"])
        ttk.Combobox(x, textvariable=self.v["proxy_type"], values=["none", "socks5", "http"],
                     state="readonly", width=10).grid(row=0, column=1, sticky="w")
        self._entry(x, 1, "Host", "proxy_host", width=30)
        self._entry(x, 2, "Port", "proxy_port")
        self._entry(x, 3, "Username", "proxy_user", width=24)
        self.v["proxy_pass"] = tk.StringVar(value=unprotect_secret(self.cfg["proxy_pass"]))
        ttk.Label(x, text="Password").grid(row=4, column=0, sticky="w", pady=4)
        ttk.Entry(x, textvariable=self.v["proxy_pass"], width=24, show="•").grid(row=4, column=1, sticky="w")
        self._hint(x, 5, "Peers, trackers and DNS lookups go through the proxy. The password is stored "
                         "encrypted with your Windows account (DPAPI).")

        # -- Safety
        s = tab("Safety")
        av = scanner_name(self.cfg)
        ttk.Label(s, text="Inspector").grid(row=0, column=0, sticky="w", padx=(0, 14))
        ttk.Label(s, text="✓ Built-in file inspector · fully offline", foreground=GREEN).grid(
            row=0, column=1, sticky="w")
        ttk.Label(s, text="Antivirus").grid(row=1, column=0, sticky="w", padx=(0, 14), pady=(4, 0))
        ttk.Label(s, text=(f"✓ {av}" if av else "None (optional)"),
                  foreground=GREEN if av else MUTED).grid(row=1, column=1, sticky="w", pady=(4, 0))
        self._hint(s, 2, "The inspector reads your files locally and never contacts anyone. It catches "
                         "programs disguised as videos, double extensions (movie.mkv.exe), fake 'codec' "
                         "installers, password-protected archives and DRM-licence scams.")
        self._check(s, 3, "Skip dangerous files before they download", "block_suspicious_files",
                    "Disguised programs and fake codecs are never downloaded. You can re-enable a file in "
                    "the Files tab.")
        self._check(s, 5, "Inspect downloads when they finish", "scan_on_complete",
                    "Torrents with dangerous files are paused immediately so you stop sharing them.")
        self._entry(s, 7, "Extra scanner (optional)", "scanner_cmd", width=48)
        self._hint(s, 8, 'Runs after the inspector. {path} becomes the download path; exit code 0 = clean.')
        self._check(s, 9, "Mark downloads as coming from the internet", "mark_of_web",
                    "Windows SmartScreen and Office Protected View then check these files when opened.")

        # -- About
        a = tab("About")
        if app.logo_big:
            ttk.Label(a, image=app.logo_big).grid(row=0, column=0, rowspan=3, sticky="nw", padx=(0, 16))
        ttk.Label(a, text=f"{APP_NAME} {APP_VERSION}", style="Title.TLabel").grid(row=0, column=1, sticky="w")
        ttk.Label(a, text=f"libtorrent {lt.__version__}  ·  Python {sys.version.split()[0]}",
                  foreground=MUTED).grid(row=1, column=1, sticky="w")
        self.update_lbl = ttk.Label(a, text="", foreground=MUTED)
        self.update_lbl.grid(row=3, column=1, sticky="w", pady=(8, 0))
        ttk.Button(a, text="Check for libtorrent security updates", command=self._check_updates).grid(
            row=2, column=1, sticky="w", pady=(12, 0))
        ttk.Button(a, text="Keyboard shortcuts", command=lambda: show_shortcuts(self)).grid(
            row=4, column=1, sticky="w", pady=(12, 0))

        self.buttons("Save", self._ok)

    # ---- widgets
    def _mbs(self, f, r, label, key):
        """Speed entry shown in MB/s, stored in KB/s."""
        self._entry(f, r, label, key)
        self.v[key].set(f"{int(self.cfg[key]) / 1024:g}")
        self.mbs_keys.add(key)

    def _entry(self, f, r, label, key, width=12, show=None):
        self.v[key] = tk.StringVar(value=str(self.cfg[key]))
        ttk.Label(f, text=label).grid(row=r, column=0, sticky="w", pady=4, padx=(0, 14))
        ttk.Entry(f, textvariable=self.v[key], width=width, show=show).grid(row=r, column=1, sticky="w", pady=4)

    def _check(self, f, r, label, key, hint=""):
        self.v[key] = tk.BooleanVar(value=bool(self.cfg[key]))
        ttk.Checkbutton(f, text=label, variable=self.v[key]).grid(row=r, column=0, columnspan=3, sticky="w", pady=(6, 0))
        if hint:
            self._hint(f, r + 1, hint, indent=28)

    def _hint(self, f, r, text, indent=0, color=MUTED):
        ttk.Label(f, text=text, foreground=color, wraplength=540).grid(
            row=r, column=0, columnspan=3, sticky="w", padx=(indent, 0))

    # ---- actions
    def _browse_dir(self):
        d = filedialog.askdirectory(initialdir=self.v["download_dir"].get(), parent=self)
        if d:
            self.v["download_dir"].set(d)

    def _browse_blocklist(self):
        f = filedialog.askopenfilename(parent=self, title="Choose blocklist",
                                       filetypes=[("Blocklists", "*.p2p *.dat *.txt *.gz"), ("All files", "*.*")])
        if f:
            self.v["blocklist_path"].set(f)

    def _register_default(self):
        try:
            register_default_app()
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Couldn't register: {e}", parent=self)
            return
        messagebox.showinfo(APP_NAME, "Hushwing is registered for magnet links and .torrent files.\n\nIf another "
                            "app still opens them, choose Hushwing in Windows Settings → Default apps.", parent=self)

    def _clear_history(self):
        if messagebox.askyesno(APP_NAME, "Remove every torrent from Hushwing and erase all saved history?\n\n"
                                         "Downloaded files are NOT deleted.", parent=self):
            self.app.clear_history()

    def _check_updates(self):
        if FROZEN:
            self.update_lbl.configure(text=f"libtorrent {lt.__version__} is built into Hushwing.exe; security "
                                           "updates come with a new Hushwing build.", foreground=MUTED)
            return
        self.update_lbl.configure(text="Checking…", foreground=MUTED)

        def work():
            py = Path(sys.executable).with_name("python.exe")
            try:
                out = subprocess.run([str(py if py.exists() else sys.executable), "-m", "pip", "index", "versions",
                                      "libtorrent"], capture_output=True, text=True, timeout=60,
                                     creationflags=NO_WINDOW).stdout
                latest = out.split("(", 1)[1].split(")", 1)[0] if "(" in out else None
            except Exception:
                latest = None
            cur = lt.__version__
            if not latest:
                msg, col = "Couldn't reach PyPI.", YELLOW
            elif cur.startswith(latest) or latest.startswith(cur.rsplit(".0", 1)[0]) and cur >= latest:
                msg, col = f"✓ Up to date (libtorrent {latest}).", GREEN
            else:
                msg, col = f"Update available: {latest}. Run:  py -3.12 -m pip install -U libtorrent", YELLOW
            try:
                self.after(0, lambda: self.update_lbl.configure(text=msg, foreground=col))
            except tk.TclError:
                pass

        threading.Thread(target=work, daemon=True).start()

    def _ok(self):
        try:
            out = {k: (v.get() if isinstance(v, tk.BooleanVar) else v.get().strip()) for k, v in self.v.items()}
            for k in self.mbs_keys:
                out[k] = int(round(float(out[k] or 0) * 1024))
            for k in ("listen_port", "proxy_port", "stop_seeding_minutes", "max_active_downloads",
                      "max_active_seeds", "i2p_port"):
                out[k] = int(out[k])
            out["stop_seeding_ratio"] = float(out["stop_seeding_ratio"])
            if not all(1 <= out[k] <= 65535 for k in ("listen_port", "proxy_port", "i2p_port")):
                raise ValueError("Ports must be 1-65535.")
            if not (1 <= out["max_active_downloads"] <= 999 and 1 <= out["max_active_seeds"] <= 999):
                raise ValueError("Active downloads / seeds must be between 1 and 999.")
            if min(out["max_download_kbps"], out["max_upload_kbps"], out["stop_seeding_minutes"],
                   out["stop_seeding_ratio"]) < 0:
                raise ValueError("Limits must be 0 or more.")
            if out["proxy_type"] != "none" and not out["proxy_host"]:
                raise ValueError("Enter a proxy host, or set the proxy type to 'none'.")
            if out["blocklist_path"] and not os.path.isfile(out["blocklist_path"]):
                raise ValueError("Blocklist file not found.")
        except ValueError as e:
            msg = str(e)
            if not msg or "could not convert" in msg or "invalid literal" in msg:
                msg = "Ports, limits and minutes must be numbers."
            messagebox.showerror("Settings", msg, parent=self)
            return
        out["proxy_pass"] = protect_secret(out["proxy_pass"])
        out["bind_interface"] = self.iface_names[self.iface_combo.current()]
        self.result = out
        self.destroy()


# --------------------------------------------------------------------------- main window
class App:
    COLUMNS = [
        ("queue", "#", 38, "center"),
        ("name", "Name", 290, "w"),
        ("size", "Size", 80, "e"),
        ("progress", "Progress", 185, "w"),
        ("status", "Status", 130, "w"),
        ("down", "Down", 90, "e"),
        ("up", "Up", 90, "e"),
        ("peers", "Seeds / Peers", 95, "center"),
        ("eta", "ETA", 65, "e"),
        ("ratio", "Ratio", 55, "e"),
        ("scan", "Safety", 95, "center"),
    ]
    FILTERS = ["All", "Downloading", "Seeding", "Queued", "Paused", "Errors"]
    SCAN_LABELS = {"scanning": "Inspecting…", "clean": "✓ Clean", "threat": "⛔ DANGER", "warning": "⚠ Check",
                   "noscanner": "No antivirus", "error": "Scan failed"}

    def __init__(self, root: tk.Tk, initial_args: list[str]):
        self.root = root
        self.cfg = load_config()
        self._flash = None
        self.engine = Engine(self.cfg)
        self.engine.on_message = self.flash
        self.engine.on_finished = self.on_torrent_finished
        self.last_save = time.time()
        self.selected_files_key = None
        self.net_state = "any"
        self._blocklist_loaded = None
        self.hist_down = deque([0] * 120, maxlen=120)
        self.hist_up = deque([0] * 120, maxlen=120)
        self.logo_small = self.logo_big = None
        self.last_privacy_verdict = None
        self._tray_hint_shown = False
        self._was_locked = False

        root.title(APP_NAME)
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        w, h = min(1220, sw - 60), min(720, sh - 120)
        root.geometry(f"{w}x{h}+{(sw - w) // 2}+{max((sh - h) // 2 - 30, 0)}")
        root.minsize(860, 480)
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self._set_icons()
        self._build_ui()
        self._setup_dnd()
        self.tray = traymod.Tray(APP_NAME, ICON_PNG)
        dark_title_bar(root)
        self.load_blocklist_async()
        threading.Thread(target=adapter_descriptions, daemon=True).start()  # warm the cache

        self.ipc = None
        try:
            self.ipc = IPCServer(lambda args: self.root.after(0, self.receive_args, args))
            self.ipc.start()
        except OSError:
            pass

        for arg in initial_args:
            self.add_from_string(arg)
        if self.engine.lock_reason == "nobind":
            self.root.after(700, self.strict_setup_dialog)
        self.tick()

    # ---- layout
    def _set_icons(self):
        if ICON_ICO.exists() and sys.platform == "win32":
            try:
                self.root.iconbitmap(default=str(ICON_ICO))
            except tk.TclError:
                pass
        if Image and ICON_PNG.exists():
            img = Image.open(ICON_PNG)
            self.logo_small = ImageTk.PhotoImage(img.resize((30, 30), Image.LANCZOS))
            self.logo_big = ImageTk.PhotoImage(img.resize((72, 72), Image.LANCZOS))
            if sys.platform != "win32":
                self.root.iconphoto(True, ImageTk.PhotoImage(img.resize((64, 64), Image.LANCZOS)))

    def _build_ui(self):
        if sv_ttk:
            sv_ttk.set_theme("dark")
        else:
            self._fallback_dark_theme()
        style = ttk.Style()
        style.configure("Treeview", rowheight=28)
        style.configure("Title.TLabel", font=("Segoe UI Semibold", 16))
        style.configure("Status.TLabel", foreground=MUTED)
        self.root.configure(bg=BG)

        header = ttk.Frame(self.root, padding=(14, 12, 14, 6))
        header.pack(fill="x")
        if self.logo_small:
            ttk.Label(header, image=self.logo_small).pack(side="left", padx=(0, 8))
        ttk.Label(header, text=APP_NAME, style="Title.TLabel").pack(side="left", padx=(0, 18))
        ttk.Button(header, text="＋  Add torrent", style="Accent.TButton", command=self.add_file_dialog).pack(side="left")
        ttk.Button(header, text="🧲  Magnet", command=self.add_magnet_dialog).pack(side="left", padx=(6, 0))
        ttk.Button(header, text="✚  Create", command=self.create_torrent).pack(side="left", padx=6)
        ttk.Separator(header, orient="vertical").pack(side="left", fill="y", padx=8)
        for text, tip, cmd in (("▶", "Resume (Ctrl+R)", self.resume_selected),
                               ("⏸", "Pause (Ctrl+P)", self.pause_selected),
                               ("✕", "Remove (Delete)", lambda: self.remove_selected(False))):
            b = ttk.Button(header, text=text, width=3, command=cmd)
            b.pack(side="left", padx=2)
            Tooltip(b, tip)
        ttk.Button(header, text="⚙  Settings", command=self.open_settings).pack(side="right")
        ttk.Button(header, text="🛡  Privacy check", command=self.privacy_check).pack(side="right", padx=(0, 6))
        self.search = tk.StringVar()
        self.search_entry = ttk.Entry(header, textvariable=self.search, width=18)
        self.search_entry.pack(side="right", padx=8)
        ttk.Label(header, text="Search", style="Status.TLabel").pack(side="right")
        self.filter = tk.StringVar(value="All")
        ttk.Combobox(header, textvariable=self.filter, values=self.FILTERS, state="readonly", width=11).pack(side="right", padx=4)

        # banner for kill switch / strict mode
        self.banner = tk.Frame(self.root, bg="#3a1d1d")
        self.banner_lbl = tk.Label(self.banner, bg="#3a1d1d", fg="#ffb4b4", font=("Segoe UI Semibold", 10),
                                   anchor="w", padx=12, pady=7)
        self.banner_lbl.pack(side="left", fill="x", expand=True)
        self.banner_btn = ttk.Button(self.banner, text="Choose VPN…", command=self.strict_setup_dialog)
        self.banner_btn.pack(side="right", padx=8, pady=4)

        self.paned = ttk.PanedWindow(self.root, orient="vertical")
        self.paned.pack(fill="both", expand=True, padx=14, pady=(6, 6))
        paned = self.paned

        list_frame = ttk.Frame(paned)
        self.tree = ttk.Treeview(list_frame, columns=[c[0] for c in self.COLUMNS], show="headings", selectmode="extended")
        for cid, title, width, anchor in self.COLUMNS:
            self.tree.heading(cid, text=title, anchor="center")  # titles centred; cells keep their own alignment
            self.tree.column(cid, width=width, anchor=anchor, stretch=(cid == "name"))
        for tag, color in (("downloading", BLUE), ("seeding", GREEN), ("paused", MUTED), ("queued", VIOLET),
                           ("error", RED), ("stalled", YELLOW), ("checking", ACCENT)):
            self.tree.tag_configure(tag, foreground=color)
        sb = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.refresh_details(force=True))
        self.tree.bind("<Delete>", lambda e: self.remove_selected(False))
        self.tree.bind("<Shift-Delete>", lambda e: self.remove_selected(True))
        self.tree.bind("<Return>", lambda e: self.open_folder())
        self.tree.bind("<Double-1>", lambda e: self.open_folder() if self.tree.identify_row(e.y) else None)
        self.tree.bind("<Button-3>", self.context_menu)
        paned.add(list_frame, weight=3)

        nb = ttk.Notebook(paned)
        self.info_text = tk.Text(nb, height=8, wrap="word", relief="flat", padx=12, pady=10, bg=PANEL, fg=FG,
                                 insertbackground=FG, font=("Consolas", 10), borderwidth=0, highlightthickness=0)
        self.info_text.configure(state="disabled")
        nb.add(self.info_text, text="  General  ")

        files_frame = ttk.Frame(nb)
        self.files = ttk.Treeview(files_frame, columns=("size", "progress", "priority"), show="tree headings")
        self.files.heading("#0", text="File   (double-click to skip / include)", anchor="w")
        self.files.column("#0", width=480)
        for cid, title in (("size", "Size"), ("progress", "Progress"), ("priority", "Download")):
            self.files.heading(cid, text=title)
            self.files.column(cid, width=150 if cid == "progress" else 90,
                              anchor={"size": "e", "progress": "w", "priority": "center"}[cid], stretch=False)
        self.files.tag_configure("risky", foreground=RED)
        self.files.tag_configure("caution", foreground=YELLOW)
        self.files.tag_configure("skipped", foreground=MUTED)
        fsb = ttk.Scrollbar(files_frame, orient="vertical", command=self.files.yview)
        self.files.configure(yscrollcommand=fsb.set)
        self.files.pack(side="left", fill="both", expand=True)
        fsb.pack(side="right", fill="y")
        self.files.bind("<Double-1>", self.toggle_file_priority)
        self.files.bind("<Button-3>", self.file_menu)
        nb.add(files_frame, text="  Files  ")

        peers_frame = ttk.Frame(nb)
        self.peers = ttk.Treeview(peers_frame, columns=("enc", "client", "progress", "down", "up"), show="tree headings")
        self.peers.heading("#0", text="Address", anchor="w")
        self.peers.column("#0", width=220)
        for cid, title, w, a in (("enc", "Encrypted", 80, "center"), ("client", "Client", 170, "w"),
                                 ("progress", "Progress", 80, "e"), ("down", "Down", 90, "e"), ("up", "Up", 90, "e")):
            self.peers.heading(cid, text=title)
            self.peers.column(cid, width=w, anchor=a)
        self.peers.tag_configure("plain", foreground=YELLOW)
        psb = ttk.Scrollbar(peers_frame, orient="vertical", command=self.peers.yview)
        self.peers.configure(yscrollcommand=psb.set)
        self.peers.pack(side="left", fill="both", expand=True)
        psb.pack(side="right", fill="y")
        nb.add(peers_frame, text="  Peers  ")

        self.graph = tk.Canvas(nb, bg=PANEL, highlightthickness=0, borderwidth=0)
        nb.add(self.graph, text="  Speed  ")
        paned.add(nb, weight=2)

        bar = ttk.Frame(self.root, padding=(14, 4, 14, 8))
        bar.pack(fill="x", side="bottom", before=paned)
        self.status = tk.StringVar()
        self.limit_lbl = ttk.Label(bar, text="", cursor="hand2", foreground=ACCENT)
        self.limit_lbl.pack(side="left", padx=(0, 14))
        self.limit_lbl.bind("<Button-1>", lambda e: self.speed_limits())
        self.status_lbl = ttk.Label(bar, textvariable=self.status, style="Status.TLabel")
        self.status_lbl.pack(side="left")
        self.privacy = tk.StringVar()
        self.privacy_lbl = ttk.Label(bar, textvariable=self.privacy)
        self.privacy_lbl.pack(side="right")

        self.seq_var = tk.BooleanVar()
        self.menu = tk.Menu(self.root, tearoff=0, bg=PANEL, fg=FG, activebackground="#2d2d2d",
                            activeforeground=FG, selectcolor=FG, borderwidth=0, relief="flat")
        self.menu.add_command(label="Resume", command=self.resume_selected)
        self.menu.add_command(label="Pause", command=self.pause_selected)
        self.menu.add_command(label="Force start (skip queue)", command=self.force_start_selected)
        qm = tk.Menu(self.menu, tearoff=0, bg=PANEL, fg=FG, activebackground="#2d2d2d", activeforeground=FG,
                     borderwidth=0, relief="flat")
        for label, where in (("Move to top", "top"), ("Move up", "up"), ("Move down", "down"),
                             ("Move to bottom", "bottom")):
            qm.add_command(label=label, command=lambda w=where: self.queue_selected(w))
        self.menu.add_cascade(label="Queue", menu=qm)
        self.menu.add_checkbutton(label="Sequential download (stream while downloading)",
                                  variable=self.seq_var, command=self.toggle_sequential)
        self.menu.add_separator()
        self.menu.add_command(label="Open folder", command=self.open_folder)
        self.menu.add_command(label="Inspect files now", command=self.scan_selected)
        self.menu.add_command(label="Copy magnet link", command=self.copy_magnet)
        self.menu.add_command(label="Force recheck", command=self.recheck_selected)
        self.menu.add_separator()
        self.menu.add_command(label="Remove", command=lambda: self.remove_selected(False))
        self.menu.add_command(label="Remove + delete data", command=lambda: self.remove_selected(True))

        self.file_menu_widget = tk.Menu(self.root, tearoff=0, bg=PANEL, fg=FG, activebackground="#2d2d2d",
                                        activeforeground=FG, borderwidth=0, relief="flat")
        self.file_menu_widget.add_command(label="Open", command=lambda: self.open_selected_file(False))
        self.file_menu_widget.add_command(label="Show in folder", command=lambda: self.open_selected_file(True))
        self.file_menu_widget.add_separator()
        self.file_menu_widget.add_command(label="Download / skip this file", command=self.toggle_selected_file)

        keys = {
            "<Control-o>": self.add_file_dialog, "<Control-m>": self.add_magnet_dialog,
            "<Control-n>": self.create_torrent, "<Control-r>": self.resume_selected,
            "<Control-p>": self.pause_selected, "<Control-s>": self.force_start_selected,
            "<Control-e>": self.open_folder, "<Control-l>": self.speed_limits, "<Control-i>": self.privacy_check,
            "<Control-comma>": self.open_settings, "<F1>": lambda: show_shortcuts(self.root),
            "<Control-q>": self.quit, "<Control-Up>": lambda: self.queue_selected("up"),
            "<Control-Down>": lambda: self.queue_selected("down"),
            "<Control-f>": lambda: (self.search_entry.focus_set(), self.search_entry.select_range(0, "end")),
        }
        for seq, fn in keys.items():
            self.root.bind(seq, lambda e, fn=fn: (fn(), "break")[1])
        self.tree.bind("<Control-a>", lambda e: (self.tree.selection_set(self.tree.get_children()), "break")[1])
        self.root.bind("<Control-v>", self.paste_magnet)

    def _fallback_dark_theme(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", background=BG, foreground=FG, fieldbackground=PANEL, bordercolor="#333")
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=FG)
        style.map("Treeview", background=[("selected", "#2f4f6f")])
        style.configure("Treeview.Heading", background="#2a2a2a", foreground=FG)
        style.configure("TButton", background="#2d2d2d")
        style.configure("Accent.TButton", background="#1f6fa8")
        style.configure("TNotebook.Tab", background="#2a2a2a", foreground=FG)

    # ---- messages
    def flash(self, text: str, level: str = "info"):
        self._flash = (text, level, time.time() + 8)
        hidden = self.root.state() == "withdrawn"
        if level == "warn":
            if hidden:
                self.notify(text.split("\n\n")[0], "Hushwing protected you")
            else:
                messagebox.showwarning(APP_NAME, text, parent=self.root)
        elif level == "error" and hidden:
            self.notify(text, APP_NAME)

    def notify(self, message: str, title: str = APP_NAME):
        if self.cfg.get("notifications", True) and getattr(self, "tray", None):
            self.tray.notify(message, title)

    # ---- window / tray
    def on_close(self):
        if self.cfg.get("close_to_tray", True) and self.tray.available:
            self.root.withdraw()
            if not self._tray_hint_shown:
                self._tray_hint_shown = True
                self.tray.notify("Still running in the tray. Right-click the icon to quit.", APP_NAME)
        else:
            self.quit()

    def show_window(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def handle_tray(self):
        while True:
            try:
                action = self.tray.actions.get_nowait()
            except Exception:
                return
            if action == "show":
                self.show_window()
            elif action == "pause_all":
                for h in self.engine.handles():
                    self.engine.pause(h)
                self.flash("All torrents paused", "ok")
            elif action == "resume_all":
                for h in self.engine.handles():
                    if self.engine.scans.get(torrent_key(h), [None])[0] != "threat":
                        self.engine.resume(h)
                self.flash("All torrents resumed (except ones flagged as dangerous)", "ok")
            elif action == "limits":
                self.show_window()
                self.speed_limits()
            elif action == "privacy":
                self.show_window()
                self.privacy_check()
            elif action == "quit":
                self.root.after_idle(self.quit)
                return

    # ---- drag and drop
    def _setup_dnd(self):
        if not TkinterDnD or not hasattr(self.root, "drop_target_register"):
            return
        self.drop_hint = tk.Label(self.root, text="Drop torrents or magnet links to add them", bg="#16324a",
                                  fg="#cfeaff", font=("Segoe UI Semibold", 13), pady=18)

        def register(w):
            try:
                w.drop_target_register(DND_FILES, DND_TEXT)
                w.dnd_bind("<<DropEnter>>", self._drag_enter)
                w.dnd_bind("<<DropLeave>>", self._drag_leave)
                w.dnd_bind("<<Drop>>", self._drop)
            except Exception:
                pass
            for c in w.winfo_children():
                register(c)

        register(self.root)

    def _drag_enter(self, e):
        self.drop_hint.place(relx=0.5, rely=0.42, anchor="center", relwidth=0.6)
        self.drop_hint.lift()
        return e.action

    def _drag_leave(self, e):
        self.drop_hint.place_forget()
        return e.action

    def _drop(self, e):
        self.drop_hint.place_forget()
        data = e.data or ""
        items = []
        if "magnet:?" in data:
            items = [t for t in data.replace("\r", "\n").split() if t.lower().startswith("magnet:?")]
        else:
            try:
                items = list(self.root.tk.splitlist(data))
            except tk.TclError:
                items = [data]
        added = 0
        for it in items:
            it = it.strip()
            if it.lower().startswith("magnet:?") or it.lower().endswith(".torrent") and os.path.isfile(it):
                self.add_from_string(it)
                added += 1
            elif it.lower().startswith(("http://", "https://")):
                self.flash("That's a web link. Save the .torrent file first, then drop the file here.", "error")
        if added:
            self.flash(f"Added {added} torrent{'s' if added != 1 else ''}", "ok")
        elif not any(i.lower().startswith(("http://", "https://")) for i in items):
            self.flash("Only .torrent files and magnet links can be dropped here.", "error")
        return e.action

    # ---- strict-mode first-run
    def strict_setup_dialog(self):
        if getattr(self, "_strict_open", False):
            return
        self._strict_open = True
        d = DarkDialog(self.root, "Protect your IP address")
        if self.logo_big:
            ttk.Label(d.body, image=self.logo_big).pack(anchor="w", pady=(0, 10))
        ttk.Label(d.body, text="Strict mode is on", style="Title.TLabel").pack(anchor="w")
        ttk.Label(d.body, wraplength=520, foreground=MUTED, text=(
            "Hushwing won't connect to anyone until you choose the network adapter of your VPN. "
            "Then all torrent traffic goes only through the VPN, and stops instantly if it disconnects.")).pack(
            anchor="w", pady=(6, 12))
        ifaces, descs = list_interfaces(), adapter_descriptions(refresh=True)
        names = [AUTO_VPN] + sorted(ifaces, key=lambda k: (not is_vpn_adapter(k, descs.get(k, "")), k))
        combo = ttk.Combobox(d.body, state="readonly", width=64, values=(
            ["Any VPN adapter — automatic (recommended)"] + [interface_label(x, ifaces, descs) for x in names[1:]]))
        combo.pack(anchor="w")
        combo.current(0)
        vpns = [x for x in names[1:] if is_vpn_adapter(x, descs.get(x, ""))]
        ttk.Label(d.body, foreground=GREEN if vpns else YELLOW, wraplength=520, text=(
            f"VPN detected: {vpns[0]} ({descs.get(vpns[0], '')}). Automatic mode follows it even when it "
            "reconnects under a new name." if vpns else
            "No VPN connected right now. Pick 'automatic' — Hushwing will start as soon as your VPN connects.")).pack(
            anchor="w", pady=(6, 0))

        def use():
            if names and combo.current() >= 0:
                self.cfg["bind_interface"] = names[combo.current()]
                self._apply_cfg()
            d.destroy()

        def disable():
            if messagebox.askyesno(APP_NAME, "Turn off strict mode?\n\nYour real IP address will be visible to "
                                             "peers whenever your VPN is off.", parent=d):
                self.cfg["strict_mode"] = False
                self._apply_cfg()
                d.destroy()

        d.buttons("Use this adapter", use, extra=[("Turn off strict mode", disable)])
        d.unbind("<Return>")  # this dialog can pop up while you're typing elsewhere: require a click
        d.show()
        self._strict_open = False

    # ---- actions
    def receive_args(self, args):
        for a in args:
            self.add_from_string(a)
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def add_from_string(self, s: str):
        s = s.strip()
        try:
            if s.lower().startswith("magnet:?"):
                self.engine.add_magnet(s)
            elif os.path.isfile(s) and s.lower().endswith(".torrent"):
                self.engine.add_torrent_file(s)
            elif os.path.isfile(s):
                messagebox.showerror(APP_NAME, "Only .torrent files can be opened.")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Could not add torrent:\n{e}")

    def add_file_dialog(self):
        for p in filedialog.askopenfilenames(title="Open torrent", filetypes=[("Torrent files", "*.torrent")]):
            self.add_from_string(p)

    def add_magnet_dialog(self):
        initial = ""
        try:
            clip = self.root.clipboard_get().strip()
            if clip.lower().startswith("magnet:?"):
                initial = clip
        except tk.TclError:
            pass
        uri = ask_string(self.root, "Add magnet link", "Magnet URI", initial)
        if uri:
            if not uri.lower().startswith("magnet:?"):
                messagebox.showerror(APP_NAME, "That doesn't look like a magnet link.")
                return
            self.add_from_string(uri)

    def paste_magnet(self, _event=None):
        if isinstance(self.root.focus_get(), (ttk.Entry, tk.Entry)):
            return
        try:
            clip = self.root.clipboard_get().strip()
        except tk.TclError:
            return
        if clip.lower().startswith("magnet:?"):
            self.add_from_string(clip)

    def selected_handles(self):
        return [h for h in (self.engine.find(k) for k in self.tree.selection()) if h]

    def resume_selected(self):
        for h in self.selected_handles():
            if self.engine.scans.get(torrent_key(h), [None])[0] == "threat":
                if not messagebox.askyesno(APP_NAME, f"'{h.status().name}' was flagged as dangerous. "
                                                     "Resume sharing it anyway?", parent=self.root):
                    continue
            self.engine.resume(h)

    def pause_selected(self):
        for h in self.selected_handles():
            self.engine.pause(h)

    def force_start_selected(self):
        for h in self.selected_handles():
            if self.engine.scans.get(torrent_key(h), [None])[0] == "threat":
                continue
            self.engine.force_start(h)

    def queue_selected(self, where: str):
        hs = self.selected_handles()
        if where in ("down", "top"):
            hs = list(reversed(hs))
        for h in hs:
            self.engine.queue_move(h, where)

    def create_torrent(self):
        CreateTorrentDialog(self).show()

    def speed_limits(self):
        new = SpeedLimitDialog(self).show()
        if new:
            self.cfg.update(new)
            self._apply_cfg()
            self.flash(f"Speed limits saved: ↓ {human_rate_limit(new['max_download_kbps'])}, "
                       f"↑ {human_rate_limit(new['max_upload_kbps'])}", "ok")

    def privacy_check(self):
        PrivacyCheckDialog(self).show()

    def recheck_selected(self):
        for h in self.selected_handles():
            h.force_recheck()

    def toggle_sequential(self):
        hs = self.selected_handles()
        if hs:
            on = self.engine.toggle_sequential(hs[0])
            self.flash(f"Sequential download {'on' if on else 'off'}", "ok")

    def remove_selected(self, delete_files: bool):
        hs = self.selected_handles()
        if not hs:
            return
        what = "and DELETE their downloaded data" if delete_files else "(downloaded files are kept)"
        if not messagebox.askyesno(APP_NAME, f"Remove {len(hs)} torrent(s) {what}?", parent=self.root):
            return
        for h in hs:
            key = torrent_key(h)
            self.engine.remove(h, delete_files)
            if self.tree.exists(key):
                self.tree.delete(key)

    def open_folder(self):
        hs = self.selected_handles()
        path = self.cfg["download_dir"]
        if hs:
            st = hs[0].status()
            candidate = os.path.join(st.save_path, st.name) if st.name else st.save_path
            path = candidate if os.path.exists(candidate) else st.save_path
        if os.path.isfile(path):
            subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
        elif os.path.isdir(path):
            os.startfile(path) if sys.platform == "win32" else subprocess.Popen(["xdg-open", path])

    def copy_magnet(self):
        hs = self.selected_handles()
        if hs:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.engine.magnet_link(hs[0]))
            self.flash("Magnet link copied", "ok")

    def context_menu(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            if row not in self.tree.selection():
                self.tree.selection_set(row)
            h = self.engine.find(row)
            if h:
                self.seq_var.set(bool(h.status().flags & lt.torrent_flags.sequential_download))
            self.menu.tk_popup(event.x_root, event.y_root)

    def _apply_cfg(self):
        save_config(self.cfg)
        self.engine.cfg = self.cfg
        self.engine.sync_guard()
        self.engine.apply_settings()
        self.net_state = self.engine.guard()
        self.load_blocklist_async()

    def open_settings(self):
        new = SettingsDialog(self, self.cfg).show()
        if new:
            self.cfg.update(new)
            self._apply_cfg()

    def clear_history(self):
        self.engine.clear_history()
        self.tree.delete(*self.tree.get_children())
        self.flash("History cleared", "ok")

    def load_blocklist_async(self):
        path = self.cfg.get("blocklist_path") or ""
        if path == self._blocklist_loaded:
            return
        self._blocklist_loaded = path
        if not path:
            self.engine.set_blocklist([])
            return

        def work():
            try:
                ranges = parse_blocklist(path)
                self.root.after(0, lambda: (self.engine.set_blocklist(ranges),
                                            self.flash(f"Blocklist loaded: {len(ranges):,} ranges", "ok")))
            except Exception as e:
                msg = str(e)
                self.root.after(0, lambda: self.flash(f"Blocklist error: {msg}", "error"))

        threading.Thread(target=work, daemon=True).start()

    def _files_handle(self):
        key = self.selected_files_key[0] if isinstance(self.selected_files_key, tuple) else self.selected_files_key
        return self.engine.find(key) if key else None

    def toggle_file_priority(self, event):
        item = self.files.identify_row(event.y)
        if item:
            self.files.selection_set(item)
            self.toggle_selected_file()

    def toggle_selected_file(self):
        sel = self.files.selection()
        h = self._files_handle()
        if not sel or not h:
            return
        prios = list(h.get_file_priorities())
        idx = int(sel[0])
        prios[idx] = 0 if prios[idx] else 4
        h.prioritize_files(prios)
        self.refresh_details(force=True)

    def file_menu(self, event):
        item = self.files.identify_row(event.y)
        if item:
            self.files.selection_set(item)
            self.file_menu_widget.tk_popup(event.x_root, event.y_root)

    def open_selected_file(self, in_folder: bool):
        sel = self.files.selection()
        h = self._files_handle()
        if not sel or not h or not h.torrent_file():
            return
        st = h.status()
        rel = h.torrent_file().files().file_path(int(sel[0]))
        path = os.path.join(st.save_path, rel)
        if not os.path.exists(path):
            self.flash("That file hasn't been downloaded yet.", "error")
            return
        if in_folder:
            subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
            return
        flagged = [f for f in self.engine.prechecks.get(torrent_key(h), []) +
                   (self.engine.scans.get(torrent_key(h), [None, "", []]) + [[]])[2] if f.get("file") == rel]
        if flagged or inspector.ext(rel) in inspector.EXECUTABLE:
            reason = flagged[0]["reason"] if flagged else "This file can run code on your PC."
            if not messagebox.askyesno(APP_NAME, f"⚠ {Path(rel).name}\n\n{reason}\n\nOpen it anyway?",
                                       icon="warning", parent=self.root):
                return
        os.startfile(path)

    # ---- safety: scan + mark-of-the-web
    def on_torrent_finished(self, h):
        key = torrent_key(h)
        if self.engine.scans.get(key, [None])[0] in ("clean", "threat", "scanning"):
            return
        if self.cfg.get("scan_on_complete") or self.cfg.get("mark_of_web"):
            self.start_scan(h, scan=bool(self.cfg.get("scan_on_complete")))
        st = h.status()
        if st.total_download > 0:  # really downloaded now, not just re-checked at startup
            self.notify(f"{st.name}", "Download complete")

    def scan_selected(self):
        for h in self.selected_handles():
            self.start_scan(h, scan=True)

    def start_scan(self, h, scan=True):
        key = torrent_key(h)
        st = h.status()
        ti = h.torrent_file()
        if not ti:
            return
        fs = ti.files()
        prios = h.get_file_priorities()
        wanted = [(path, size) for i, path, size in real_files(fs) if prios[i]]
        files = [os.path.join(st.save_path, rel) for rel, _ in wanted]
        target = os.path.join(st.save_path, st.name)
        if not os.path.exists(target):
            target = st.save_path
        if scan:
            self.engine.scans[key] = ["scanning", ""]
        mark = bool(self.cfg.get("mark_of_web"))
        cfg = dict(self.cfg)

        def work():
            if mark:
                mark_of_the_web(files)
            if scan:
                result = run_scan(cfg, target, st.save_path, wanted)
                self.root.after(0, self.scan_done, key, st.name, result)

        threading.Thread(target=work, daemon=True).start()

    def scan_done(self, key, name, result):
        status, detail, findings = result
        self.engine.scans[key] = [status, detail, findings]
        self.engine.save_scans()
        if status == "threat":
            h = self.engine.find(key)
            if h:
                self.engine.pause(h)
            bad = [f for f in findings if f["level"] == "threat"]
            lines = "\n".join(f"• {Path(f['file']).name + ': ' if f['file'] else ''}{f['reason']}" for f in bad[:8])
            self.notify(f"Dangerous files in '{name}'. The torrent was paused.", "Hushwing protected you")
            if self.root.state() == "withdrawn":
                self.show_window()
            messagebox.showerror(APP_NAME, f"⛔ Dangerous files in '{name}'.\n\n{lines}\n\nThe torrent has been "
                                           "paused so you stop sharing it. Don't open these files; deleting "
                                           "the torrent and its files is safest.", parent=self.root)
        elif status == "warning":
            self.flash(f"⚠ '{name}': {findings[0]['reason']} (see Files tab)", "error")
        elif status == "clean":
            self.flash(f"✓ '{name}' inspected: nothing suspicious", "ok")
        else:
            self.flash(f"Scan of '{name}' failed: {detail}", "error")

    # ---- periodic refresh
    def tick(self):
        try:
            self.handle_tray()
            self.net_state = self.engine.guard()
            if self.engine.lock_reason == "down" and not self._was_locked:
                self.notify("VPN disconnected: all torrent traffic stopped until it reconnects.", "Kill switch")
            self._was_locked = self.engine.lock_reason == "down"
            self.engine.process_alerts()
            self.engine.process_guard_results()
            self.engine.enforce_seed_limits()
            self.refresh_list()
            self.refresh_details()
            self.refresh_status()
            self.draw_graph()
            if time.time() - self.last_save > 60:
                self.engine.request_save_all()
                self.last_save = time.time()
        except Exception as e:
            print("tick error:", e, file=sys.stderr)
        self.root.after(1000, self.tick)

    def refresh_list(self):
        seen = set()
        flt, query = self.filter.get(), self.search.get().strip().lower()
        locked = self.engine.lock_reason
        for h in self.engine.handles():
            st = h.status()
            key = torrent_key(h)
            paused = is_paused(st)
            raw = str(st.state).split(".")[-1]
            state, tag = STATE_NAMES.get(raw, raw), "downloading"
            scan = self.engine.scans.get(key, [None, ""])[0]
            if st.errc.value():
                state, tag = "Error: " + st.errc.message(), "error"
            elif locked:
                state, tag = ("Blocked (kill switch)" if locked == "down" else "Blocked (strict mode)"), "error"
            elif scan == "threat":
                state, tag = "Dangerous — paused", "error"
            elif paused and st.flags & lt.torrent_flags.auto_managed:
                state, tag = "Queued", "queued"
            elif paused:
                state, tag = "Paused", "paused"
            elif raw.startswith("checking") or raw == "allocating":
                tag = "checking"
            elif st.is_seeding or raw == "finished":
                tag = "seeding"
            elif raw == "downloading" and st.num_peers == 0:
                state, tag = "Stalled", "stalled"

            if flt == "Downloading" and tag not in ("downloading", "stalled", "checking"):
                continue
            if flt == "Seeding" and tag != "seeding":
                continue
            if flt == "Paused" and tag != "paused":
                continue
            if flt == "Queued" and tag != "queued":
                continue
            if flt == "Errors" and tag != "error":
                continue
            if query and query not in (st.name or "").lower():
                continue
            seen.add(key)

            remaining = st.total_wanted - st.total_wanted_done
            eta = remaining / st.download_rate if st.download_rate > 0 else float("inf")
            idle = paused or bool(locked)
            values = (
                str(st.queue_position + 1) if st.queue_position >= 0 else "",
                st.name or key,
                human_size(st.total_wanted) if st.has_metadata else "?",
                progress_bar(st.progress),
                state,
                "" if idle else human_speed(st.download_rate),
                "" if idle else human_speed(st.upload_rate),
                f"{st.num_seeds} / {st.num_peers}",
                "" if st.is_seeding or idle else human_eta(eta),
                f"{share_ratio(st):.2f}",
                self.SCAN_LABELS.get(scan, ""),
            )
            if self.tree.exists(key):
                self.tree.item(key, values=values, tags=(tag,))
            else:
                self.tree.insert("", "end", iid=key, values=values, tags=(tag,))
        for iid in self.tree.get_children():
            if iid not in seen:
                self.tree.delete(iid)

    def _set_info(self, text):
        self.info_text.configure(state="normal")
        self.info_text.delete("1.0", "end")
        self.info_text.insert("1.0", text)
        self.info_text.configure(state="disabled")

    def refresh_details(self, force=False):
        sel = self.tree.selection()
        h = self.engine.find(sel[0]) if sel else None
        if not h:
            self._set_info("Select a torrent to see its details.")
            self.files.delete(*self.files.get_children())
            self.peers.delete(*self.peers.get_children())
            self.selected_files_key = None
            return
        key = torrent_key(h)
        st = h.status()
        ti = h.torrent_file()

        trackers = self.engine.original_trackers(h)
        scan = self.engine.scans.get(key)
        lines = [
            f"Name         {st.name}",
            f"Info hash    {key}",
            f"Save path    {st.save_path}",
            f"Transferred  ↓ {human_size(st.all_time_download)}   ↑ {human_size(st.all_time_upload)}"
            f"   ratio {share_ratio(st):.2f}",
            f"Swarm        {st.num_connections} connections · seeds {st.num_seeds} ({st.list_seeds} known)"
            f" · peers {st.num_peers} ({st.list_peers} known)",
            f"Safety       {scan[1] if scan and scan[1] else self.SCAN_LABELS.get(scan[0], '') if scan else 'Not scanned yet'}",
        ]
        for f in (scan[2] if scan and len(scan) > 2 else [])[:8]:
            lines.append(f"             {'⛔' if f['level'] == 'threat' else '⚠'} "
                         f"{Path(f['file']).name + ': ' if f['file'] else ''}{f['reason']}")
        if st.flags & lt.torrent_flags.sequential_download:
            lines.append("Mode         sequential download")
        if ti:
            lines.append(f"Pieces       {ti.num_pieces()} × {human_size(ti.piece_length())} · total {human_size(ti.total_size())}"
                         f" · {'private torrent (DHT/PEX disabled)' if ti.priv() else 'public torrent'}")
            if ti.comment():
                lines.append(f"Comment      {ti.comment()}")
        lines.append(f"Trackers     {len(trackers)}")
        lines += [f"             {u}" for u in trackers[:10]]
        self._set_info("\n".join(lines))

        if ti:
            fs = ti.files()
            shown = real_files(fs)
            n = len(shown)
            flags = {}
            for f in self.engine.prechecks.get(key, []) + (scan[2] if scan and len(scan) > 2 else []):
                if f["file"] and (f["file"] not in flags or f["level"] == "threat"):
                    flags[f["file"]] = f
            sig = (key, len(flags), n)
            if force or self.selected_files_key != sig or len(self.files.get_children()) != n:
                self.files.delete(*self.files.get_children())
                for i, path, size in shown:
                    f = flags.get(path)
                    label = (f"{'⛔' if f['level'] == 'threat' else '⚠'} {path}    — {f['reason']}" if f else path)
                    self.files.insert("", "end", iid=str(i), text=label, values=(human_size(size), "", ""))
            progress = h.file_progress()
            prios = h.get_file_priorities()
            for i, path, size in shown[:2000]:
                pct = progress[i] / size if size else 1.0
                f = flags.get(path)
                tags = (("risky",) if f["level"] == "threat" else ("caution",)) if f else \
                    (("skipped",) if prios[i] == 0 else ())
                self.files.item(str(i), values=(human_size(size), progress_bar(pct, 8), "Skip" if prios[i] == 0 else "Yes"),
                                tags=tags)
        else:
            self.files.delete(*self.files.get_children())
        self.selected_files_key = sig if ti else key

        self.peers.delete(*self.peers.get_children())
        try:
            enc_mask = lt.peer_info.rc4_encrypted | lt.peer_info.plaintext_encrypted
            pending = lt.peer_info.connecting | lt.peer_info.handshake
            for p in h.get_peer_info():
                if p.flags & pending:  # half-open attempts: not real connections yet
                    continue
                ip, port = p.ip
                enc = bool(p.flags & enc_mask)
                client = p.client.decode("utf-8", "replace") if isinstance(p.client, bytes) else p.client
                self.peers.insert("", "end", text=f"{ip}:{port}", tags=(() if enc else ("plain",)), values=(
                    "🔒 yes" if enc else "no", client, f"{p.progress * 100:.1f}%",
                    human_speed(p.down_speed), human_speed(p.up_speed)))
        except Exception:
            pass

    def refresh_status(self):
        handles = self.engine.handles()
        sts = [h.status() for h in handles]
        down = sum(s.download_rate for s in sts)
        up = sum(s.upload_rate for s in sts)
        self.hist_down.append(down)
        self.hist_up.append(up)
        n = len(handles)
        text = f"↓ {human_speed(down) or '0 B/s'}    ↑ {human_speed(up) or '0 B/s'}    ·    {n} torrent{'s' if n != 1 else ''}"
        color = MUTED
        if self._flash and self._flash[2] > time.time():
            text += f"    ·    {self._flash[0]}"
            color = {"error": RED, "warn": YELLOW, "ok": GREEN}.get(self._flash[1], FG)
        self.status.set(text)
        self.status_lbl.configure(foreground=color)
        dl, ul = int(self.cfg["max_download_kbps"]), int(self.cfg["max_upload_kbps"])
        self.limit_lbl.configure(text=("Limit ↓ " + human_rate_limit(dl) + " ↑ " + human_rate_limit(ul))
                                 if dl or ul else "No speed limit")
        if getattr(self, "tray", None):
            self.tray.set_tooltip(f"{APP_NAME} · ↓ {human_speed(down) or '0 B/s'} ↑ {human_speed(up) or '0 B/s'}"
                                  + (" · traffic stopped" if self.engine.lock_reason else ""))

        c = self.cfg
        lock = self.engine.lock_reason
        if lock:
            what = "no VPN is connected" if c["bind_interface"] == AUTO_VPN else f"'{c['bind_interface']}' is down"
            msg = (f"⛔  Kill switch active — {what}. All traffic stopped until your VPN connects."
                   if lock == "down" else
                   "⛔  Strict mode — Hushwing won't connect until you choose your VPN adapter.")
            self.banner_lbl.configure(text=msg)
            if lock == "nobind":
                self.banner_btn.pack(side="right", padx=8, pady=4)
            else:
                self.banner_btn.pack_forget()
            if not self.banner.winfo_ismapped():
                self.banner.pack(fill="x", padx=14, pady=(4, 0), before=self.paned)
            self.privacy.set("⛔ No traffic")
            self.privacy_lbl.configure(foreground=RED)
            return
        if self.banner.winfo_ismapped():
            self.banner.pack_forget()

        parts = ["🔒 Encrypted" if c["force_encryption"] else "⚠ Encryption optional"]
        if c["anonymous_mode"]:
            parts.append("Anonymous")
        if self.net_state == "up":
            parts.append(f"VPN: {self.engine.bound_name} ({self.engine.bound_ip})")
        elif self.engine._proxy_on():
            parts.append(f"Proxy {c['proxy_type']}")
        else:
            parts.append("⚠ Not bound to VPN")
        if c["strict_mode"]:
            parts.append("Strict")
        if c["incognito"]:
            parts.append("Incognito")
        parts.append(f"Port {self.engine.port}")
        if self.engine.blocked_ranges:
            parts.append(f"Blocklist {self.engine.blocked_ranges:,}")
        if c.get("i2p_enabled"):
            parts.append("I2P")
        secure = c["force_encryption"] and (self.net_state == "up" or self.engine._proxy_on())
        self.privacy.set("   ·   ".join(parts))
        self.privacy_lbl.configure(foreground=GREEN if secure else YELLOW)

    def draw_graph(self):
        cv = self.graph
        w, h = cv.winfo_width(), cv.winfo_height()
        if w < 50 or h < 50 or not cv.winfo_ismapped():
            return
        cv.delete("all")
        left, right, top, bottom = 70, 14, 34, 22
        gw, gh = w - left - right, h - top - bottom
        peak = max(max(self.hist_down), max(self.hist_up), 64 * 1024) * 1.15
        for i in range(5):
            y = top + gh * i / 4
            cv.create_line(left, y, w - right, y, fill="#2c2c2c")
            cv.create_text(left - 8, y, text=human_speed(peak * (4 - i) / 4) or "0", fill=MUTED, anchor="e",
                           font=("Segoe UI", 8))
        cv.create_text(left, h - 8, text="2 min ago", fill=MUTED, anchor="w", font=("Segoe UI", 8))
        cv.create_text(w - right, h - 8, text="now", fill=MUTED, anchor="e", font=("Segoe UI", 8))
        for series, color in ((self.hist_up, GREEN), (self.hist_down, BLUE)):
            pts = []
            n = len(series)
            for i, v in enumerate(series):
                pts += [left + gw * i / (n - 1), top + gh - gh * v / peak]
            cv.create_polygon(left, top + gh, *pts, w - right, top + gh, fill=blend(PANEL, color, 0.18), outline="")
            cv.create_line(*pts, fill=color, width=2, smooth=True)
        cv.create_text(left, 16, anchor="w", fill=BLUE, font=("Segoe UI Semibold", 10),
                       text=f"↓ {human_speed(self.hist_down[-1]) or '0 B/s'}")
        cv.create_text(left + 140, 16, anchor="w", fill=GREEN, font=("Segoe UI Semibold", 10),
                       text=f"↑ {human_speed(self.hist_up[-1]) or '0 B/s'}")

    def quit(self):
        self.status.set("Saving state…")
        self.root.update_idletasks()
        self.tray.stop()
        self.engine.shutdown()
        if self.ipc:
            self.ipc.close()
        self.root.destroy()


def main():
    migrate_legacy_state()
    args = sys.argv[1:]
    if forward_to_running_instance(args):
        return
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)  # own taskbar icon
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    root = TkinterDnD.Tk() if TkinterDnD else tk.Tk()
    App(root, args)
    root.mainloop()


if __name__ == "__main__":
    main()
