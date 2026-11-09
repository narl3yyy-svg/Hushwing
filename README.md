<div align="center">

# 🪶 Hushwing

**A privacy-first BitTorrent client for Windows**

One portable `.exe` · nothing to install · no accounts · no telemetry

![Platform](https://img.shields.io/badge/platform-Windows-0078D6)
![Python](https://img.shields.io/badge/python-3.12-3776AB)
![Engine](https://img.shields.io/badge/engine-libtorrent%202.x-555)
![License](https://img.shields.io/badge/license-GPL--3.0-blue)

</div>

---

## Contents

1. [Features at a glance](#features-at-a-glance)
2. [Quick start](#quick-start)
3. [What Hushwing protects you from](#what-hushwing-protects-you-from)
4. [The main window](#the-main-window)
5. [Adding torrents](#adding-torrents)
6. [Managing torrents](#managing-torrents)
7. [Speed limits](#speed-limits)
8. [The download queue](#the-download-queue)
9. [Safety: the built-in file inspector](#safety-the-built-in-file-inspector)
10. [Privacy: strict mode, kill switch and DNS guard](#privacy-strict-mode-kill-switch-and-dns-guard)
11. [Privacy check (leak test)](#privacy-check-leak-test)
12. [Creating your own torrents](#creating-your-own-torrents)
13. [System tray and notifications](#system-tray-and-notifications)
14. [Settings, tab by tab](#settings-tab-by-tab)
15. [I2P (optional)](#i2p-optional)
16. [Keyboard shortcuts](#keyboard-shortcuts)
17. [Where Hushwing keeps its data](#where-hushwing-keeps-its-data)
18. [Troubleshooting](#troubleshooting)
19. [Limits and honest notes](#limits-and-honest-notes)
20. [Building from source](#building-from-source)
21. [License](#license)

---

## Features at a glance

| | |
|---|---|
| 🔒 **VPN kill switch** | Traffic is tied to your VPN adapter and stops the instant the VPN drops |
| 🛡️ **Strict mode** | Nothing connects until Hushwing is bound to a VPN or proxy |
| 🌐 **DNS guard** | Tracker names are looked up only through the VPN's own DNS, never Windows |
| 🔍 **Privacy check** | One-click, fully local leak test of sockets, public IP and DNS |
| 🧪 **File inspector** | Offline scanner that catches disguised programs and fake "videos" |
| 🕶️ **Anonymous by default** | Forced encryption, no client fingerprint, random port each launch |
| 📋 **Download queue** | Set how many torrents download and seed at once |
| 🐢 **Speed limiter** | Set-and-forget download and upload caps |
| ✨ **Create torrents** | Hybrid v1 + v2, private torrents, no identifying metadata |
| 🖱️ **Drag and drop** | Drop `.torrent` files or magnet links onto the window |
| 🔔 **Tray and notifications** | Keeps running quietly in the system tray |
| 🧅 **I2P support** | Optional anonymous network through your own I2P router |

---

## Quick start

1. **Connect your VPN** (for example Proton VPN).
2. **Run `Hushwing.exe`.** Nothing is installed. The program is this one file.
   > The first time, Windows SmartScreen may say *"Windows protected your PC"* because the file isn't digitally signed. Click **More info → Run anyway**.
3. In the **Protect your IP address** window, leave **Any VPN adapter – automatic (recommended)** selected and click **Use this adapter**.
4. **Add a torrent:** click **+ Add torrent**, click **Magnet**, or drag a `.torrent` file or magnet link onto the window.
5. Downloads go to your **Downloads** folder unless you change it in **Settings → General**. Files stay where they're saved until you move them yourself.

The status bar at the bottom right should show something like:

```
Encrypted · Anonymous · VPN: ProtonVPN (10.2.0.2) · Strict · Port 51413
```

🟢 Green means protected. 🟡 Yellow or 🔴 red means look at the warning.

---

## What Hushwing protects you from

| Threat | Protection |
|---|---|
| Your real IP showing up in torrent swarms | **Strict mode** refuses all traffic until Hushwing is tied to your VPN, and the **kill switch** stops everything the instant the VPN drops |
| Your ISP seeing torrent traffic | **Encryption is forced** on every peer connection |
| Being fingerprinted | **Anonymous mode** hides the client name, version and your local IP, and a **random port** is picked every launch |
| Fake or malware torrents | The **inspector** blocks disguised programs before they download and checks every finished download |
| History left on your PC | **Incognito mode**, plus a one-click **Clear history** |
| DNS leaks | The **DNS guard** looks up tracker names only through your VPN's own DNS server and never asks Windows. The **Privacy check** proves it |

---

## The main window

### Toolbar (left to right)

| Button | What it does |
|---|---|
| **+ Add torrent** | Open `.torrent` files |
| **Magnet** | Paste a magnet link (filled in automatically if one is on your clipboard) |
| **+ Create** | Make your own torrent ([details](#creating-your-own-torrents)) |
| **▶ ⏸ ✕** | Resume, pause or remove the selected torrents (hover for a tooltip) |
| **Filter** | All / Downloading / Seeding / Queued / Paused / Errors |
| **Search** | Type part of a name to filter the list |
| **Privacy check** | The leak test ([details](#privacy-check-leak-test)) |
| **Settings** | All options ([details](#settings-tab-by-tab)) |

### Torrent list columns

| Column | Meaning |
|---|---|
| **#** | Place in the download queue (blank for seeding torrents) |
| **Name, Size, Progress** | The basics |
| **Status** | Downloading, Seeding, Stalled (no peers), Queued, Paused, Fetching metadata, Checking, Blocked (kill switch), Blocked (strict mode), Dangerous – paused |
| **Down / Up** | Current speeds |
| **Seeds / Peers** | How many you're connected to |
| **ETA, Ratio** | Time left; uploaded divided by downloaded |
| **Safety** | Inspecting…, Clean, Check (worth a look), DANGER (dangerous files found) |

**Row colours:** 🔵 downloading · 🟢 seeding · 🟣 queued · ⚪ paused · 🟡 stalled · 🔴 error or blocked

### Detail tabs (for the selected torrent)

| Tab | Shows |
|---|---|
| **General** | Name, info hash, save folder, totals, swarm, safety results, pieces, comment, trackers |
| **Files** | Every file with size, progress and whether it downloads. Flagged files are red (dangerous) or yellow (caution), with the reason |
| **Peers** | Who you're connected to, their client, progress, speeds, and whether the connection is encrypted |
| **Speed** | Live graph of the last 2 minutes (blue = down, green = up) |

### Status bar

- **Bottom left:** your speed limit (click it to change), total speeds, torrent count and recent messages.
- **Bottom right:** privacy status. When traffic is blocked, a red banner also appears across the top.

---

## Adding torrents

- **+ Add torrent** (`Ctrl+O`): pick one or more `.torrent` files.
- **Magnet** (`Ctrl+M`): paste a magnet link.
- **`Ctrl+V`** anywhere in the window adds the magnet link on your clipboard.
- **Drag and drop** `.torrent` files (several at once is fine) or a magnet link onto the window. A blue *"Drop torrents or magnet links"* banner appears while you drag.
  > Web links (`http://…`) can't be dropped. Save the `.torrent` file first, then drop the file.
- **Default app:** once Hushwing is your default for torrents (**Settings → General**), double-clicking a `.torrent` file or clicking a magnet link in your browser opens it in Hushwing. Only one Hushwing window runs; new torrents are handed to the window that's already open.

As soon as Hushwing knows a torrent's file list, it checks the file names. Dangerous files are skipped automatically and a pop-up tells you what was blocked.

---

## Managing torrents

Select a torrent (`Ctrl+A` selects all), then:

| Action | How |
|---|---|
| Resume / Pause | `Ctrl+R` / `Ctrl+P` |
| Remove (keeps downloaded files) | `Delete` |
| Remove + delete data | `Shift+Delete` (Hushwing always asks first) |
| Open folder | `Enter`, `Ctrl+E`, or double-click the torrent |

### Right-click menu on a torrent

- **Resume / Pause**
- **Force start (skip queue):** starts now even if the queue is full
- **Queue:** move to top / up / down / bottom
- **Sequential download:** downloads in order, so you can start watching a video before it finishes
- **Open folder**
- **Inspect files now:** re-runs the safety inspector
- **Copy magnet link**
- **Force recheck:** re-verifies the files already on disk
- **Remove / Remove + delete data**

### Files tab

Double-click a file to switch it between downloading and skipped. Right-click a file for:

- **Open** (asks first if the file is flagged or can run code)
- **Show in folder**
- **Download / skip this file**

---

## Speed limits

*Set it and forget it.*

Click the **No speed limit / Limit …** text at the bottom left, press `Ctrl+L`, or use the tray menu.

- Enter download and upload limits in **MB/s** (`0` = unlimited), or click a preset: **Unlimited, 1, 5 or 10 MB/s**.
- Limits are saved and apply to all torrents until you change them.
- The same values are in **Settings → General**.

---

## The download queue

By default **3 torrents download** and **5 seed** at the same time. The others show **Queued** and start by themselves when a slot frees up. Change the numbers in **Settings → General** (*Max active downloads*, *Max active seeding torrents*).

- The **#** column shows each torrent's place in the queue.
- Move a torrent with `Ctrl+↑` / `Ctrl+↓` or **right-click → Queue**.
- **Force start** (`Ctrl+S`) starts a torrent immediately and leaves it outside the queue.
- Torrents that are barely moving don't take up a slot, so a dead torrent won't hold up the others.

---

## Safety: the built-in file inspector

Hushwing has its own scanner. It **reads files only on your PC, never contacts anyone**, and needs no installation or updates. It looks for the tricks fake torrents use.

### Before downloading (file names)

**Skipped automatically** (*Skip dangerous files before they download*):

- Double extensions: `Movie.2024.mkv.exe`
- Real extensions hidden behind spaces: `Movie 1080p                 .scr`
- Hidden Unicode characters that reverse a file name
- `.exe`, `.bat`, `.vbs`, `.lnk` and similar files inside a video or music torrent (the "codec" / "player" scam)
- `.scr`, `.pif` and `.lnk` files in any torrent

**Flagged in yellow only:**

- Programs and scripts in ordinary software torrents
- Office files with macros
- Disk images (`.iso`, `.img`) in video or music torrents

### After downloading (file contents)

- Programs disguised as other files (a `sample.mp4` or `subs.srt` that is really an `.exe`)
- "Videos" that are actually archives or documents
- Password-protected ZIP, RAR and 7-Zip archives — antivirus can't see inside them, so they're a favourite hiding place
- Programs hidden inside archives
- Windows Media videos locked with DRM that send you to a website for a "licence" or codec (a classic scam)
- PDFs that can launch programs or contain JavaScript
- Tiny "videos" that aren't real video files

> [!WARNING]
> If anything dangerous is found, the torrent is **paused at once** so you stop sharing it, and a window lists each file and the reason. Its status becomes **Dangerous – paused** and Hushwing asks before letting you resume it. Deleting the torrent and its files is the safest choice.

### Other safety features

- **Mark of the Web:** downloaded files are tagged as "from the internet", so Windows SmartScreen and Office Protected View check them when opened.
- **Extra scanner (optional):** if you install an antivirus later, put its command in **Settings → Safety**. `{path}` is replaced with the download path, and exit code `0` means clean. Microsoft Defender is used automatically if it's present.

> [!NOTE]
> The inspector doesn't recognise specific known viruses. A real program that is itself infected, in a software torrent you meant to download, only gets a yellow "check" note. Only run programs from sources you trust.

---

## Privacy: strict mode, kill switch and DNS guard

### Strict mode *(on by default)*

Hushwing won't connect to anyone until it's tied to a VPN adapter (or a proxy is set). This prevents leaks if you forget to turn the VPN on.

### VPN binding / kill switch

**Settings → Network → Bind to adapter**

Choose **Any VPN adapter – automatic (recommended)**. Hushwing follows whichever VPN adapter is connected, even when the VPN app changes the adapter's name between connections.

- All torrent traffic uses **only the VPN's address**.
- If the VPN disconnects, traffic **stops instantly**, the red banner appears and you get a notification.
- Everything resumes when the VPN comes back.

### Also on by default

- Forced encryption on all peer connections
- Anonymous mode: no client name, version or local IP revealed
- A random port every launch
- UPnP / NAT-PMP and local peer discovery turned off
- Secure tracker checks (HTTPS validation, SSRF protection)
- Seeding stops at ratio 1.0, so your IP spends less time in swarms

### DNS guard *(on by default — Settings → Privacy)*

Normally a torrent program asks Windows for a tracker's address (*"where is tracker.example.org?"*). Windows can send that question to your router or ISP instead of through the VPN — a **DNS leak** that reveals you use BitTorrent and which trackers you use.

With the DNS guard on, **the torrent engine never sees a tracker name**:

| What | How it's looked up |
|---|---|
| **UDP trackers** | Hushwing asks your VPN's own DNS server from inside the tunnel, then gives the engine only the IP address |
| **HTTP / HTTPS trackers** | The engine talks to a tiny relay inside Hushwing. The relay looks the name up the same way, connects from the VPN address, and checks the HTTPS certificate against the real name. It only accepts connections from this PC |
| **DHT start-up servers** | Looked up the same way |
| **VPN down** | No lookups happen at all. Nothing falls back to Windows |

**What you'll notice:**

- Nothing in daily use. The General tab, **Copy magnet link** and the saved torrent list all show the trackers' real names.
- Web seeds (direct HTTP download sources inside some torrents) are skipped while the guard is on. They're kept in the torrent and come back if you turn the guard off.

The guard works whenever Hushwing is bound to a VPN adapter. It isn't needed with a SOCKS5 proxy, which looks names up itself.

### Optional

- **Incognito mode:** nothing is saved. When Hushwing closes, the torrent list and history are erased. Downloaded files stay.
- **Clear history now:** forgets every torrent. Files stay.
- **IP blocklist:** load a P2P or DAT list (`.gz` is fine) to block known bad IP ranges.
- **SOCKS5 or HTTP proxy.** The password is stored encrypted with your Windows account (DPAPI).

---

## Privacy check (leak test)

Click **Privacy check** in the toolbar, press `Ctrl+I`, or use the tray menu. **Every check runs on your PC — nothing is sent to an outside website.**

| # | Check | What it tells you |
|---|---|---|
| 1 | **Binding** | Whether traffic is tied to your VPN, or stopped completely |
| 2 | **Socket audit** | Every connection and listening port Hushwing has open must use the VPN's address. Any that don't are listed in red |
| 3 | **What the swarm sees** | The public IP that trackers and peers report back. It should match your VPN app's IP, not your home IP (appears after the first tracker contact) |
| 4 | **DNS guard** | Confirms the guard is on, which DNS server it uses (your VPN's), and how many lookups it has handled |
| 5 | **DNS leak test** | For *other* apps on this PC: sends a harmless query for `invalid.` (a name that never exists) to the DNS servers of your non-VPN adapters |

For the DNS leak test:

- **No answer** — those servers are blocked while the VPN is on. No leak path.
- **An answer** — Windows could send lookups that way. That would show your ISP you use BitTorrent (not what you download, and peers still can't see your IP). Fix it by turning on DNS leak protection or the kill switch in your VPN app.

The overall result is 🟢 green (all good), 🟡 yellow (see the warning) or 🔴 red (your IP may be exposed). Click **Run again** after fixing anything.

---

## Creating your own torrents

Click **+ Create** or press `Ctrl+N`.

| Field | Notes |
|---|---|
| **File or folder** | What to share (`Thumbs.db`, `desktop.ini` and hidden files are left out) |
| **Trackers** | One per line (`http://`, `https://` or `udp://`). Leave a blank line between groups for backup tiers. Leave empty for a DHT-only torrent |
| **Comment** | Optional |
| **Format** | Hybrid v1 + v2 (recommended), or v1 only for very old clients |
| **Private torrent** | Shared only through its trackers: no DHT or peer exchange |
| **Start seeding it now** | Adds it to Hushwing straight away |

Click **Create…**, choose where to save the `.torrent` file and wait for the progress bar. For privacy, Hushwing leaves out the *created by* tag and the creation date.

> [!NOTE]
> Anyone who gets the `.torrent` or its magnet link can download what you share.

---

## System tray and notifications

Closing the window (✕) keeps Hushwing running in the system tray near the clock, and downloads keep going. Look for the shield icon; if it's hidden, click the **^** arrow next to the clock.

**Click** the tray icon to reopen the window. **Right-click** it for:

> Open Hushwing · Pause all · Resume all · Speed limits… · Privacy check… · Quit Hushwing

*Resume all* skips torrents flagged as dangerous.

To quit fully, use **Quit Hushwing** in the tray menu or press `Ctrl+Q`. To make ✕ quit instead, untick **Keep running in the system tray** in **Settings → General**.

### Notifications (Windows pop-ups)

- Download complete
- Dangerous files blocked or found
- Kill switch: VPN disconnected and traffic stopped

Turn them off with **Show notifications** in **Settings → General**.

---

## Settings, tab by tab

<details>
<summary><b>General</b></summary>

| Setting | Notes |
|---|---|
| Download folder | Where new torrents save |
| Max download / upload speed (MB/s) | `0` = unlimited |
| Max active downloads / seeding | Queue sizes (default 3 / 5) |
| Stop seeding at ratio | Default 1.0 (`0` = never) |
| Stop seeding after minutes | `0` = never |
| Keep running in the system tray | On by default |
| Show notifications | On by default |
| Make Hushwing the default for magnet links and `.torrent` files | Changes settings for your Windows account only. Windows may ask you to confirm in **Settings → Apps → Default apps** |

</details>

<details>
<summary><b>Privacy</b></summary>

- Strict mode
- Force encryption
- Anonymous mode
- Random port every launch (or a fixed port)
- Incognito mode
- Clear history now
- DNS guard (look up tracker names only through the VPN)

</details>

<details>
<summary><b>Network</b></summary>

| Setting | Notes |
|---|---|
| Bind to adapter (kill switch) | Choose **Any VPN adapter – automatic** |
| DHT | Finds peers without trackers; needed for most magnet links (on) |
| Local peer discovery | Broadcasts on your home network (off) |
| UPnP / NAT-PMP | Opens a router port (off; useless behind a VPN anyway) |
| IP blocklist | Optional |
| I2P settings | See [I2P](#i2p-optional) |

</details>

<details>
<summary><b>Proxy</b></summary>

Type (none / SOCKS5 / HTTP), host, port, username, password.

</details>

<details>
<summary><b>Safety</b></summary>

- Shows the inspector status and whether an antivirus is present
- Skip dangerous files before they download (on)
- Inspect downloads when they finish (on)
- Extra scanner (optional)
- Mark downloads as coming from the internet (on)

</details>

<details>
<summary><b>About</b></summary>

Version, the built-in libtorrent version, and the keyboard shortcut list. In the `.exe`, libtorrent updates come with a new Hushwing build.

</details>

---

## I2P (optional)

I2P is an anonymous network, similar to Tor. With it, nobody (not even your VPN company) can tell who you are — but it's much slower and only reaches I2P torrents.

1. Install and start an I2P router, for example **i2pd**. Hushwing doesn't include one.
2. **Settings → Network:** tick **I2P anonymous network**. The usual router address is `127.0.0.1`, port `7656`.
3. The line under the settings says **I2P router found** when Hushwing can reach it.
4. **Mixed mode** also lets I2P torrents use normal peers. It's faster, but those peers can see your VPN address.

The status bar shows **I2P** while it's enabled.

---

## Keyboard shortcuts

Press `F1` in the app for this list.

| Shortcut | Action |
|---|---|
| `Ctrl+O` | Add `.torrent` file |
| `Ctrl+M` | Add magnet link |
| `Ctrl+V` | Paste magnet link from the clipboard |
| `Ctrl+N` | Create a torrent |
| `Ctrl+A` | Select all torrents |
| `Ctrl+R` / `Ctrl+P` | Resume / pause selected |
| `Ctrl+S` | Force start selected (skip the queue) |
| `Ctrl+↑` / `Ctrl+↓` | Move up / down in the queue |
| `Delete` | Remove (keep files) |
| `Shift+Delete` | Remove and delete files |
| `Enter` / `Ctrl+E` | Open folder |
| `Ctrl+F` | Search |
| `Ctrl+L` | Speed limits |
| `Ctrl+I` | Privacy check |
| `Ctrl+,` | Settings |
| `F1` | Shortcut list |
| `Ctrl+Q` | Quit |

---

## Where Hushwing keeps its data

Settings and the torrent list live in `%USERPROFILE%\.hushwing\`:

| File | Contents |
|---|---|
| `config.json` | Your settings |
| `resume\` | One file per torrent, so downloads continue after a restart |
| `scans.json` | Safety inspection results |

- Nothing is written to the registry unless you click **Make Hushwing the default…**.
- Incognito mode and **Clear history now** erase the torrent list. Downloaded files are never touched.
- To move Hushwing to another PC, copy `Hushwing.exe` (and the `.hushwing` folder if you want to keep your torrent list).

---

## Troubleshooting

<details>
<summary><b>"Blocked (strict mode)" on every torrent</b></summary>

Hushwing isn't tied to your VPN yet. Click **Choose VPN…** in the red banner and pick **automatic**.
</details>

<details>
<summary><b>"Blocked (kill switch)"</b></summary>

Your VPN is off or reconnecting. Turn it on and Hushwing resumes by itself within a second or two.
</details>

<details>
<summary><b>Torrent stuck on "Fetching metadata"</b></summary>

A magnet link needs peers to get the file list. Keep DHT on. Some links are simply dead.
</details>

<details>
<summary><b>"Stalled"</b></summary>

No peers right now. Old or unpopular torrents can take a while.
</details>

<details>
<summary><b>"Queued" and not starting</b></summary>

The queue is full. Force start it (`Ctrl+S`) or raise **Max active downloads**.
</details>

<details>
<summary><b>Files show "Skip" and won't download</b></summary>

The inspector blocked them as dangerous. You can double-click a file to download it anyway, but think twice.
</details>

<details>
<summary><b>I closed the window and it's still running</b></summary>

It's in the tray. Right-click the tray icon → **Quit Hushwing**.
</details>

<details>
<summary><b>Windows SmartScreen warning when starting</b></summary>

Expected for an unsigned program: **More info → Run anyway**.
</details>

---

## Limits and honest notes

- A VPN hides your IP from peers. It doesn't make downloading copyrighted material legal.
- The inspector catches disguise tricks, not every known virus. Treat any program from a torrent with suspicion.
- **DNS:** the DNS guard keeps Hushwing's own lookups inside the VPN. It was tested with a Windows packet capture plus the Windows DNS cache: with the guard on, Windows never resolved a single tracker name. Other apps on your PC still depend on your VPN app's leak protection.
- **A VPN only hides you if it exits to the internet somewhere else.** If the Privacy check shows the same public IP with and without the VPN, the "VPN" is just a tunnel back to your own network (for example a WireGuard server on your home router), and peers can see your home IP. Hushwing can't tell those apart by itself, so compare the address with the one your VPN app shows.
- I2P needs a separate I2P router, which isn't included.
- Hushwing is built on libtorrent, the same engine as qBittorrent and Deluge. It hasn't been through an outside security audit.

---

## Building from source

**Requirements:** Windows, Python 3.12

```bat
py -3.12 -m pip install libtorrent sv-ttk psutil pillow pystray tkinterdnd2 pyinstaller
source\build_exe.bat
```

The portable `Hushwing.exe` is written to the repository root (the folder above `source`).

To run without building:

```bat
py -3.12 source\torrent_client.py
```

### Project layout

| Path | Purpose |
|---|---|
| `source/torrent_client.py` | The app: engine, window, dialogs, settings |
| `source/dnsguard.py` | DNS guard: VPN-only lookups and the HTTP(S) tracker relay |
| `source/inspector.py` | Offline file inspector |
| `source/privacy_check.py` | Local leak test |
| `source/tray.py` | System tray icon and menu |
| `source/assets/` | Icons (`make_icon.py` regenerates them) |
| `source/build_exe.bat` | Builds the single-file `Hushwing.exe` with PyInstaller |

---

## License

Hushwing is released under the [GNU General Public License v3.0](LICENSE).
