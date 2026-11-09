================================================================================
                               HUSHWING  3.0
               A privacy-first BitTorrent client for Windows
================================================================================

CONTENTS
  1.  Quick start
  2.  What Hushwing protects you from
  3.  The main window
  4.  Adding torrents
  5.  Managing torrents (pause, queue, remove, files)
  6.  Speed limits
  7.  The download queue
  8.  Safety: the built-in file inspector
  9.  Privacy: strict mode, VPN kill switch and more
  10. Privacy check (leak test)
  11. Creating your own torrents
  12. System tray and notifications
  13. Settings, tab by tab
  14. I2P (anonymous network, optional)
  15. Keyboard shortcuts
  16. Where Hushwing keeps its data
  17. Troubleshooting
  18. Limits and honest notes
  19. Rebuilding Hushwing.exe from source


--------------------------------------------------------------------------------
1. QUICK START
--------------------------------------------------------------------------------
  1. Connect your VPN (for example Proton VPN).
  2. Double-click Hushwing.exe. Nothing is installed. The program is this one
     file.
       * The first time, Windows SmartScreen may say "Windows protected your
         PC" because the file isn't digitally signed. Click "More info", then
         "Run anyway".
  3. On first launch, a "Protect your IP address" window appears. Leave
     "Any VPN adapter - automatic (recommended)" selected and click
     "Use this adapter".
  4. Add a torrent: click "+ Add torrent", click "Magnet", or drag a .torrent
     file or magnet link onto the window.
  5. Downloads go to your Downloads folder unless you change it in
     Settings -> General. Files stay where they're saved until you move
     them yourself.

  The status bar at the bottom right should show something like:
      Encrypted . Anonymous . VPN: ProtonVPN (10.2.0.2) . Strict . Port 51413
  Green means protected. Yellow or red means look at the warning.


--------------------------------------------------------------------------------
2. WHAT HUSHWING PROTECTS YOU FROM
--------------------------------------------------------------------------------
  * Your real IP showing up in torrent swarms:
      - Strict mode refuses all traffic until Hushwing is tied to your VPN.
      - The kill switch stops everything the instant the VPN drops.
  * Your ISP seeing torrent traffic: encryption is forced on every peer
    connection.
  * Being fingerprinted: anonymous mode hides the client name, version and
    your local IP, and Hushwing picks a random port every launch.
  * Fake or malware torrents: the built-in inspector blocks disguised
    programs before they download and checks every finished download.
  * History on your PC: incognito mode, plus a one-click "Clear history".
  * DNS leaks: the DNS guard looks up tracker names only through your VPN's
    own DNS server and never asks Windows (section 10). The Privacy check
    proves it.


--------------------------------------------------------------------------------
3. THE MAIN WINDOW
--------------------------------------------------------------------------------
  TOOLBAR (left to right)
    + Add torrent    open .torrent files
    Magnet           paste a magnet link (it fills in automatically if one is
                     on your clipboard)
    + Create         make your own torrent (section 11)
    >   (Resume)  ||  (Pause)  X  (Remove)
                     act on the selected torrents. Hover for a tooltip.
    Filter           All / Downloading / Seeding / Queued / Paused / Errors
    Search           type part of a name to filter the list
    Privacy check    the leak test (section 10)
    Settings         all options (section 13)

  TORRENT LIST COLUMNS
    #              place in the download queue (blank for seeding torrents)
    Name, Size, Progress
    Status         Downloading, Seeding, Stalled (no peers), Queued, Paused,
                   Fetching metadata (magnet links), Checking,
                   Blocked (kill switch), Blocked (strict mode),
                   Dangerous - paused
    Down / Up      current speeds
    Seeds / Peers  how many you're connected to
    ETA, Ratio     time left, uploaded divided by downloaded
    Safety         Inspecting..., Clean, Check (worth a look),
                   DANGER (dangerous files found)

    Colours: blue = downloading, green = seeding, violet = queued,
    grey = paused, yellow = stalled, red = error or blocked.

  DETAIL TABS (bottom half, for the selected torrent)
    General  name, info hash, save folder, totals, swarm, safety results,
             pieces, comment, trackers
    Files    every file with size, progress and whether it downloads.
             Flagged files are red (dangerous) or yellow (caution), with
             the reason shown.
    Peers    who you're connected to, their client, progress, speeds, and
             whether the connection is encrypted
    Speed    live graph of the last 2 minutes (blue = down, green = up)

  STATUS BAR
    Bottom left:  your speed limit (click it to change), total speeds,
                  torrent count, and recent messages.
    Bottom right: privacy status. When traffic is blocked, a red banner also
                  appears across the top.


--------------------------------------------------------------------------------
4. ADDING TORRENTS
--------------------------------------------------------------------------------
  * "+ Add torrent" (Ctrl+O): pick one or more .torrent files.
  * "Magnet" (Ctrl+M): paste a magnet link.
  * Ctrl+V anywhere in the window: adds the magnet link on your clipboard.
  * Drag and drop: drop .torrent files (several at once is fine) or a magnet
    link onto the window. A blue "Drop torrents or magnet links" banner
    appears while you drag. Web links (http://...) can't be dropped: save
    the .torrent file first, then drop the file.
  * Double-clicking a .torrent file or clicking a magnet link in your browser
    opens it in Hushwing, once Hushwing is your default app (Settings ->
    General). Only one Hushwing window runs. New torrents are handed to the
    window that's already open.

  As soon as Hushwing knows a torrent's file list, it checks the file names
  (section 8). Dangerous files are skipped automatically and a pop-up tells
  you what was blocked.


--------------------------------------------------------------------------------
5. MANAGING TORRENTS
--------------------------------------------------------------------------------
  Select a torrent (Ctrl+A selects all), then:
    Resume (Ctrl+R) / Pause (Ctrl+P)
    Remove (Delete): removes the torrent but keeps the downloaded files.
    Remove + delete data (Shift+Delete): also deletes the files. Hushwing
        always asks first.
    Open folder: Enter, Ctrl+E, or double-click the torrent.

  RIGHT-CLICK MENU ON A TORRENT
    Resume / Pause
    Force start (skip queue): starts now even if the queue is full
    Queue: move to top / up / down / bottom
    Sequential download: downloads in order, so you can start watching a
        video before it finishes
    Open folder
    Inspect files now: re-runs the safety inspector
    Copy magnet link
    Force recheck: re-verifies the files already on disk
    Remove / Remove + delete data

  FILES TAB
    Double-click a file to switch it between downloading and skipped.
    Right-click a file for:
      Open: asks first if the file is flagged or can run code
      Show in folder
      Download / skip this file


--------------------------------------------------------------------------------
6. SPEED LIMITS (set and forget)
--------------------------------------------------------------------------------
  Click the "No speed limit" / "Limit ..." text at the bottom left, press
  Ctrl+L, or use the tray menu. Enter download and upload limits in MB/s
  (0 = unlimited), or click a preset: Unlimited, 1, 5 or 10 MB/s. Limits are
  saved and apply to all torrents until you change them. The same values
  are also in Settings -> General.


--------------------------------------------------------------------------------
7. THE DOWNLOAD QUEUE
--------------------------------------------------------------------------------
  By default 3 torrents download and 5 seed at the same time. The others
  show "Queued" and start by themselves when a slot frees up. Change the
  numbers in Settings -> General ("Max active downloads", "Max active
  seeding torrents").

  * The # column shows each torrent's place in the queue.
  * Move a torrent with Ctrl+Up / Ctrl+Down or right-click -> Queue.
  * "Force start" (Ctrl+S) starts a torrent immediately and leaves it outside
    the queue.
  * Torrents that are barely moving don't take up a slot, so a dead torrent
    won't hold up the others.


--------------------------------------------------------------------------------
8. SAFETY: THE BUILT-IN FILE INSPECTOR
--------------------------------------------------------------------------------
  Hushwing has its own scanner. It reads files only on your PC, never
  contacts anyone, and needs no installation or updates. It looks for the
  tricks fake torrents use.

  BEFORE DOWNLOADING (file names only)
    Skipped automatically ("Skip dangerous files before they download"):
      * Double extensions:       Movie.2024.mkv.exe
      * Hidden real extensions:  Movie 1080p                 .scr
      * Hidden Unicode characters that reverse a file name
      * .exe, .bat, .vbs, .lnk and similar files inside a video or music
        torrent (the "codec" / "player" scam)
      * .scr, .pif and .lnk files in any torrent
    Flagged in yellow only:
      * Programs and scripts in ordinary software torrents
      * Office files with macros
      * Disk images (.iso, .img) in video or music torrents

  AFTER DOWNLOADING (file contents, not names)
      * Programs disguised as other files (for example a "sample.mp4" or
        "subs.srt" that is really an .exe)
      * "Videos" that are actually archives or documents
      * Password-protected ZIP, RAR and 7-Zip archives. Antivirus can't see
        inside them, so they're a favourite hiding place.
      * Programs hidden inside archives
      * Windows Media videos locked with DRM that send you to a website for
        a "licence" or codec (a classic scam)
      * PDFs that can launch programs, or that contain JavaScript
      * Tiny "videos" that aren't real video files

  If anything dangerous is found, the torrent is paused at once so you stop
  sharing it, and a window lists each file and the reason. Its status
  becomes "Dangerous - paused". Hushwing asks before letting you resume it.
  Deleting the torrent and its files is the safest choice.

  OTHER SAFETY FEATURES
    * Mark of the Web: downloaded files are tagged as "from the internet", so
      Windows SmartScreen and Office Protected View check them when opened.
    * Extra scanner (optional): if you install an antivirus later, put its
      command in Settings -> Safety. {path} is replaced with the download
      path, and exit code 0 means clean. Microsoft Defender is used
      automatically if it's present.

  What the inspector can't do: it doesn't recognise specific known viruses.
  A real program that is itself infected, in a software torrent you meant to
  download, only gets a yellow "check" note. Only run programs from sources
  you trust.


--------------------------------------------------------------------------------
9. PRIVACY: STRICT MODE, VPN KILL SWITCH AND MORE
--------------------------------------------------------------------------------
  STRICT MODE (on by default)
    Hushwing won't connect to anyone until it's tied to a VPN adapter (or
    a proxy is set). This prevents leaks if you forget to turn the VPN on.

  VPN BINDING / KILL SWITCH (Settings -> Network -> Bind to adapter)
    "Any VPN adapter - automatic (recommended)": Hushwing follows whichever
    VPN adapter is connected. Proton VPN changes its adapter name between
    connections (for example "ProtonVPN" one time and "ProtonUS-42" the next),
    and automatic mode handles that. All torrent traffic uses only the
    VPN's address. If the VPN disconnects, traffic stops instantly, the red
    banner appears and you get a notification. Everything resumes when the
    VPN comes back.

  ALSO ON BY DEFAULT
    * Forced encryption on all peer connections
    * Anonymous mode: no client name, version or local IP revealed
    * A random port every launch
    * UPnP / NAT-PMP and local peer discovery turned off
    * Secure tracker checks (HTTPS validation, SSRF protection)
    * Seeding stops at ratio 1.0, so your IP spends less time in swarms

  DNS GUARD (on by default; Settings -> Privacy)
    Normally a torrent program asks Windows for a tracker's address (for
    example "where is tracker.opentrackr.org?"). Windows can send that
    question to your router or ISP instead of through the VPN: a DNS leak.
    It reveals that you use BitTorrent and which trackers you use.
    With the DNS guard on, the torrent engine never sees a tracker name:
      * UDP trackers: Hushwing looks the name up itself. It asks your VPN's
        own DNS server from inside the tunnel, then gives the engine only the
        IP address.
      * HTTP and HTTPS trackers: the engine talks to a tiny relay inside
        Hushwing. The relay looks the name up the same way, connects from
        the VPN address, and checks the HTTPS certificate against the real
        name. The relay only accepts connections from this PC.
      * DHT start-up servers: looked up the same way.
      * If the VPN is down, no lookups happen at all. Nothing falls back to
        Windows.
    What you'll notice:
      * Nothing in daily use. The General tab, "Copy magnet link" and the
        saved torrent list all show the trackers' real names.
      * Web seeds (direct HTTP download sources inside some torrents) are
        skipped while the guard is on. They're kept in the torrent and come
        back if you turn the guard off.
    The guard works whenever Hushwing is bound to a VPN adapter. It isn't
    needed with a SOCKS5 proxy, which looks names up itself.

  OPTIONAL
    * Incognito mode: nothing is saved. When Hushwing closes, the torrent
      list and history are erased. Downloaded files stay.
    * Clear history now: forgets every torrent. Files stay.
    * IP blocklist: load a P2P or DAT list (.gz is fine) to block known bad
      IP ranges.
    * SOCKS5 or HTTP proxy. The password is stored encrypted with your
      Windows account (DPAPI).


--------------------------------------------------------------------------------
10. PRIVACY CHECK (LEAK TEST)
--------------------------------------------------------------------------------
  Click "Privacy check" in the toolbar, press Ctrl+I, or use the tray menu.
  Every check runs on your PC. Nothing is sent to an outside website. It
  shows:

    1. Binding: whether traffic is tied to your VPN, or stopped completely.
    2. Socket audit: every network connection and listening port Hushwing
       has open must use the VPN's address. Any that don't are listed in red.
    3. What the swarm sees: the public IP that trackers and peers report
       back. It should match the IP shown in your VPN app, not your home IP.
       (It appears after a torrent has contacted its first tracker.)
    4. DNS guard: confirms the guard is on, which DNS server it uses (your
       VPN's), and how many lookups and tracker requests it has handled.
    5. DNS leak test (for other apps on this PC): Hushwing sends a harmless question ("invalid.", a name
       that never exists) to the DNS servers of your non-VPN adapters, such
       as your router.
         - No answer: they're blocked while the VPN is on. No leak path.
         - An answer: Windows could send tracker name lookups that way. That
           would show your ISP you use BitTorrent, though not what you
           download, and peers still can't see your IP. Fix it by turning
           on DNS leak protection or the kill switch in your VPN app.

  The result at the bottom is green (all good), yellow (see the warning) or
  red (your IP may be exposed). Click "Run again" after fixing anything.


--------------------------------------------------------------------------------
11. CREATING YOUR OWN TORRENTS
--------------------------------------------------------------------------------
  Click "+ Create" or press Ctrl+N.
    File or folder   what to share (Thumbs.db, desktop.ini and hidden files
                     are left out)
    Trackers         one per line (http://, https:// or udp://). Leave a
                     blank line between groups to make backup tiers. Leave
                     the box empty for a DHT-only torrent.
    Comment          optional
    Format           Hybrid v1 + v2 (recommended), or v1 only for very old
                     clients
    Private torrent  shared only through its trackers: no DHT or peer
                     exchange
    Start seeding it now   adds it to Hushwing straight away
  Click "Create...", choose where to save the .torrent file, and wait for
  the progress bar. For privacy, Hushwing leaves out the "created by" tag
  and the creation date.

  Note: anyone who gets the .torrent or its magnet link can download what
  you share.


--------------------------------------------------------------------------------
12. SYSTEM TRAY AND NOTIFICATIONS
--------------------------------------------------------------------------------
  Closing the window (X) keeps Hushwing running in the system tray, near the
  clock. Downloads keep going. Look for the shield icon. If it's hidden,
  click the "^" arrow next to the clock.

  Click the tray icon to reopen the window. Right-click it for:
      Open Hushwing . Pause all . Resume all . Speed limits... .
      Privacy check... . Quit Hushwing
  ("Resume all" skips torrents flagged as dangerous.)

  To quit fully, use "Quit Hushwing" in the tray menu or press Ctrl+Q. To
  make X quit instead, untick "Keep running in the system tray" in Settings
  -> General.

  NOTIFICATIONS (Windows pop-ups)
    * Download complete
    * Dangerous files blocked or found
    * Kill switch: VPN disconnected and traffic stopped
  Turn them off with "Show notifications" in Settings -> General.


--------------------------------------------------------------------------------
13. SETTINGS, TAB BY TAB
--------------------------------------------------------------------------------
  GENERAL
    Download folder                      where new torrents save
    Max download / upload speed (MB/s)   0 = unlimited
    Max active downloads / seeding       queue sizes (default 3 / 5)
    Stop seeding at ratio                default 1.0 (0 = never)
    Stop seeding after minutes           0 = never
    Keep running in the system tray      on by default
    Show notifications                   on by default
    Make Hushwing the default for magnet links and .torrent files
        Changes settings for your Windows account only. Windows may ask you
        to confirm in Settings -> Apps -> Default apps.

  PRIVACY
    Strict mode, Force encryption, Anonymous mode, Random port every launch
    (or a fixed port), Incognito mode, Clear history now,
    DNS guard (look up tracker names only through the VPN)

  NETWORK
    Bind to adapter (kill switch)     choose "Any VPN adapter - automatic"
    DHT                               finds peers without trackers; needed
                                      for most magnet links (on)
    Local peer discovery              broadcasts on your home network (off)
    UPnP / NAT-PMP                    opens a router port (off; useless
                                      behind a VPN anyway)
    IP blocklist                      optional
    I2P settings                      see section 14

  PROXY
    Type (none / socks5 / http), host, port, username, password

  SAFETY
    Shows the inspector status and whether an antivirus is present.
    Skip dangerous files before they download (on)
    Inspect downloads when they finish (on)
    Extra scanner (optional)
    Mark downloads as coming from the internet (on)

  ABOUT
    Version, the built-in libtorrent version, and Keyboard shortcuts.
    (In the .exe, libtorrent updates come with a new Hushwing build.)


--------------------------------------------------------------------------------
14. I2P (ANONYMOUS NETWORK, OPTIONAL)
--------------------------------------------------------------------------------
  I2P is an anonymous network, similar to Tor. With it, nobody (not even
  your VPN company) can tell who you are, but it's much slower and only has
  I2P torrents.
    1. Install and start an I2P router, for example i2pd. Hushwing doesn't
       include one.
    2. Settings -> Network: tick "I2P anonymous network". The usual router
       address is 127.0.0.1, port 7656.
    3. The line under the settings says "I2P router found" when Hushwing can
       reach it.
    4. "Mixed mode" also lets I2P torrents use normal peers. It's faster, but
       those peers can see your VPN address.
  The status bar shows "I2P" while it's enabled.


--------------------------------------------------------------------------------
15. KEYBOARD SHORTCUTS (also: press F1 in the app)
--------------------------------------------------------------------------------
    Ctrl+O            Add .torrent file
    Ctrl+M            Add magnet link
    Ctrl+V            Paste magnet link from the clipboard
    Ctrl+N            Create a torrent
    Ctrl+A            Select all torrents
    Ctrl+R / Ctrl+P   Resume / pause selected
    Ctrl+S            Force start selected (skip the queue)
    Ctrl+Up / Down    Move up / down in the queue
    Delete            Remove (keep files)
    Shift+Delete      Remove and delete files
    Enter / Ctrl+E    Open folder
    Ctrl+F            Search
    Ctrl+L            Speed limits
    Ctrl+I            Privacy check
    Ctrl+,            Settings
    F1                Shortcut list
    Ctrl+Q            Quit


--------------------------------------------------------------------------------
16. WHERE HUSHWING KEEPS ITS DATA
--------------------------------------------------------------------------------
  Settings and the torrent list:  C:\Users\<you>\.hushwing\
      config.json   your settings
      resume\       one file per torrent, so downloads continue after a
                    restart
      scans.json    safety inspection results
  Nothing is written to the registry unless you click "Make Hushwing the
  default...". Incognito mode and "Clear history now" erase the torrent
  list. Downloaded files are never touched.

  To move Hushwing to another PC, copy Hushwing.exe (and the .hushwing
  folder if you want to keep your torrent list).


--------------------------------------------------------------------------------
17. TROUBLESHOOTING
--------------------------------------------------------------------------------
  "Blocked (strict mode)" on every torrent
      Hushwing isn't tied to your VPN yet. Click "Choose VPN..." in the red
      banner and pick "automatic".
  "Blocked (kill switch)"
      Your VPN is off or reconnecting. Turn it on and Hushwing resumes by
      itself within a second or two.
  Torrent stuck on "Fetching metadata"
      A magnet link needs peers to get the file list. Keep DHT on. Some
      links are simply dead.
  "Stalled"
      No peers right now. Old or unpopular torrents can take a while.
  "Queued" and not starting
      The queue is full. Force start it (Ctrl+S) or raise "Max active
      downloads".
  Files show "Skip" and won't download
      The inspector blocked them as dangerous. You can double-click a file
      to download it anyway, but think twice.
  I closed the window and it's still running
      It's in the tray. Right-click the tray icon -> Quit Hushwing.
  Windows SmartScreen warning when starting
      Expected for an unsigned program: More info -> Run anyway.


--------------------------------------------------------------------------------
18. LIMITS AND HONEST NOTES
--------------------------------------------------------------------------------
  * A VPN hides your IP from peers. It doesn't make downloading copyrighted
    material legal.
  * The inspector catches disguise tricks, not every known virus. Treat any
    program from a torrent with suspicion.
  * DNS: the DNS guard keeps Hushwing's own lookups inside the VPN. It was
    tested with a Windows packet capture plus Windows' DNS cache: with the
    guard on, Windows never resolved a single tracker name. Other apps on
    your PC still depend on your VPN app's leak protection.
  * A VPN only hides you if it exits to the internet somewhere else. If the
    Privacy check shows the same public IP with and without the VPN, the
    "VPN" is just a tunnel back to your own network (for example a WireGuard
    server on your home router) and peers can see your home IP. Hushwing
    can't tell those apart by itself, so compare the address with the one
    your VPN app shows.
  * I2P needs a separate I2P router, which isn't included.
  * Hushwing is built on libtorrent, the same engine as qBittorrent and
    Deluge. It hasn't been through an outside security audit.


--------------------------------------------------------------------------------
19. REBUILDING HUSHWING.EXE FROM SOURCE
--------------------------------------------------------------------------------
  The source code is in the "source" folder. To rebuild:
      py -3.12 -m pip install libtorrent sv-ttk psutil pillow pystray tkinterdnd2 pyinstaller
      source\build_exe.bat
  The new Hushwing.exe is written next to this README.
================================================================================
