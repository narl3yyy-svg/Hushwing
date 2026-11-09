"""System-tray icon + Windows notifications for Hushwing (pystray).

All menu clicks are put on a queue; the Tk main loop picks them up (Tk isn't thread-safe)."""
from __future__ import annotations

import queue

try:
    import pystray
    from PIL import Image
except ImportError:  # tray is optional
    pystray = None


class Tray:
    def __init__(self, name: str, icon_png):
        self.actions: queue.Queue = queue.Queue()
        self.icon = None
        if not pystray or not icon_png or not icon_png.exists():
            return
        img = Image.open(icon_png).convert("RGBA").resize((64, 64), Image.LANCZOS)

        def act(name_):
            return lambda _icon=None, _item=None: self.actions.put(name_)

        menu = pystray.Menu(
            pystray.MenuItem(f"Open {name}", act("show"), default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Pause all", act("pause_all")),
            pystray.MenuItem("Resume all", act("resume_all")),
            pystray.MenuItem("Speed limits…", act("limits")),
            pystray.MenuItem("Privacy check…", act("privacy")),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(f"Quit {name}", act("quit")),
        )
        self.icon = pystray.Icon(name, img, name, menu)
        try:
            self.icon.run_detached()
        except Exception:
            self.icon = None

    @property
    def available(self) -> bool:
        return self.icon is not None

    def set_tooltip(self, text: str):
        if self.icon:
            try:
                self.icon.title = text[:120]
            except Exception:
                pass

    def notify(self, message: str, title: str = ""):
        if self.icon:
            try:
                self.icon.notify(message[:250], title[:60])
            except Exception:
                pass

    def stop(self):
        if self.icon:
            try:
                self.icon.stop()
            except Exception:
                pass
