@echo off
rem Rebuilds Hushwing.exe (one portable file) into the folder above this one.
rem Needs: py -3.12 -m pip install libtorrent sv-ttk psutil pillow pystray tkinterdnd2 pyinstaller
set "SRC=%~dp0"
py -3.12 -m PyInstaller --noconfirm --onefile --windowed --name Hushwing --icon "%SRC%assets\hushwing.ico" ^
  --add-data "%SRC%assets\hushwing.ico;assets" --add-data "%SRC%assets\hushwing_256.png;assets" ^
  --collect-data sv_ttk --collect-all tkinterdnd2 --hidden-import pystray._win32 ^
  --exclude-module matplotlib --exclude-module numpy ^
  --distpath "%SRC%.." --workpath "%TEMP%\hushwing-build" --specpath "%TEMP%\hushwing-build" "%SRC%torrent_client.py"
