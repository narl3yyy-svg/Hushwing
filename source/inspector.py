"""Hushwing's built-in offline file inspector.

Catches the tricks that torrent malware relies on, without signatures, downloads or any network access:
  * programs disguised as other files (checked by content, not by name)
  * double extensions ("movie.mkv.exe"), right-to-left-override names, padded extensions
  * scripts, shortcuts and installers hidden in video / music torrents
  * password-protected archives (ZIP, RAR, 7-Zip): the classic way to slip past antivirus
  * executables hidden inside archives
  * DRM "license" videos that send you to a website for a fake codec / player
  * PDFs that run JavaScript or launch programs, Office files with macros

Everything here reads local files only.
"""
from __future__ import annotations

import os
import re
import struct
import zipfile
from pathlib import Path

THREAT, WARNING = "threat", "warning"

VIDEO = {".mkv", ".mp4", ".m4v", ".avi", ".mov", ".wmv", ".mpg", ".mpeg", ".ts", ".m2ts", ".webm", ".flv",
         ".vob", ".3gp", ".ogv", ".divx", ".asf", ".rmvb"}
AUDIO = {".mp3", ".flac", ".aac", ".m4a", ".ogg", ".opus", ".wav", ".wma", ".alac", ".ape", ".m4b", ".dts", ".ac3"}
IMAGE = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff"}
DOC = {".txt", ".nfo", ".srt", ".ass", ".ssa", ".sub", ".idx", ".vtt", ".pdf", ".epub", ".mobi", ".azw3", ".cbz",
       ".cbr", ".sfv", ".md5", ".sha1", ".sha256", ".cue", ".log", ".m3u", ".m3u8"}
PROGRAM = {".exe", ".dll", ".sys", ".ocx", ".drv", ".efi", ".cpl", ".msi", ".msp", ".msix", ".appx", ".com"}
SCRIPT = {".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".jar",
          ".reg", ".inf", ".scf", ".url", ".chm", ".msc", ".gadget", ".application", ".xll", ".iqy", ".settingcontent-ms"}
ALWAYS_BAD = {".scr", ".pif", ".lnk"}  # practically never legitimate inside a torrent
CONTAINER = {".iso", ".img", ".vhd", ".vhdx"}  # mount as drives, hide whatever is inside
ARCHIVE = {".zip", ".rar", ".7z", ".cab", ".tar", ".gz", ".bz2", ".xz", ".001"}
MACRO = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm", ".ppsm", ".xlam", ".ppam"}
EXECUTABLE = PROGRAM | SCRIPT | ALWAYS_BAD
LIB_EXT = {".so", ".dylib", ".bin", ".node", ".pyd", ".mui", ".ax", ".acm", ".tlb", ".ime", ".flt", ".api",
           ".asi", ".xpl", ".vst", ".vst3", ".aex", ".8bf", ".plugin", ".mex", ".mexw64", ".fon"}
SAFE_LOOKING = VIDEO | AUDIO | IMAGE | DOC | {".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt", ".rtf"}

# unicode tricks: right-to-left override / embedding / isolates, zero-width chars
BIDI = re.compile("[‪-‮⁦-⁩‎‏؜​-‍﻿]")
PADDED = re.compile(r"\s{3,}\.[A-Za-z0-9]{2,5}$|[._ -]{8,}\.[A-Za-z0-9]{2,5}$")

ASF_DRM = (bytes.fromhex("fbb31122 23bdd211 b4b700a0 c955fc6e".replace(" ", "")),  # Content Encryption Object
           bytes.fromhex("14e68a29 2226174c b935dae0 7ee9289c".replace(" ", "")))  # Extended Content Encryption
SEVENZIP_AES = b"\x06\xf1\x07\x01"


def ext(name: str) -> str:
    return Path(name).suffix.lower()


def kind_of(name: str) -> str:
    e = ext(name)
    for k, s in (("video", VIDEO), ("audio", AUDIO), ("program", EXECUTABLE), ("archive", ARCHIVE),
                 ("container", CONTAINER), ("image", IMAGE)):
        if e in s:
            return k
    return "other"


def is_media_torrent(files: list[tuple[str, int]]) -> bool:
    """True when most of the torrent (by size) is video or audio."""
    total = sum(s for _, s in files) or 1
    media = sum(s for n, s in files if kind_of(n) in ("video", "audio"))
    return media / total >= 0.5


# --------------------------------------------------------------------------- name checks (before download)
def check_name(rel_path: str, media: bool) -> tuple[str, str] | None:
    """Judge one file by its name alone. Returns (level, reason) or None."""
    name = rel_path.replace("\\", "/").rsplit("/", 1)[-1]
    e = ext(name)
    if BIDI.search(name):
        return THREAT, "Name contains hidden Unicode characters that disguise its real file type"
    parts = name.lower().split(".")
    if e in EXECUTABLE and len(parts) >= 3 and "." + parts[-2] in SAFE_LOOKING:
        return THREAT, f"Double extension: looks like a .{parts[-2]} file but is really a {e} program"
    if e in EXECUTABLE and PADDED.search(name):
        return THREAT, f"Real extension ({e}) is pushed out of sight with spaces or dots"
    if e in ALWAYS_BAD:
        return THREAT, f"{e} files run code when opened and are almost never legitimate in a torrent"
    if media and e in EXECUTABLE:
        return THREAT, f"A video/music torrent shouldn't contain a {e} file (fake 'codec' / 'player' trick)"
    if media and e in CONTAINER:
        return WARNING, f"Disk image ({e}) in a video/music torrent can hide programs"
    if e in PROGRAM:
        return WARNING, f"Program file ({e}): only run it if you trust the source"
    if e in SCRIPT:
        return WARNING, f"Script/shortcut file ({e}) can run code when opened"
    if e in MACRO:
        return WARNING, "Office file with macros enabled"
    return None


def check_names(files: list[tuple[str, int]]) -> list[dict]:
    media = is_media_torrent(files)
    out = []
    for rel, _ in files:
        r = check_name(rel, media)
        if r:
            out.append({"file": rel, "level": r[0], "reason": r[1]})
    return out


# --------------------------------------------------------------------------- content checks (after download)
def sniff(head: bytes) -> str | None:
    """Real file type from the first bytes."""
    if head[:2] == b"MZ":
        return "exe"
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "macho"
    if head[:4] == b"L\x00\x00\x00" and head[4:8] == b"\x01\x14\x02\x00":
        return "lnk"
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"  # .doc/.xls/.msi
    if head[:4] == b"PK\x03\x04" or head[:4] == b"PK\x05\x06":
        return "zip"
    if head[:7] == b"Rar!\x1a\x07\x00":
        return "rar4"
    if head[:8] == b"Rar!\x1a\x07\x01\x00":
        return "rar5"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if head[:4] == b"MSCF":
        return "cab"
    if head[:5] == b"%PDF-":
        return "pdf"
    if head[:4] == b"\x1aE\xdf\xa3":
        return "mkv"
    if head[4:8] == b"ftyp":
        return "mp4"
    if head[:4] == b"RIFF":
        return "riff"
    if head[:16] == bytes.fromhex("3026b2758e66cf11a6d900aa0062ce6c"):
        return "asf"
    if head[:3] == b"ID3" or head[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"):
        return "mp3"
    if head[:4] in (b"fLaC", b"OggS"):
        return "audio"
    if head[:3] == b"\x00\x00\x01" or head[:1] == b"\x47":
        return "mpeg"
    if head[:2] == b"#!" or head[:12].lower().startswith((b"@echo", b"<script", b"<hta:")):
        return "script"
    return None


EXEC_KINDS = {"exe": "Windows program", "elf": "Linux program", "macho": "macOS program", "lnk": "Windows shortcut",
              "script": "script"}
ARCHIVE_KINDS = {"zip", "rar4", "rar5", "7z", "cab"}


def _vint(buf: bytes, i: int):
    n = shift = 0
    while i < len(buf):
        b = buf[i]
        n |= (b & 0x7F) << shift
        i += 1
        if not b & 0x80:
            return n, i
        shift += 7
    raise ValueError("bad vint")


def rar_info(path: str, kind: str):
    """(encrypted, [names]) for a RAR archive; names may be empty when headers are encrypted."""
    names, encrypted = [], False
    with open(path, "rb") as f:
        if kind == "rar4":
            f.seek(7)
            for _ in range(5000):
                hdr = f.read(7)
                if len(hdr) < 7:
                    break
                _crc, typ, flags, size = struct.unpack("<HBHH", hdr)
                if size < 7:
                    break
                body = f.read(size - 7)
                add = 0
                if typ == 0x73 and flags & 0x0080:  # main header: block headers encrypted
                    return True, names
                if typ == 0x74:  # file header
                    if flags & 0x04:
                        encrypted = True
                    add, = struct.unpack("<I", body[:4])
                    if flags & 0x100:  # 64-bit sizes
                        add += struct.unpack("<I", body[25:29])[0] << 32
                    nlen, = struct.unpack("<H", body[19:21])
                    off = 25 + (8 if flags & 0x100 else 0)
                    names.append(body[off:off + nlen].decode("utf-8", "replace").split("\x00")[0])
                elif flags & 0x8000:
                    add, = struct.unpack("<I", body[:4])
                if typ == 0x7B:
                    break
                f.seek(add, 1)
        else:
            f.seek(8)
            for _ in range(5000):
                pre = f.read(7)
                if len(pre) < 5:
                    break
                size, j = _vint(pre, 4)
                f.seek(-(len(pre) - j), 1)
                body = f.read(size)
                if len(body) < size:
                    break
                typ, k = _vint(body, 0)
                hflags, k = _vint(body, k)
                extra_size = data_size = 0
                if hflags & 1:
                    extra_size, k = _vint(body, k)
                if hflags & 2:
                    data_size, k = _vint(body, k)
                if typ == 4:  # archive encryption header: everything is encrypted
                    return True, names
                if typ in (2, 3):  # file / service header
                    _ff, k = _vint(body, k)
                    _usize, k = _vint(body, k)
                    _attr, k = _vint(body, k)
                    if _ff & 2:
                        k += 4
                    if _ff & 4:
                        k += 4
                    _comp, k = _vint(body, k)
                    _host, k = _vint(body, k)
                    nlen, k = _vint(body, k)
                    name = body[k:k + nlen].decode("utf-8", "replace")
                    k += nlen
                    if typ == 2:
                        names.append(name)
                    end = len(body)
                    k = end - extra_size
                    while k < end:  # extra records; type 1 = file encryption
                        rsize, k2 = _vint(body, k)
                        rtype, _ = _vint(body, k2)
                        if rtype == 1 and typ == 2:
                            encrypted = True
                        k = k2 + rsize
                if typ == 5:
                    break
                f.seek(data_size, 1)
    return encrypted, names


def sevenzip_encrypted(path: str) -> bool:
    """7-Zip header lists coders; AES-256 (06F10701) means password protected."""
    with open(path, "rb") as f:
        sig = f.read(32)
        if len(sig) < 32:
            return False
        next_off, next_size = struct.unpack("<QQ", sig[12:28])
        if next_size > 64 * 1024 * 1024:
            return False
        f.seek(32 + next_off)
        hdr = f.read(next_size)
    return SEVENZIP_AES in hdr


def inspect_archive(path: str, kind: str, media: bool) -> list[tuple[str, str]]:
    found = []
    names, encrypted = [], False
    try:
        if kind == "zip":
            with zipfile.ZipFile(path) as z:
                infos = z.infolist()
                names = [i.filename for i in infos]
                encrypted = any(i.flag_bits & 0x1 for i in infos)
        elif kind in ("rar4", "rar5"):
            encrypted, names = rar_info(path, kind)
        elif kind == "7z":
            encrypted = sevenzip_encrypted(path)
    except Exception:
        return [(WARNING, "Archive is damaged or uses an unusual format; couldn't look inside")]
    if encrypted:
        found.append((THREAT if media else WARNING,
                      "Password-protected archive: antivirus can't see inside, a common malware trick"
                      + (" (and a video/music torrent shouldn't need one)" if media else "")))
    inner = []
    for n in names:
        r = check_name(n, media)
        if r:
            inner.append((r[0], f"Inside archive: {n} — {r[1]}"))
    found += inner[:5]
    if len(inner) > 5:
        rest = inner[5:]
        found.append((THREAT if any(lv == THREAT for lv, _ in rest) else WARNING,
                      f"…and {len(rest)} more suspicious file(s) inside the archive"))
    return found


def inspect_file(path: str, rel: str, media: bool) -> list[tuple[str, str]]:
    found = []
    r = check_name(rel, media)
    if r:
        found.append(r)
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            head = f.read(64 * 1024)
    except OSError:
        return found
    e = ext(rel)
    real = sniff(head)

    # content says "program" but the name says something harmless
    # Windows only runs these by double-click, so an unrunnable shell script or a Linux/macOS binary
    # without an extension is just odd, not dangerous
    windows_runnable = real in ("exe", "lnk") or (real == "script" and e in SAFE_LOOKING)
    disguised = e in SAFE_LOOKING or e in ARCHIVE
    if real in EXEC_KINDS and e not in EXECUTABLE and (disguised or real in ("exe", "lnk")):
        if disguised and windows_runnable:
            found.append((THREAT, f"Disguised {EXEC_KINDS[real]}: named {e or 'without an extension'} "
                                  f"but its contents are executable"))
        elif e not in LIB_EXT:
            found.append((WARNING, f"Hidden {EXEC_KINDS[real]} with an unusual extension ({e})"))
    elif real == "exe" and e in PROGRAM and media and not r:
        found.append((THREAT, "Windows program inside a video/music torrent"))

    # media file whose bytes are actually an archive / document
    if e in VIDEO | AUDIO and real in ARCHIVE_KINDS | {"pdf", "ole"}:
        found.append((THREAT, f"Named like a media file but it's really a {real.upper()} file"))

    if real in ARCHIVE_KINDS:
        found += inspect_archive(path, real, media)

    if real == "asf" or e in (".wmv", ".wma", ".asf"):
        if any(g in head for g in ASF_DRM):
            found.append((THREAT, "DRM-locked Windows Media file: these send you to a website to 'buy a "
                                  "license' or install a fake codec"))

    if real == "pdf":
        try:
            with open(path, "rb") as f:
                blob = head + f.read(8 * 1024 * 1024)
            if re.search(rb"/(Launch|EmbeddedFile)\b", blob):
                found.append((THREAT if re.search(rb"/Launch\b", blob) else WARNING,
                              "PDF can launch programs or carries embedded files"))
            elif re.search(rb"/(JavaScript|JS)\b", blob):
                found.append((WARNING, "PDF contains JavaScript"))
        except OSError:
            pass

    if real == "zip" and e in (".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"):
        try:
            with zipfile.ZipFile(path) as z:
                if any(n.lower().endswith("vbaproject.bin") for n in z.namelist()):
                    found.append((WARNING, "Office document contains macros"))
        except Exception:
            pass

    # tiny "movie" next to programs = bait
    if e in VIDEO and size < 3 * 1024 * 1024 and real not in ("mkv", "mp4", "riff", "asf", "mpeg"):
        found.append((WARNING, "Very small 'video' that doesn't look like a real video file"))
    return found


def inspect(root: str, rel_files: list[tuple[str, int]]) -> tuple[str, str, list[dict]]:
    """Inspect downloaded files. rel_files = [(path relative to root, size)].
    Returns (status, summary, findings) with status clean | warning | threat."""
    media = is_media_torrent(rel_files)
    findings, seen = [], set()
    for rel, _ in rel_files:
        p = os.path.join(root, rel)
        if not os.path.isfile(p):
            continue
        for level, reason in inspect_file(p, rel, media):
            if (rel, reason) in seen:
                continue
            seen.add((rel, reason))
            findings.append({"file": rel, "level": level, "reason": reason})
    findings.sort(key=lambda f: f["level"] != THREAT)
    threats = [f for f in findings if f["level"] == THREAT]
    if threats:
        return THREAT, f"Inspector: {len(threats)} dangerous file(s) — {threats[0]['reason']}", findings
    if findings:
        return WARNING, f"Inspector: {len(findings)} file(s) worth a look — {findings[0]['reason']}", findings
    return "clean", "Inspector: no disguised programs or tricks found", findings
