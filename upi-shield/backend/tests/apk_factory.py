"""Build small synthetic APKs for tests (binary AndroidManifest.xml + DEX string table).

Real malware samples are not committed to the repository. This factory produces
archives that the production parser (pyaxmlparser + our DEX reader) handles exactly
like real APKs, with configurable package, label, permissions, icon and strings.
"""
from __future__ import annotations

import io
import struct
import zipfile

ANDROID_NS = "http://schemas.android.com/apk/res/android"
_TYPE_STRING = 0x03
_NO = 0xFFFFFFFF


class _Axml:
    def __init__(self) -> None:
        self.strings: list[str] = []
        self.body = b""

    def s(self, value: str) -> int:
        if value not in self.strings:
            self.strings.append(value)
        return self.strings.index(value)

    def _node(self, kind: int, payload: bytes) -> None:
        self.body += struct.pack("<HHI", kind, 0x10, 8 + 8 + len(payload)) + struct.pack("<II", 1, _NO) + payload

    def start_ns(self) -> None:
        self._node(0x0100, struct.pack("<II", self.s("android"), self.s(ANDROID_NS)))

    def end_ns(self) -> None:
        self._node(0x0101, struct.pack("<II", self.s("android"), self.s(ANDROID_NS)))

    def start(self, tag: str, attrs: dict[str, str]) -> None:
        packed = b""
        for key, value in attrs.items():
            ns = self.s(ANDROID_NS) if key.startswith("android:") else _NO
            name = self.s(key.removeprefix("android:"))
            val = self.s(value)
            packed += struct.pack("<III", ns, name, val) + struct.pack("<HBBI", 8, 0, _TYPE_STRING, val)
        head = struct.pack("<IIHHHHHH", _NO, self.s(tag), 0x14, 0x14, len(attrs), 0, 0, 0)
        self._node(0x0102, head + packed)

    def end(self, tag: str) -> None:
        self._node(0x0103, struct.pack("<II", _NO, self.s(tag)))

    def to_bytes(self) -> bytes:
        data = b""
        offsets = []
        for value in self.strings:
            raw = value.encode("utf-8")
            assert len(raw) < 0x80, "factory supports short strings only"
            offsets.append(len(data))
            data += bytes([len(value), len(raw)]) + raw + b"\x00"
        data += b"\x00" * (-len(data) % 4)
        header_size = 28
        strings_start = header_size + 4 * len(offsets)
        pool = struct.pack("<HHIIIIII", 0x0001, header_size, strings_start + len(data), len(offsets), 0,
                           0x100, strings_start, 0)
        pool += b"".join(struct.pack("<I", o) for o in offsets) + data
        content = pool + self.body
        return struct.pack("<HHI", 0x0003, 8, 8 + len(content)) + content


def manifest(package: str, label: str, permissions: list[str], launcher: bool = True) -> bytes:
    x = _Axml()
    x.start_ns()
    x.start("manifest", {"package": package, "android:versionName": "1.0"})
    for perm in permissions:
        x.start("uses-permission", {"android:name": perm})
        x.end("uses-permission")
    x.start("application", {"android:label": label, "android:icon": "res/mipmap-xxhdpi/ic_launcher.png"})
    x.start("activity", {"android:name": f"{package}.MainActivity"})
    if launcher:
        x.start("intent-filter", {})
        x.start("action", {"android:name": "android.intent.action.MAIN"})
        x.end("action")
        x.start("category", {"android:name": "android.intent.category.LAUNCHER"})
        x.end("category")
        x.end("intent-filter")
    x.end("activity")
    x.end("application")
    x.end("manifest")
    x.end_ns()
    return x.to_bytes()


def dex(strings: list[str]) -> bytes:
    """Minimal DEX: header with a string_ids table followed by MUTF-8 string data."""
    header = bytearray(0x70)
    header[0:8] = b"dex\n035\x00"
    table_off = 0x70
    data_off = table_off + 4 * len(strings)
    ids, data = b"", b""
    for value in strings:
        raw = value.encode("utf-8")
        ids += struct.pack("<I", data_off + len(data))
        length = len(value)
        uleb = b""
        while True:
            byte = length & 0x7F
            length >>= 7
            uleb += bytes([byte | (0x80 if length else 0)])
            if not length:
                break
        data += uleb + raw + b"\x00"
    struct.pack_into("<II", header, 0x38, len(strings), table_off)
    return bytes(header) + ids + data


def build_apk(package: str, label: str, permissions: list[str] | None = None, strings: list[str] | None = None,
              icon: bytes | None = None, launcher: bool = True) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest(package, label, permissions or [], launcher))
        zf.writestr("classes.dex", dex(strings or []))
        if icon:
            zf.writestr("res/mipmap-xxhdpi/ic_launcher.png", icon)
    return out.getvalue()
