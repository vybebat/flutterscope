"""Hand-built inputs, so every check can be tested on both sides with no Flutter SDK, no
Blutter and no binary in the repository.

The shapes copy what real builds produce: the snapshot header layout, the libflutter version
string, and Blutter's pp.txt and asm/ layout. tests/test_real_fixtures.py checks the same
rules against real builds when they are present.
"""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

HASH = "ace654289f5abc240509fc941453ebc5"
RELEASE = ("product no-code_comments no-dwarf_stack_traces_mode dedup_instructions "
           "no-asan no-msan no-tsan no-shared_data arm64 android compressed-pointers")
RELEASE_SPLIT = RELEASE.replace("no-dwarf_stack_traces_mode", "dwarf_stack_traces_mode")
PROFILE = RELEASE.replace("product ", "")

# Assembled here, not written out, so repository secret scanners do not match this file.
FAKE_AWS = "AKIA" + "Q3FLUTTERSCOPE7X"
AWS_DOC_EXAMPLE = "AKIA" + "IOSFODNN7EXAMPLE"
FAKE_PEM = "-----BEGIN " + "PRIVATE KEY-----\nMIIBVQIBADANfixture\n-----END " + "PRIVATE KEY-----"
FAKE_GOOGLE = "AIza" + "SyFIXTUREflutterscope0123456789abcd"


def libapp(features: str = RELEASE, strings: list[str] = ()) -> bytes:
    header = b"\xf5\xf5\xdc\xdc" + struct.pack("<qq", 4096, 2) + HASH.encode()
    body = b"\0".join(s.encode() for s in strings)
    return b"\x7fELF" + b"\0" * 60 + header + features.encode() + b"\0" + b"\0" * 16 + body


def libflutter(version: str = "3.12.2") -> bytes:
    return (b"\x7fELF" + b"\0" * 32 +
            f'{version} (stable) (Tue Jun 9 01:11:39 2026 -0700) on "android_arm64"'.encode()
            + b"\0")


def apk(tmp: Path, name: str = "app.apk", *, app: bytes | None = None,
        flutter: bytes | None = None, abi: str = "arm64-v8a", kernel: bool = False) -> Path:
    path = tmp / name
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", b"\0")
        if app is not None:
            z.writestr(f"lib/{abi}/libapp.so", app)
        if flutter is not None:
            z.writestr(f"lib/{abi}/libflutter.so", flutter)
        if kernel:
            z.writestr("assets/flutter_assets/kernel_blob.bin", b"\0kernel")
    return path


def blutter(tmp: Path, libs: dict[str, str], pp: str = "") -> Path:
    """A fresh Blutter output directory. `libs` maps asm/ relative paths to file text."""
    n = sum(1 for _ in tmp.glob("blutter*"))
    out = tmp / f"blutter{n}"
    (out / "asm").mkdir(parents=True)
    (out / "pp.txt").write_text("pool heap offset: 0x480080\n" + pp, encoding="utf-8")
    (out / "objs.txt").write_text("", encoding="utf-8")
    for rel, text in libs.items():
        p = out / "asm" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return out


def app_main(pkg: str = "demo", body: str = "") -> dict[str, str]:
    return {f"{pkg}/main.dart": f"// lib: , url: package:{pkg}/main.dart\n\nclass :: {{\n{body}\n}}\n"}


def readable_libs(n: int = 40) -> dict[str, str]:
    return {f"somepkg/src/lib{i}.dart": f"// lib: , url: package:somepkg/src/lib{i}.dart\n"
            for i in range(n)}


def obfuscated_libs(n: int = 200, readable: int = 4) -> dict[str, str]:
    names = [f"{chr(97 + i % 26)}{chr(65 + (i // 26) % 26)}m" for i in range(n)]
    libs = {f"{x}.dart": f"// lib: , url: {x}\n" for x in names}
    libs.update({f"plugin{i}/plugin.dart": "" for i in range(readable)})
    return libs
