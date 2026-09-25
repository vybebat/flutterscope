"""Read a Blutter output directory into Facts.

Blutter (https://github.com/worawit/blutter) rebuilds the Dart object pool (`pp.txt`), an
object dump (`objs.txt`) and one disassembly file per Dart library (`asm/<package>/<path>.dart`)
from libapp.so. This module only records what is there and who refers to it. It makes no
security claims.
"""

from __future__ import annotations

import re
from pathlib import Path

from .model import Facts, Signal

# Token -> signal slug. A token that survives AOT compilation is code the app can reach, since
# a release build removes what is never called. Each token below was checked on the twin
# fixtures: present in the vulnerable build, absent from the clean one.
#
# Class and function names are renamed by --obfuscate, and with them every token here except
# addJavaScriptChannel, which lives in a string constant. judge.py therefore refuses to pass a
# name-based check on an obfuscated build.
SIGNALS = {
    "RC4Engine": "weak-cipher",
    "DESEngine": "weak-cipher",
    "DESedeEngine": "weak-cipher",
    "MD5Digest": "weak-hash",
    "SHA1Digest": "weak-hash",
    "ECBBlockCipher": "ecb-mode",
    # dart:io process spawning. Tree-shaken when unused.
    "_ProcessImpl": "process-exec",
    # webview_flutter's JavaScript channel registration. A WebView with JavaScript but no
    # channel does not carry it.
    "addJavaScriptChannel": "webview-js-channel",
}

# Tokens whose presence alone proves nothing, mapped to the package that defines them.
#
# pointycastle's Registry builds algorithms by name, so its registration code refers to every
# engine and digest it knows. An app that only ever asks for AES still carries RC4Engine and
# MD5Digest as constructor stubs. Such a token counts only when a library outside the defining
# package refers to it.
DEFINED_BY = {
    "RC4Engine": "pointycastle",
    "DESEngine": "pointycastle",
    "DESedeEngine": "pointycastle",
    "MD5Digest": "pointycastle",
    "SHA1Digest": "pointycastle",
    "ECBBlockCipher": "pointycastle",
}

# How a call site names the thing in the disassembly comments. Used to find who calls it.
CALL_SITES = {
    "_ProcessImpl": ("Process::run", "Process::start", "::_runNonInteractiveProcess",
                     "::_runNonInteractiveProcessSync"),
    "addJavaScriptChannel": ("addJavaScriptChannel",),
}

# Packages whose own libraries refer to a token as part of implementing it. A reference from
# here says nothing about who uses the feature.
IMPLEMENTERS = {
    "addJavaScriptChannel": ("webview_flutter", "webview_flutter_android",
                             "webview_flutter_wkwebview", "webview_flutter_platform_interface"),
}

# An obfuscated library is written as a flat file with a short generated name, e.g. `aAm.dart`.
_GENERATED = re.compile(r"^[A-Za-z0-9_$]{1,4}$")
_LIB_URL = re.compile(r"^// lib: .*url: package:([a-z][a-z0-9_]*)/main\.dart")


def is_readable(rel: str) -> bool:
    rel = rel.replace("\\", "/").strip("/")
    stem = rel.rsplit("/", 1)[-1].removesuffix(".dart")
    return "/" in rel or not _GENERATED.match(stem)


def library_readability(rel_paths: list[str]) -> tuple[int, int]:
    """(readable, total) over recovered Dart libraries, ignoring Blutter's build scaffolding."""
    libs = [p.replace("\\", "/").strip("/") for p in rel_paths]
    libs = [p for p in libs if p.endswith(".dart") and not p.startswith(".dart_tool/")]
    return sum(1 for p in libs if is_readable(p)), len(libs)


def origin_of(referrers: list[str], app_package: str | None, skip: tuple[str, ...] = ()) -> str:
    """Who is responsible for a reference: the app, a named package, or unknown."""
    outside = [r for r in referrers if not r.startswith(tuple(p + "/" for p in skip))]
    if app_package and any(r.startswith(app_package + "/") for r in outside):
        return "app"
    named = sorted({r.split("/", 1)[0] for r in outside if "/" in r})
    if named:
        return "package:" + named[0]
    return "unknown"


def ingest(f: Facts, out: Path) -> None:
    pool = ""
    for name in ("pp.txt", "objs.txt"):
        p = out / name
        if p.is_file():
            pool += p.read_text(encoding="utf-8", errors="replace")
    asm = out / "asm"
    texts: dict[str, str] = {}
    if asm.is_dir():
        for src in sorted(asm.rglob("*.dart")):
            rel = src.relative_to(asm).as_posix()
            try:
                texts[rel] = src.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
    if not pool and not texts:
        f.deep_reason = (f"The Blutter directory {out} holds no pp.txt, objs.txt or asm/. "
                         "Blutter probably failed for this Dart version.")
        return

    f.libs_readable, f.libs_total = library_readability(list(texts))
    for rel, text in texts.items():
        if rel.count("/") == 1 and rel.endswith("/main.dart"):
            m = _LIB_URL.match(text)
            if m:
                f.app_package = m.group(1)
                break

    class_lines = "\n".join(line.strip() for t in texts.values()
                            for line in t.splitlines() if line.lstrip().startswith("class "))
    blob = pool + "\n" + class_lines

    found: dict[str, Signal] = {}
    for token, slug in SIGNALS.items():
        referrers = sorted(r for r, t in texts.items() if token in t)
        owner = DEFINED_BY.get(token)
        if owner:
            outside = [r for r in referrers if not r.startswith(owner + "/")]
            if not outside:
                continue  # registry stubs only, or not there at all
            origin = origin_of(outside, f.app_package)
        else:
            if token not in blob and not referrers:
                continue
            callers = sorted(r for r, t in texts.items()
                             if any(c in t for c in CALL_SITES.get(token, ())))
            referrers = callers or referrers
            origin = origin_of(referrers, f.app_package, IMPLEMENTERS.get(token, ()))
        sig = found.get(slug)
        if sig is None:
            found[slug] = Signal(slug=slug, token=token, referrers=referrers, origin=origin)
        elif origin == "app" and sig.origin != "app":
            found[slug] = Signal(slug=slug, token=token, referrers=referrers, origin=origin)
    f.signals = list(found.values())

    for c in f.constants:
        needle = c.value[:16]
        c.referrers = sorted(r for r, t in texts.items() if needle in t)
        c.origin = origin_of(c.referrers, f.app_package)

    f.deep = True
    f.deep_reason = ""
