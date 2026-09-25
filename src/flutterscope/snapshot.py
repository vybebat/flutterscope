"""Read what the compiled Flutter binaries say about how they were built.

No Blutter needed. Pure functions over bytes, so they are tested with hand-built buffers.
"""

from __future__ import annotations

import re

from .model import Snapshot

# A Dart snapshot starts with the magic 0xdcdcf5f5 (little endian on disk), then an int64
# length and an int64 kind, then a 32 character hex hash of the VM version, then a
# NUL-terminated list of features the snapshot was compiled with.
_MAGIC = b"\xf5\xf5\xdc\xdc"
_HASH_AT = 4 + 8 + 8
_HEX32 = re.compile(rb"[0-9a-f]{32}")

# libflutter.so embeds the Dart SDK version string, e.g.
#   3.12.2 (stable) (Tue Jun 9 01:11:39 2026 -0700) on "android_arm64"
_DART_VERSION = re.compile(
    rb"(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?) \((stable|beta|dev|main)\) \([^)]{5,60}\) on \"")


def parse_snapshot(data: bytes) -> Snapshot | None:
    """The first well-formed snapshot header in `data`, or None.

    libapp.so carries two (the VM and the isolate snapshot). They share the hash and the
    features, so the first one is enough.
    """
    start = 0
    while True:
        at = data.find(_MAGIC, start)
        if at < 0:
            return None
        h = data[at + _HASH_AT: at + _HASH_AT + 32]
        if _HEX32.fullmatch(h):
            end = data.find(b"\0", at + _HASH_AT + 32, at + _HASH_AT + 32 + 1024)
            if end > 0:
                raw = data[at + _HASH_AT + 32: end].decode("ascii", "replace")
                return Snapshot(hash=h.decode(), features=raw.split())
        start = at + 1


def dart_version(data: bytes) -> str | None:
    """The Dart SDK version embedded in libflutter.so (or Flutter.framework), or None."""
    m = _DART_VERSION.search(data)
    return m.group(1).decode() if m else None


_PRINTABLE = re.compile(rb"[\x20-\x7e\t\n]{6,}")


def strings(data: bytes) -> list[str]:
    """Printable ASCII runs of six or more bytes, deduplicated in first-seen order.

    Dart keeps one-byte strings in the snapshot as plain bytes, so constants such as URLs and
    keys survive here. Two-byte (non Latin-1) strings do not, which is a known blind spot.
    """
    seen: dict[str, None] = {}
    for m in _PRINTABLE.finditer(data):
        seen.setdefault(m.group().decode("ascii"), None)
    return list(seen)
