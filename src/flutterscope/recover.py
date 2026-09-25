"""Stage one: recover facts from an artifact. No security judgement lives here.

Accepted inputs:
  - an .apk, .aab or .ipa
  - a directory of split APKs (base plus split_config.arm64_v8a.apk and friends)
  - a directory that already holds libapp.so and libflutter.so
"""

from __future__ import annotations

import hashlib
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path

from . import blutter, snapshot
from .model import Constant, Facts

# Preferred order. Blutter reads arm64 only, and nearly every real device runs it.
ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86")

_LIB = re.compile(r"(?:^|/)lib/([^/]+)/(libapp|libflutter)\.so$")
_IOS_APP = re.compile(r"^Payload/[^/]+\.app/Frameworks/App\.framework/App$")
_IOS_FLUTTER = re.compile(r"^Payload/[^/]+\.app/Frameworks/Flutter\.framework/Flutter$")
_KERNEL = re.compile(r"(?:^|/)flutter_assets/kernel_blob\.bin$")

_PACKAGE = re.compile(r"package:([a-z][a-z0-9_]{1,40})/")
_URL = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,300}")
# An absolute path from the machine that built the app. Windows drive, or a Unix home.
_BUILD_PATH = re.compile(r"file:///(?:[A-Za-z]:/|home/|Users/|root/)[^\s\"']{3,300}")

# Credential-shaped constants. Recovery only records them; judge.py decides what they mean.
SECRET_PATTERNS = {
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    "aws-access-key-id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "google-api-key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "stripe-secret-key": re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b"),
    "slack-token": re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"),
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
}


# Placeholder credentials that vendors print in their own documentation.
DOCUMENTED_EXAMPLES = {"AKIAIOSFODNN7EXAMPLE"}


@dataclass
class _Payload:
    libapp: bytes | None = None
    libapp_abi: str | None = None
    libflutter: bytes | None = None
    abis: tuple[str, ...] = ()
    kernel_blob: bool = False
    platform: str = "android"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    if path.is_file():
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    return h.hexdigest()


def _read_zips(zips: list[Path]) -> _Payload:
    libs: dict[tuple[str, str], tuple[Path, str]] = {}
    ios_app = ios_flutter = None
    kernel = False
    for zp in zips:
        with zipfile.ZipFile(zp) as z:
            for name in z.namelist():
                m = _LIB.search(name)
                if m:
                    libs[(m.group(1), m.group(2))] = (zp, name)
                elif _IOS_APP.match(name):
                    ios_app = (zp, name)
                elif _IOS_FLUTTER.match(name):
                    ios_flutter = (zp, name)
                elif _KERNEL.search(name):
                    kernel = True

    def read(ref: tuple[Path, str] | None) -> bytes | None:
        if not ref:
            return None
        with zipfile.ZipFile(ref[0]) as z:
            return z.read(ref[1])

    p = _Payload(kernel_blob=kernel)
    if ios_app or ios_flutter:
        p.platform = "ios"
        p.libapp, p.libflutter = read(ios_app), read(ios_flutter)
        p.libapp_abi = "arm64" if ios_app else None
        p.abis = ("arm64",) if (ios_app or ios_flutter) else ()
        return p
    p.abis = tuple(sorted({abi for abi, kind in libs if kind == "libflutter"},
                          key=lambda a: ABIS.index(a) if a in ABIS else 99))
    for abi in ABIS:
        if (abi, "libapp") in libs:
            p.libapp, p.libapp_abi = read(libs[(abi, "libapp")]), abi
            p.libflutter = read(libs.get((abi, "libflutter")))
            break
    if p.libflutter is None:
        for (abi, kind), ref in libs.items():
            if kind == "libflutter":
                p.libflutter = read(ref)
                break
    return p


def _read_dir(d: Path) -> _Payload:
    zips = sorted(q for q in d.iterdir() if q.suffix.lower() in (".apk", ".aab", ".ipa"))
    if zips:
        return _read_zips(zips)
    p = _Payload()
    app, flt = next(d.rglob("libapp.so"), None), next(d.rglob("libflutter.so"), None)
    p.libapp = app.read_bytes() if app else None
    p.libflutter = flt.read_bytes() if flt else None
    p.libapp_abi = app.parent.name if app and app.parent.name in ABIS else None
    p.abis = (p.libapp_abi,) if p.libapp_abi else ()
    p.kernel_blob = next(d.rglob("kernel_blob.bin"), None) is not None
    return p


def recover(artifact: Path, blutter_dir: Path | None = None) -> Facts:
    artifact = Path(artifact)
    f = Facts(artifact=artifact.name)
    if artifact.is_dir():
        payload = _read_dir(artifact)
    else:
        f.sha256 = _sha256(artifact)
        try:
            payload = _read_zips([artifact])
        except zipfile.BadZipFile:
            f.notes.append("The artifact is not a readable zip archive.")
            return f

    f.platform = payload.platform
    f.abis = list(payload.abis)
    f.kernel_blob = payload.kernel_blob
    f.is_flutter = payload.libflutter is not None or payload.libapp is not None or f.kernel_blob
    if not f.is_flutter:
        f.notes.append("No Flutter engine or Dart payload found. This is not a Flutter app.")
        return f

    if payload.libflutter:
        f.dart_version = snapshot.dart_version(payload.libflutter)
    if payload.libapp:
        f.snapshot = snapshot.parse_snapshot(payload.libapp)
        if f.snapshot is None:
            f.notes.append("libapp.so holds no readable Dart snapshot header.")
        _strings(f, snapshot.strings(payload.libapp))
    elif f.kernel_blob:
        f.notes.append("Debug build: Dart ships as a kernel blob, there is no AOT snapshot.")

    if blutter_dir is not None:
        blutter.ingest(f, Path(blutter_dir))
    elif f.platform == "ios":
        f.deep_reason = "Blutter does not read iOS snapshots, so the deep checks cannot run."
    elif payload.libapp_abi != "arm64-v8a":
        f.deep_reason = "No arm64-v8a libapp.so in the artifact, and Blutter reads arm64 only."
    else:
        runtime = f"Dart {f.dart_version}" if f.dart_version else "the app's Dart version"
        f.deep_reason = (f"No Blutter output was given. Run Blutter for {runtime} on "
                         "lib/arm64-v8a and pass its output directory with --blutter.")
    _mask(f)
    return f


def _mask(f: Facts) -> None:
    """Never write a full credential into facts or reports. Attribution has already run on the
    real value; from here on only a prefix and a fingerprint travel."""
    for c in f.constants:
        c.documented_example = c.value in DOCUMENTED_EXAMPLES
        if c.kind == "private-key":
            continue  # the matched text is the PEM header, not key material
        digest = hashlib.sha256(c.value.encode()).hexdigest()[:12]
        c.value = f"{c.value[:8]}... (sha256:{digest})"


def _strings(f: Facts, found: list[str]) -> None:
    pkgs: set[str] = set()
    urls: dict[str, None] = {}
    paths: dict[str, None] = {}
    consts: dict[tuple[str, str], None] = {}
    for s in found:
        pkgs.update(_PACKAGE.findall(s))
        for u in _URL.findall(s):
            urls.setdefault(u.rstrip(".,;:)'\""), None)
        for p in _BUILD_PATH.findall(s):
            paths.setdefault(p, None)
        for kind, rx in SECRET_PATTERNS.items():
            for m in rx.finditer(s):
                consts.setdefault((kind, m.group()), None)
    f.packages = sorted(pkgs)
    f.urls = list(urls)
    f.build_paths = list(paths)
    f.constants = [Constant(kind=k, value=v) for k, v in consts]
