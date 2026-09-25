"""Build the real twin fixture APKs from fixtures/apps/.

    python scripts/build_fixtures.py [--out fixtures/build] [--only NAME]

Needs a Flutter SDK on PATH. Produces five release APKs (arm64 only):

    twin_vuln.apk              must fire
    twin_clean.apk             must stay silent
    twin_vuln-obfuscated.apk   attributed signals must survive renaming
    twin_clean-obfuscated.apk  obfuscation counterfactual from the same source
    twin_clean-splitonly.apk   --split-debug-info without --obfuscate

The APKs are not committed. They are large and they are rebuilt from source, so a reader can
check that a fixture holds exactly what its source says. The Dart version they are built with
is recorded in fixtures/build/BUILD-INFO.txt, because the snapshot format changes with it.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APPS = ROOT / "fixtures" / "apps"
DEPS = ["pointycastle:^4.0.0", "webview_flutter:^4.14.1"]

# (output name, source app, extra build flags)
VARIANTS = [
    ("twin_vuln", "twin_vuln", "plain"),
    ("twin_clean", "twin_clean", "plain"),
    ("twin_vuln-obfuscated", "twin_vuln", "obfuscate"),
    ("twin_clean-obfuscated", "twin_clean", "obfuscate"),
    ("twin_clean-splitonly", "twin_clean", "split"),
]


def run(cmd: list[str], cwd: Path) -> str:
    print("  $", " ".join(cmd), flush=True)
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", shell=(sys.platform == "win32"))
    if proc.returncode != 0:
        sys.exit(f"failed ({proc.returncode}):\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")
    return proc.stdout


def build(name: str, app: str, mode: str, out: Path, work: Path) -> Path:
    project = work / name.replace("-", "_")
    run(["flutter", "create", "--platforms", "android", "--org", "dev.flutterscope",
         "--project-name", app, str(project)], cwd=work)
    shutil.copy(APPS / app / "lib" / "main.dart", project / "lib" / "main.dart")
    shutil.rmtree(project / "test", ignore_errors=True)
    run(["flutter", "pub", "add", *DEPS], cwd=project)
    cmd = ["flutter", "build", "apk", "--release", "--target-platform", "android-arm64"]
    if mode in ("obfuscate", "split"):
        cmd += [f"--split-debug-info={project / 'symbols'}"]
    if mode == "obfuscate":
        cmd += ["--obfuscate"]
    run(cmd, cwd=project)
    built = project / "build" / "app" / "outputs" / "flutter-apk" / "app-release.apk"
    dest = out / f"{name}.apk"
    shutil.copy(built, dest)
    return dest


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, default=ROOT / "fixtures" / "build")
    ap.add_argument("--only", help="build one variant, e.g. twin_vuln")
    args = ap.parse_args()
    if not shutil.which("flutter"):
        sys.exit("flutter is not on PATH")
    args.out.mkdir(parents=True, exist_ok=True)
    version = run(["flutter", "--version"], cwd=ROOT)
    (args.out / "BUILD-INFO.txt").write_text(version, encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="fscope-") as tmp:
        for name, app, mode in VARIANTS:
            if args.only and args.only != name:
                continue
            print(f"building {name}", flush=True)
            print("  ->", build(name, app, mode, args.out, Path(tmp)), flush=True)


if __name__ == "__main__":
    main()
