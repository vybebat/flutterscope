"""Command line entry point.

    flutterscope scan   <artifact> [--blutter DIR] [--json OUT] [--sarif OUT] [--fail-on LEVEL]
    flutterscope recover <artifact> [--blutter DIR] -o facts.json
    flutterscope judge  facts.json [--json OUT] [--sarif OUT]

Exit codes: 0 no finding at or above --fail-on, 1 at least one, 2 usage or input error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .judge import judge
from .model import Facts, Result, Status
from .recover import recover
from .sarif import to_sarif

_RANK = {"low": 1, "medium": 2, "high": 3, "none": 99}


def _summary(f: Facts, r: Result) -> str:
    out = [f"flutterscope {__version__}  {f.artifact}"]
    if not f.is_flutter:
        out.append("  not a Flutter app")
        out += [f"  note: {n}" for n in f.notes]
        return "\n".join(out)
    snap = f.snapshot
    out.append(f"  platform {f.platform}, ABIs {', '.join(f.abis) or 'none'}, "
               f"Dart {f.dart_version or 'unknown'}")
    if snap:
        out.append(f"  snapshot {snap.hash}  {'release' if snap.is_product else 'NOT release'}")
    out.append(f"  deep analysis: {'yes, ' + str(f.libs_total) + ' libraries' if f.deep else 'no'}"
               + (f"  ({f.deep_reason})" if not f.deep and f.deep_reason else ""))
    out.append("")
    width = max((len(c.check) for c in r.checks), default=10)
    for c in r.checks:
        out.append(f"  {c.status.value:<10} {c.check:<{width}}  {c.control}")
        if c.status in (Status.NOT_TESTED, Status.REVIEW):
            out.append(f"  {'':<10} {'':<{width}}  {c.reason}")
    if r.findings:
        out.append("")
        for x in r.findings:
            out.append(f"  [{x.severity.value.upper()}] {x.title} ({x.control}, origin {x.origin})")
    if r.observations:
        out.append("")
        out.append(f"  {len(r.observations)} observation(s), see the JSON output")
    return "\n".join(out)


def _write(path: str | None, data: dict) -> None:
    if not path:
        return
    text = json.dumps(data, indent=2, ensure_ascii=False)
    if path == "-":
        print(text)
    else:
        Path(path).write_text(text + "\n", encoding="utf-8")


def _emit(f: Facts, r: Result, args: argparse.Namespace) -> int:
    report = {"tool": "flutterscope", "version": __version__, "facts": f.to_dict(), **r.to_dict()}
    _write(args.json, report)
    if args.sarif:
        _write(args.sarif, to_sarif(f, r))
    if args.json != "-":
        print(_summary(f, r))
    worst = max((_RANK[x.severity.value] for x in r.findings), default=0)
    return 1 if worst >= _RANK[args.fail_on] else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="flutterscope",
                                 description="Security facts from compiled Flutter apps.")
    ap.add_argument("--version", action="version", version=f"flutterscope {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def outputs(p: argparse.ArgumentParser) -> None:
        p.add_argument("--json", help="write the full report as JSON ('-' for stdout)")
        p.add_argument("--sarif", help="write a SARIF 2.1.0 file")
        p.add_argument("--fail-on", choices=["low", "medium", "high", "none"], default="high",
                       help="exit 1 when a finding reaches this severity (default: high)")

    s = sub.add_parser("scan", help="recover and judge in one step")
    s.add_argument("artifact", type=Path)
    s.add_argument("--blutter", type=Path, help="Blutter output directory for this app")
    outputs(s)

    rc = sub.add_parser("recover", help="recover facts only, no judgement")
    rc.add_argument("artifact", type=Path)
    rc.add_argument("--blutter", type=Path)
    rc.add_argument("-o", "--out", default="-", help="facts JSON path ('-' for stdout)")

    j = sub.add_parser("judge", help="judge a facts JSON written by recover")
    j.add_argument("facts", type=Path)
    outputs(j)

    args = ap.parse_args(argv)
    try:
        if args.cmd == "recover":
            _write(args.out, recover(args.artifact, args.blutter).to_dict())
            return 0
        if args.cmd == "judge":
            f = Facts.from_dict(json.loads(args.facts.read_text(encoding="utf-8")))
        else:
            if not args.artifact.exists():
                raise FileNotFoundError(args.artifact)
            if args.blutter and not args.blutter.is_dir():
                raise FileNotFoundError(args.blutter)
            f = recover(args.artifact, args.blutter)
        return _emit(f, judge(f), args)
    except (OSError, ValueError, KeyError) as exc:
        print(f"flutterscope: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
