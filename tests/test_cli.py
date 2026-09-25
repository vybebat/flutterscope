"""The command line, the JSON round trip and the SARIF export."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from flutterscope.cli import main
from flutterscope.snapshot import dart_version, parse_snapshot

from helpers import FAKE_PEM, HASH, RELEASE, apk, libapp, libflutter


def run(argv: list[str]) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        code = main(argv)
    return code, buf.getvalue()


class Snapshot(unittest.TestCase):
    def test_header(self):
        snap = parse_snapshot(libapp())
        self.assertEqual(snap.hash, HASH)
        self.assertTrue(snap.is_product)
        self.assertIs(snap.dwarf_stack_traces, False)

    def test_no_header(self):
        self.assertIsNone(parse_snapshot(b"\xf5\xf5\xdc\xdc" + b"x" * 64))
        self.assertIsNone(parse_snapshot(b""))

    def test_dart_version(self):
        self.assertEqual(dart_version(libflutter("2.19.0")), "2.19.0")
        self.assertIsNone(dart_version(b"no version here"))


class Cli(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.vuln = apk(self.tmp, "vuln.apk", app=libapp(RELEASE, [FAKE_PEM]), flutter=libflutter())
        self.clean = apk(self.tmp, "clean.apk", app=libapp(RELEASE, []), flutter=libflutter())

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_exit_code_follows_fail_on(self):
        self.assertEqual(run(["scan", str(self.vuln)])[0], 1)
        self.assertEqual(run(["scan", str(self.clean)])[0], 0)
        self.assertEqual(run(["scan", str(self.vuln), "--fail-on", "none"])[0], 0)

    def test_missing_input_is_an_error_not_a_pass(self):
        self.assertEqual(run(["scan", str(self.tmp / "nope.apk")])[0], 2)
        self.assertEqual(run(["scan", str(self.clean), "--blutter", str(self.tmp / "no")])[0], 2)

    def test_not_a_zip(self):
        bad = self.tmp / "bad.apk"
        bad.write_bytes(b"not a zip")
        code, out = run(["scan", str(bad)])
        self.assertEqual(code, 0)
        self.assertIn("not a Flutter app", out)

    def test_directory_of_split_apks(self):
        splits = self.tmp / "splits"
        splits.mkdir()
        apk(splits, "base.apk")
        apk(splits, "split_config.arm64_v8a.apk", app=libapp(RELEASE, [FAKE_PEM]),
            flutter=libflutter())
        code, out = run(["scan", str(splits)])
        self.assertEqual(code, 1)
        self.assertIn("Dart 3.12.2", out)

    def test_recover_then_judge_equals_scan(self):
        facts = self.tmp / "facts.json"
        run(["recover", str(self.vuln), "-o", str(facts)])
        a, b = self.tmp / "a.json", self.tmp / "b.json"
        run(["judge", str(facts), "--json", str(a)])
        run(["scan", str(self.vuln), "--json", str(b)])
        ja, jb = json.loads(a.read_text()), json.loads(b.read_text())
        for key in ("checks", "findings", "observations"):
            self.assertEqual(ja[key], jb[key])

    def test_sarif_reports_untested_checks(self):
        out = self.tmp / "out.sarif"
        run(["scan", str(self.vuln), "--sarif", str(out)])
        sarif = json.loads(out.read_text())
        runs = sarif["runs"][0]
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual({r["level"] for r in runs["results"]}, {"error"})
        notes = runs["invocations"][0]["toolExecutionNotifications"]
        self.assertIn("weak-crypto", {n["descriptor"]["id"] for n in notes})
        self.assertIn("tls-certificate-callback", {n["descriptor"]["id"] for n in notes})


if __name__ == "__main__":
    unittest.main()
