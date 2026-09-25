"""The same rules against real builds of fixtures/apps.

Skipped unless the builds exist. Create them with:

    python scripts/build_fixtures.py
    # then, for the deep checks, Blutter on each lib/arm64-v8a/libapp.so into
    # fixtures/build/blutter/<name>/  (see docs/BLUTTER.md)

Without Blutter output, only the checks that need none are compared. The expected verdicts
below are the ones recorded on Flutter 3.44.2 / Dart 3.12.2.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from flutterscope.judge import judge
from flutterscope.recover import recover

BUILD = Path(__file__).resolve().parents[1] / "fixtures" / "build"

SHALLOW = ("release-build", "hardcoded-credentials", "cleartext-urls", "build-path-leak")

# name -> {check: (verdict without Blutter, verdict with Blutter)}
EXPECTED = {
    "twin_vuln": {
        "release-build": ("PASS", "PASS"),
        "dart-obfuscation": ("FAIL", "FAIL"),
        "hardcoded-credentials": ("FAIL", "FAIL"),
        "cleartext-urls": ("PASS", "PASS"),
        "weak-crypto": ("NOT_TESTED", "FAIL"),
        "process-exec": ("NOT_TESTED", "FAIL"),
        "webview-js-channel": ("NOT_TESTED", "FAIL"),
    },
    "twin_clean": {
        "release-build": ("PASS", "PASS"),
        "dart-obfuscation": ("FAIL", "FAIL"),
        "hardcoded-credentials": ("PASS", "PASS"),
        "cleartext-urls": ("PASS", "PASS"),
        "weak-crypto": ("NOT_TESTED", "PASS"),
        "process-exec": ("NOT_TESTED", "PASS"),
        "webview-js-channel": ("NOT_TESTED", "PASS"),
    },
    "twin_vuln-obfuscated": {
        "dart-obfuscation": ("NOT_TESTED", "PASS"),
        "hardcoded-credentials": ("FAIL", "FAIL"),
        # Renamed by --obfuscate. Must not pass.
        "weak-crypto": ("NOT_TESTED", "NOT_TESTED"),
        "process-exec": ("NOT_TESTED", "NOT_TESTED"),
        # A string constant, so it survives renaming.
        "webview-js-channel": ("NOT_TESTED", "FAIL"),
    },
    "twin_clean-obfuscated": {
        "dart-obfuscation": ("NOT_TESTED", "PASS"),
        "hardcoded-credentials": ("PASS", "PASS"),
        "weak-crypto": ("NOT_TESTED", "NOT_TESTED"),
        "process-exec": ("NOT_TESTED", "NOT_TESTED"),
        "webview-js-channel": ("NOT_TESTED", "PASS"),
    },
    "twin_clean-splitonly": {
        "dart-obfuscation": ("NOT_TESTED", "FAIL"),
        "weak-crypto": ("NOT_TESTED", "PASS"),
    },
}


class RealFixtures(unittest.TestCase):
    def test_expected_verdicts(self):
        ran = 0
        for name, expected in EXPECTED.items():
            artifact = BUILD / f"{name}.apk"
            if not artifact.is_file():
                continue
            deep = BUILD / "blutter" / name
            for use_blutter in (False, True):
                if use_blutter and not (deep / "pp.txt").is_file():
                    continue
                result = judge(recover(artifact, deep if use_blutter else None))
                for check, verdicts in expected.items():
                    want = verdicts[1 if use_blutter else 0]
                    with self.subTest(fixture=name, check=check, blutter=use_blutter):
                        self.assertEqual(result.check(check).status.value, want)
                ran += 1
        if not ran:
            self.skipTest("no real fixture builds in fixtures/build")


if __name__ == "__main__":
    unittest.main()
