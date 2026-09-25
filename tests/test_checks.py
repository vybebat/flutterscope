"""Every check, both sides. A check that has only a firing test does not ship.

Each test class pairs a case that must fire with a case that must stay silent, built to differ
in the one fact the check is about.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from flutterscope.judge import judge
from flutterscope.model import Severity, Status
from flutterscope.recover import recover

from helpers import (AWS_DOC_EXAMPLE, FAKE_AWS, FAKE_GOOGLE, FAKE_PEM, PROFILE, RELEASE,
                     RELEASE_SPLIT, apk, app_main, blutter, libapp, libflutter,
                     obfuscated_libs, readable_libs)

EVERY_CHECK = {
    "release-build", "dart-obfuscation", "build-path-leak", "hardcoded-credentials",
    "cleartext-urls", "tls-certificate-callback", "weak-crypto", "process-exec",
    "webview-js-channel",
}


class Case(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_on(self, *, features=RELEASE, strings=(), kernel=False, app=True, libs=None,
               pp="", abi="arm64-v8a"):
        path = apk(self.tmp, app=libapp(features, list(strings)) if app else None,
                   flutter=libflutter(), kernel=kernel, abi=abi)
        bdir = blutter(self.tmp, libs, pp) if libs is not None else None
        facts = recover(path, bdir)
        return facts, judge(facts)

    def status(self, result, check):
        c = result.check(check)
        self.assertIsNotNone(c, f"{check} returned no verdict")
        return c.status


class EveryCheckAnswers(Case):
    def test_each_check_gives_exactly_one_verdict(self):
        for kwargs in ({}, {"libs": readable_libs()}, {"kernel": True, "app": False}):
            _, r = self.run_on(**kwargs)
            names = [c.check for c in r.checks]
            self.assertEqual(sorted(names), sorted(EVERY_CHECK), kwargs)

    def test_not_flutter_gives_no_verdicts(self):
        path = apk(self.tmp)
        facts = recover(path)
        self.assertFalse(facts.is_flutter)
        self.assertEqual(judge(facts).checks, [])

    def test_without_blutter_deep_checks_say_why(self):
        _, r = self.run_on()
        for check in ("weak-crypto", "process-exec", "webview-js-channel"):
            c = r.check(check)
            self.assertIs(c.status, Status.NOT_TESTED)
            self.assertIn("Blutter", c.reason)
            self.assertIn("3.12.2", c.reason)

    def test_other_abi_is_not_tested_for_deep(self):
        _, r = self.run_on(abi="armeabi-v7a")
        self.assertIn("arm64", r.check("weak-crypto").reason)

    def test_tls_callback_is_never_decided_statically(self):
        _, r = self.run_on(libs=readable_libs(), pp="_onBadCertificateWrapper\n")
        self.assertIs(self.status(r, "tls-certificate-callback"), Status.NOT_TESTED)
        _, r = self.run_on(libs=readable_libs())
        self.assertIs(self.status(r, "tls-certificate-callback"), Status.NOT_TESTED)


class ReleaseBuild(Case):
    def test_fires_on_debug_kernel(self):
        _, r = self.run_on(app=False, kernel=True)
        self.assertIs(self.status(r, "release-build"), Status.FAIL)
        self.assertIn("release-build", {f.rule for f in r.findings})

    def test_fires_on_profile_snapshot(self):
        _, r = self.run_on(features=PROFILE)
        self.assertIs(self.status(r, "release-build"), Status.FAIL)

    def test_silent_on_release(self):
        _, r = self.run_on()
        self.assertIs(self.status(r, "release-build"), Status.PASS)
        self.assertNotIn("release-build", {f.rule for f in r.findings})


class Obfuscation(Case):
    def test_fires_on_header_without_split_debug_info(self):
        _, r = self.run_on(features=RELEASE)
        self.assertIs(self.status(r, "dart-obfuscation"), Status.FAIL)

    def test_missing_hardening_is_never_a_rated_finding(self):
        _, r = self.run_on(features=RELEASE)
        self.assertNotIn("dart-obfuscation", {f.rule for f in r.findings})
        self.assertIn("dart-obfuscation", {o.rule for o in r.observations})

    def test_split_debug_info_alone_is_not_decided(self):
        _, r = self.run_on(features=RELEASE_SPLIT)
        self.assertIs(self.status(r, "dart-obfuscation"), Status.NOT_TESTED)

    def test_silent_on_renamed_namespace(self):
        _, r = self.run_on(features=RELEASE_SPLIT, libs=obfuscated_libs())
        self.assertIs(self.status(r, "dart-obfuscation"), Status.PASS)

    def test_fires_on_split_without_obfuscate(self):
        _, r = self.run_on(features=RELEASE_SPLIT, libs=readable_libs())
        self.assertIs(self.status(r, "dart-obfuscation"), Status.FAIL)

    def test_conflict_is_not_forced(self):
        _, r = self.run_on(features=RELEASE, libs=obfuscated_libs())
        c = r.check("dart-obfuscation")
        self.assertIs(c.status, Status.NOT_TESTED)
        self.assertIn("conflict", c.reason)

    def test_too_few_libraries(self):
        _, r = self.run_on(features=RELEASE_SPLIT, libs=readable_libs(5))
        self.assertIs(self.status(r, "dart-obfuscation"), Status.NOT_TESTED)

    def test_middle_band_is_not_forced(self):
        libs = obfuscated_libs(60, readable=40)
        _, r = self.run_on(features=RELEASE_SPLIT, libs=libs)
        self.assertIs(self.status(r, "dart-obfuscation"), Status.NOT_TESTED)


class BuildPaths(Case):
    PATH = "file:///C:/Users/dev/projects/app/.dart_tool/flutter_build/dart_plugin_registrant.dart"

    def test_fires_on_absolute_path(self):
        _, r = self.run_on(strings=[self.PATH])
        self.assertIs(self.status(r, "build-path-leak"), Status.FAIL)
        self.assertNotIn("build-path-leak", {f.rule for f in r.findings})

    def test_fires_on_unix_home(self):
        _, r = self.run_on(strings=["file:///home/ci/app/.dart_tool/x.dart"])
        self.assertIs(self.status(r, "build-path-leak"), Status.FAIL)

    def test_silent_on_bare_scheme(self):
        _, r = self.run_on(strings=["file:///", "file:///android_asset/flutter_assets"])
        self.assertIs(self.status(r, "build-path-leak"), Status.PASS)


class Credentials(Case):
    def test_fires_on_private_key(self):
        _, r = self.run_on(strings=[FAKE_PEM])
        f = next(x for x in r.findings if x.rule == "hardcoded-credentials")
        self.assertIs(f.severity, Severity.HIGH)
        self.assertEqual(f.control, "MASVS-CRYPTO-2")

    def test_fires_on_access_key_id(self):
        _, r = self.run_on(strings=[FAKE_AWS])
        f = next(x for x in r.findings if x.rule == "hardcoded-credentials")
        self.assertIs(f.severity, Severity.MEDIUM)

    def test_silent_on_documented_example(self):
        _, r = self.run_on(strings=[AWS_DOC_EXAMPLE])
        self.assertIs(self.status(r, "hardcoded-credentials"), Status.PASS)
        self.assertFalse([x for x in r.findings if x.rule == "hardcoded-credentials"])

    def test_google_key_is_an_observation_not_a_finding(self):
        _, r = self.run_on(strings=[FAKE_GOOGLE])
        self.assertFalse([x for x in r.findings if x.rule == "hardcoded-credentials"])
        self.assertIn("hardcoded-credentials", {o.rule for o in r.observations})

    def test_silent_on_clean(self):
        _, r = self.run_on(strings=["https://api.example.com", "Bearer "])
        self.assertIs(self.status(r, "hardcoded-credentials"), Status.PASS)

    def test_value_is_never_written_in_full(self):
        facts, r = self.run_on(strings=[FAKE_AWS])
        text = json.dumps(facts.to_dict()) + json.dumps(r.to_dict())
        self.assertNotIn(FAKE_AWS, text)

    def test_attributed_to_app_with_blutter(self):
        libs = {**readable_libs(), **app_main("demo", f'r1 = "{FAKE_AWS}"')}
        _, r = self.run_on(strings=[FAKE_AWS], libs=libs)
        f = next(x for x in r.findings if x.rule == "hardcoded-credentials")
        self.assertEqual(f.origin, "app")

    def test_attributed_to_package(self):
        libs = {**readable_libs(), **app_main("demo"),
                "vendor_sdk/src/config.dart": f'r1 = "{FAKE_AWS}"'}
        _, r = self.run_on(strings=[FAKE_AWS], libs=libs)
        f = next(x for x in r.findings if x.rule == "hardcoded-credentials")
        self.assertEqual(f.origin, "package:vendor_sdk")


class Cleartext(Case):
    def test_fires_on_http_endpoint(self):
        _, r = self.run_on(strings=["http://api.example.com/v1/login"])
        self.assertIs(self.status(r, "cleartext-urls"), Status.REVIEW)

    def test_silent_on_identifiers_and_https(self):
        _, r = self.run_on(strings=["http://www.w3.org/2000/svg",
                                    "http://schemas.android.com/apk/res/android",
                                    "http://www.ibm.com/data/dtd/v11/ibmxhtml1-transitional.dtd",
                                    "https://api.example.com/v1/login"])
        self.assertIs(self.status(r, "cleartext-urls"), Status.PASS)


REGISTRY = {
    "pointycastle/src/registry/registration.dart": "RC4Engine MD5Digest DESedeEngine",
    "pointycastle/stream/rc4_engine.dart": "class RC4Engine extends BaseStreamCipher {}",
    "pointycastle/digests/md5.dart": "class MD5Digest extends MD4FamilyDigest {}",
}


class WeakCrypto(Case):
    def test_fires_when_app_constructs_rc4(self):
        libs = {**readable_libs(), **REGISTRY,
                **app_main("demo", "r0 = RC4Engine()  ; [package:pointycastle] RC4Engine")}
        _, r = self.run_on(libs=libs)
        self.assertIs(self.status(r, "weak-crypto"), Status.FAIL)
        f = next(x for x in r.findings if x.rule == "weak-crypto")
        self.assertEqual((f.severity, f.origin), (Severity.HIGH, "app"))

    def test_silent_when_only_the_registry_names_it(self):
        _, r = self.run_on(libs={**readable_libs(), **REGISTRY, **app_main("demo")})
        self.assertIs(self.status(r, "weak-crypto"), Status.PASS)
        self.assertFalse([x for x in r.findings if x.rule == "weak-crypto"])

    def test_weak_hash_alone_is_review_not_finding(self):
        libs = {**readable_libs(), **REGISTRY, **app_main("demo", "MD5Digest()")}
        _, r = self.run_on(libs=libs)
        self.assertIs(self.status(r, "weak-crypto"), Status.REVIEW)
        self.assertFalse([x for x in r.findings if x.rule == "weak-crypto"])

    def test_never_passes_on_obfuscated_names(self):
        _, r = self.run_on(features=RELEASE_SPLIT, libs=obfuscated_libs())
        self.assertIs(self.status(r, "weak-crypto"), Status.NOT_TESTED)

    def test_still_fires_on_obfuscated_build_when_found(self):
        libs = obfuscated_libs()
        libs["aAm.dart"] += "RC4Engine()\n"
        _, r = self.run_on(features=RELEASE_SPLIT, libs=libs)
        self.assertIs(self.status(r, "weak-crypto"), Status.FAIL)
        self.assertEqual(next(x for x in r.findings if x.rule == "weak-crypto").origin, "unknown")


class ProcessExec(Case):
    PP = "[pp+0xa370] Field <_ProcessImpl@16069316._path@16069316>: late (offset: 0xc)\n"
    CALL = "bl #0x26d040  ; [dart:io] ::_runNonInteractiveProcess"

    def test_fires_when_app_runs_a_process(self):
        libs = {**readable_libs(), **app_main("demo", self.CALL)}
        _, r = self.run_on(libs=libs, pp=self.PP)
        self.assertIs(self.status(r, "process-exec"), Status.FAIL)
        self.assertEqual(next(x for x in r.findings if x.rule == "process-exec").origin, "app")

    def test_silent_when_absent(self):
        _, r = self.run_on(libs={**readable_libs(), **app_main("demo")})
        self.assertIs(self.status(r, "process-exec"), Status.PASS)

    def test_never_passes_on_obfuscated_names(self):
        _, r = self.run_on(features=RELEASE_SPLIT, libs=obfuscated_libs())
        self.assertIs(self.status(r, "process-exec"), Status.NOT_TESTED)


WEBVIEW_PKGS = {
    "webview_flutter/src/webview_controller.dart": "class WebViewController {}",
    "webview_flutter_android/src/android_webview_controller.dart": "setJavaScriptMode",
}


class WebViewChannel(Case):
    PP = ('[pp+0x9f20] String: "dev.flutter.pigeon.webview_flutter_android.WebView.'
          'addJavaScriptChannel"\n')

    def test_fires_when_app_registers_a_channel(self):
        libs = {**readable_libs(), **WEBVIEW_PKGS,
                **app_main("demo", "r0 = addJavaScriptChannel()")}
        _, r = self.run_on(libs=libs, pp=self.PP)
        self.assertIs(self.status(r, "webview-js-channel"), Status.FAIL)
        self.assertEqual(next(x for x in r.findings if x.rule == "webview-js-channel").origin,
                         "app")

    def test_silent_on_webview_without_channel(self):
        _, r = self.run_on(libs={**readable_libs(), **WEBVIEW_PKGS, **app_main("demo")})
        self.assertIs(self.status(r, "webview-js-channel"), Status.PASS)

    def test_survives_obfuscation(self):
        _, r = self.run_on(features=RELEASE_SPLIT, libs=obfuscated_libs(), pp=self.PP)
        self.assertIs(self.status(r, "webview-js-channel"), Status.FAIL)


if __name__ == "__main__":
    unittest.main()
