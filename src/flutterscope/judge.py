"""Stage two: judge recovered facts. All security claims live here and nowhere else.

Every check returns exactly one verdict, so nothing can silently not run. A check that could
not be made says NOT_TESTED with the reason. It is never left out and never shown as a pass.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from .model import Check, Facts, Finding, Observation, Result, Severity, Status

# Obfuscation is judged on how much of the Dart library namespace kept readable names.
# Below the floor the ratio means nothing. The two thresholds leave a band in between that is
# reported as not decidable rather than forced either way.
LIB_FLOOR = 25
READABLE_FAILS = 0.60
READABLE_PASSES = 0.20

# http:// URLs that are identifiers, not network endpoints. Matched on the host.
NAMESPACE_HOSTS = {
    "www.w3.org", "w3.org", "schemas.android.com", "schemas.microsoft.com", "ns.adobe.com",
    "purl.org", "xmlpull.org", "www.apache.org", "apache.org", "xml.org", "www.xml.org",
    "json-schema.org", "schemas.xmlsoap.org", "www.opengis.net", "iptc.org", "ns.useplus.org",
}

CREDENTIAL_TITLES = {
    "private-key": "Private key compiled into the app",
    "aws-access-key-id": "Cloud access key identifier compiled into the app",
    "stripe-secret-key": "Payment provider secret key compiled into the app",
    "slack-token": "Chat workspace token compiled into the app",
    "github-token": "Source hosting access token compiled into the app",
}


def judge(f: Facts) -> Result:
    r = Result()
    if not f.is_flutter:
        return r
    _release_build(f, r)
    _obfuscation(f, r)
    _build_paths(f, r)
    _credentials(f, r)
    _cleartext(f, r)
    _tls_callback(f, r)
    _weak_crypto(f, r)
    _process_exec(f, r)
    _webview_channel(f, r)
    return r


def _signal(f: Facts, slug: str):
    return next((s for s in f.signals if s.slug == slug), None)


def _where(origin: str) -> str:
    if origin == "app":
        return "the app's own Dart code"
    if origin.startswith("package:"):
        return f"the third-party package `{origin[8:]}`"
    return "a library whose name was obfuscated, so the owner is not known"


def _refs(referrers: list[str], limit: int = 4) -> str:
    shown = ", ".join(f"`{r}`" for r in referrers[:limit])
    more = len(referrers) - limit
    return shown + (f" and {more} more" if more > 0 else "")


# --------------------------------------------------------------------------------------------

def _release_build(f: Facts, r: Result) -> None:
    check, control, maswe = "release-build", "MASVS-RESILIENCE-4", "MASWE-0063"
    snap = f.snapshot
    if f.kernel_blob or (snap and not snap.is_product):
        how = ("ships `flutter_assets/kernel_blob.bin`, the Dart kernel of a debug build"
               if f.kernel_blob else
               f"has a Dart snapshot compiled without the `product` mode "
               f"(features: {' '.join(snap.features[:4])} ...), which means a profile build")
        r.findings.append(Finding(
            rule=check,
            title="The shipped build is a debug or profile build, not a release build",
            severity=Severity.MEDIUM, control=control, maswe=maswe,
            cwe="CWE-489: Active Debug Code", origin="app",
            evidence=f"The artifact {how}.",
            impact=("Debug and profile builds keep developer tooling that a release build "
                    "removes. A debug build's kernel blob gives back the app's Dart code almost "
                    "as written, and both keep the Dart VM service code in the app."),
            remediation=("Build the store artifact in release mode:\n\n"
                         "```\nflutter build appbundle --release\n```"),
        ))
        r.checks.append(Check(check, control, maswe, Status.FAIL, "Not a release build."))
    elif snap:
        r.checks.append(Check(check, control, maswe, Status.PASS,
                              "The Dart snapshot was compiled in product (release) mode."))
    else:
        r.checks.append(Check(check, control, maswe, Status.NOT_TESTED,
                              "No Dart snapshot header and no kernel blob could be read."))


def _obfuscation(f: Facts, r: Result) -> None:
    check, control, maswe = "dart-obfuscation", "MASVS-RESILIENCE-3", "MASWE-0059"
    snap = f.snapshot
    dwarf = snap.dwarf_stack_traces if snap else None
    ratio_ok = f.deep and f.libs_total >= LIB_FLOOR
    share = f.libs_readable / f.libs_total if f.libs_total else 0.0
    names = (f"{f.libs_readable} of {f.libs_total} recovered Dart libraries "
             f"({share:.1%}) kept a readable name")

    if snap is None:
        r.checks.append(Check(check, control, maswe, Status.NOT_TESTED,
                              "No Dart snapshot header could be read, so the build flags are "
                              "unknown."))
        return

    if dwarf is False:
        # The flutter tool refuses --obfuscate without --split-debug-info, and
        # --split-debug-info compiles the snapshot with dwarf_stack_traces_mode.
        if ratio_ok and share <= READABLE_PASSES:
            r.checks.append(Check(check, control, maswe, Status.NOT_TESTED,
                                  "The evidence conflicts: the snapshot was built without "
                                  f"--split-debug-info, yet {names}. The app may have been "
                                  "compiled outside the flutter tool. Review by hand."))
            return
        extra = f" Blutter agrees: {names}." if ratio_ok else ""
        r.observations.append(Observation(
            check, control,
            "The Dart code was compiled without `--obfuscate`. The snapshot header lists "
            "`no-dwarf_stack_traces_mode`, and the flutter tool will not obfuscate without "
            "`--split-debug-info`, which turns that mode on. Class, method and library names "
            "are therefore readable to anyone who unpacks the app." + extra
            + " This is missing hardening, not a vulnerability. To add it:\n\n"
            "```\nflutter build appbundle --release --obfuscate "
            "--split-debug-info=build/symbols\n```"))
        r.checks.append(Check(check, control, maswe, Status.FAIL,
                              "Built without --obfuscate (no --split-debug-info in the "
                              "snapshot flags)."))
        return

    # dwarf is True or unknown: the header alone cannot settle it.
    if not ratio_ok:
        why = (f.deep_reason or
               f"only {f.libs_total} Dart libraries were recovered, too few to judge")
        pre = ("The snapshot was built with --split-debug-info, which --obfuscate needs but "
               "does not imply. " if dwarf else "")
        r.checks.append(Check(check, control, maswe, Status.NOT_TESTED,
                              pre + "The library namespace is needed to decide: " + why))
        return
    if share <= READABLE_PASSES:
        r.checks.append(Check(check, control, maswe, Status.PASS,
                              f"Obfuscation confirmed: only {names}. The readable ones are "
                              "plugin and framework names that --obfuscate leaves behind."))
    elif share >= READABLE_FAILS:
        r.observations.append(Observation(
            check, control,
            f"The Dart code is not obfuscated: {names}. The build used "
            "`--split-debug-info` but not `--obfuscate`. This is missing hardening, not a "
            "vulnerability."))
        r.checks.append(Check(check, control, maswe, Status.FAIL,
                              f"Not obfuscated: {names}."))
    else:
        r.checks.append(Check(check, control, maswe, Status.NOT_TESTED,
                              f"Inconclusive: {names}. That is neither the handful left "
                              "after --obfuscate nor an intact namespace. Review by hand."))


def _build_paths(f: Facts, r: Result) -> None:
    check, control, maswe = "build-path-leak", "MASVS-RESILIENCE-3", "MASWE-0061"
    if f.snapshot is None:
        r.checks.append(Check(check, control, maswe, Status.NOT_TESTED,
                              "No AOT snapshot to read strings from."))
        return
    if f.build_paths:
        shown = ", ".join(f"`{p}`" for p in f.build_paths[:3])
        r.observations.append(Observation(
            check, control,
            f"The snapshot contains absolute paths from the machine that built it: {shown}. "
            "They can reveal a user name and the project layout. Build in a neutral location, "
            "such as a CI workspace, to keep them out."))
        r.checks.append(Check(check, control, maswe, Status.FAIL,
                              f"{len(f.build_paths)} build machine path(s) in the snapshot."))
    else:
        r.checks.append(Check(check, control, maswe, Status.PASS,
                              "No absolute build machine path in the snapshot strings."))


def _credentials(f: Facts, r: Result) -> None:
    check, control, maswe = "hardcoded-credentials", "MASVS-STORAGE-1", "MASWE-0004"
    if f.snapshot is None:
        r.checks.append(Check(check, control, maswe, Status.NOT_TESTED,
                              "No AOT snapshot to read constants from."))
        return
    real = [c for c in f.constants if not c.documented_example and c.kind != "google-api-key"]
    for c in f.constants:
        if c.documented_example:
            r.observations.append(Observation(
                check, control,
                f"`{c.value}` matches a placeholder published in vendor documentation and "
                "was not reported."))
        elif c.kind == "google-api-key":
            r.observations.append(Observation(
                check, control,
                f"A Google API key ({c.value}) is in the snapshot. These keys are meant to "
                "ship in the client. Confirm in the Google Cloud console that it is "
                "restricted to this app and to the APIs it needs."))
    for c in real:
        high = c.kind != "aws-access-key-id"
        where = _where(c.origin) if f.deep else "the Dart snapshot (run with Blutter to attribute it)"
        r.findings.append(Finding(
            rule=check,
            title=CREDENTIAL_TITLES[c.kind],
            severity=Severity.HIGH if high else Severity.MEDIUM,
            control="MASVS-CRYPTO-2" if c.kind == "private-key" else control,
            maswe="MASWE-0003" if c.kind == "private-key" else maswe,
            cwe="CWE-798: Use of Hard-coded Credentials",
            origin=c.origin,
            evidence=(f"A {c.kind} constant ({c.value}) in {where}"
                      + (f", referenced from {_refs(c.referrers)}." if c.referrers else ".")),
            impact=("Anyone who downloads the app can extract this value. Whatever it unlocks "
                    "is available to them with the app's privileges."
                    + ("" if high else " An access key ID is only half of an AWS credential, "
                       "but it is rarely shipped without its secret, so look for that too.")),
            remediation=("Remove the credential from the app and rotate it now, since every "
                         "copy already shipped still holds it. Have the app ask your backend "
                         "for a short-lived, scoped token instead:\n\n"
                         "```dart\nfinal token = await api.post('/session/token');\n```"),
        ))
    if real:
        r.checks.append(Check(check, control, maswe, Status.FAIL,
                              f"{len(real)} credential-shaped constant(s) in the snapshot."))
    else:
        r.checks.append(Check(check, control, maswe, Status.PASS,
                              "No credential-shaped constant in the snapshot. Two-byte "
                              "(non Latin-1) strings and values built at runtime are not "
                              "visible to this check."))


def _cleartext(f: Facts, r: Result) -> None:
    check, control, maswe = "cleartext-urls", "MASVS-NETWORK-1", "MASWE-0026"
    if f.snapshot is None:
        r.checks.append(Check(check, control, maswe, Status.NOT_TESTED,
                              "No AOT snapshot to read URLs from."))
        return
    plain = []
    for u in f.urls:
        if not u.startswith("http://"):
            continue
        parts = urlsplit(u)
        host = (parts.hostname or "").lower()
        # Document type and schema locations are identifiers that parsers resolve offline.
        if host and host not in NAMESPACE_HOSTS and not parts.path.endswith((".dtd", ".xsd")):
            plain.append(u)
    if plain:
        shown = ", ".join(f"`{u}`" for u in plain[:6])
        r.observations.append(Observation(
            check, control,
            f"{len(plain)} http:// URL(s) are compiled into the Dart code: {shown}. dart:io "
            "asks the platform whether cleartext is allowed, so whether these connections can "
            "happen depends on the Android network security config or iOS ATS settings, which "
            "flutterscope does not read. Confirm each one."))
        r.checks.append(Check(check, control, maswe, Status.REVIEW,
                              f"{len(plain)} cleartext URL candidate(s) need the platform "
                              "network policy to decide."))
    else:
        r.checks.append(Check(check, control, maswe, Status.PASS,
                              "No http:// URL constant in the Dart code. URLs assembled at "
                              "runtime are not visible to this check."))


def _tls_callback(f: Facts, r: Result) -> None:
    # Deliberately never decided statically. The SDK keeps the same certificate-callback
    # wrapper for every app that opens a dart:io TLS socket, whether or not it overrides
    # validation, so the wrapper's presence proves nothing. See docs/CHECKS.md.
    r.checks.append(Check(
        "tls-certificate-callback", "MASVS-NETWORK-1", "MASWE-0027",
        Status.NOT_TESTED,
        "Whether the Dart code accepts bad certificates cannot be decided from the compiled "
        "snapshot. It needs a dynamic test that presents an untrusted certificate."))


def _deep_or_skip(f: Facts, r: Result, check: str, control: str, maswe: str) -> bool:
    if f.deep:
        return True
    r.checks.append(Check(check, control, maswe, Status.NOT_TESTED,
                          f.deep_reason or "Blutter output was not available."))
    return False


def names_readable(f: Facts) -> bool:
    """True when enough of the Dart namespace kept its names for a name-based check to pass.

    --obfuscate renames classes and functions, including RC4Engine and dart:io's _ProcessImpl.
    On the obfuscated vulnerable twin both disappear, so "not found" means nothing there. A
    name-based check may still FAIL on an obfuscated build when it finds its token, but it
    must not PASS.
    """
    return (f.deep and f.libs_total >= LIB_FLOOR
            and f.libs_readable / f.libs_total >= READABLE_FAILS)


_RENAMED = ("Class and function names in this build are obfuscated, and this check looks for "
            "them by name, so a renamed {what} would not be seen. Not finding it proves nothing.")


def _weak_crypto(f: Facts, r: Result) -> None:
    check, control, maswe = "weak-crypto", "MASVS-CRYPTO-1", "MASWE-0007"
    if not _deep_or_skip(f, r, check, control, maswe):
        return
    cipher, ecb, hashes = (_signal(f, s) for s in ("weak-cipher", "ecb-mode", "weak-hash"))
    if cipher:
        r.findings.append(Finding(
            rule=check,
            title="Broken cipher used in the Dart code",
            severity=Severity.HIGH, control=control, maswe=maswe,
            cwe="CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
            origin=cipher.origin,
            evidence=(f"`{cipher.token}` is reached from {_where(cipher.origin)}: "
                      f"{_refs(cipher.referrers)}. References from pointycastle's own "
                      "algorithm registry are not counted, since it names every algorithm it "
                      "can build."),
            impact=("RC4 has practical keystream biases and DES keys can be brute-forced. "
                    "Data protected this way should be treated as readable by an attacker "
                    "who captures it."),
            remediation=("Use authenticated AES-GCM:\n\n"
                         "```dart\nfinal cipher = GCMBlockCipher(AESEngine())\n"
                         "  ..init(true, AEADParameters(KeyParameter(key), 128, nonce, aad));\n"
                         "```\n\nOr use `package:cryptography`, whose `AesGcm` is harder to "
                         "misuse."),
        ))
    for sig, what in ((ecb, "ECB mode leaks patterns across blocks. It is only acceptable "
                            "for wrapping a single key block."),
                      (hashes, "MD5 and SHA-1 are broken for signatures, integrity and "
                               "passwords, and fine for non-security checksums.")):
        if sig:
            r.observations.append(Observation(
                check, control,
                f"`{sig.token}` is reached from {_where(sig.origin)}: {_refs(sig.referrers)}. "
                f"{what} Check what it is used for."))
    if cipher:
        r.checks.append(Check(check, control, maswe, Status.FAIL,
                              "A broken cipher is reachable from outside pointycastle."))
    elif not names_readable(f):
        r.checks.append(Check(check, control, maswe, Status.NOT_TESTED,
                              _RENAMED.format(what="cipher engine")))
    elif ecb or hashes:
        r.checks.append(Check(check, control, maswe, Status.REVIEW,
                              "ECB mode or a weak hash is reachable. Its use decides it."))
    else:
        r.checks.append(Check(check, control, maswe, Status.PASS,
                              "No RC4, DES, 3DES, ECB, MD5 or SHA-1 from pointycastle is "
                              "reached outside pointycastle itself. Other crypto libraries and "
                              "key handling are not covered by this check."))


def _process_exec(f: Facts, r: Result) -> None:
    check, control, maswe = "process-exec", "MASVS-CODE-4", "MASWE-0050"
    if not _deep_or_skip(f, r, check, control, maswe):
        return
    sig = _signal(f, "process-exec")
    if not sig and not names_readable(f):
        r.checks.append(Check(check, control, maswe, Status.NOT_TESTED,
                              _RENAMED.format(what="process call")))
        return
    if not sig:
        r.checks.append(Check(check, control, maswe, Status.PASS,
                              "dart:io process execution is not reachable in the Dart code."))
        return
    r.findings.append(Finding(
        rule=check,
        title="The app runs operating system commands from Dart",
        severity=Severity.LOW, control=control, maswe=maswe,
        cwe="CWE-78: Improper Neutralization of Special Elements used in an OS Command",
        origin=sig.origin,
        evidence=(f"dart:io `Process` is reachable" +
                  (f", called from {_refs(sig.referrers)}." if sig.referrers else ".") +
                  " The compiler removes it when unused, so its presence means it can run."),
        impact=("A normal app rarely needs a shell. If any part of the command comes from "
                "outside the app, it is command injection."),
        remediation=("Replace the command with a platform channel to a specific native API. If "
                     "a command is unavoidable, pass a fixed argument list and keep outside "
                     "input off it:\n\n"
                     "```dart\nawait Process.run('/system/bin/toolname', const ['--fixed']);\n"
                     "```"),
    ))
    r.checks.append(Check(check, control, maswe, Status.FAIL,
                          "dart:io process execution is reachable."))


def _webview_channel(f: Facts, r: Result) -> None:
    check, control, maswe = "webview-js-channel", "MASVS-PLATFORM-2", "MASWE-0033"
    if not _deep_or_skip(f, r, check, control, maswe):
        return
    sig = _signal(f, "webview-js-channel")
    if not sig:
        r.checks.append(Check(check, control, maswe, Status.PASS,
                              "No webview_flutter JavaScript channel is registered."))
        return
    r.findings.append(Finding(
        rule=check,
        title="A WebView exposes a Dart callback to page scripts",
        severity=Severity.MEDIUM, control=control, maswe=maswe,
        cwe="CWE-749: Exposed Dangerous Method or Function",
        origin=sig.origin,
        evidence=(f"`addJavaScriptChannel` is registered from {_where(sig.origin)}: "
                  f"{_refs(sig.referrers)}."),
        impact=("Every script in the page can call the channel, including scripts from ads, "
                "redirects or a compromised site. The risk depends on what the WebView loads "
                "and what the callback does, so confirm both."),
        remediation=("Only register a channel on a WebView that loads content you control, "
                     "and check the origin before acting on a message:\n\n"
                     "```dart\ncontroller.setNavigationDelegate(NavigationDelegate(\n"
                     "  onNavigationRequest: (req) => req.url.startsWith('https://app.example.com/')\n"
                     "      ? NavigationDecision.navigate\n"
                     "      : NavigationDecision.prevent,\n));\n```"),
    ))
    r.checks.append(Check(check, control, maswe, Status.FAIL,
                          "A JavaScript channel is registered."))
