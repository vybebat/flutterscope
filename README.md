# flutterscope

Security facts from compiled Flutter apps, mapped to OWASP MASVS v2.1.

> **Status: 0.1, alpha.** Android only. Nine checks, each tested on both sides. Expect the
> output format to change before 1.0.

## The problem

Flutter compiles Dart ahead of time into a native snapshot, `libapp.so` on Android. The free
mobile scanners treat that file as an opaque blob. They see no readable class names, no Dart
network code and no JavaScript bridge, and they do not say that they did not look.

So a report on a Flutter app can be silent about whole classes of problem while looking clean.
flutterscope reads the snapshot, says what it found, and says which checks it could not make.

## Quick start

```bash
pip install git+https://github.com/vybebat/flutterscope
flutterscope scan app-release.apk
```

That runs the checks that need nothing but the APK. For the code-level checks, run
[Blutter](https://github.com/worawit/blutter) on the app first and pass its output:

```bash
flutterscope scan app-release.apk --blutter out/app --json report.json --sarif report.sarif
```

flutterscope tells you which Dart version the app was built with, which is the Blutter runtime
you need. See [docs/BLUTTER.md](docs/BLUTTER.md).

Example output on the deliberately vulnerable fixture:

```
flutterscope 0.1.0  twin_vuln.apk
  platform android, ABIs arm64-v8a, Dart 3.12.2
  snapshot ace654289f5abc240509fc941453ebc5  release
  deep analysis: yes, 297 libraries

  PASS       release-build             MASVS-RESILIENCE-4
  FAIL       dart-obfuscation          MASVS-RESILIENCE-3
  FAIL       build-path-leak           MASVS-RESILIENCE-3
  FAIL       hardcoded-credentials     MASVS-STORAGE-1
  PASS       cleartext-urls            MASVS-NETWORK-1
  NOT_TESTED tls-certificate-callback  MASVS-NETWORK-1
  FAIL       weak-crypto               MASVS-CRYPTO-1
  FAIL       process-exec              MASVS-CODE-4
  FAIL       webview-js-channel        MASVS-PLATFORM-2

  [HIGH] Private key compiled into the app (MASVS-CRYPTO-2, origin app)
  [MEDIUM] Cloud access key identifier compiled into the app (MASVS-STORAGE-1, origin app)
  [HIGH] Broken cipher used in the Dart code (MASVS-CRYPTO-1, origin app)
  [LOW] The app runs operating system commands from Dart (MASVS-CODE-4, origin app)
  [MEDIUM] A WebView exposes a Dart callback to page scripts (MASVS-PLATFORM-2, origin app)
```

## The checks

| Check | MASVS | MASWE | Needs Blutter |
|---|---|---|---|
| `release-build` | RESILIENCE-4 | MASWE-0063 | no |
| `dart-obfuscation` | RESILIENCE-3 | MASWE-0059 | sometimes |
| `build-path-leak` | RESILIENCE-3 | MASWE-0061 | no |
| `hardcoded-credentials` | STORAGE-1, CRYPTO-2 | MASWE-0004, MASWE-0003 | no, but it adds the owner |
| `cleartext-urls` | NETWORK-1 | MASWE-0026 | no |
| `tls-certificate-callback` | NETWORK-1 | MASWE-0027 | always NOT_TESTED, see below |
| `weak-crypto` | CRYPTO-1 | MASWE-0007 | yes |
| `process-exec` | CODE-4 | MASWE-0050 | yes |
| `webview-js-channel` | PLATFORM-2 | MASWE-0033 | yes |

What each one fires on, what keeps it silent, and its known limits are in
[docs/CHECKS.md](docs/CHECKS.md).

Each check covers a slice of a MASVS control, never the whole control. A PASS means "this check
found nothing", not "the app meets MASVS-CRYPTO-1". Which controls a machine can decide at all
is mapped in [vybebat/masvs-coverage](https://github.com/vybebat/masvs-coverage).

## Verdicts

| Verdict | Meaning |
|---|---|
| `PASS` | The check ran and found nothing. |
| `FAIL` | The check ran and found the problem. |
| `REVIEW` | The check found candidates that a person has to confirm. |
| `NOT_TESTED` | The check could not run. The reason is always given. |

Every check returns exactly one verdict on every run, so nothing can quietly not run. In SARIF,
`NOT_TESTED` checks are written as tool notifications, so a CI job that only counts results
does not read them as clean.

## Rules this project holds itself to

1. **A check ships only when it fires on a vulnerable fixture and stays silent on a clean one.**
   Both sides, every time, and the clean fixture is the same app with the one fact changed.
2. **Silence never looks like a pass.** A check that cannot see what it looks for says
   NOT_TESTED. An unsupported Dart version, a missing arm64 library and an obfuscated build all
   produce NOT_TESTED, never PASS.
3. **Findings in third-party packages are labelled.** Each finding carries an `origin`: `app`,
   `package:<name>`, or `unknown` when obfuscation removed the names. A developer cannot fix
   what they did not write.
4. **Recovery and judgement are separate.** `flutterscope recover` writes facts and makes no
   security claim. `flutterscope judge` reads facts. That split is what lets every rule be
   tested without a binary.
5. **Missing hardening is not a vulnerability.** No obfuscation is reported as a failed check
   with an observation, never as a severity-rated finding.

## What we got wrong on the way

These were real mistakes, caught by the rules above. They are why the checks look the way
they do.

- **A TLS wrapper that proves nothing.** An earlier check read the SDK's certificate-callback
  wrapper in the snapshot as "the app overrides certificate validation". A clean twin that
  makes a plain HTTPS request carries the same wrapper. The check was removed. It is now
  always NOT_TESTED, because the snapshot cannot answer the question.
- **Registry stubs.** pointycastle's algorithm registry names every cipher it can build, so an
  app that only uses AES still carries `RC4Engine`. A cipher now counts only when something
  outside pointycastle refers to it.
- **Obfuscation hides the evidence.** On the obfuscated build of the vulnerable twin,
  `RC4Engine` and dart:io's `_ProcessImpl` are renamed, so the name-based checks found
  nothing and would have passed. They now say NOT_TESTED on an obfuscated build unless they
  find their target anyway.
- **Surviving package names are not proof of no obfuscation.** `--obfuscate` leaves some
  plugin names in place. Obfuscation is now judged from the snapshot header and from the share
  of the whole library namespace that kept its names.

## Fixtures

`fixtures/apps/` holds two tiny Flutter apps, a vulnerable twin and a clean twin that use the
same packages on the same code path. `scripts/build_fixtures.py` builds five APKs from them,
including obfuscated and split-debug-info variants. The APKs are not committed; rebuild them
and `tests/test_real_fixtures.py` checks every verdict against them.

The unit tests use hand-built inputs in the same shapes, so they run anywhere with no Flutter
SDK and no Blutter:

```bash
PYTHONPATH=src:tests python -m unittest discover -s tests
```

## Scope and limits

- Android only in 0.1. An `.ipa` is recognised and reported, but Blutter does not read iOS
  snapshots, so the code-level checks are NOT_TESTED there.
- Strings are read as one-byte text. Non Latin-1 string constants are not seen.
- Values built at runtime (a URL joined from parts, a key decoded from base64) are not seen.
- This is a static tool. It says what the code can do, not what it did. Pair it with dynamic
  testing for anything about live traffic.

## Related work

- [Blutter](https://github.com/worawit/blutter) rebuilds Dart structure from the snapshot. The
  code-level checks read its output. Parsing fixes found here go back upstream.
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) is the reference free
  mobile scanner. flutterscope covers the Dart part it cannot see, and SARIF output lets the
  two be read side by side.
- [reFlutter](https://github.com/Impact-I/reFlutter) patches the Flutter engine for traffic
  interception. That is dynamic analysis and answers a different question.
- [OWASP MASTG](https://mas.owasp.org/MASTG/) and [MASWE](https://mas.owasp.org/MASWE/) are
  the references each check maps to.

## Licence

GPL-3.0-or-later. See [LICENSE](LICENSE).
