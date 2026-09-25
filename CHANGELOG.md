# Changelog

## 0.1.0 - 2026-09-25

First working release. Android only.

- `recover`, `judge` and `scan` commands. JSON and SARIF 2.1.0 output.
- Dart version from `libflutter.so` and snapshot hash and flags from `libapp.so`, with no
  Blutter needed.
- Nine checks: `release-build`, `dart-obfuscation`, `build-path-leak`,
  `hardcoded-credentials`, `cleartext-urls`, `tls-certificate-callback`, `weak-crypto`,
  `process-exec`, `webview-js-channel`.
- Obfuscation decided from the snapshot header when the build had no `--split-debug-info`.
- Name-based checks return NOT_TESTED on obfuscated builds instead of PASS.
- Twin fixture apps and a script that builds five real variants from them.
