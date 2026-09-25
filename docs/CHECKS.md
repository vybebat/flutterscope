# Checks

For each check: what it reads, what makes it fire, what keeps it silent, and what it cannot
see. "Twin" means the fixture apps in `fixtures/apps/`. All real-build results below were
recorded with Flutter 3.44.2 and Dart 3.12.2.

## `release-build` (MASVS-RESILIENCE-4, MASWE-0063)

- **Reads:** the Dart snapshot header in `libapp.so`, and whether
  `flutter_assets/kernel_blob.bin` is in the package.
- **Fires:** a kernel blob is present (debug build), or the snapshot lacks the `product`
  feature (profile build). Finding, Medium.
- **Silent:** a snapshot with `product` in its features. Both twins.
- **Not tested:** no snapshot header and no kernel blob.

## `dart-obfuscation` (MASVS-RESILIENCE-3, MASWE-0059)

Two independent signals.

1. **The snapshot header.** `flutter build --obfuscate` refuses to run without
   `--split-debug-info`, and `--split-debug-info` compiles the snapshot with
   `dwarf_stack_traces_mode`. So `no-dwarf_stack_traces_mode` in the header means the Dart
   code was not obfuscated. No Blutter needed. Confirmed on all five twin builds: the two plain
   builds say `no-dwarf_stack_traces_mode`, the obfuscated and split-only builds say
   `dwarf_stack_traces_mode`.
2. **The library namespace.** With Blutter output, the share of recovered libraries that kept
   a readable name. The obfuscated twins keep a handful of plugin names among about 200; the
   split-only twin keeps all 284.

| Header | Readable share | Verdict |
|---|---|---|
| no dwarf mode | above 20%, or no Blutter | FAIL |
| no dwarf mode | 20% or less | NOT_TESTED, the signals conflict |
| dwarf mode | no Blutter, or under 25 libraries | NOT_TESTED |
| dwarf mode | 20% or less | PASS |
| dwarf mode | 60% or more | FAIL (split-debug-info without obfuscate) |
| dwarf mode | between | NOT_TESTED |

A FAIL here is an observation, never a severity-rated finding. Obfuscation is optional
hardening.

- **Limit:** someone who calls `gen_snapshot` directly can obfuscate without DWARF stack
  traces. The conflict row exists for that case.

## `build-path-leak` (MASVS-RESILIENCE-3, MASWE-0061)

- **Reads:** snapshot strings.
- **Fires:** an absolute `file:///` path under a drive letter, `/home`, `/Users` or `/root`.
  Flutter writes the path of the generated `dart_plugin_registrant.dart` into the snapshot of
  any app with plugins, so this fires on every twin, obfuscated or not. It is an observation,
  not a finding.
- **Silent:** only relative or bare `file:///` strings.
- **Why it matters:** the path often holds the developer's user name and project layout.
  Building in a neutral CI workspace avoids it.

## `hardcoded-credentials` (MASVS-STORAGE-1 / CRYPTO-2, MASWE-0004 / MASWE-0003)

- **Reads:** snapshot strings, and with Blutter, which library refers to each one.
- **Fires:** a PEM private key header, a cloud access key ID, a live payment provider secret
  key, a chat workspace token or a source hosting token. Private keys and secret tokens are
  High. An access key ID alone is Medium, since it is half of a credential.
- **Observation only:** Google API keys (`AIza...`). They are designed to ship in clients;
  the question is whether they are restricted, which the package cannot answer.
- **Silent:** placeholder keys that vendors publish in their documentation, and anything that
  does not match the patterns.
- **Never written in full:** reports carry the first 8 characters and a SHA-256 fingerprint.
- **Limits:** non Latin-1 strings, and values assembled or decoded at runtime.

## `cleartext-urls` (MASVS-NETWORK-1, MASWE-0026)

- **Reads:** `http://` URLs in snapshot strings.
- **REVIEW:** any `http://` URL whose host is not a known XML namespace host and whose path is
  not a `.dtd` or `.xsd`. dart:io asks the platform whether cleartext is allowed, so whether the
  connection can happen depends on the Android network security config, which flutterscope
  does not read. That is why this is REVIEW and not FAIL.
- **Silent:** only `https://` URLs and namespace identifiers.

## `tls-certificate-callback` (MASVS-NETWORK-1, MASWE-0027)

Always NOT_TESTED, on purpose.

The obvious static signal is the SDK's certificate-callback wrapper
(`_RawSecureSocket._onBadCertificateWrapper`). The clean twin makes an ordinary HTTPS request
with no callback, and the wrapper is there all the same. It marks "this app opens a TLS
socket", not "this app accepts bad certificates". The only difference between the twins is an
unnamed closure allocation next to `HttpClient`, an instruction pattern that changes with
inlining. Answering this needs a dynamic test that presents an untrusted certificate.

## `weak-crypto` (MASVS-CRYPTO-1, MASWE-0007)

- **Reads (Blutter):** references to pointycastle's `RC4Engine`, `DESEngine`, `DESedeEngine`,
  `ECBBlockCipher`, `MD5Digest` and `SHA1Digest`, and which libraries make them.
- **Fires:** a broken cipher referred to from outside pointycastle. Finding, High.
- **REVIEW:** ECB mode or MD5 / SHA-1 referred to from outside pointycastle. Both have
  legitimate uses, so they are observations.
- **Silent:** references only from inside pointycastle. Its algorithm registry names every
  algorithm it can build, so an AES-only app still carries RC4 as a constructor stub.
- **Not tested:** no Blutter output, or an obfuscated namespace. On the obfuscated vulnerable
  twin the class names are gone, so not finding them proves nothing.
- **Limits:** other crypto packages, and whether keys and IVs are handled correctly.

## `process-exec` (MASVS-CODE-4, MASWE-0050)

- **Reads (Blutter):** dart:io's `_ProcessImpl` in the object pool, and callers of
  `Process.run`, `Process.start` or the SDK's `_runNonInteractiveProcess`.
- **Fires:** process execution is reachable. It is removed from release builds when unused.
  Finding, Low.
- **Silent:** the clean twin, which imports dart:io for HTTP but never runs a process.
- **Not tested:** no Blutter output, or an obfuscated namespace.

## `webview-js-channel` (MASVS-PLATFORM-2, MASWE-0033)

- **Reads (Blutter):** `addJavaScriptChannel`, which webview_flutter keeps as a platform
  channel name in the object pool, and who calls it.
- **Fires:** a JavaScript channel is registered. Finding, Medium.
- **Silent:** the clean twin, which shows a WebView with JavaScript on but no channel.
- **Survives obfuscation:** the channel name is a string, not a symbol, so this still fires on
  the obfuscated vulnerable twin and stays silent on the obfuscated clean one.
