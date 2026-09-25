# Running Blutter for flutterscope

[Blutter](https://github.com/worawit/blutter) rebuilds Dart structure from `libapp.so`. It
compiles a Dart VM matching the app's Dart version, so each Dart version needs its own build.
Follow upstream's README for setup. These notes are what we learned using it.

## Which version do I need?

```bash
flutterscope scan app.apk
```

The first lines name the Dart version, read from `libflutter.so`, and the snapshot hash. That
is the runtime Blutter has to build.

## Run it

Blutter reads arm64 only. Unpack the APK and point Blutter at the directory that holds
`libapp.so` and `libflutter.so`:

```bash
unzip -o app.apk 'lib/arm64-v8a/*' -d app
python3 blutter.py app/lib/arm64-v8a out/app
flutterscope scan app.apk --blutter out/app
```

For a Play Store install, the arm64 libraries sit in the `split_config.arm64_v8a.apk` split.
flutterscope accepts a directory of split APKs as its artifact.

## What we saw

- **Linux (and WSL) built every version we tried:** Dart 2.19.0, 3.8.1, 3.9.2 and 3.10.7. The first run for a version
  compiles the VM and takes 10 to 20 minutes. Later runs take under a minute.
- **Windows with MSVC** built Dart 3.12.2 after adding `/Zc:preprocessor` to both CMake files,
  because newer Dart sources use `__VA_OPT__`. Other versions failed to compile there. Use
  Linux or WSL for anything else.
- Blutter does not create nested output directories. Make the parent first.
- If Blutter fails, flutterscope reports the deep checks as NOT_TESTED with the reason. It
  never falls back to a guess.

## Files flutterscope reads

| File | Used for |
|---|---|
| `pp.txt` | object pool: string constants, field and closure names |
| `objs.txt` | object dump, searched alongside `pp.txt` |
| `asm/**.dart` | one file per library: the namespace, and who refers to what |
