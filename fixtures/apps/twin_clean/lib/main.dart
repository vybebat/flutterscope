// The "must stay silent" twin. Same packages as ../twin_vuln, reached on the same live path,
// each used the safe way:
//
//   - AES-GCM and SHA-256 from the same pointycastle import, no RC4, DES or MD5
//   - a WebView with JavaScript on but no JavaScript channel
//   - no Process.run
//   - no credential-shaped constants
//
// The same source is also built with --obfuscate --split-debug-info, which gives the
// obfuscation check a counterfactual from the same app rather than from a different one.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:pointycastle/export.dart';
import 'package:webview_flutter/webview_flutter.dart' as wv;

const String backendUrl = 'https://api.example.invalid/v1/data';

String strongCipher(String secret) {
  final key = Uint8List.fromList(utf8.encode('0123456789abcdef'));
  final nonce = Uint8List.fromList(utf8.encode('0123456789ab'));
  final input = Uint8List.fromList(utf8.encode(secret));
  final gcm = GCMBlockCipher(AESEngine())
    ..init(true, AEADParameters(KeyParameter(key), 128, nonce, Uint8List(0)));
  final out = gcm.process(input);
  final digest = SHA256Digest().process(input);
  return base64.encode(out) + base64.encode(digest);
}

wv.WebViewController plainWebView() {
  return wv.WebViewController()
    ..setJavaScriptMode(wv.JavaScriptMode.unrestricted)
    ..loadRequest(Uri.parse(backendUrl));
}

Future<String> run() async {
  final client = HttpClient();
  final request = await client.getUrl(Uri.parse(backendUrl));
  final response = await request.close();
  final webview = plainWebView();
  return '${response.statusCode} ${strongCipher('hello')} ${webview.hashCode}';
}

void main() => runApp(const FixtureApp());

class FixtureApp extends StatelessWidget {
  const FixtureApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        body: FutureBuilder<String>(
          future: run(),
          builder: (context, s) => Center(child: Text(s.data ?? 'loading')),
        ),
      ),
    );
  }
}
