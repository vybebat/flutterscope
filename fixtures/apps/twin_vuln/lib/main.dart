// The "must fire" twin. Deliberately insecure. Every value is fake.
//
// Each weakness is reached from the live path in main(), so the AOT compiler keeps it. Code
// that is never reached is removed from a release build, and a fixture that only declares a
// weakness proves nothing.
//
// The clean twin (../twin_clean) uses the same packages on the same path, the safe way. A
// check that fires on both is reacting to the dependency, not to the behaviour.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:pointycastle/export.dart';
import 'package:webview_flutter/webview_flutter.dart' as wv;

const String backendUrl = 'https://api.example.invalid/v1/data';

// Split across adjacent literals so that repository secret scanners do not match this file.
// The compiler joins them, so the snapshot holds the whole fake key.
const String fakeAwsKeyId = 'AKIA' 'Q3FLUTTERSCOPE7X';
const String fakePrivateKey = '-----BEGIN ' 'PRIVATE KEY-----\n'
    'MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAflutterscopefixture\n'
    '-----END ' 'PRIVATE KEY-----';

// RC4 is broken. Constructed by app code, not only by the pointycastle registry.
String weakCipher(String secret) {
  final key = Uint8List.fromList(utf8.encode('0123456789abcdef'));
  final input = Uint8List.fromList(utf8.encode(secret));
  final rc4 = RC4Engine()..init(true, KeyParameter(key));
  final out = Uint8List(input.length);
  rc4.processBytes(input, 0, input.length, out, 0);
  final digest = MD5Digest().process(input);
  return base64.encode(out) + base64.encode(digest);
}

// A JavaScript channel exposes a Dart callback to every script in the page.
wv.WebViewController bridgedWebView() {
  return wv.WebViewController()
    ..setJavaScriptMode(wv.JavaScriptMode.unrestricted)
    ..addJavaScriptChannel('Native', onMessageReceived: (wv.JavaScriptMessage m) {});
}

Future<String> run() async {
  final client = HttpClient();
  final request = await client.getUrl(Uri.parse(backendUrl));
  final response = await request.close();
  final proc = await Process.run('sh', <String>['-c', 'id']);
  final webview = bridgedWebView();
  return '${response.statusCode} ${weakCipher('$fakeAwsKeyId$fakePrivateKey')} '
      '${proc.exitCode} ${webview.hashCode}';
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
