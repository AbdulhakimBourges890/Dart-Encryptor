import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

final _aesGcm = AesGcm.with256bits();
final _pbkdf2 = Pbkdf2(
  macAlgorithm: Hmac.sha256(),
  iterations: 100000,
  bits: 256,
);

/// Generate secure random bytes
Uint8List randomBytes(int length) {
  final rng = Random.secure();
  final bytes = List<int>.generate(length, (_) => rng.nextInt(256));
  return Uint8List.fromList(bytes);
}

/// Encrypt file
Future<void> encryptFile({
  required String inputPath,
  required String outputPath,
  required SecretKey secretKey,
}) async {
  final inputFile = File(inputPath);
  final outputFile = File(outputPath);

  if (!await inputFile.exists()) throw Exception('Input file does not exist');

  final plain = await inputFile.readAsBytes();
  final nonce = _aesGcm.newNonce();

  final secretBox = await _aesGcm.encrypt(
    plain,
    secretKey: secretKey,
    nonce: nonce,
  );

  final outBytes = BytesBuilder()
    ..add(secretBox.nonce)
    ..add(secretBox.mac.bytes)
    ..add(secretBox.cipherText);

  await outputFile.writeAsBytes(outBytes.toBytes(), flush: true);
  print('Encrypted file written: $outputPath');
}

/// Decrypt file
Future<void> decryptFile({
  required String inputPath,
  required String outputPath,
  required SecretKey secretKey,
}) async {
  final inputFile = File(inputPath);
  final outputFile = File(outputPath);

  if (!await inputFile.exists()) throw Exception('Encrypted file does not exist');

  final all = await inputFile.readAsBytes();
  if (all.length < 28) throw Exception('Invalid encrypted file');

  final nonce = all.sublist(0, 12);
  final mac = all.sublist(12, 28);
  final ciphertext = all.sublist(28);

  final secretBox = SecretBox(ciphertext, nonce: nonce, mac: Mac(mac));
  final clear = await _aesGcm.decrypt(secretBox, secretKey: secretKey);

  await outputFile.writeAsBytes(clear, flush: true);
  print('Decrypted file written: $outputPath');
}

/// Generate a random 256-bit key
Future<void> generateRandomKey({int bytes = 32}) async {
  final keyBytes = randomBytes(bytes);
  print('Random key (base64): ${base64Encode(keyBytes)}');
  print('Random key (hex): ${_hex(keyBytes)}');
}

/// Derive key from password
Future<SecretKey> deriveKeyFromPassword(String password, {List<int>? salt}) async {
  final usedSalt = salt ?? randomBytes(16);
  final secretKey = await _pbkdf2.deriveKey(
    secretKey: SecretKey(utf8.encode(password)),
    nonce: usedSalt,
  );
  print('Salt (base64): ${base64Encode(usedSalt)}');
  return secretKey;
}

String _hex(List<int> bytes) => bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

SecretKey secretKeyFromBase64(String b64) {
  final bytes = base64Decode(b64);
  return SecretKey(bytes);
}

void printUsage() {
  print('''
Usage:
  dart run encryptor.dart genkey
  dart run encryptor.dart encrypt <infile> <outfile> <base64-key>
  dart run encryptor.dart decrypt <infile> <outfile> <base64-key>
  dart run encryptor.dart derive <password>
''');
}

Future<int> main(List<String> args) async {
  try {
    if (args.isEmpty) {
      printUsage();
      return 0;
    }

    final cmd = args[0].toLowerCase();
    switch (cmd) {
      case 'genkey':
        await generateRandomKey();
        break;

      case 'encrypt':
        if (args.length != 4) return 1;
        final key = secretKeyFromBase64(args[3]);
        await encryptFile(inputPath: args[1], outputPath: args[2], secretKey: key);
        break;

      case 'decrypt':
        if (args.length != 4) return 1;
        final key = secretKeyFromBase64(args[3]);
        await decryptFile(inputPath: args[1], outputPath: args[2], secretKey: key);
        break;

      case 'derive':
        if (args.length < 2) return 1;
        final sk = await deriveKeyFromPassword(args[1]);
        final exportedBytes = await sk.extractBytes();
        print('Derived key (base64): ${base64Encode(exportedBytes)}');
        break;

      default:
        printUsage();
        return 1;
    }

    return 0;
  } catch (e) {
    stderr.writeln('Error: $e');
    return 2;
  }
}

