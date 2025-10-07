# Dart-Encryptor

[![Dart](https://img.shields.io/badge/Dart-2.20-blue?logo=dart&logoColor=white)](https://dart.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A secure Dart script to **encrypt and decrypt any file** using **AES-GCM (256-bit)**.  
Supports **random key generation**, **password-based key derivation (PBKDF2)**, and **authenticated encryption**.

---

## Features

- **Random Key Generation:** Create cryptographically secure 256-bit keys (Base64 & Hex output).  
- **Password-Based Encryption:** Derive keys from passwords using PBKDF2 with salt.  
- **AES-GCM Encryption:** Secure encryption with 16-byte authentication tag.  
- **Salt Management:** Store salt with encrypted file for deterministic key derivation.  
- **Cross-Platform:** Works on any platform supported by Dart.

---

## Installation

Clone the repository and get dependencies:

```bash
git clone https://github.com/AbdulhakimBourges890/Dart-Encryptor
cd Dart-Encryptor
dart pub get
```

## Usage

### 1. Generate a random key

```bash
dart run main.dart genkey
```

* Generates a secure 256-bit random key.
* Displays the key in Base64 and Hex formats.

### 2. Encrypt a file

```bash
dart run main.dart encrypt <input_file> <output_file> <base64_key>
```

* `<input_file>`: the file you want to encrypt.
* `<output_file>`: the resulting encrypted file.
* `<base64_key>`: the key generated earlier.

### 3. Decrypt a file

```bash
dart run main.dart decrypt <input_file> <output_file> <base64_key>
```

* `<input_file>`: the encrypted file.
* `<output_file>`: the decrypted output file.
* `<base64_key>`: the same key used for encryption.

### 4. Derive a key from a password

```bash
dart run main.dart derive "your-strong-password"
```

* Generates a key from a password using PBKDF2.
* Prints the salt (Base64) which must be saved to decrypt later.

### 5. Full example

```bash
dart run main.dart genkey
dart run main.dart encrypt example/test.txt test.enc BASE64_KEY
dart run main.dart decrypt test.enc test.txt BASE64_KEY
dart run main.dart derive "my-password"
```

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
