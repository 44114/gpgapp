# GPG Key Manager

A privacy-focused OpenPGP / GPG toolkit for Android. Generate, manage, import, export and use PGP keys to encrypt, decrypt and sign text — all locally on your device.

## Features

- **Key generation** — Create Ed25519 (sign) + X25519 (encrypt) key pairs, or classic RSA keys (2048 / 3072 / 4096-bit), protected by a passphrase.
- **Key management** — View, delete, import and export ASCII-armored public and private keys.
- **Encrypt / Decrypt** — Encrypt text with a recipient's public key and decrypt with your private key.
- **Sign / Verify** — Sign text with your private key (Ed25519 and RSA supported).
- **Fully offline** — All operations run on-device; no network access, no servers, no tracking.
- **Modern UI** — Material 3 design with light/dark theme and Android 12+ Dynamic Color support.
- **Multi-language** — English, Simplified Chinese, Traditional Chinese and 16 other languages.
- **F-Droid friendly** — Reproducible builds with no dependency metadata in the APK signing block.

## Screens

| Screen | Description |
| --- | --- |
| Home | Overview of stored keys and quick actions |
| My Keys | List, search, import, export and delete keys |
| Key Details | Fingerprint, key ID, type, creation date and armored export |
| Generate Key | Create a new Ed25519 or RSA key pair |
| Encrypt | Encrypt a message with a public key |
| Decrypt | Decrypt a message with a private key |

## Requirements

- Android 8.0 (API 26) or higher
- minSdk 26 / targetSdk 34

## Building

```bash
./gradlew assembleDebug
```

The debug APK will be generated at `app/build/outputs/apk/debug/app-debug.apk`.

To build a release APK:

```bash
./gradlew assembleRelease
```

## Libraries

- [Bouncy Castle](https://www.bouncycastle.org/) — OpenPGP (bcpg) and cryptography provider (bcprov)
- Jetpack Compose — modern declarative UI toolkit
- AndroidX Navigation — in-app navigation
- Kotlin Coroutines — asynchronous operations

## Security notes

- Keys are stored in the app's private internal storage (`filesDir`) — other apps cannot access them.
- Private keys are encrypted at rest with AES-256 using your passphrase.
- Passphrases are never stored; they are required each time you use a private key.
- The app never requires internet access and makes no network calls.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
