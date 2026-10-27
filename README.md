# GPG Key Manager

A privacy-focused OpenPGP / GPG toolkit for Android. Generate, manage, import, export and use PGP keys to encrypt, decrypt and sign text — all locally on your device.

## Features

- **Key generation** — Create Ed25519 (sign) + X25519 (encrypt) key pairs, or classic RSA keys (2048 / 3072 / 4096-bit), protected by a passphrase.
- **Key management** — View, delete, import and export public and private keys. Keys can be imported from a file (armored or binary) or pasted as armored text.
- **Open key files** — `.asc`, `.pgp` and `.gpg` files appear in Android's "Open with" list. Key files go to the import confirmation; encrypted or signed messages open in Decrypt.
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
| My Keys | List, search, import (from a file or pasted), export and delete keys |
| Key Details | Fingerprint, key ID, type, creation date and armored export |
| Generate Key | Create a new Ed25519 or RSA key pair |
| Encrypt | Encrypt a message with a public key |
| Decrypt | Decrypt a message with a private key |
| Sign | Sign text with a private key |
| Verify | Verify a signed message with a public key |

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
- Messages are encrypted with AES-256 and an integrity-protection (MDC) packet. Decryption
  **verifies** that packet and refuses to return plaintext when the check fails, or when a
  message carries no integrity protection at all.
- `FLAG_SECURE` is set on the main window, so key material, passphrases and decrypted text are
  excluded from screenshots, screen recordings and the recent-apps thumbnail.
- Files opened from other apps are classified by parsing them, never by their extension, and
  are capped at 4 MiB before they are read. A key is imported only after the user confirms;
  when it is a private key, an existing private key with the same key ID is replaced and the
  user is told so.

## Testing

The OpenPGP layer is covered by host-side tests that exercise the same `PGPManager` the app
ships. They include an interoperability check against the system `gpg` binary: GnuPG must be
able to decrypt what the app produces, and the app must decrypt what GnuPG produces, in both
cases addressing the encryption subkey.

```bash
./gradlew :app:testDebugUnitTest
```

The GnuPG interoperability test skips itself automatically when `gpg` is not installed.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
