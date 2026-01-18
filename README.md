# 🔐 Secure Audio Exchange System

A complete cryptographic system for secure audio file exchange, implementing:
- **Camellia-128** cipher (OFB mode) for symmetric encryption
- **ECDH** (Elliptic Curve Diffie-Hellman) for key exchange
- **Schnorr Signatures** for digital authentication

Built from scratch without relying on high-level cryptographic libraries.

---

## 🚀 Quick Start

```bash
python gui.py
```

This launches the graphical interface with Alice (sender) and Bob (receiver) panels.

---

## 📁 Project Structure

```
project/
├── gui.py                 # Main GUI application
├── secure_system.py       # Core encryption system
├── crypto/                # Cryptographic implementations
│   ├── __init__.py
│   ├── camellia.py        # Camellia-128 cipher
│   ├── ecc.py             # Elliptic curve operations
│   ├── schnorr.py         # Schnorr signatures
│   └── utils.py           # Helper functions
└── audio/                 # Audio file handling
    ├── __init__.py
    └── io_handler.py      # File I/O operations
```

---

## 📄 File Descriptions

### Main Files

| File | Description |
|------|-------------|
| `gui.py` | **Main entry point**. Tkinter-based GUI with split-panel design for Alice (encryption) and Bob (decryption). |
| `secure_system.py` | **Core system**. Integrates all cryptographic components and provides high-level API for encryption/decryption workflows. |

### crypto/ - Cryptographic Modules

| File | Description |
|------|-------------|
| `camellia.py` | **Camellia-128 Cipher** implementation. Provides symmetric encryption using OFB (Output Feedback) mode. Includes key scheduling, S-boxes, and block operations. |
| `ecc.py` | **Elliptic Curve Cryptography**. Implements secp256r1 curve, point operations, scalar multiplication, and ECDH key exchange. |
| `schnorr.py` | **Schnorr Digital Signatures**. Provides signing and verification for message authenticity. Uses the same ECC infrastructure. |
| `utils.py` | Helper functions for byte/integer conversions and other utilities. |
| `__init__.py` | Package initializer. Exports `Camellia`, `ECC`, `ECPoint`, `Schnorr`. |

### audio/ - Audio Handling

| File | Description |
|------|-------------|
| `io_handler.py` | **Audio File I/O**. Reads and writes binary audio files (MP3, WAV, FLAC, etc.). Includes format validation using magic bytes. |
| `__init__.py` | Package initializer. Exports `AudioHandler`. |

---

## 🔄 How It Works

### Encryption Flow (Alice → Bob)

```
1. Alice generates ECDH key pair + Schnorr signing key pair
2. Bob generates ECDH key pair
3. Alice and Bob exchange public keys
4. Alice:
   ├── Derives session key: ECDH(Alice_private, Bob_public)
   ├── Encrypts audio: Camellia-128-OFB(audio, session_key, IV)
   └── Signs ciphertext: Schnorr_Sign(hash(ciphertext), signing_key)
5. Alice sends: ciphertext + IV + signature + public keys
```

### Decryption Flow (Bob receives)

```
1. Bob receives the encrypted package
2. Bob:
   ├── Verifies signature: Schnorr_Verify(signature, Alice_signing_public)
   ├── Derives session key: ECDH(Bob_private, Alice_public)
   └── Decrypts: Camellia-128-OFB(ciphertext, session_key, IV)
3. Original audio file is recovered
```

---

## 🔐 Cryptographic Details

### Camellia-128 (OFB Mode)
- 128-bit block cipher designed by Mitsubishi and NTT
- OFB mode converts it to a stream cipher (no padding needed)
- Random 128-bit IV for each encryption

### ECDH Key Exchange
- Uses secp256r1 (P-256) curve
- 256-bit private keys, 512-bit public keys
- Shared secret derived via scalar multiplication

### Schnorr Signatures
- Based on discrete logarithm problem
- Produces (R, s) signature pairs
- Provides authentication and integrity

---

## 📦 Output Files

When encrypting a file like `song.mp3`, the system creates:

| File | Size | Contents |
|------|------|----------|
| `song_encrypted.bin` | Same as original | Encrypted ciphertext |
| `song_encrypted.bin.meta` | ~266 bytes | IV, public keys, signature, metadata |

---

## 🖥️ GUI Features

- **Split-panel design**: Alice (sender) on left, Bob (receiver) on right
- **Key generation**: Separate buttons for ECDH and Schnorr keys
- **File selection**: Choose any audio format (MP3, WAV, FLAC, etc.)
- **Status logs**: Real-time cryptographic operation logging
- **Auto-load**: Encrypted files automatically appear in Bob's panel
- **Demo mode**: One-click demonstration with sample files

---

## 📋 Requirements

- Python 3.8+
- tkinter (included with Python)
- No external cryptographic libraries required

---

## 👥 Authors

Developed as part of an Information Security course project.

---

## 📜 License

Educational use only.
