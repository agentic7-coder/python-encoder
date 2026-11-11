
# python-encoder

A Python text encryption and decryption library
using AES-256-GCM.

## Features

- AES-256-GCM authenticated encryption
- Password-based key derivation using Scrypt
- Random salt and nonce for every encryption
- Base64URL output
- Unicode text support
- Detects incorrect keys and modified messages

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```python
from python_encoder import encode, decode

text = "Hello World"
key = "MySecretKey123"

encrypted = encode(text, key)

print("Encrypted:", encrypted)

decrypted = decode(encrypted, key)

print("Decrypted:", decrypted)
```

## Security

Keep your encryption key confidential.

Every encryption generates a new random salt
and nonce.

The same key is required for decryption.

Never share the key in the same channel as
the encrypted message when confidentiality matters.
