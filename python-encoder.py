
"""
Python-Encoder
-------------
AES-256-GCM text encryption and decryption.

Functions:
    encode(text, key) -> str
    decode(encoded_text, key) -> str

Requirements:
    pip install cryptography
"""

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# Configuration
VERSION = "NE1"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1

AAD = b"python-encoder-v1"


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit encryption key from the supplied password."""

    if not isinstance(password, str) or not password:
        raise ValueError("A valid key is required.")

    kdf = Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )

    return kdf.derive(password.encode("utf-8"))


def encode(text: str, key: str) -> str:
    """
    Encrypt text using AES-256-GCM.

    Args:
        text: Original text.
        key: User-provided password/key.

    Returns:
        A versioned Base64URL encrypted string.
    """

    if not isinstance(text, str):
        raise TypeError("Text must be a string.")

    if not isinstance(key, str) or not key:
        raise ValueError("A valid key is required.")

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    encryption_key = _derive_key(key, salt)

    aes = AESGCM(encryption_key)

    ciphertext = aes.encrypt(
        nonce,
        text.encode("utf-8"),
        AAD,
    )

    payload = salt + nonce + ciphertext

    encoded = base64.urlsafe_b64encode(
        payload
    ).decode("ascii").rstrip("=")

    return f"{VERSION}.{encoded}"


def decode(encoded_text: str, key: str) -> str:
    """
    Decrypt text previously encrypted with encode().

    Args:
        encoded_text: Encrypted output.
        key: Original encryption key.

    Returns:
        Original plaintext.
    """

    if not isinstance(encoded_text, str):
        raise TypeError("Encoded text must be a string.")

    if not isinstance(key, str) or not key:
        raise ValueError("A valid key is required.")

    try:
        version, encoded_payload = encoded_text.split(".", 1)

        if version != VERSION:
            raise ValueError("Unsupported encoder version.")

        padding = "=" * (-len(encoded_payload) % 4)

        payload = base64.urlsafe_b64decode(
            encoded_payload + padding
        )

        minimum_size = SALT_SIZE + NONCE_SIZE + 16

        if len(payload) < minimum_size:
            raise ValueError("Invalid encrypted message.")

        salt = payload[:SALT_SIZE]

        nonce = payload[
            SALT_SIZE:SALT_SIZE + NONCE_SIZE
        ]

        ciphertext = payload[
            SALT_SIZE + NONCE_SIZE:
        ]

        encryption_key = _derive_key(key, salt)

        aes = AESGCM(encryption_key)

        plaintext = aes.decrypt(
            nonce,
            ciphertext,
            AAD,
        )

        return plaintext.decode("utf-8")

    except InvalidTag:
        raise ValueError(
            "Decryption failed: incorrect key or modified message."
        ) from None

    except (ValueError, TypeError):
        raise

    except Exception:
        raise ValueError(
            "Unable to decode the encrypted message."
        ) from None


if __name__ == "__main__":

    print("PYTHON ENCODER")
    print("----------------------")

    original_text = input("Enter text: ")
    secret_key = input("Enter encryption key: ")

    encrypted = encode(original_text, secret_key)

    print("\nENCRYPTED OUTPUT:")
    print(encrypted)

    print("\nDECRYPTION TEST:")

    decrypted = decode(encrypted, secret_key)

    print(decrypted)

    if decrypted == original_text:
        print("\nSUCCESS: Encryption and decryption verified.")
