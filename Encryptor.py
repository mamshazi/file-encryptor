"""
File Encryption Tool
---------------------
Encrypts and decrypts files using a password, via symmetric encryption
(Fernet, from the `cryptography` library) with a PBKDF2-derived key.

Usage:
    python encryptor.py encrypt <file> <password>
    python encryptor.py decrypt <file> <password>
"""

import argparse
import base64
import os
import sys

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
ITERATIONS = 480_000  # OWASP-recommended minimum for PBKDF2-HMAC-SHA256 (2023)


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a URL-safe base64 Fernet key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key)


def encrypt_file(filepath: str, password: str):
    if not os.path.isfile(filepath):
        print(f"[!] File not found: {filepath}")
        return

    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    with open(filepath, "rb") as f:
        data = f.read()

    encrypted = fernet.encrypt(data)
    out_path = filepath + ".enc"

    # Store the salt alongside the encrypted data so it can be
    # retrieved again at decryption time.
    with open(out_path, "wb") as f:
        f.write(salt + encrypted)

    print(f"[+] Encrypted file written to: {out_path}")


def decrypt_file(filepath: str, password: str):
    if not os.path.isfile(filepath):
        print(f"[!] File not found: {filepath}")
        return

    with open(filepath, "rb") as f:
        raw = f.read()

    salt, encrypted = raw[:SALT_SIZE], raw[SALT_SIZE:]
    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        decrypted = fernet.decrypt(encrypted)
    except InvalidToken:
        print("[!] Decryption failed. Wrong password or corrupted file.")
        sys.exit(1)

    if filepath.endswith(".enc"):
        out_path = filepath[:-4]
    else:
        out_path = filepath + ".dec"

    with open(out_path, "wb") as f:
        f.write(decrypted)

    print(f"[+] Decrypted file written to: {out_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt a file using a password."
    )
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Operation to perform")
    parser.add_argument("file", help="Path to the file to encrypt/decrypt")
    parser.add_argument("password", help="Password to use for encryption/decryption")

    args = parser.parse_args()

    if args.mode == "encrypt":
        encrypt_file(args.file, args.password)
    else:
        decrypt_file(args.file, args.password)


if __name__ == "__main__":
    main()