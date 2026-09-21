# File Encryption Tool

A command-line tool for encrypting and decrypting files using a password. It uses symmetric encryption (Fernet, from Python's `cryptography` library) with a password-derived key via PBKDF2-HMAC-SHA256.

## How It Works

1. A random 16-byte **salt** is generated for each encryption.
2. The password and salt are run through **PBKDF2-HMAC-SHA256** (480,000 iterations, per current OWASP guidance) to derive a secure encryption key.
3. The file's contents are encrypted using **Fernet** (AES-128 in CBC mode with HMAC authentication).
4. The salt is stored alongside the encrypted data, so the same password can regenerate the correct key later for decryption.
5. If the wrong password is used, decryption fails safely rather than producing corrupted output — Fernet verifies data integrity before decrypting.

## Requirements

- Python 3.7+
- `cryptography` library

Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

**Encrypt a file:**
```bash
python encryptor.py encrypt myfile.txt mypassword123
```
This creates `myfile.txt.enc`.

**Decrypt a file:**
```bash
python encryptor.py decrypt myfile.txt.enc mypassword123
```
This restores the original file (removing the `.enc` extension).

## Security Notes

- Use a strong, unique password — the security of the encrypted file depends entirely on it.
- This tool is for learning and personal use. For production-grade encryption needs, use well-audited, established tools (e.g. VeraCrypt, GPG).
- The original unencrypted file is **not** deleted automatically after encryption — remove it yourself if needed.

## Future Improvements

- [ ] Add an option to securely delete the original file after encryption
- [ ] Support encrypting entire directories
- [ ] Add a `--output` flag to control output file name/location
- [ ] Hide password input from the terminal (using `getpass`)

## License

This project is for educational purposes.