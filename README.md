# Secure Run (sr)

**Version:** 0.1.0
**Author:** Viren  
**License:** Proprietary © 2025  

Secure Run (`sr`) is a Python utility designed to securely encrypt, manage, and execute Python scripts. It uses strong encryption (ChaCha20-Poly1305) combined with PBKDF2 key derivation to protect your code, while allowing scripts to be run directly from memory without exposing the plaintext on disk.

---

## Features

- **Secure Encryption:** Protect Python scripts with password-based encryption.
- **Memory-Only Execution:** Run scripts securely without writing decrypted files to disk.
- **Password Management:** Change the password of locked scripts safely.
- **Bundles:** Group multiple scripts together and execute them as a set.
- **Plugins:** Extend functionality using custom plugins. PLUGIN RUNS WITH NO SANDBOX, BE CAREFUL!
- **Backup & Restore:** Create backups of all your data and restore them when needed.
- **Cloning & Renaming:** Duplicate or rename locked scripts easily.
- **Memory Safety:** Runtime cache zeroes decrypted data to reduce exposure in memory.
- **Cross-Platform:** Works on Windows, Linux, and macOS.

---

## Overview

Secure Run allows Python developers to encrypt their scripts so that they can be stored and shared safely. Scripts can be executed without ever exposing the source code to disk, minimizing the risk of accidental leaks or tampering. It also includes features like bundling multiple scripts, plugin support, and tools for backup, restore, renaming, and cloning.

The system ensures integrity of the scripts by using SHA256 hashes, so any tampering with the encrypted files is detected. Decrypted scripts are only held in memory and cleared automatically when no longer needed.

---

## Security Notes

- **Encryption Method:** ChaCha20-Poly1305 with PBKDF2 key derivation for secure password-based encryption.
- **Integrity Checks:** SHA256 hash verification ensures scripts have not been altered.
- **Memory Safety:** Decrypted scripts are stored in a runtime cache and are zeroed after use to reduce memory exposure.
- **Disclaimer:** This software should only be used for legitimate purposes. The author is not responsible for misuse, damage, or loss of data.

---

## Extending Secure Run

Plugins allow you to add custom commands or features. Secure Run automatically loads plugins stored in the designated plugin directory and registers any commands they provide. Bundles allow combining multiple scripts into a single executable workflow.

---

## Getting Started

1. Install the package via Python's package manager.
2. Use the library functions to lock, run, or manage Python scripts securely.
3. Optionally, use plugins and bundles to extend and organize your workflow.
