# 🔐 Encrypted Offline Messenger (Hybrid Encryption - RSA + AES)

This project implements a secure offline messaging system using **hybrid encryption**, combining the speed of **AES (symmetric encryption)** with the security of **RSA (asymmetric encryption)**.

> 💡 Inspired by concepts from the book *Serious Cryptography*, this project demonstrates a practical application of secure end-to-end encryption using Python.

---

## 📦 Features

- AES-256 encryption for secure message confidentiality.
- RSA public/private key system for secure key exchange.
- Base64-encoded encrypted messages bundled in a single `.enc` file.
- No internet required — secure offline communication.
- Ideal for secure document transfer or private messaging.

---

## 🔧 How It Works

### Sender Side (encrypt_message.py)

1. Generates a **random AES key**.
2. Encrypts the message using **AES-CBC** mode.
3. Encrypts the AES key using the **receiver's RSA public key**.
4. Packages and saves the encrypted message, AES key, and IV into a file: `message_bundle.enc`.

### Receiver Side (decrypt_message.py)

1. Loads `message_bundle.enc`.
2. Decrypts the AES key using their **private key** (`private.pem`).
3. Decrypts the message using the recovered AES key and IV.
4. Displays the original plaintext message.

---

## 🛠 Requirements

- Python 3.8+
- `cryptography` library

Install it via:

```bash
pip install cryptography
python generate_keys.py
python encrypt_message.py
python decrypt_message.py

