from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import json
import os

def decrypt_message(private_key_path, bundle_path):
    # Load private RSA key
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Load encrypted bundle
    with open(bundle_path, "r") as f:
        bundle = json.load(f)

    enc_aes_key = base64.b64decode(bundle["enc_aes_key"])
    iv = base64.b64decode(bundle["iv"])
    ciphertext = base64.b64decode(bundle["ciphertext"])

    # Decrypt AES key using private RSA key
    aes_key = private_key.decrypt(
        enc_aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt message using AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    pad_len = padded_plaintext[-1]
    plaintext = padded_plaintext[:-pad_len]

    print("\n✅ Decrypted message:\n")
    print(plaintext.decode())

if __name__ == "__main__":
    private_key_path = input("🔑 Enter the path to your private key (e.g., private.pem): ").strip()
    bundle_path = input("📦 Enter the path to the message bundle (e.g., message_bundle.enc): ").strip()
    decrypt_message(private_key_path, bundle_path)
