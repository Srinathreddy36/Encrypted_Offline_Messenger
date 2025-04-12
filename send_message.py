from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import json
import base64

# 🔐 AES encryption function
def encrypt_message_aes(message, aes_key):
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
    return iv, encrypted_message

# 🔐 Encrypt AES key with receiver's public key
def encrypt_aes_key_rsa(aes_key, public_key_path):
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return encrypted_key

# 💾 Save encrypted components to file
def save_encrypted_bundle(iv, encrypted_message, encrypted_key):
    bundle = {
        "enc_aes_key": base64.b64encode(encrypted_key).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(encrypted_message).decode()
    }

    with open("message_bundle.enc", "w") as f:
        json.dump(bundle, f)
    print("✅ Message encrypted and saved to 'message_bundle.enc'")


    with open("message_bundle.enc", "w") as f:
        json.dump(bundle, f)
    print("✅ Message encrypted and saved to 'message_bundle.enc'")

def main():
    message = input("✉️  Enter the message you want to send securely: ")
    receiver_key_path = input("📁 Enter the path to the receiver's public key (e.g., public.pem): ")

    aes_key = os.urandom(32)  # AES-256
    iv, encrypted_message = encrypt_message_aes(message, aes_key)
    encrypted_key = encrypt_aes_key_rsa(aes_key, receiver_key_path)
    save_encrypted_bundle(iv, encrypted_message, encrypted_key)

if __name__ == "__main__":
    main()
