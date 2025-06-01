from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import json
import base64

def encrypt_helper_data(passphrase: str, helper_data: bytes) -> dict:
    salt = os.urandom(16)

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    key = kdf.derive(passphrase.encode())

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, helper_data, None)

    return {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def decrypt_helper_data(passphrase: str, encrypted: dict) -> bytes:
    salt = base64.b64decode(encrypted["salt"])
    nonce = base64.b64decode(encrypted["nonce"])
    ciphertext = base64.b64decode(encrypted["ciphertext"])

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    key = kdf.derive(passphrase.encode())

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


if __name__ == "__main__":
    helper_data = b"some raw helper data, e.g., for fuzzy extractor"
    passphrase = "MySecretPassphrase!"

    encrypted = encrypt_helper_data(passphrase, helper_data)

    encrypted_json = json.dumps(encrypted)

    print(encrypted_json)

    original_data = decrypt_helper_data(passphrase, encrypted)
    print(original_data)
