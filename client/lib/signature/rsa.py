import hashlib
from pathlib import Path
from typing import Union
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from .base import BaseDataSigner


class RSADataSigner(BaseDataSigner):
    """
    Подписывает строку (IPFSHash + UploadedBy + Timestamp) RSA-PSS подписью.
    """

    def __init__(self, private_key_path: Union[str, Path]):
        with open(private_key_path, "rb") as f:
            self.key = RSA.import_key(f.read())
        if not self.key.has_private():
            raise ValueError("Provided key is not a private RSA key")

    def sign_image(self, ipfs_hash: str, uploaded_by: str, timestamp: str) -> str:
        message = ipfs_hash + uploaded_by + timestamp
        return self.sign_string(message)
    
    def sign_string(self, string: str) -> str:
        digest = SHA256.new(string.encode("utf-8"))
        signer = pss.new(self.key)
        signature = signer.sign(digest)
        return signature.hex()
