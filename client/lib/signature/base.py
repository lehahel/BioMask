from abc import ABC, abstractmethod
from typing import Union
from pathlib import Path


class BaseDataSigner(ABC):
    @abstractmethod
    def sign_image(self, ipfs_hash: str, uploaded_by: str, timestamp: str) -> str:
        pass

    @abstractmethod
    def sign_string(self, string: str) -> str:
        pass


class FakeDataSigner(BaseDataSigner):
    def sign_image(self, ipfs_hash: str, uploaded_by: str, timestamp: str) -> str:
        return "fake_hash"
    
    def sign_string(self, string: str) -> str:
        return "fake_hash"
