import asyncio
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Type
from hfc.fabric import Client
import aioipfs
from .datacls import IPFSImage, PhotoVote
from .crypto import extract_uploader_id
import json
from hfc.fabric.user import User
from lib.signature.rsa import RSADataSigner
from PIL import Image
import io
import random
from lib.fuzzy_extractor.extractor import fuzzy_gen, fuzzy_recover


CHAINCODE_NAME = "photovote"


class BiomaskClient:
    def __init__(
        self, 
        network_config_path: Union[str, Path], 
        org_name: str,
        name: str,
        channel: str,
        peers: List[str],
        private_key_path: Union[str, Path],
        public_key_path: Union[str, Path],
    ) -> None:
        self.client = Client(net_profile=network_config_path)
        self.ipfs = aioipfs.AsyncIPFS()
        self.user: Optional[User] = self.client.get_user(org_name, name)
        self.channel = channel 
        self.peers = peers
        self.signer = RSADataSigner(private_key_path)
        with open(public_key_path, "r") as f:
            self.public_key = f.read()

    async def close(self) -> None:
        # await self.client.close_grpc_channels()
        await self.ipfs.close()

    async def __aenter__(self) -> "BiomaskClient":
        return self

    async def __aexit__(self, exc_type, exc_value, traceback) -> None:
        await self.close()

    def set_user(self, org_name: str, name: str) -> None:
        self.user = self.client.get_user(org_name, name)
    
    async def __upload_image(self, image: Union[str, Path]) -> str:
        # Открываем изображение
        img = Image.open(image).convert("RGB")

        # Выбираем случайный пиксель
        width, height = img.size
        x = random.randint(0, width - 1)
        y = random.randint(0, height - 1)

        # Получаем текущий цвет и вносим незначительное изменение
        r, g, b = img.getpixel((x, y))
        channel = random.choice(["r", "g", "b"])
        delta = random.choice([-1, 1])

        if channel == "r":
            r = (r + delta) % 256
        elif channel == "g":
            g = (g + delta) % 256
        else:
            b = (b + delta) % 256

        img.putpixel((x, y), (r, g, b))

        # Сохраняем изменённое изображение в память
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        modified_bytes = buf.read()

        # Загружаем в IPFS
        result = await self.ipfs.add_bytes(modified_bytes)
        return result["Hash"]

    async def __prepare_image(
        self, 
        image: Union[str, Path], 
        description: str = "",
    ) -> IPFSImage:
        hash = await self.__upload_image(image)
        uploaded_by = self.__get_uploader_id()
        timestamp = str(int(asyncio.get_event_loop().time()))
        signature = self.signer.sign_image(hash, uploaded_by, timestamp)
        return IPFSImage(
            ipfs_hash=hash,
            signature=signature,
            uploaded_by=uploaded_by,
            timestamp=timestamp,
            description=description,
        )
    
    def __get_uploader_id(self) -> str:
        assert self.user is not None
        cert_pem = self.user.enrollment._cert
        return extract_uploader_id(cert_pem)
    
    @property
    def default_args(self) -> Dict[str, str]:
        return {
            "requestor": self.user,
            "channel_name": self.channel,
            "peers": self.peers,
            "cc_name": CHAINCODE_NAME,
        }
    
    async def __chaincode_query(self, fcn: str, *args) -> Any:
        return await self.client.chaincode_query(
            **self.default_args,
            fcn=fcn,
            args=args,
        )
    
    async def __chaincode_invoke(self, fcn: str, *args) -> Any:
        return await self.client.chaincode_invoke(
            **self.default_args,
            fcn=fcn,
            args=args,
            wait_for_event=True,
        )
    
    # Do not use, just for testing purposes
    async def _create_vote_impl(self, images: List[Union[str, Path]], start_public_key: str) -> PhotoVote:
        ipfs_photos = await asyncio.gather(
            *[
                # images are signed with self.public_key, not with start_public_key
                self.__prepare_image(image)
                for image in images
            ]
        )
        json_photos = json.dumps([i.to_dict() for i in ipfs_photos])
        response_str = await self.__chaincode_invoke("StartPhotoVote", json_photos, start_public_key)
        try:
            response = json.loads(response_str)
        except json.JSONDecodeError:
            raise ValueError(f"Response kinda bad: {response_str}")
        return PhotoVote.from_dict(response)

    async def create_vote(self, images: List[Union[str, Path]]) -> PhotoVote:
        return await self._create_vote_impl(images, self.public_key)

    async def get_vote_status(self, vote_id: str) -> PhotoVote:
        response = await self.__chaincode_query("GetVoteStatus", vote_id)
        response_json = json.loads(response)
        return PhotoVote.from_dict(response_json)
    
    async def cast_vote(self, vote_id: str, is_valid: bool) -> None:
        await self.__chaincode_invoke("CastVote", vote_id, str(is_valid).lower())

    async def generate_key(
        self, 
        image_path: str, 
        public_key_path: str,
        user_nickname: str,
    ) -> str:
        r, p = fuzzy_gen(image_path)
        with open(public_key_path, "r") as f:
            device_public_key = f.read()
        pub_key_hash = hashlib.sha256(device_public_key.encode()).hexdigest()
        signature = self.signer.sign_string(p)
        await self.__chaincode_invoke("StoreHelperData", p, pub_key_hash, signature, user_nickname)
        return r
    
    async def restore_key(
        self,
        image_path: str,
        user_nickname: str,
    ) -> str:
        p = await self.__chaincode_query("GetHelperData", user_nickname)
        r = fuzzy_recover(image_path, p)
        return r
