from biomask.client import BiomaskClient
import asyncio
from pprint import pprint


async def good() -> None:
    async with BiomaskClient(
        network_config_path="network-config.json",
        org_name="org1.example.com",
        name="Admin",
        channel="mychannel",
        peers=["peer0.org1.example.com"],
        private_key_path="keys/private_key.pem",
        public_key_path="keys/public_key.pem",
    ) as client:
        client.client.new_channel("mychannel")
        vote = await client.create_vote(images=["test_images/image.png"])
        
        vote_info = await client.get_vote_status(vote.vote_id)
        print(vote_info, end="\n\n")
        
        await client.cast_vote(vote.vote_id, is_valid=True)
        
        vote_info = await client.get_vote_status(vote.vote_id)
        print(vote_info, end="\n\n")

        generated_key = await client.generate_key(
            image_path="test_images/face1.jpg",
            public_key_path="keys/public_key.pem",
            user_nickname="test_user",
        )
        print(generated_key)

        restored_key = await client.restore_key(
            image_path="test_images/face2.jpg",
            user_nickname="test_user",
        )
        print(restored_key)

        assert generated_key == restored_key


async def bad() -> None:
    with open("fake_keys/public_key.pem", "r") as f:
        start_public_key = f.read()

    async with BiomaskClient(
        network_config_path="network-config.json",
        org_name="org1.example.com",
        name="Admin",
        channel="mychannel",
        peers=["peer0.org1.example.com"],
        private_key_path="keys/private_key.pem",
        public_key_path="keys/public_key.pem",
    ) as client:
        client.client.new_channel("mychannel")
        vote = await client._create_vote_impl(images=["test_images/image.png"], start_public_key=start_public_key)
        
        vote_info = await client.get_vote_status(vote.vote_id)
        print(vote_info, end="\n\n")
        
        await client.cast_vote(vote.vote_id, is_valid=True)
        
        vote_info = await client.get_vote_status(vote.vote_id)
        print(vote_info, end="\n\n")


if __name__ == "__main__":
    asyncio.run(good())
