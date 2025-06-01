from dataclasses import dataclass
from typing import List


@dataclass
class IPFSImage:
    ipfs_hash: str
    signature: str
    uploaded_by: str
    timestamp: str
    description: str

    def to_dict(self) -> dict:
        return {
            "IPFSHash": self.ipfs_hash,
            "Signature": self.signature,
            "UploadedBy": self.uploaded_by,
            "TimeStamp": self.timestamp,
            "Description": self.description,
        }


@dataclass
class PhotoVote:
    vote_id: str
    photo_ipfs_hashes: List[str]
    vote_count: int
    valid_votes: int
    invalid_votes: int
    status: str
    voters: List[str]
    
    @staticmethod
    def from_dict(data: dict) -> "PhotoVote":
        return PhotoVote(
            vote_id=data["voteId"],
            photo_ipfs_hashes=data["photoIPFSHashes"],
            vote_count=data["voteCount"],
            valid_votes=data["validVotes"],
            invalid_votes=data["invalidVotes"],
            status=data["status"],
            voters=data["voters"],
        )
