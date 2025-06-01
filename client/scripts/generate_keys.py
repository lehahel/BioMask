from Crypto.PublicKey import RSA
from pathlib import Path

def generate_rsa_keys(key_size: int = 2048, private_key_path: str = "private_key.pem", public_key_path: str = "public_key.pem"):
    """
    Generate RSA key pair and save them to files.
    
    Args:
        key_size: Size of the RSA key in bits (default: 2048)
        private_key_path: Path to save the private key
        public_key_path: Path to save the public key
    """
    # Generate new RSA key pair
    key = RSA.generate(key_size)
    
    # Get private key in PEM format
    private_key = key.export_key()
    
    # Get public key in PEM format
    public_key = key.publickey().export_key()
    
    # Save private key
    with open(private_key_path, "wb") as f:
        f.write(private_key)
    
    # Save public key
    with open(public_key_path, "wb") as f:
        f.write(public_key)
    
    print(f"Private key saved to: {private_key_path}")
    print(f"Public key saved to: {public_key_path}")

if __name__ == "__main__":
    # Create keys directory if it doesn't exist
    keys_dir = Path("fake_keys")
    keys_dir.mkdir(exist_ok=True)
    
    # Generate keys in the keys directory
    generate_rsa_keys(
        private_key_path=str(keys_dir / "private_key.pem"),
        public_key_path=str(keys_dir / "public_key.pem")
    ) 