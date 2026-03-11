"""
veriwall.core.signer
Ed25519 key generation and signing utilities.
"""
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption,
)


def generate_keypair() -> tuple[str, str]:
    """Return (priv_b64, pub_b64) for a fresh Ed25519 key pair."""
    private_key = Ed25519PrivateKey.generate()
    priv_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_bytes  = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(priv_bytes).decode(), base64.b64encode(pub_bytes).decode()


def sign(priv_b64: str, message: bytes) -> str:
    """Sign *message* with the raw-encoded private key and return a base64 signature."""
    priv_bytes  = base64.b64decode(priv_b64)
    private_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    sig_bytes   = private_key.sign(message)
    return base64.b64encode(sig_bytes).decode()


def verify_signature(pub_b64: str, message: bytes, sig_b64: str) -> bool:
    """Return True if *sig_b64* is a valid Ed25519 signature of *message* by *pub_b64*."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    pub_bytes  = base64.b64decode(pub_b64)
    public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
    sig_bytes  = base64.b64decode(sig_b64)
    try:
        public_key.verify(sig_bytes, message)
        return True
    except InvalidSignature:
        return False
