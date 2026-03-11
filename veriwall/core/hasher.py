"""
veriwall.core.hasher
Deterministic hashing utilities.
"""
import hashlib
import json


def canonical_json(obj: dict) -> bytes:
    """Serialise *obj* to canonical (sorted-keys, no-space) UTF-8 JSON bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha256_hex(data: bytes) -> str:
    """Return the hex-encoded SHA-256 digest of *data*."""
    return hashlib.sha256(data).hexdigest()


def hash_content(content: dict) -> str:
    """Return the SHA-256 hex digest of a policy content dict."""
    return sha256_hex(canonical_json(content))
