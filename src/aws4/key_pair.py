import random
import secrets
from dataclasses import dataclass


@dataclass
class KeyPair:
    """Representation of a key pair."""

    access_key_id: str
    secret_access_key: str


def generate_secret_access_key(length: int = 40) -> str:
    """Generate a secret string of given length."""
    return secrets.token_urlsafe(nbytes=length)[:length]


def generate_access_key_id(prefix: str = "AKIA") -> str:
    """Convert a random string to an access key id `AKIA....` format."""
    # Generate a 16 character key
    key = "".join([random.choice("ABCDEFGHIJKLMNOPQRSTUVWKYZ234567") for _ in range(16)])  # noqa: S311

    # Prepend prefix for a 20 character access_key_id to mimic AWS
    return f"{prefix}{key}".upper()


def generate_key_pair(prefix: str = "AKIA") -> KeyPair:
    """Generate an access_key_id and a secret_access_key."""
    return KeyPair(
        access_key_id=generate_access_key_id(prefix=prefix),
        secret_access_key=generate_secret_access_key(),
    )
