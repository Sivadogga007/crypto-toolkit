"""Diffie-Hellman Key Exchange over Finite Prime Fields."""

import random
from dataclasses import dataclass
from crypto_toolkit.rsa.primitives import modular_pow, generate_safe_prime


@dataclass
class DHParameters:
    p: int  # Prime modulus
    g: int  # Generator

    @property
    def bit_length(self) -> int:
        return self.p.bit_length()


@dataclass
class DHPrivateKey:
    params: DHParameters
    x: int  # Secret exponent in [2, p - 2]

    @property
    def public_key(self) -> int:
        return modular_pow(self.params.g, self.x, self.params.p)


class DiffieHellmanParty:
    """Simulated party in Diffie-Hellman Key Exchange."""

    def __init__(self, params: DHParameters, private_key: int = None):
        self.params = params
        rng = random.SystemRandom()
        self.x = private_key if private_key is not None else rng.randrange(2, params.p - 1)
        self.y = modular_pow(params.g, self.x, params.p)

    @property
    def public_key(self) -> int:
        return self.y

    def compute_shared_secret(self, peer_public_key: int) -> int:
        """Derives shared secret S = (peer_Y ^ x) % p."""
        if peer_public_key <= 1 or peer_public_key >= self.params.p - 1:
            raise ValueError("Invalid peer public key (small subgroup attack check)")
        return modular_pow(peer_public_key, self.x, self.params.p)
