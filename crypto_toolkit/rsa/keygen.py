"""RSA Key Generation, Encryption, and Decryption from Pure Primitives."""

from dataclasses import dataclass
import math
from crypto_toolkit.utils.math_utils import egcd, modinv
from crypto_toolkit.rsa.primitives import generate_prime, modular_pow


@dataclass
class RSAPublicKey:
    e: int
    n: int

    @property
    def bit_length(self) -> int:
        return self.n.bit_length()


@dataclass
class RSAPrivateKey:
    d: int
    n: int
    p: int
    q: int
    phi: int

    @property
    def public_key(self) -> RSAPublicKey:
        e = modinv(self.d, self.phi)
        return RSAPublicKey(e=e, n=self.n)


@dataclass
class RSAKeyPair:
    public: RSAPublicKey
    private: RSAPrivateKey


def rsa_keygen(bits: int = 1024, e: int = 65537) -> RSAKeyPair:
    """Generates an RSA keypair from scratch using pure mathematical primitives."""
    if bits < 16:
        raise ValueError("Key bit length must be at least 16")

    p_bits = bits // 2
    q_bits = bits - p_bits

    while True:
        p = generate_prime(p_bits)
        q = generate_prime(q_bits)
        if p == q:
            continue
        
        phi = (p - 1) * (q - 1)
        g, _, _ = egcd(e, phi)
        if g == 1:
            n = p * q
            d = modinv(e, phi)
            pub = RSAPublicKey(e=e, n=n)
            priv = RSAPrivateKey(d=d, n=n, p=p, q=q, phi=phi)
            return RSAKeyPair(public=pub, private=priv)


def rsa_encrypt(message: int, pub_key: RSAPublicKey) -> int:
    """Encrypts an integer message: c = (m^e) % n."""
    if message < 0 or message >= pub_key.n:
        raise ValueError("Message representative out of range [0, n - 1]")
    return modular_pow(message, pub_key.e, pub_key.n)


def rsa_decrypt(ciphertext: int, priv_key: RSAPrivateKey) -> int:
    """Decrypts ciphertext using private key: m = (c^d) % n."""
    if ciphertext < 0 or ciphertext >= priv_key.n:
        raise ValueError("Ciphertext representative out of range [0, n - 1]")
    return modular_pow(ciphertext, priv_key.d, priv_key.n)


def bytes_to_int(data: bytes) -> int:
    """Converts bytes to a big-endian integer."""
    return int.from_bytes(data, byteorder='big')


def int_to_bytes(n: int, length: int = None) -> bytes:
    """Converts a big-endian integer to bytes."""
    if length is None:
        length = (n.bit_length() + 7) // 8 or 1
    return n.to_bytes(length, byteorder='big')
