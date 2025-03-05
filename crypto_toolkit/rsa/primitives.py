"""RSA Primitives: Miller-Rabin primality testing, modular exponentiation, and prime generation."""

import os
import random
from typing import Tuple
from crypto_toolkit.utils.math_utils import egcd, modinv


def modular_pow(base: int, exp: int, mod: int) -> int:
    """Square-and-multiply modular exponentiation algorithm.
    
    Computes (base^exp) % mod in O(log exp) multiplications.
    """
    if mod == 1:
        return 0
    res = 1
    cur = base % mod
    e = exp
    while e > 0:
        if e & 1:
            res = (res * cur) % mod
        cur = (cur * cur) % mod
        e >>= 1
    return res


def miller_rabin(n: int, k_witnesses: int = 25) -> bool:
    """Miller-Rabin probabilistic primality test with tunable witness count.
    
    Error probability for composite n is at most 4^(-k_witnesses).
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False

    # Write n - 1 as 2^s * d with d odd
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # Deterministic small bases for fast rejection
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for a in small_primes:
        if n == a:
            return True
        if n % a == 0:
            return False

    # Random witness trials
    rng = random.SystemRandom()
    for _ in range(k_witnesses):
        a = rng.randrange(2, n - 1)
        x = modular_pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                composite = False
                break
        if composite:
            return False

    return True


def generate_prime(bits: int, k_witnesses: int = 25) -> int:
    """Generates a random prime of the specified bit-length using cryptographic randomness."""
    if bits < 2:
        raise ValueError("Bit length must be at least 2")
    rng = random.SystemRandom()

    while True:
        # Generate odd candidate with highest bit set
        candidate = rng.getrandbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if miller_rabin(candidate, k_witnesses=k_witnesses):
            return candidate


def generate_safe_prime(bits: int, k_witnesses: int = 25) -> Tuple[int, int]:
    """Generates a safe prime p = 2*q + 1 where both p and q are prime.
    
    Returns (safe_prime_p, sophie_germain_prime_q).
    """
    if bits < 4:
        raise ValueError("Bit length must be at least 4")
    rng = random.SystemRandom()

    while True:
        q = rng.getrandbits(bits - 1)
        q |= (1 << (bits - 2)) | 1
        if miller_rabin(q, k_witnesses=k_witnesses):
            p = 2 * q + 1
            if p.bit_length() == bits and miller_rabin(p, k_witnesses=k_witnesses):
                return p, q
