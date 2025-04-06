"""Common-modulus attack.

If the same message is encrypted under one modulus N with two coprime public
exponents e1 and e2, the plaintext falls out with no factoring at all:

    gcd(e1, e2) = 1  =>  exists s1, s2 with e1*s1 + e2*s2 = 1
    c1^s1 * c2^s2 = m^(e1*s1) * m^(e2*s2) = m^1 = m  (mod N)

Negative Bezout coefficients are handled by inverting the corresponding
ciphertext first.

Ported from the E-cryptanalysis prototype, rewritten against
crypto_toolkit.utils.math_utils.
"""
from __future__ import annotations

from ..utils.math_utils import egcd, modinv


def common_modulus_attack(N: int, e1: int, e2: int, c1: int, c2: int) -> int:
    """Recover m from c1 = m^e1 mod N and c2 = m^e2 mod N.

    Raises ValueError if the exponents share a factor, in which case the attack
    does not apply.
    """
    g, s1, s2 = egcd(e1, e2)
    if g != 1:
        raise ValueError(f"exponents are not coprime: gcd(e1, e2) = {g}")

    a, b = c1, c2
    if s1 < 0:
        a = modinv(c1, N)
        s1 = -s1
    if s2 < 0:
        b = modinv(c2, N)
        s2 = -s2

    return (pow(a, s1, N) * pow(b, s2, N)) % N
