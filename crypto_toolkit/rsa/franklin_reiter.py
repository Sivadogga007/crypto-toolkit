"""Franklin-Reiter Related-Message Attack on RSA."""

from typing import Tuple, Optional
from crypto_toolkit.utils.math_utils import poly_gcd, poly_sub, modinv


def expand_linear_binomial_power(a: int, b: int, e: int, mod: int) -> list:
    """Expands (a*x + b)^e modulo N as a polynomial [c0, c1, ..., ce]."""
    import math
    coeffs = [0] * (e + 1)
    for k in range(e + 1):
        # Binomial coeff C(e, k) * a^k * b^(e - k)
        comb = math.comb(e, k)
        ak = pow(a, k, mod)
        b_ek = pow(b, e - k, mod)
        coeffs[k] = (comb * ak * b_ek) % mod
    return coeffs


def franklin_reiter_attack(c1: int, c2: int, n: int, e: int, a: int, b: int) -> Tuple[Optional[int], bool]:
    """Executes the Franklin-Reiter related-message attack on RSA.
    
    Precondition:
      - Two plaintexts have a known linear relation: M2 = a * M1 + b (mod N).
      - Both messages encrypted under same RSA key (e, N):
          c1 = M1^e (mod N)
          c2 = M2^e = (a * M1 + b)^e (mod N)
      - Small public exponent e (e.g., e=3).
    
    Algorithm:
      1. Defines f1(x) = x^e - c1 (mod N).
      2. Defines f2(x) = (a * x + b)^e - c2 (mod N).
      3. Computes g(x) = gcd(f1, f2) mod N.
      4. If g(x) is linear (x - M1), extracts M1 = -g[0] * g[1]^(-1) mod N.
    
    Returns (recovered_m1, success_boolean).
    """
    # Construct f1(x) = x^e - c1
    f1 = [(-c1) % n] + [0] * (e - 1) + [1]

    # Construct f2(x) = (a*x + b)^e - c2
    f2 = expand_linear_binomial_power(a, b, e, n)
    f2[0] = (f2[0] - c2) % n

    # Compute polynomial gcd
    try:
        g = poly_gcd(f1, f2, n)
    except Exception:
        return None, False

    # Check if g is linear (degree 1): g(x) = x + c0 (monic)
    if len(g) == 2 and g[1] == 1:
        m1 = (-g[0]) % n
        return m1, True
    elif len(g) == 2 and g[1] != 0:
        inv = modinv(g[1], n)
        m1 = (-g[0] * inv) % n
        return m1, True

    return None, False
