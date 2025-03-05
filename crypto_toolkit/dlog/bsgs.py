"""Baby-Step Giant-Step (BSGS) Discrete Logarithm Algorithm."""

import math
from typing import Optional
from crypto_toolkit.utils.math_utils import modinv
from crypto_toolkit.rsa.primitives import modular_pow


def baby_step_giant_step(g: int, h: int, p: int, order: Optional[int] = None) -> Optional[int]:
    """Solves the Discrete Logarithm Problem: g^x = h (mod p).
    
    Time Complexity: O(sqrt(order))
    Space Complexity: O(sqrt(order))
    
    Algorithm:
      Let m = ceil(sqrt(order)).
      Write x = i * m + j with 0 <= j < m and 0 <= i < m.
      Then g^(i*m + j) = h (mod p)
      <=> (g^(-m))^i * h = g^j (mod p).
      1. Precomputes baby steps: table[g^j mod p] = j for j in [0, m-1].
      2. Computes gamma = g^(-m) mod p.
      3. For giant steps i in [0, m-1]:
           cur = h * (gamma^i) mod p
           if cur in table -> return i * m + table[cur]
    """
    g = g % p
    h = h % p
    if h == 1:
        return 0
    if g == h:
        return 1

    n = order if order is not None else p - 1
    m = math.isqrt(n) + 1

    # Baby steps: compute g^j mod p for j in [0, m-1]
    table = {}
    cur = 1
    for j in range(m):
        if cur not in table:
            table[cur] = j
        cur = (cur * g) % p

    # Giant steps: gamma = g^(-m) mod p
    g_m = modular_pow(g, m, p)
    gamma = modinv(g_m, p)

    cur = h
    for i in range(m + 1):
        if cur in table:
            x = (i * m + table[cur]) % n
            if modular_pow(g, x, p) == h:
                return x
        cur = (cur * gamma) % p

    return None
