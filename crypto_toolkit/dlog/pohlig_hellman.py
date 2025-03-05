"""Pohlig-Hellman Algorithm for Discrete Logarithms in Smooth Groups."""

import math
from typing import List, Tuple, Dict, Optional
from crypto_toolkit.utils.math_utils import crt, modinv
from crypto_toolkit.rsa.primitives import modular_pow
from crypto_toolkit.dlog.bsgs import baby_step_giant_step


def trial_factor(n: int, max_factor: int = 1000000) -> Dict[int, int]:
    """Factoring integer n via trial division up to max_factor.
    
    Returns dict mapping prime factor -> exponent.
    Raises ValueError if n cannot be completely factored within limit.
    """
    factors = {}
    d = 2
    temp = n
    while d * d <= temp and d <= max_factor:
        if temp % d == 0:
            count = 0
            while temp % d == 0:
                count += 1
                temp //= d
            factors[d] = count
        d = 3 if d == 2 else d + 2

    if temp > 1:
        if temp <= max_factor or temp < 100000000:
            factors[temp] = factors.get(temp, 0) + 1
        else:
            raise ValueError(f"Group order contains large prime cofactor {temp} exceeding smoothness limit")

    return factors


def pohlig_hellman(g: int, h: int, p: int, order: Optional[int] = None, factors: Optional[Dict[int, int]] = None) -> Optional[int]:
    """Solves the Discrete Logarithm Problem g^x = h (mod p) for smooth group orders.
    
    Precondition:
      - The group order N = ord(g) divides p - 1.
      - N has small prime factors: N = prod(q_i ^ e_i).
    
    Algorithm:
      1. For each prime power factor q^e dividing N:
         Recovers x mod q^e digit-by-digit:
           x_q = sum_{k=0}^{e-1} d_k * q^k
         At each step, reduces to finding d_k in a subgroup of prime order q via BSGS.
      2. Recombines the congruences x = r_i (mod q_i^e_i) via Chinese Remainder Theorem.
    
    Returns secret exponent x in [0, N - 1].
    """
    n = order if order is not None else p - 1
    if factors is None:
        factors = trial_factor(n)

    remainders: List[int] = []
    moduli: List[int] = []

    for q, e in factors.items():
        q_e = q ** e
        # Recover x mod q^e
        x_val = 0
        gamma = modular_pow(g, n // q, p)  # Element of prime order q

        for k in range(e):
            # Formulate subproblem: g^{(n / q^(k+1)) * (x - x_val)} = (h * g^(-x_val))^(n / q^(k+1))
            inv_g_x = modinv(modular_pow(g, x_val, p), p)
            h_k = (h * inv_g_x) % p
            exp_k = n // (q ** (k + 1))
            target = modular_pow(h_k, exp_k, p)

            # Solve d_k such that gamma^d_k = target (mod p)
            d_k = baby_step_giant_step(gamma, target, p, order=q)
            if d_k is None:
                return None
            x_val += d_k * (q ** k)

        remainders.append(x_val % q_e)
        moduli.append(q_e)

    # Recombine via CRT
    x_total = crt(remainders, moduli)
    return x_total
