"""Wiener's attack: recovers a small private exponent d from (N, e) alone.

Applies when d < (1/3) * N^(1/4). Under that bound, k/d appears as a convergent
of the continued-fraction expansion of e/N, so we can enumerate convergents and
test each as a candidate.

Ported from the E-cryptanalysis prototype and rewritten against
crypto_toolkit.utils.math_utils so the toolkit has one set of number-theory
helpers rather than two.
"""
from __future__ import annotations

import math
from typing import Iterator, Optional, Tuple


def continued_fraction(numerator: int, denominator: int) -> list[int]:
    """Continued-fraction expansion of numerator/denominator."""
    cf: list[int] = []
    while denominator:
        q = numerator // denominator
        cf.append(q)
        numerator, denominator = denominator, numerator - q * denominator
    return cf


def convergents(cf: list[int]) -> Iterator[Tuple[int, int]]:
    """Successive rational convergents p_k / q_k of a continued fraction."""
    p_prev, p_curr = 0, 1
    q_prev, q_curr = 1, 0
    for a in cf:
        p_next = a * p_curr + p_prev
        q_next = a * q_curr + q_prev
        yield p_next, q_next
        p_prev, p_curr = p_curr, p_next
        q_prev, q_curr = q_curr, q_next


def _is_perfect_square(n: int) -> Tuple[bool, int]:
    if n < 0:
        return False, 0
    r = math.isqrt(n)
    return r * r == n, r


def wiener_attack(N: int, e: int) -> Optional[int]:
    """Recover d from (N, e), or None if d is not small enough to be exposed.

    For each convergent k/d of e/N we reconstruct phi = (e*d - 1)/k and check
    whether x^2 - (N - phi + 1)x + N has integer roots -- if it does, those roots
    are p and q and the candidate d is correct.
    """
    for k, d in convergents(continued_fraction(e, N)):
        if k == 0 or d % 2 == 0:
            continue
        if (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k

        # p and q are roots of x^2 - s*x + N where s = p + q = N - phi + 1
        s = N - phi + 1
        disc = s * s - 4 * N
        if disc < 0:
            continue
        ok, root = _is_perfect_square(disc)
        if not ok:
            continue
        if (s + root) % 2 == 0:
            return d
    return None
