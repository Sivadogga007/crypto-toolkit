"""Mathematical utility functions for cryptographic primitives and cryptanalysis.

Contains exact integer arithmetic, Extended GCD, modular inverse, exact integer roots,
Chinese Remainder Theorem (CRT), and polynomial operations over finite fields / modular rings.
"""

from typing import List, Tuple, Optional


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean Algorithm.
    
    Returns (g, x, y) such that a*x + b*y = g = gcd(a, b).
    """
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y


def modinv(a: int, m: int) -> int:
    """Modular multiplicative inverse: returns x such that (a * x) % m == 1.
    
    Raises ValueError if gcd(a, m) != 1.
    """
    if m <= 0:
        raise ValueError("Modulus must be positive")
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist for {a} mod {m} (gcd={g})")
    return x % m


def iroot(n: int, k: int) -> Tuple[int, bool]:
    """Computes floor(n**(1/k)) using integer Newton-Raphson iteration.
    
    Returns (root, is_exact) where is_exact is True if root**k == n.
    """
    if n < 0:
        if k % 2 == 1:
            r, exact = iroot(-n, k)
            return -r, exact
        raise ValueError("Cannot take even root of negative number")
    if n == 0:
        return 0, True
    if k <= 0:
        raise ValueError("Root degree k must be positive")
    if k == 1:
        return n, True

    # Initial guess
    u = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        # Newton step: x_{new} = ((k - 1) * x + n // (x**(k - 1))) // k
        d = u ** (k - 1)
        if d == 0:
            break
        v = ((k - 1) * u + n // d) // k
        if v >= u:
            break
        u = v

    # Check neighborhood
    while (u + 1) ** k <= n:
        u += 1
    while u ** k > n:
        u -= 1

    return u, (u ** k == n)


def crt(remainders: List[int], moduli: List[int]) -> int:
    """Chinese Remainder Theorem for pairwise coprime moduli.
    
    Finds x such that x = remainders[i] (mod moduli[i]) for all i.
    """
    if len(remainders) != len(moduli) or not remainders:
        raise ValueError("Remainders and moduli must be non-empty and of equal length")

    total_prod = 1
    for m in moduli:
        total_prod *= m

    result = 0
    for r, m in zip(remainders, moduli):
        m_i = total_prod // m
        inv = modinv(m_i, m)
        result = (result + r * m_i * inv) % total_prod

    return result


# ---------------------------------------------------------------------------
# Polynomial operations modulo N
# Representation: list of coefficients [a0, a1, ..., ad] where P(x) = sum(ai * x^i)
# ---------------------------------------------------------------------------

def poly_clean(p: List[int], mod: Optional[int] = None) -> List[int]:
    """Removes trailing zero coefficients and applies modulo if specified."""
    if mod is not None:
        p = [c % mod for c in p]
    while len(p) > 1 and p[-1] == 0:
        p.pop()
    return p if p else [0]


def poly_add(p1: List[int], p2: List[int], mod: int) -> List[int]:
    """Adds two polynomials modulo N."""
    deg = max(len(p1), len(p2))
    res = [0] * deg
    for i in range(deg):
        c1 = p1[i] if i < len(p1) else 0
        c2 = p2[i] if i < len(p2) else 0
        res[i] = (c1 + c2) % mod
    return poly_clean(res, mod)


def poly_sub(p1: List[int], p2: List[int], mod: int) -> List[int]:
    """Subtracts polynomial p2 from p1 modulo N."""
    deg = max(len(p1), len(p2))
    res = [0] * deg
    for i in range(deg):
        c1 = p1[i] if i < len(p1) else 0
        c2 = p2[i] if i < len(p2) else 0
        res[i] = (c1 - c2) % mod
    return poly_clean(res, mod)


def poly_mul(p1: List[int], p2: List[int], mod: int) -> List[int]:
    """Multiplies two polynomials modulo N."""
    if p1 == [0] or p2 == [0]:
        return [0]
    res = [0] * (len(p1) + len(p2) - 1)
    for i, c1 in enumerate(p1):
        for j, c2 in enumerate(p2):
            res[i + j] = (res[i + j] + c1 * c2) % mod
    return poly_clean(res, mod)


def poly_divmod(p1: List[int], p2: List[int], mod: int) -> Tuple[List[int], List[int]]:
    """Polynomial division with remainder: returns (quotient, remainder) such that
    p1 = quotient * p2 + remainder (mod N).
    
    Leading coefficient of p2 must be invertible modulo N.
    """
    p1 = poly_clean(p1, mod)
    p2 = poly_clean(p2, mod)
    if p2 == [0]:
        raise ZeroDivisionError("Polynomial division by zero")

    deg1 = len(p1) - 1
    deg2 = len(p2) - 1

    if deg1 < deg2:
        return [0], p1[:]

    lead_inv = modinv(p2[-1], mod)
    quot = [0] * (deg1 - deg2 + 1)
    rem = list(p1)

    for i in range(deg1 - deg2, -1, -1):
        if len(rem) - 1 == i + deg2:
            coeff = (rem[-1] * lead_inv) % mod
            quot[i] = coeff
            for j in range(deg2 + 1):
                rem[i + j] = (rem[i + j] - coeff * p2[j]) % mod
            rem = poly_clean(rem, mod)

    return poly_clean(quot, mod), poly_clean(rem, mod)


def poly_gcd(p1: List[int], p2: List[int], mod: int) -> List[int]:
    """Monic greatest common divisor of two polynomials modulo N using Euclidean algorithm.
    
    Assumes all encountered leading coefficients are invertible mod N.
    """
    a = poly_clean(p1, mod)
    b = poly_clean(p2, mod)

    while b != [0]:
        _, rem = poly_divmod(a, b, mod)
        a, b = b, rem

    # Make monic
    if a != [0] and a[-1] != 1:
        lead_inv = modinv(a[-1], mod)
        a = [(c * lead_inv) % mod for c in a]
    return a


def poly_eval(poly: List[int], x: int, mod: int) -> int:
    """Evaluates polynomial at x modulo N using Horner's method."""
    res = 0
    for c in reversed(poly):
        res = (res * x + c) % mod
    return res
