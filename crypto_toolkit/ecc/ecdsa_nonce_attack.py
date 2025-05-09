from dataclasses import dataclass
from typing import Tuple

# Simple Elliptic Curve over F_p: y^2 = x^3 + a*x + b (mod p)
@dataclass
class Point:
    x: int
    y: int
    is_infinity: bool = False

class EllipticCurve:
    def __init__(self, p: int, a: int, b: int, G: Point, n: int):
        self.p = p # Field prime
        self.a = a
        self.b = b
        self.G = G # Base generator point
        self.n = n # Subgroup order

    def add(self, P: Point, Q: Point) -> Point:
        if P.is_infinity: return Q
        if Q.is_infinity: return P
        if P.x == Q.x and (P.y != Q.y or P.y == 0):
            return Point(0, 0, is_infinity=True)

        if P.x == Q.x and P.y == Q.y:
            # Point doubling: lambda = (3*x1^2 + a) / (2*y1) mod p
            num = (3 * P.x * P.x + self.a) % self.p
            den = (2 * P.y) % self.p
            lam = (num * pow(den, self.p - 2, self.p)) % self.p
        else:
            # Point addition: lambda = (y2 - y1) / (x2 - x1) mod p
            num = (Q.y - P.y) % self.p
            den = (Q.x - P.x) % self.p
            lam = (num * pow(den, self.p - 2, self.p)) % self.p

        x3 = (lam * lam - P.x - Q.x) % self.p
        y3 = (lam * (P.x - x3) - P.y) % self.p
        return Point(x3, y3)

    def mul(self, k: int, P: Point) -> Point:
        R = Point(0, 0, is_infinity=True)
        current = P
        while k > 0:
            if k & 1:
                R = self.add(R, current)
            current = self.add(current, current)
            k >>= 1
        return R

class ECDSANonceReuseAttack:
    """
    ECDSA Duplicate Nonce Private Key Recovery
    Given two signatures (r, s1) and (r, s2) on messages z1 and z2 generated with same nonce k:
    k = (z1 - z2) / (s1 - s2) mod n
    d = (s1 * k - z1) / r mod n
    """
    @staticmethod
    def recover_private_key(n: int, z1: int, z2: int, r: int, s1: int, s2: int) -> Tuple[int, int]:
        delta_z = (z1 - z2) % n
        delta_s = (s1 - s2) % n

        if delta_s == 0:
            raise ValueError("Identical signature values")

        # Nonce recovery
        inv_delta_s = pow(delta_s, n - 2, n)
        k = (delta_z * inv_delta_s) % n

        # Private key recovery: d = (s1 * k - z1) * r^(-1) mod n
        inv_r = pow(r, n - 2, n)
        d = ((s1 * k - z1) * inv_r) % n

        return k, d
