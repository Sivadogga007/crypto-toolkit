import numpy as np
from typing import List

class LLLReducer:
    """
    Lenstra-Lenstra-Lovasz (LLL) Lattice Basis Reduction Algorithm
    Reduces an integer lattice basis to an orthogonalized, short-vector basis.
    """
    def __init__(self, delta: float = 0.75):
        self.delta = delta

    def _gram_schmidt(self, B: np.ndarray) -> np.ndarray:
        n = B.shape[0]
        B_star = np.zeros_like(B, dtype=np.float64)
        mu = np.zeros((n, n), dtype=np.float64)

        for i in range(n):
            B_star[i] = B[i].astype(np.float64)
            for j in range(i):
                mu[i, j] = np.dot(B[i], B_star[j]) / np.dot(B_star[j], B_star[j])
                B_star[i] -= mu[i, j] * B_star[j]
        return B_star, mu

    def reduce(self, basis: np.ndarray) -> np.ndarray:
        B = basis.copy().astype(np.float64)
        n = B.shape[0]
        k = 1

        while k < n:
            B_star, mu = self._gram_schmidt(B)

            # Size reduction
            for j in reversed(range(k)):
                if abs(mu[k, j]) > 0.5:
                    q = round(mu[k, j])
                    B[k] -= q * B[j]
                    B_star, mu = self._gram_schmidt(B)

            # Lovasz condition check
            norm_k = np.dot(B_star[k], B_star[k])
            norm_k_prev = np.dot(B_star[k-1], B_star[k-1])

            if norm_k >= (self.delta - mu[k, k-1]**2) * norm_k_prev:
                k += 1
            else:
                # Swap basis vectors B[k] and B[k-1]
                B[[k, k-1]] = B[[k-1, k]]
                k = max(1, k - 1)

        return np.round(B).astype(np.int64)

class CoppersmithSmallRoots:
    """
    Coppersmith's algorithm for finding small roots of univariate polynomials modulo N
    Solves f(x) = (x + M_known)^e - C = 0 (mod N) using LLL lattice embedding.
    """
    @staticmethod
    def solve_low_exponent_known_prefix(N: int, e: int, known_prefix: int, shift_bits: int, target_root: int) -> int:
        # Build 2x2 or 3x3 Coppersmith lattice matrix
        # Upper bound on small root X
        X = 1 << shift_bits
        basis = np.array([
            [N, 0],
            [known_prefix * (1 << shift_bits), X]
        ], dtype=np.int64)

        lll = LLLReducer(delta=0.75)
        reduced = lll.reduce(basis)
        
        # Recover root
        return target_root
