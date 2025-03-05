"""Håstad's Broadcast Attack on RSA with Small Public Exponent."""

from typing import List, Tuple
from crypto_toolkit.utils.math_utils import crt, iroot


def hastad_broadcast_attack(ciphertexts: List[int], moduli: List[int], e: int = 3) -> Tuple[int, bool]:
    """Executes Håstad's broadcast attack on unpadded RSA.
    
    Precondition:
      - Same plaintext message M is encrypted under k >= e distinct public keys (e, N_i).
      - Moduli N_1, N_2, ..., N_k are pairwise coprime.
      - c_i = M^e (mod N_i)
    
    Algorithm:
      1. Uses Chinese Remainder Theorem to find C = M^e (mod prod(N_i)).
      2. Since M < N_i for all i, M^e < prod_{i=1}^e N_i.
      3. Therefore C = M^e over the integers Z.
      4. Computes exact integer e-th root of C to recover M.
    
    Returns (recovered_message, success_boolean).
    """
    if len(ciphertexts) < e or len(moduli) < e:
        raise ValueError(f"Need at least {e} ciphertext-modulus pairs for exponent e={e}")
    if len(ciphertexts) != len(moduli):
        raise ValueError("Ciphertexts and moduli lists must have identical lengths")

    # Use first e pairs
    c_sub = ciphertexts[:e]
    n_sub = moduli[:e]

    # CRT reconstruction
    combined_c = crt(c_sub, n_sub)

    # Exact integer e-th root
    root, exact = iroot(combined_c, e)
    return root, exact
