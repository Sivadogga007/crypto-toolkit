"""Friedman Test and Index of Coincidence (IoC) key-length estimation for polyalphabetic ciphers."""

from collections import Counter
from typing import List, Tuple
from crypto_toolkit.utils.corpus import clean_text, ENGLISH_IC, UNIFORM_IC


def index_of_coincidence(text: str) -> float:
    """Calculates the Index of Coincidence (IC) of text.
    
    Formula: IC = sum(f_i * (f_i - 1)) / (N * (N - 1))
    where f_i is count of each letter and N is total text length.
    """
    clean_t = clean_text(text)
    n = len(clean_t)
    if n <= 1:
        return 0.0

    counts = Counter(clean_t)
    sum_fi = sum(f * (f - 1) for f in counts.values())
    return sum_fi / (n * (n - 1))


def estimate_key_length_friedman(ciphertext: str, min_len: int = 1, max_len: int = 20) -> List[Tuple[int, float]]:
    """Estimates the Vigenère key length using coset Index of Coincidence analysis.
    
    For each candidate key length m in [min_len, max_len]:
      1. Splits ciphertext into m cosets: C_j = { c_{i*m + j} }
      2. Computes the average IC across the m cosets.
      3. Ranks candidates by proximity of average IC to English IC (~0.0667).
    
    Returns a list of (candidate_length, average_ic) sorted in descending order of average IC.
    """
    clean_c = clean_text(ciphertext)
    n = len(clean_c)
    if n < 10:
        return [(1, 0.0)]

    results: List[Tuple[int, float]] = []
    
    for m in range(min_len, min(max_len + 1, n // 2 + 1)):
        # Extract cosets
        coset_ics = []
        for j in range(m):
            coset = clean_c[j::m]
            if len(coset) > 1:
                coset_ics.append(index_of_coincidence(coset))
            else:
                coset_ics.append(UNIFORM_IC)
        
        avg_ic = sum(coset_ics) / len(coset_ics) if coset_ics else 0.0
        results.append((m, avg_ic))

    # Sort descending by average IC
    results.sort(key=lambda item: item[1], reverse=True)
    return results
