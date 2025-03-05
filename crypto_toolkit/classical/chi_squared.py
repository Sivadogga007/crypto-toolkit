"""Chi-Squared Frequency Analysis for Caesar/Vigenère Coset Cryptanalysis."""

import string
from collections import Counter
from typing import Tuple
from crypto_toolkit.utils.corpus import clean_text, ENGLISH_LETTER_FREQ


def chi_squared_stat(coset_text: str, shift: int) -> float:
    """Computes Chi-squared statistic for coset_text shifted backwards by `shift`
    against standard English letter frequency distribution.
    
    Formula: chi^2 = sum_i ( (Observed_i - Expected_i)^2 / Expected_i )
    Lower chi-squared indicates closer fit to natural English.
    """
    n = len(coset_text)
    if n == 0:
        return float('inf')

    # Decrypt coset with candidate shift
    shifted_counts = Counter()
    for ch in coset_text:
        c_val = ord(ch) - ord('A')
        p_val = (c_val - shift) % 26
        shifted_counts[chr(ord('A') + p_val)] += 1

    chi2 = 0.0
    for ch in string.ascii_uppercase:
        observed = shifted_counts[ch]
        expected = n * ENGLISH_LETTER_FREQ[ch]
        if expected > 0:
            diff = observed - expected
            chi2 += (diff * diff) / expected

    return chi2


def crack_caesar_coset(coset_text: str) -> Tuple[int, str, float]:
    """Finds optimal Caesar shift (0-25) minimizing Chi-squared statistic.
    
    Returns (best_shift, best_key_char, best_chi2).
    """
    clean_c = clean_text(coset_text)
    if not clean_c:
        return 0, 'A', float('inf')

    best_shift = 0
    best_chi2 = float('inf')

    for shift in range(26):
        score = chi_squared_stat(clean_c, shift)
        if score < best_chi2:
            best_chi2 = score
            best_shift = shift

    key_char = chr(ord('A') + best_shift)
    return best_shift, key_char, best_chi2
