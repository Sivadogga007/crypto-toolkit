"""Independent Two-Stage Vigenère Cipher Key Recovery Engine."""

from dataclasses import dataclass
from typing import Optional, List, Tuple

from crypto_toolkit.utils.corpus import clean_text
from crypto_toolkit.classical.vigenere import vigenere_decrypt
from crypto_toolkit.classical.friedman import estimate_key_length_friedman
from crypto_toolkit.classical.chi_squared import crack_caesar_coset


@dataclass
class VigenereRecoveryResult:
    """Structured result of automated Vigenère cryptanalysis."""
    recovered_key: str
    decrypted_text: str
    estimated_key_length: int
    coset_avg_ic: float
    coset_avg_chi2: float
    candidate_lengths: List[Tuple[int, float]]


class VigenereCracker:
    """Automated Vigenère cryptanalysis via independent Friedman and Chi-squared stages.
    
    CRITICAL QUALITY GATE INVARIANT:
    - Stage 1 (Key Length): Friedman test determines candidate key lengths purely from ciphertext.
    - Stage 2 (Key Content): Chi-squared minimization independently cracks each coset.
    - Neither stage accesses plaintext or ground truth.
    """

    def __init__(self, max_key_len: int = 15):
        self.max_key_len = max_key_len

    def crack(self, ciphertext: str, known_key_len: Optional[int] = None) -> VigenereRecoveryResult:
        """Executes independent 2-stage key recovery on ciphertext."""
        clean_c = clean_text(ciphertext)
        if not clean_c:
            raise ValueError("Ciphertext must contain at least one valid alphabet character")

        # Stage 1: Key-length estimation via Friedman IoC
        candidates = estimate_key_length_friedman(clean_c, min_len=1, max_len=self.max_key_len)
        
        if known_key_len is not None:
            chosen_len = known_key_len
            chosen_ic = next((ic for k, ic in candidates if k == known_key_len), 0.0)
        else:
            chosen_len, chosen_ic = candidates[0]

        # Stage 2: Independent Chi-squared minimization per coset
        recovered_key_chars = []
        chi2_scores = []

        for j in range(chosen_len):
            coset = clean_c[j::chosen_len]
            _, key_char, chi2 = crack_caesar_coset(coset)
            recovered_key_chars.append(key_char)
            chi2_scores.append(chi2)

        recovered_key = ''.join(recovered_key_chars)
        decrypted = vigenere_decrypt(clean_c, recovered_key)
        avg_chi2 = sum(chi2_scores) / len(chi2_scores) if chi2_scores else 0.0

        return VigenereRecoveryResult(
            recovered_key=recovered_key,
            decrypted_text=decrypted,
            estimated_key_length=chosen_len,
            coset_avg_ic=chosen_ic,
            coset_avg_chi2=avg_chi2,
            candidate_lengths=candidates
        )
