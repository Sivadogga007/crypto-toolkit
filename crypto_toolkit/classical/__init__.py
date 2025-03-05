"""Classical Cryptography and Cryptanalysis Package."""

from crypto_toolkit.classical.vigenere import vigenere_encrypt, vigenere_decrypt
from crypto_toolkit.classical.friedman import index_of_coincidence, estimate_key_length_friedman
from crypto_toolkit.classical.chi_squared import chi_squared_stat, crack_caesar_coset
from crypto_toolkit.classical.cracker import VigenereCracker, VigenereRecoveryResult

__all__ = [
    "vigenere_encrypt",
    "vigenere_decrypt",
    "index_of_coincidence",
    "estimate_key_length_friedman",
    "chi_squared_stat",
    "crack_caesar_coset",
    "VigenereCracker",
    "VigenereRecoveryResult",
]
