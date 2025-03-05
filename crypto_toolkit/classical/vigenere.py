"""Vigenère Cipher Implementation."""

import string
from crypto_toolkit.utils.corpus import clean_text


def vigenere_encrypt(plaintext: str, key: str) -> str:
    """Encrypts plaintext using Vigenère cipher with uppercase alphabet A-Z."""
    clean_p = clean_text(plaintext)
    clean_k = clean_text(key)
    if not clean_k:
        raise ValueError("Key must contain at least one valid alphabet character")
    if not clean_p:
        return ""

    key_len = len(clean_k)
    key_shifts = [ord(ch) - ord('A') for ch in clean_k]
    
    ciphertext = []
    for i, ch in enumerate(clean_p):
        p_val = ord(ch) - ord('A')
        shift = key_shifts[i % key_len]
        c_val = (p_val + shift) % 26
        ciphertext.append(chr(ord('A') + c_val))

    return ''.join(ciphertext)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """Decrypts ciphertext using Vigenère cipher with uppercase alphabet A-Z."""
    clean_c = clean_text(ciphertext)
    clean_k = clean_text(key)
    if not clean_k:
        raise ValueError("Key must contain at least one valid alphabet character")
    if not clean_c:
        return ""

    key_len = len(clean_k)
    key_shifts = [ord(ch) - ord('A') for ch in clean_k]

    plaintext = []
    for i, ch in enumerate(clean_c):
        c_val = ord(ch) - ord('A')
        shift = key_shifts[i % key_len]
        p_val = (c_val - shift) % 26
        plaintext.append(chr(ord('A') + p_val))

    return ''.join(plaintext)
