"""Unit tests for classical Vigenère encryption and cryptanalysis."""

import unittest
from crypto_toolkit.utils.corpus import clean_text, ENGLISH_IC, generate_sample_plaintext
from crypto_toolkit.classical.vigenere import vigenere_encrypt, vigenere_decrypt
from crypto_toolkit.classical.friedman import index_of_coincidence, estimate_key_length_friedman
from crypto_toolkit.classical.chi_squared import crack_caesar_coset
from crypto_toolkit.classical.cracker import VigenereCracker


class TestVigenere(unittest.TestCase):

    def test_encrypt_decrypt_roundtrip(self):
        plaintext = "ATTACKATDAWN"
        key = "LEMON"
        ciphertext = vigenere_encrypt(plaintext, key)
        self.assertEqual(ciphertext, "LXFOPVEFRNHR")
        decrypted = vigenere_decrypt(ciphertext, key)
        self.assertEqual(decrypted, plaintext)

    def test_index_of_coincidence(self):
        # Natural English should have IC close to 0.0667
        sample = generate_sample_plaintext(min_length=1000, seed=123)
        ic = index_of_coincidence(sample)
        self.assertAlmostEqual(ic, ENGLISH_IC, delta=0.015)

    def test_caesar_coset_crack(self):
        sample = generate_sample_plaintext(min_length=400, seed=42)
        # Shift by K (shift = 10)
        shift = 10
        shifted = vigenere_encrypt(sample, "K")
        best_shift, key_char, _ = crack_caesar_coset(shifted)
        self.assertEqual(best_shift, shift)
        self.assertEqual(key_char, "K")

    def test_two_stage_vigenere_crack(self):
        sample = generate_sample_plaintext(min_length=600, seed=777)
        true_key = "CRYPTO"
        ciphertext = vigenere_encrypt(sample, true_key)

        cracker = VigenereCracker(max_key_len=10)
        result = cracker.crack(ciphertext)

        self.assertEqual(result.recovered_key, true_key)
        self.assertEqual(result.estimated_key_length, len(true_key))
        self.assertEqual(result.decrypted_text, sample)


if __name__ == "__main__":
    unittest.main()
