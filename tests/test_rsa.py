"""Unit tests for RSA primitives, keygen, and algebraic attacks."""

import unittest
from crypto_toolkit.rsa.primitives import miller_rabin, modular_pow, generate_prime
from crypto_toolkit.rsa.keygen import rsa_keygen, rsa_encrypt, rsa_decrypt, bytes_to_int, int_to_bytes
from crypto_toolkit.rsa.hastad_broadcast import hastad_broadcast_attack
from crypto_toolkit.rsa.franklin_reiter import franklin_reiter_attack


class TestRSA(unittest.TestCase):

    def test_miller_rabin_known_values(self):
        # Known primes
        primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 65537, 104729]
        for p in primes:
            self.assertTrue(miller_rabin(p), f"Failed on prime {p}")

        # Known composites & Carmichael numbers
        composites = [4, 6, 8, 9, 15, 21, 561, 1105, 1729, 2465, 2821]
        for c in composites:
            self.assertFalse(miller_rabin(c), f"Failed on composite/Carmichael {c}")

    def test_modular_pow(self):
        self.assertEqual(modular_pow(2, 10, 1000), 24)
        self.assertEqual(modular_pow(7, 256, 13), pow(7, 256, 13))

    def test_rsa_keygen_encrypt_decrypt(self):
        keypair = rsa_keygen(bits=256, e=65537)
        msg_bytes = b"Hello, RSA!"
        m = bytes_to_int(msg_bytes)

        c = rsa_encrypt(m, keypair.public)
        dec_m = rsa_decrypt(c, keypair.private)
        dec_bytes = int_to_bytes(dec_m)

        self.assertEqual(dec_m, m)
        self.assertEqual(dec_bytes, msg_bytes)

    def test_hastad_broadcast_attack(self):
        e = 3
        msg_bytes = b"SECRET MSG"
        m = bytes_to_int(msg_bytes)

        # Generate 3 independent RSA keypairs with e=3
        keypairs = [rsa_keygen(bits=256, e=e) for _ in range(e)]
        ciphertexts = [rsa_encrypt(m, kp.public) for kp in keypairs]
        moduli = [kp.public.n for kp in keypairs]

        recovered_m, success = hastad_broadcast_attack(ciphertexts, moduli, e=e)
        self.assertTrue(success)
        self.assertEqual(recovered_m, m)
        self.assertEqual(int_to_bytes(recovered_m), msg_bytes)

    def test_franklin_reiter_attack(self):
        e = 3
        keypair = rsa_keygen(bits=256, e=e)
        n = keypair.public.n

        m1 = 123456789012345
        a = 1
        b = 777
        m2 = (a * m1 + b) % n

        c1 = rsa_encrypt(m1, keypair.public)
        c2 = rsa_encrypt(m2, keypair.public)

        recovered_m1, success = franklin_reiter_attack(c1, c2, n, e, a, b)
        self.assertTrue(success)
        self.assertEqual(recovered_m1, m1)


if __name__ == "__main__":
    unittest.main()
