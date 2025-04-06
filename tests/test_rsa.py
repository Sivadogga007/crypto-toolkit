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


# --- ported from E-cryptanalysis-toolkit during the merge ------------------

def test_wiener_small_d():
    from crypto_toolkit.rsa.wiener import wiener_attack
    from crypto_toolkit.utils.math_utils import egcd, modinv
    # 64-bit primes => N ~ 128 bits => Wiener bound N^(1/4)/3 ~ 1.4e9,
    # so a 20-bit d sits comfortably inside the vulnerable range.
    p_, q_ = 18446744073709551557, 18446744073709551533
    N = p_ * q_
    phi = (p_ - 1) * (q_ - 1)
    d = 1048583                      # ~2^20, odd, coprime to phi
    assert egcd(d, phi)[0] == 1
    e = modinv(d, phi)
    recovered = wiener_attack(N, e)
    assert recovered == d, f"expected d={d}, got {recovered}"
    print("[PASSED] test_wiener_small_d")


def test_wiener_rejects_large_d():
    from crypto_toolkit.rsa.wiener import wiener_attack
    # standard e=65537 => d is large => attack must NOT claim a result
    p_, q_ = 18446744073709551557, 18446744073709551533
    N = p_ * q_
    phi = (p_ - 1) * (q_ - 1)
    e = 65537
    from crypto_toolkit.utils.math_utils import modinv
    d = modinv(e, phi)
    got = wiener_attack(N, e)
    assert got is None or got == d, "must return None or the true d, never a wrong d"
    print("[PASSED] test_wiener_rejects_large_d")


def test_common_modulus():
    from crypto_toolkit.rsa.common_modulus import common_modulus_attack
    p, q = 1000003, 1000033
    N = p * q
    m = 123456789
    e1, e2 = 17, 65537          # coprime
    c1, c2 = pow(m, e1, N), pow(m, e2, N)
    assert common_modulus_attack(N, e1, e2, c1, c2) == m
    print("[PASSED] test_common_modulus")


def test_common_modulus_rejects_shared_factor():
    from crypto_toolkit.rsa.common_modulus import common_modulus_attack
    N = 1000003 * 1000033
    try:
        common_modulus_attack(N, 4, 6, 1, 1)   # gcd = 2
    except ValueError:
        print("[PASSED] test_common_modulus_rejects_shared_factor")
        return
    raise AssertionError("should have rejected non-coprime exponents")
