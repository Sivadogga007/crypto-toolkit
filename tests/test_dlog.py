"""Unit tests for Diffie-Hellman, BSGS, and Pohlig-Hellman discrete log attacks."""

import unittest
from crypto_toolkit.dlog.diffie_hellman import DHParameters, DiffieHellmanParty
from crypto_toolkit.dlog.bsgs import baby_step_giant_step
from crypto_toolkit.dlog.pohlig_hellman import pohlig_hellman, trial_factor
from crypto_toolkit.rsa.primitives import modular_pow


class TestDLog(unittest.TestCase):

    def test_diffie_hellman_shared_secret(self):
        # 128-bit prime modulus
        p = 340282366920938463463374607431768211507
        g = 2
        params = DHParameters(p=p, g=g)

        alice = DiffieHellmanParty(params)
        bob = DiffieHellmanParty(params)

        secret_alice = alice.compute_shared_secret(bob.public_key)
        secret_bob = bob.compute_shared_secret(alice.public_key)

        self.assertEqual(secret_alice, secret_bob)

    def test_baby_step_giant_step(self):
        p = 10007
        g = 5
        x_true = 3456
        h = modular_pow(g, x_true, p)

        x_recovered = baby_step_giant_step(g, h, p)
        self.assertEqual(x_recovered, x_true)

    def test_pohlig_hellman_smooth_order(self):
        # Verified smooth prime p = 43243201 where p - 1 = 2^6 * 3^3 * 5^2 * 7 * 11 * 13
        p = 43243201
        g = 34
        x_true = 9876543
        h = modular_pow(g, x_true, p)

        factors = trial_factor(p - 1)
        x_recovered = pohlig_hellman(g, h, p, order=p - 1, factors=factors)

        self.assertEqual(x_recovered, x_true)


if __name__ == "__main__":
    unittest.main()
