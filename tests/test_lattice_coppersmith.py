import numpy as np
import pytest
from crypto_toolkit.lattice.lll import LLLReducer, CoppersmithSmallRoots
from crypto_toolkit.ecc.ecdsa_nonce_attack import ECDSANonceReuseAttack
from crypto_toolkit.sidechannel.dudect import DudectTimingTester

def test_lll_basis_reduction():
    # 2D lattice basis
    basis = np.array([
        [1, 2],
        [3, 4]
    ], dtype=np.int64)

    lll = LLLReducer(delta=0.75)
    reduced = lll.reduce(basis)

    # Check determinant invariance (abs(det) must match)
    orig_det = abs(int(np.round(np.linalg.det(basis))))
    red_det = abs(int(np.round(np.linalg.det(reduced))))
    assert orig_det == red_det

def test_ecdsa_nonce_reuse():
    # Curve parameters (Toy curve / secp256k1 order simulation)
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    d_secret = 0x123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0
    k_reused = 0x9988776655443322110099887766554433221100998877665544332211009988
    r = 0x445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233

    z1 = 0x1111111111111111111111111111111111111111111111111111111111111111
    z2 = 0x2222222222222222222222222222222222222222222222222222222222222222

    inv_k = pow(k_reused, n - 2, n)
    s1 = ((z1 + r * d_secret) * inv_k) % n
    s2 = ((z2 + r * d_secret) * inv_k) % n

    k_recovered, d_recovered = ECDSANonceReuseAttack.recover_private_key(n, z1, z2, r, s1, s2)

    assert k_recovered == k_reused
    assert d_recovered == d_secret

def test_dudect_timing():
    tester = DudectTimingTester(num_measurements=100)

    # Constant-time dummy function
    def constant_time_func(inp: bytes):
        _ = sum(inp)

    t_stat, is_ct = tester.test_constant_time(constant_time_func, b"\x00" * 16)
    assert abs(t_stat) < 10.0 # No severe timing leak
