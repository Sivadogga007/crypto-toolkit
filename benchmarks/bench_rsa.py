"""Benchmark harness for RSA algebraic attacks (Håstad Broadcast and Franklin-Reiter)."""

import time
import random
from typing import Dict
from crypto_toolkit.rsa.keygen import rsa_keygen, rsa_encrypt, bytes_to_int
from crypto_toolkit.rsa.hastad_broadcast import hastad_broadcast_attack
from crypto_toolkit.rsa.franklin_reiter import franklin_reiter_attack


def benchmark_hastad(num_trials: int = 50, key_bits: int = 256, e: int = 3) -> Dict[str, float]:
    """Evaluates Håstad's Broadcast Attack over multiple independent trials."""
    success_count = 0
    durations = []

    for trial in range(num_trials):
        msg = f"TEST_PAYLOAD_{trial:04d}".encode()
        m = bytes_to_int(msg)

        # Generate e independent keypairs
        keypairs = [rsa_keygen(bits=key_bits, e=e) for _ in range(e)]
        ciphertexts = [rsa_encrypt(m, kp.public) for kp in keypairs]
        moduli = [kp.public.n for kp in keypairs]

        t0 = time.perf_counter()
        recovered_m, success = hastad_broadcast_attack(ciphertexts, moduli, e=e)
        elapsed = time.perf_counter() - t0

        if success and recovered_m == m:
            success_count += 1
            durations.append(elapsed)

    durations.sort()
    median_time_ms = (durations[len(durations) // 2] * 1000.0) if durations else 0.0
    success_rate = (success_count / num_trials) * 100.0

    return {
        "trials": num_trials,
        "success_rate": success_rate,
        "median_time_ms": median_time_ms,
        "key_bits": key_bits,
        "exponent": e
    }


def benchmark_franklin_reiter(num_trials: int = 50, key_bits: int = 256, e: int = 3) -> Dict[str, float]:
    """Evaluates Franklin-Reiter Related-Message Attack over multiple independent trials."""
    success_count = 0
    durations = []
    rng = random.Random(42)

    for trial in range(num_trials):
        keypair = rsa_keygen(bits=key_bits, e=e)
        n = keypair.public.n

        m1 = rng.randint(1000000, 99999999)
        a = rng.randint(1, 10)
        b = rng.randint(1, 1000)
        m2 = (a * m1 + b) % n

        c1 = rsa_encrypt(m1, keypair.public)
        c2 = rsa_encrypt(m2, keypair.public)

        t0 = time.perf_counter()
        recovered_m1, success = franklin_reiter_attack(c1, c2, n, e, a, b)
        elapsed = time.perf_counter() - t0

        if success and recovered_m1 == m1:
            success_count += 1
            durations.append(elapsed)

    durations.sort()
    median_time_ms = (durations[len(durations) // 2] * 1000.0) if durations else 0.0
    success_rate = (success_count / num_trials) * 100.0

    return {
        "trials": num_trials,
        "success_rate": success_rate,
        "median_time_ms": median_time_ms,
        "key_bits": key_bits,
        "exponent": e
    }


if __name__ == "__main__":
    print("Running Håstad Broadcast benchmark...")
    h_res = benchmark_hastad(num_trials=20)
    print(f"Håstad: {h_res['success_rate']:.1f}% success, median {h_res['median_time_ms']:.3f} ms")

    print("Running Franklin-Reiter benchmark...")
    fr_res = benchmark_franklin_reiter(num_trials=20)
    print(f"Franklin-Reiter: {fr_res['success_rate']:.1f}% success, median {fr_res['median_time_ms']:.3f} ms")
