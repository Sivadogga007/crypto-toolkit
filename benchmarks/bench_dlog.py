"""Benchmark harness for discrete logarithm cryptanalysis (Pohlig-Hellman and BSGS)."""

import time
import random
from typing import Dict, List
from crypto_toolkit.rsa.primitives import modular_pow
from crypto_toolkit.dlog.bsgs import baby_step_giant_step
from crypto_toolkit.dlog.pohlig_hellman import pohlig_hellman, trial_factor


def benchmark_pohlig_hellman(num_trials: int = 20) -> Dict[str, float]:
    """Evaluates Pohlig-Hellman discrete log recovery time on smooth prime order."""
    p = 43243201  # 26-bit smooth prime: p - 1 = 2^6 * 3^3 * 5^2 * 7 * 11 * 13
    g = 34
    factors = trial_factor(p - 1)
    rng = random.Random(42)

    durations = []
    success_count = 0

    for _ in range(num_trials):
        x_true = rng.randint(2, p - 2)
        h = modular_pow(g, x_true, p)

        t0 = time.perf_counter()
        x_rec = pohlig_hellman(g, h, p, order=p - 1, factors=factors)
        elapsed = time.perf_counter() - t0

        if x_rec == x_true:
            success_count += 1
            durations.append(elapsed)

    durations.sort()
    median_time_ms = (durations[len(durations) // 2] * 1000.0) if durations else 0.0
    success_rate = (success_count / num_trials) * 100.0

    return {
        "trials": num_trials,
        "success_rate": success_rate,
        "median_time_ms": median_time_ms,
        "prime_bits": p.bit_length(),
        "max_subgroup_order": max(factors.keys())
    }


def benchmark_bsgs(num_trials: int = 20) -> Dict[str, float]:
    """Evaluates Baby-Step Giant-Step on a prime order group."""
    p = 100003  # 17-bit prime
    g = 2
    rng = random.Random(42)

    durations = []
    success_count = 0

    for _ in range(num_trials):
        x_true = rng.randint(2, p - 2)
        h = modular_pow(g, x_true, p)

        t0 = time.perf_counter()
        x_rec = baby_step_giant_step(g, h, p, order=p - 1)
        elapsed = time.perf_counter() - t0

        if x_rec == x_true:
            success_count += 1
            durations.append(elapsed)

    durations.sort()
    median_time_ms = (durations[len(durations) // 2] * 1000.0) if durations else 0.0
    success_rate = (success_count / num_trials) * 100.0

    return {
        "trials": num_trials,
        "success_rate": success_rate,
        "median_time_ms": median_time_ms,
        "prime_bits": p.bit_length()
    }


if __name__ == "__main__":
    ph_res = benchmark_pohlig_hellman()
    print(f"Pohlig-Hellman: {ph_res['success_rate']:.1f}% success, median {ph_res['median_time_ms']:.3f} ms")

    bsgs_res = benchmark_bsgs()
    print(f"BSGS: {bsgs_res['success_rate']:.1f}% success, median {bsgs_res['median_time_ms']:.3f} ms")
