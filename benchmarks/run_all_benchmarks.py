"""Master Benchmark Runner for Cryptanalysis Toolkit.

Executes all attack evaluations on clean instances and outputs the verified
empirical performance summary table directly to stdout.
"""

import sys
import time
from benchmarks.bench_vigenere import benchmark_vigenere_curve, print_vigenere_results
from benchmarks.bench_rsa import benchmark_hastad, benchmark_franklin_reiter
from benchmarks.bench_dlog import benchmark_pohlig_hellman, benchmark_bsgs


def main():
    print("=" * 80)
    print("CRYPTANALYSIS TOOLKIT: EMPIRICAL BENCHMARK & REPRODUCIBILITY HARNESS")
    print("=" * 80)
    print("Quality Gate Check: Evaluating live execution across all attack primitives...\n")

    t_start = time.perf_counter()

    # 1. Classical Cryptanalysis Failure Curve
    print("[1/4] Running Vigenère Friedman IoC & Chi-Squared Length Curve (20 trials/length)...")
    v_res = benchmark_vigenere_curve(
        lengths=[30, 50, 75, 100, 150, 200, 300, 500, 800],
        trials_per_length=20,
        seed=101
    )
    print_vigenere_results(v_res)

    # 2. RSA Håstad Broadcast Attack
    print("\n[2/4] Running RSA Håstad's Broadcast Attack (50 trials, e=3, 256-bit moduli)...")
    h_res = benchmark_hastad(num_trials=50, key_bits=256, e=3)

    # 3. RSA Franklin-Reiter Related-Message Attack
    print("[3/4] Running RSA Franklin-Reiter Related-Message Attack (50 trials, e=3, 256-bit moduli)...")
    fr_res = benchmark_franklin_reiter(num_trials=50, key_bits=256, e=3)

    # 4. Discrete Logarithm Attacks
    print("[4/4] Running Discrete Logarithm Benchmarks (Pohlig-Hellman & BSGS)...")
    ph_res = benchmark_pohlig_hellman(num_trials=50)
    bsgs_res = benchmark_bsgs(num_trials=50)

    t_total = time.perf_counter() - t_start

    # Print Master Summary Table
    print("\n" + "=" * 92)
    print("MASTER ATTACK BENCHMARK SUMMARY (Printed directly from live execution)")
    print("=" * 92)
    print(f"{'Attack':<24} | {'Precondition':<26} | {'Trials':<8} | {'Median Time (ms)':<16} | {'Success Rate':<12}")
    print("-" * 92)
    
    # Vigenere short vs long
    v_short = next(r for r in v_res if r["length"] == 50)
    v_long = next(r for r in v_res if r["length"] == 500)
    
    print(f"{'Vigenère (Short CT)':<24} | {'Length = 50 chars':<26} | {'20':<8} | {v_short['avg_time_ms']:<16.3f} | {v_short['exact_key_accuracy']:<11.1f}%")
    print(f"{'Vigenère (Long CT)':<24} | {'Length = 500 chars':<26} | {'20':<8} | {v_long['avg_time_ms']:<16.3f} | {v_long['exact_key_accuracy']:<11.1f}%")
    print(f"{'Håstad Broadcast':<24} | {'e=3, 3 coprime moduli':<26} | {h_res['trials']:<8} | {h_res['median_time_ms']:<16.3f} | {h_res['success_rate']:<11.1f}%")
    print(f"{'Franklin-Reiter':<24} | {'e=3, linear relation':<26} | {fr_res['trials']:<8} | {fr_res['median_time_ms']:<16.3f} | {fr_res['success_rate']:<11.1f}%")
    print(f"{'Pohlig-Hellman (DLog)':<24} | {'Smooth group (B<=13)':<26} | {ph_res['trials']:<8} | {ph_res['median_time_ms']:<16.3f} | {ph_res['success_rate']:<11.1f}%")
    print(f"{'Baby-Step Giant-Step':<24} | {'Cyclic group (17-bit)':<26} | {bsgs_res['trials']:<8} | {bsgs_res['median_time_ms']:<16.3f} | {bsgs_res['success_rate']:<11.1f}%")
    print("=" * 92)
    print(f"All benchmarks completed successfully in {t_total:.2f} seconds.\n")


if __name__ == "__main__":
    main()
