import numpy as np
import time
from typing import Callable, Tuple

class DudectTimingTester:
    """
    Dude, is my code constant time? (Reparaz et al., 2016)
    Evaluates timing leakage using Welch's two-sample t-test comparing execution times
    for Fixed vs Random input distributions.
    |t| > 4.5 indicates statistical evidence of timing side-channel leakage.
    """
    def __init__(self, num_measurements: int = 5000):
        self.num_measurements = num_measurements

    def test_constant_time(self, crypto_func: Callable[[bytes], None], fixed_input: bytes, input_len: int = 16) -> Tuple[float, bool]:
        exec_times_fixed = []
        exec_times_random = []

        for i in range(self.num_measurements):
            # Alternate between fixed and random input
            if i % 2 == 0:
                inp = fixed_input
                t0 = time.perf_counter_ns()
                crypto_func(inp)
                t1 = time.perf_counter_ns()
                exec_times_fixed.append(t1 - t0)
            else:
                inp = bytes(np.random.randint(0, 256, input_len, dtype=np.uint8))
                t0 = time.perf_counter_ns()
                crypto_func(inp)
                t1 = time.perf_counter_ns()
                exec_times_random.append(t1 - t0)

        # Welch's t-test
        mean_fixed = np.mean(exec_times_fixed)
        var_fixed = np.var(exec_times_fixed, ddof=1)
        n_fixed = len(exec_times_fixed)

        mean_random = np.mean(exec_times_random)
        var_random = np.var(exec_times_random, ddof=1)
        n_random = len(exec_times_random)

        std_err = np.sqrt((var_fixed / n_fixed) + (var_random / n_random))
        if std_err == 0:
            return 0.0, True

        t_statistic = (mean_fixed - mean_random) / std_err
        is_constant_time = abs(t_statistic) < 4.5

        return float(t_statistic), is_constant_time
