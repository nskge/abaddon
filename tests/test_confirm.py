"""Unit tests for the confirmation primitives (false-positive reduction)."""

import unittest

from scanner.confirm import confirm_time_based, confirm_repeated


class TestConfirmTimeBased(unittest.TestCase):
    """Differential-timing confirmation."""

    def test_scaling_delay_confirmed(self):
        """A delay that scales with the sleep (3.5s @ 2s, 7.0s @ 4s) is confirmed."""
        confirmed, second = confirm_time_based(
            measure=lambda d: 7.0,        # 2x sleep -> ~2x delay
            base_delay=2.0,
            first_elapsed=3.5,
            baseline_avg=0.1,
        )
        self.assertTrue(confirmed)
        self.assertEqual(second, 7.0)

    def test_nonscaling_spike_rejected(self):
        """A one-off spike (first slow, re-test fast) is rejected."""
        confirmed, second = confirm_time_based(
            measure=lambda d: 0.2,        # 2x sleep but stays fast
            base_delay=2.0,
            first_elapsed=3.5,
            baseline_avg=0.1,
        )
        self.assertFalse(confirmed)

    def test_failed_request_rejected(self):
        """If the confirmation request fails (None), it is not confirmed."""
        confirmed, second = confirm_time_based(
            measure=lambda d: None,
            base_delay=2.0,
            first_elapsed=3.5,
            baseline_avg=0.1,
        )
        self.assertFalse(confirmed)
        self.assertIsNone(second)

    def test_slow_but_not_scaling_rejected(self):
        """Constant high latency (same time regardless of sleep) is rejected by slope check."""
        # second_elapsed equals first_elapsed -> extra sleep didn't show up
        confirmed, _ = confirm_time_based(
            measure=lambda d: 3.5,
            base_delay=2.0,
            first_elapsed=3.5,
            baseline_avg=0.1,
        )
        self.assertFalse(confirmed)

    def test_measure_receives_doubled_delay(self):
        """The confirmation must request 2x the base delay by default."""
        seen = []

        def measure(d):
            seen.append(d)
            return 7.0

        confirm_time_based(measure, base_delay=2.0, first_elapsed=3.5, baseline_avg=0.1)
        self.assertEqual(seen, [4.0])


class TestConfirmRepeated(unittest.TestCase):
    def test_all_true_confirms(self):
        self.assertTrue(confirm_repeated(lambda: True, attempts=3))

    def test_any_false_rejects(self):
        calls = iter([True, False])
        self.assertFalse(confirm_repeated(lambda: next(calls), attempts=2))

    def test_zero_attempts_is_true(self):
        self.assertTrue(confirm_repeated(lambda: False, attempts=0))


if __name__ == "__main__":
    unittest.main()
