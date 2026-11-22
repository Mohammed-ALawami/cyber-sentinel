"""Lines that arrive out of order (backfills, batched uploads) must count
exactly like ordered ones, and ancient lines must not inflate the window."""
from datetime import datetime, timedelta

from cyber_sentinel.config import Config
from cyber_sentinel.detectors import BruteForceDetector
from cyber_sentinel.models import AuthEvent, EventKind

T0 = datetime(2026, 11, 22, 10, 0, 0)


def fail(at):
    return AuthEvent(at, EventKind.AUTH_FAILED, "admin", "203.0.113.7",
                     "srv", "password", "raw")


def test_shuffled_arrival_still_detects_once():
    d = BruteForceDetector(Config())
    offsets = [30, 0, 40, 10, 50, 20, 60, 70, 80, 90]  # shuffled, all in window
    fired = []
    for off in offsets:
        fired.extend(d.on_event(fail(T0 + timedelta(seconds=off))))
    assert len(fired) == 1


def test_ancient_backfill_does_not_inflate_window():
    d = BruteForceDetector(Config())
    d.on_event(fail(T0 + timedelta(seconds=1000)))  # establishes "now"
    d.on_event(fail(T0))                            # ancient: outside the window
    fired = []
    for i in range(8):                              # 9 in-window so far
        fired.extend(d.on_event(fail(T0 + timedelta(seconds=1001 + i))))
    assert fired == [], "ancient line must not count toward the threshold"
    fired = d.on_event(fail(T0 + timedelta(seconds=1010)))
    assert len(fired) == 1, "the 10th in-window failure fires"
