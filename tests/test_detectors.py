from datetime import datetime, timedelta

from cyber_sentinel.config import Config
from cyber_sentinel.detectors import (BruteForceDetector, NewSourceDetector,
                                      OffHoursDetector, PasswordSprayDetector)
from cyber_sentinel.models import AuthEvent, EventKind

CFG = Config()
T0 = datetime(2026, 11, 22, 10, 0, 0)


def fail(user="user1", ip="203.0.113.7", at=T0):
    return AuthEvent(at, EventKind.AUTH_FAILED, user, ip, "srv", "password", "raw")


def ok(user="user1", ip="198.51.100.11", at=T0):
    return AuthEvent(at, EventKind.AUTH_SUCCESS, user, ip, "srv", "password", "raw")


class TestBruteForce:
    def test_below_threshold_is_quiet(self):
        d = BruteForceDetector(CFG)
        for i in range(CFG.brute_force_threshold - 1):
            assert d.on_event(fail(at=T0 + timedelta(seconds=i))) == []

    def test_fires_at_threshold_with_explanation(self):
        d = BruteForceDetector(CFG)
        sigs = []
        for i in range(CFG.brute_force_threshold):
            sigs = d.on_event(fail(user="admin", at=T0 + timedelta(seconds=i * 5)))
        assert len(sigs) == 1
        sig = sigs[0]
        assert sig.detector == "brute_force" and sig.points > 0
        assert "admin" in sig.explanation and sig.evidence

    def test_cooldown_prevents_refire(self):
        d = BruteForceDetector(CFG)
        for i in range(CFG.brute_force_threshold):
            d.on_event(fail(at=T0 + timedelta(seconds=i * 5)))
        assert d.on_event(fail(at=T0 + timedelta(seconds=60))) == []

    def test_spaced_failures_never_fill_window(self):
        d = BruteForceDetector(CFG)
        for i in range(8):
            assert d.on_event(fail(at=T0 + timedelta(seconds=i * 80))) == []

    def test_successes_do_not_count(self):
        d = BruteForceDetector(CFG)
        for i in range(20):
            assert d.on_event(ok(at=T0 + timedelta(seconds=i))) == []


class TestPasswordSpray:
    def test_needs_distinct_users(self):
        d = PasswordSprayDetector(CFG)
        for i in range(8):
            assert d.on_event(fail(user="same", at=T0 + timedelta(seconds=i))) == []

    def test_fires_on_spread(self):
        d = PasswordSprayDetector(CFG)
        sigs = []
        for i, user in enumerate(["a", "b", "c", "d", "e"]):
            sigs = d.on_event(fail(user=user, at=T0 + timedelta(seconds=i * 10)))
        assert len(sigs) == 1 and sigs[0].detector == "password_spray"


class TestNewSource:
    def test_first_fire_only_after_baseline(self):
        d = NewSourceDetector(CFG)
        home = "198.51.100.11"
        for i in range(CFG.new_source_min_history):
            assert d.on_event(ok(ip=home, at=T0 + timedelta(minutes=i))) == []
        sigs = d.on_event(ok(ip="203.0.113.9", at=T0 + timedelta(minutes=9)))
        assert len(sigs) == 1 and "first time" in sigs[0].explanation

    def test_known_address_stays_quiet(self):
        d = NewSourceDetector(CFG)
        home = "198.51.100.11"
        for i in range(5):
            d.on_event(ok(ip=home, at=T0 + timedelta(minutes=i)))
        assert d.on_event(ok(ip=home, at=T0 + timedelta(minutes=9))) == []


class TestOffHours:
    def test_sensitive_user_at_3am_fires(self):
        d = OffHoursDetector(CFG)
        at = datetime(2026, 11, 23, 3, 12, 0)
        sigs = d.on_event(ok(user="root", at=at))
        assert len(sigs) == 1 and sigs[0].detector == "off_hours"

    def test_sensitive_user_at_noon_is_quiet(self):
        d = OffHoursDetector(CFG)
        at = datetime(2026, 11, 22, 12, 0, 0)
        assert d.on_event(ok(user="root", at=at)) == []

    def test_ordinary_user_at_3am_is_quiet(self):
        d = OffHoursDetector(CFG)
        at = datetime(2026, 11, 23, 3, 12, 0)
        assert d.on_event(ok(user="sara", at=at)) == []


class TestSlowBrute:
    def test_spaced_failures_fire(self):
        from cyber_sentinel.detectors import SlowBruteDetector
        d = SlowBruteDetector(CFG)
        fired = []
        for i in range(8):  # 80s apart: under the burst window, over the span minimum
            fired.extend(d.on_event(fail(user="admin", at=T0 + timedelta(seconds=i * 80))))
        assert len(fired) == 1
        assert fired[0].detector == "slow_brute"
        assert "admin" in fired[0].explanation and fired[0].evidence

    def test_burst_does_not_double_report(self):
        from cyber_sentinel.detectors import SlowBruteDetector
        d = SlowBruteDetector(CFG)
        # 10 failures in 50s: over the long-window threshold but under the span minimum
        for i in range(10):
            assert d.on_event(fail(at=T0 + timedelta(seconds=i * 5))) == []

    def test_below_long_threshold_is_quiet(self):
        from cyber_sentinel.detectors import SlowBruteDetector
        d = SlowBruteDetector(CFG)
        for i in range(CFG.slow_brute_threshold - 1):
            assert d.on_event(fail(at=T0 + timedelta(seconds=i * 80))) == []

    def test_span_boundary(self):
        from cyber_sentinel.detectors import SlowBruteDetector
        # failures exactly at the minimum span must fire; one second less must not
        d = SlowBruteDetector(CFG)
        n = CFG.slow_brute_threshold
        step = CFG.slow_min_span_seconds // (n - 1)
        sigs = []
        for i in range(n):
            sigs = d.on_event(fail(at=T0 + timedelta(seconds=i * step)))
        assert len(sigs) == 1  # span == exactly slow_min_span_seconds

        d2 = SlowBruteDetector(CFG)
        step2 = (CFG.slow_min_span_seconds - 1) // (n - 1)
        for i in range(n):
            assert d2.on_event(fail(at=T0 + timedelta(seconds=i * step2))) == []

    def test_cooldown_prevents_refire(self):
        from cyber_sentinel.detectors import SlowBruteDetector
        d = SlowBruteDetector(CFG)
        for i in range(8):
            d.on_event(fail(at=T0 + timedelta(seconds=i * 80)))
        assert d.on_event(fail(at=T0 + timedelta(seconds=700))) == []

    def test_successes_do_not_count(self):
        from cyber_sentinel.detectors import SlowBruteDetector
        d = SlowBruteDetector(CFG)
        for i in range(20):
            assert d.on_event(ok(at=T0 + timedelta(seconds=i * 60))) == []


class TestMitreMapping:
    """Every detector either names its ATT&CK technique or honestly has none."""

    def test_mappings_present_and_verified(self):
        from cyber_sentinel.detectors import default_detectors
        mapping = {d.name: getattr(d, "mitre", None) for d in default_detectors(CFG)}
        assert mapping == {
            "brute_force": "T1110 Brute Force",
            "password_spray": "T1110.003 Password Spraying",
            "slow_brute": "T1110 Brute Force",
            "new_source": "T1078 Valid Accounts",
            "off_hours": None,  # contextual rule, no direct ATT&CK technique
        }
