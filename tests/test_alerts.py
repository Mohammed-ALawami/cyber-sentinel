from datetime import datetime, timedelta

from cyber_sentinel.alerts import AlertEngine
from cyber_sentinel.config import Config
from cyber_sentinel.models import Signal

T0 = datetime(2026, 11, 22, 10, 0, 0)


def sig(detector, points, key="203.0.113.7", at=T0):
    return Signal(detector=detector, title=f"{detector} fired",
                  explanation="because reasons", points=points, ts=at, key=key)


class TestAlertGrouping:
    def test_same_key_joins_one_alert(self):
        eng = AlertEngine(Config())
        a1, created1 = eng.absorb(sig("brute_force", 50))
        a2, created2 = eng.absorb(sig("new_source", 40, at=T0 + timedelta(minutes=2)))
        assert created1 and not created2
        assert a1 is a2 and a1.score == 90

    def test_detector_takes_strongest_not_sum(self):
        eng = AlertEngine(Config())
        eng.absorb(sig("brute_force", 50))
        alert, _ = eng.absorb(sig("brute_force", 62, at=T0 + timedelta(minutes=3)))
        assert alert.score == 62  # escalated, not 112

    def test_stale_key_starts_new_alert(self):
        eng = AlertEngine(Config())
        eng.absorb(sig("brute_force", 50))
        _, created = eng.absorb(
            sig("brute_force", 50, at=T0 + timedelta(seconds=Config().alert_grouping_seconds + 60)))
        assert created

    def test_summary_names_contributions(self):
        eng = AlertEngine(Config())
        alert, _ = eng.absorb(sig("password_spray", 45))
        assert "password spray +45" in alert.summary()
