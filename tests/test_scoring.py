from cyber_sentinel import scoring
from cyber_sentinel.models import severity_for


def test_severity_bands():
    assert severity_for(0) == "info"
    assert severity_for(1) == "low"
    assert severity_for(29) == "low"
    assert severity_for(30) == "medium"
    assert severity_for(60) == "high"
    assert severity_for(85) == "critical"
    assert severity_for(100) == "critical"


def test_brute_force_points_scale_and_cap():
    base = scoring.brute_force_points(10, 10, sensitive=False)
    more = scoring.brute_force_points(40, 10, sensitive=False)
    sens = scoring.brute_force_points(40, 10, sensitive=True)
    assert base == scoring.BRUTE_FORCE_BASE
    assert more == scoring.BRUTE_FORCE_BASE + scoring.BRUTE_FORCE_EXTRA_CAP
    assert sens == more + scoring.SENSITIVE_USER_BONUS


def test_combine_caps_at_100():
    assert scoring.combine({"a": 70, "b": 70}) == 100
    assert scoring.combine({"a": 40, "b": 25}) == 65
    assert scoring.combine({}) == 0
