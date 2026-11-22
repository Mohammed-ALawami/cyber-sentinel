"""Point weights for explainable risk scoring.

Every point an alert carries comes from a named rule below, and the alert
keeps the per-signal breakdown so the UI can show exactly where the score
came from. A score is NOT a probability: 70 means "signals worth 70 points
fired", never "70% likely to be an attack".
"""

SCORE_CAP = 100

# Repeated failed logins from one source.
BRUTE_FORCE_BASE = 35
BRUTE_FORCE_PER_EXTRA_FAILURE = 2
BRUTE_FORCE_EXTRA_CAP = 20

# Low-and-slow failed logins under the burst window.
SLOW_BRUTE_POINTS = 30

# One source failing against many distinct accounts.
SPRAY_BASE = 45
SPRAY_PER_EXTRA_USER = 3
SPRAY_EXTRA_CAP = 24

# Modifiers and standalone signals.
SENSITIVE_USER_BONUS = 15
NEW_SOURCE_POINTS = 25
OFF_HOURS_POINTS = 20


def brute_force_points(failures: int, threshold: int, sensitive: bool) -> int:
    extra = min(BRUTE_FORCE_EXTRA_CAP,
                BRUTE_FORCE_PER_EXTRA_FAILURE * max(0, failures - threshold))
    return BRUTE_FORCE_BASE + extra + (SENSITIVE_USER_BONUS if sensitive else 0)


def spray_points(distinct_users: int, threshold: int, sensitive_hit: bool) -> int:
    extra = min(SPRAY_EXTRA_CAP,
                SPRAY_PER_EXTRA_USER * max(0, distinct_users - threshold))
    return SPRAY_BASE + extra + (SENSITIVE_USER_BONUS if sensitive_hit else 0)


def combine(points_by_detector: dict) -> int:
    """One contribution per detector (the strongest seen), summed and capped."""
    return min(SCORE_CAP, sum(points_by_detector.values()))
