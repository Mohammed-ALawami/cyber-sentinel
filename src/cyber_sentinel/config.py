"""Tunable thresholds for detection and alerting.

Defaults are chosen for the replayed demo scenarios; every value is
injectable so tests and the evaluation harness can vary them. Nothing here
is secret and nothing is tuned to make results look better than they are.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet


@dataclass(frozen=True)
class Config:
    window_seconds: int = 300             # shared sliding window for burst detectors
    brute_force_threshold: int = 10       # failed logins from one IP inside the window
    slow_window_seconds: int = 900        # longer horizon for low-and-slow attempts
    slow_brute_threshold: int = 6         # failures from one IP inside the long window
    slow_min_span_seconds: int = 420      # min failure spread, so bursts are not double-reported
    spray_threshold: int = 5              # distinct users targeted by one IP inside the window
    detector_cooldown_seconds: int = 300  # min gap before a detector re-fires on the same key
    alert_grouping_seconds: int = 900     # signals within this gap join the same open alert
    off_hours_start: int = 7              # 07:00 local ...
    off_hours_end: int = 22               # ... to 22:00 local counts as normal activity
    sensitive_users: FrozenSet[str] = frozenset({"root", "admin", "administrator"})
    new_source_min_history: int = 3       # successes a user needs before a new IP is suspicious
    evidence_lines: int = 5               # raw lines kept per signal
    assumed_year: int = 2026              # syslog lines carry no year; replayed data uses this one
