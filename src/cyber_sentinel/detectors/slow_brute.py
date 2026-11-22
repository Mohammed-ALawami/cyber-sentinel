from __future__ import annotations

from bisect import insort
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List

from .. import scoring
from ..models import AuthEvent, Signal
from .base import Detector


class SlowBruteDetector(Detector):
    """Low-and-slow failed logins: few enough to dodge the burst window,
    persistent enough to matter over a longer horizon.

    Fires when one source IP accumulates `slow_brute_threshold` failures
    inside `slow_window_seconds` AND those failures span at least
    `slow_min_span_seconds`. The span requirement is what keeps ordinary
    bursts from being reported twice: a fast attack is already caught by
    BruteForceDetector, this one exists for attacks paced under it.
    """

    name = "slow_brute"
    mitre = "T1110 Brute Force"

    def __init__(self, config) -> None:
        super().__init__(config)
        self._failures: Dict[str, List[AuthEvent]] = defaultdict(list)
        self._latest: Dict[str, datetime] = {}

    def reset(self) -> None:
        super().reset()
        self._failures.clear()
        self._latest.clear()

    def on_event(self, event: AuthEvent) -> List[Signal]:
        if not event.is_failure or not event.source_ip:
            return []
        ip = event.source_ip
        latest = max(self._latest.get(ip, event.ts), event.ts)
        self._latest[ip] = latest

        q = self._failures[ip]
        insort(q, event, key=lambda e: e.ts)
        horizon = latest - timedelta(seconds=self.config.slow_window_seconds)
        while q and q[0].ts < horizon:
            q.pop(0)

        if len(q) < self.config.slow_brute_threshold:
            return []
        span = (q[-1].ts - q[0].ts).total_seconds()
        if span < self.config.slow_min_span_seconds:
            return []  # fast attack: BruteForceDetector's job, not this one's
        if not self._cooldown_ok(ip, event.ts):
            return []

        per_user: Dict[str, int] = defaultdict(int)
        for ev in q:
            per_user[ev.user or "?"] += 1
        top_user, top_count = max(per_user.items(), key=lambda kv: kv[1])
        sensitive = any(u in self.config.sensitive_users for u in per_user)
        points = scoring.SLOW_BRUTE_POINTS + (
            scoring.SENSITIVE_USER_BONUS if sensitive else 0)
        explanation = (
            f"{len(q)} failed logins from {ip} spread over {int(span)}s "
            f"(too slow for the {self.config.window_seconds}s burst window). "
            f"Most targeted account: '{top_user}' ({top_count} attempts, "
            f"{len(per_user)} account(s) total)."
        )
        return [Signal(
            detector=self.name,
            title="Slow, persistent failed logins",
            explanation=explanation,
            points=points,
            ts=event.ts,
            evidence=tuple(ev.raw for ev in q[-self.config.evidence_lines:]),
            key=ip,
        )]
