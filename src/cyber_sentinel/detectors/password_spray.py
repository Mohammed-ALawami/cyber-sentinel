from __future__ import annotations

from bisect import insort
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List

from .. import scoring
from ..models import AuthEvent, Signal
from .base import Detector


class PasswordSprayDetector(Detector):
    """One source IP failing against many distinct accounts in a window.

    This is the low-and-slow pattern a per-account counter misses: few
    attempts per user, but a wide spread across users. The window is kept
    sorted and pruned against the newest timestamp seen, so out-of-order
    lines count the same as ordered ones.
    """

    name = "password_spray"
    mitre = "T1110.003 Password Spraying"

    def __init__(self, config) -> None:
        super().__init__(config)
        self._attempts: Dict[str, List[AuthEvent]] = defaultdict(list)
        self._latest: Dict[str, datetime] = {}

    def reset(self) -> None:
        super().reset()
        self._attempts.clear()
        self._latest.clear()

    def on_event(self, event: AuthEvent) -> List[Signal]:
        if not event.is_failure or not event.source_ip:
            return []
        ip = event.source_ip
        latest = max(self._latest.get(ip, event.ts), event.ts)
        self._latest[ip] = latest

        q = self._attempts[ip]
        insort(q, event, key=lambda e: e.ts)
        horizon = latest - timedelta(seconds=self.config.window_seconds)
        while q and q[0].ts < horizon:
            q.pop(0)

        users = {ev.user for ev in q if ev.user}
        if len(users) < self.config.spray_threshold:
            return []
        if not self._cooldown_ok(ip, event.ts):
            return []

        sensitive_hit = bool(users & set(self.config.sensitive_users))
        points = scoring.spray_points(len(users), self.config.spray_threshold, sensitive_hit)
        span = int((q[-1].ts - q[0].ts).total_seconds())
        sample = ", ".join(sorted(users)[:6]) + (" ..." if len(users) > 6 else "")
        explanation = (
            f"{ip} failed against {len(users)} distinct accounts "
            f"within {span}s ({sample}). One password tried across many accounts "
            f"fits password spraying."
        )
        return [Signal(
            detector=self.name,
            title="Possible password spraying",
            explanation=explanation,
            points=points,
            ts=event.ts,
            evidence=tuple(ev.raw for ev in q[-self.config.evidence_lines:]),
            key=ip,
        )]
