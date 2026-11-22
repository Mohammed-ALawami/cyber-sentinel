from __future__ import annotations

from bisect import insort
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List

from .. import scoring
from ..models import AuthEvent, Signal
from .base import Detector


class BruteForceDetector(Detector):
    """Many failed logins from one source IP inside a sliding window.

    The window is kept sorted by event time and pruned against the newest
    timestamp seen for that IP, so lines that arrive out of order (backfills,
    batched uploads) count the same as perfectly ordered ones.
    """

    name = "brute_force"
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
        horizon = latest - timedelta(seconds=self.config.window_seconds)
        while q and q[0].ts < horizon:
            q.pop(0)

        if len(q) < self.config.brute_force_threshold:
            return []
        if not self._cooldown_ok(ip, event.ts):
            return []

        per_user: Dict[str, int] = defaultdict(int)
        for ev in q:
            per_user[ev.user or "?"] += 1
        top_user, top_count = max(per_user.items(), key=lambda kv: kv[1])
        sensitive = any(u in self.config.sensitive_users for u in per_user)
        points = scoring.brute_force_points(len(q), self.config.brute_force_threshold, sensitive)
        span = int((q[-1].ts - q[0].ts).total_seconds())
        explanation = (
            f"{len(q)} failed logins from {ip} within {span}s. "
            f"Most targeted account: '{top_user}' ({top_count} attempts, "
            f"{len(per_user)} account(s) total)."
        )
        return [Signal(
            detector=self.name,
            title="Possible brute-force login attempts",
            explanation=explanation,
            points=points,
            ts=event.ts,
            evidence=tuple(ev.raw for ev in q[-self.config.evidence_lines:]),
            key=ip,
        )]
