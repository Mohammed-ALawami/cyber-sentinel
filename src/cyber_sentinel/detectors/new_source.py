from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Set

from .. import scoring
from ..models import AuthEvent, EventKind, Signal
from .base import Detector


class NewSourceDetector(Detector):
    """Successful login from an IP the account has never used before.

    Requires a baseline of prior successes (config.new_source_min_history),
    so the first logins in a fresh dataset do not all fire. Grouped by
    source IP, so a success after a brute-force burst from the same IP
    escalates the existing alert instead of opening a second one.
    """

    name = "new_source"
    mitre = "T1078 Valid Accounts"

    def __init__(self, config) -> None:
        super().__init__(config)
        self._known_ips: Dict[str, Set[str]] = defaultdict(set)
        self._success_count: Dict[str, int] = defaultdict(int)

    def reset(self) -> None:
        super().reset()
        self._known_ips.clear()
        self._success_count.clear()

    def on_event(self, event: AuthEvent) -> List[Signal]:
        if event.kind is not EventKind.AUTH_SUCCESS or not event.user or not event.source_ip:
            return []
        user, ip = event.user, event.source_ip
        known = self._known_ips[user]
        history = self._success_count[user]
        first_seen = ip not in known
        known.add(ip)
        self._success_count[user] += 1

        if not first_seen or history < self.config.new_source_min_history:
            return []
        if not self._cooldown_ok(f"{user}@{ip}", event.ts):
            return []

        sensitive = user in self.config.sensitive_users
        points = scoring.NEW_SOURCE_POINTS + (scoring.SENSITIVE_USER_BONUS if sensitive else 0)
        explanation = (
            f"Account '{user}' logged in successfully from {ip} for the first time "
            f"after {history} previous logins from other addresses."
        )
        return [Signal(
            detector=self.name,
            title="Login from a new source address",
            explanation=explanation,
            points=points,
            ts=event.ts,
            evidence=(event.raw,),
            key=ip,
        )]
