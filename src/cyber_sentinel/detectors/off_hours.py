from __future__ import annotations

from typing import List

from .. import scoring
from ..models import AuthEvent, EventKind, Signal
from .base import Detector


class OffHoursDetector(Detector):
    """Successful login for a sensitive account outside normal hours.

    Normal hours are a configured local-time window (default 07:00-22:00).
    This only watches sensitive accounts; ordinary users working late are
    not suspicious on their own.
    """

    name = "off_hours"

    def on_event(self, event: AuthEvent) -> List[Signal]:
        if event.kind is not EventKind.AUTH_SUCCESS or not event.user:
            return []
        if event.user not in self.config.sensitive_users:
            return []
        hour = event.ts.hour
        if self.config.off_hours_start <= hour < self.config.off_hours_end:
            return []
        if not self._cooldown_ok(f"{event.user}@{event.source_ip}", event.ts):
            return []

        points = scoring.OFF_HOURS_POINTS
        explanation = (
            f"Sensitive account '{event.user}' logged in at "
            f"{event.ts.strftime('%H:%M')}, outside the configured normal window "
            f"({self.config.off_hours_start:02d}:00-{self.config.off_hours_end:02d}:00)."
        )
        return [Signal(
            detector=self.name,
            title="Sensitive login outside normal hours",
            explanation=explanation,
            points=points,
            ts=event.ts,
            evidence=(event.raw,),
            key=event.source_ip or event.user,
        )]
