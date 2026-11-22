"""Group signals into alerts and keep scores explainable.

Signals that blame the same key (normally a source IP) within
config.alert_grouping_seconds join one alert. The alert score is the capped
sum of the strongest signal from each detector, so a detector that fires
repeatedly can escalate an alert but never double-counts itself.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from . import scoring
from .config import Config
from .models import Signal, severity_for


@dataclass
class Alert:
    key: str
    title: str
    first_seen: datetime
    last_seen: datetime
    points_by_detector: Dict[str, int] = field(default_factory=dict)
    signals: List[Signal] = field(default_factory=list)
    id: Optional[int] = None

    @property
    def score(self) -> int:
        return scoring.combine(self.points_by_detector)

    @property
    def severity(self) -> str:
        return severity_for(self.score)

    def summary(self) -> str:
        parts = [f"{det.replace('_', ' ')} +{pts}" for det, pts in
                 sorted(self.points_by_detector.items(), key=lambda kv: -kv[1])]
        return "; ".join(parts)


class AlertEngine:
    def __init__(self, config: Config) -> None:
        self.config = config
        self._open: Dict[str, Alert] = {}

    def absorb(self, signal: Signal) -> Tuple[Alert, bool]:
        key = signal.key or signal.detector
        alert = self._open.get(key)
        if alert is not None and \
                (signal.ts - alert.last_seen).total_seconds() > self.config.alert_grouping_seconds:
            alert = None  # too old: a new incident, not a continuation
        created = alert is None
        if created:
            alert = Alert(key=key, title=signal.title,
                          first_seen=signal.ts, last_seen=signal.ts)
            self._open[key] = alert
        alert.last_seen = max(alert.last_seen, signal.ts)
        alert.signals.append(signal)
        previous = alert.points_by_detector.get(signal.detector, 0)
        alert.points_by_detector[signal.detector] = max(previous, signal.points)
        return alert, created

    def reset(self) -> None:
        self._open.clear()
