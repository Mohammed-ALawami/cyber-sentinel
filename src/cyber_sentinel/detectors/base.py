from __future__ import annotations

import abc
from datetime import datetime
from typing import Dict, List

from ..config import Config
from ..models import AuthEvent, Signal


class Detector(abc.ABC):
    """A stateful rule that inspects one event at a time.

    Detectors keep their own sliding-window state and fire at most once per
    key per cooldown period, so a long attack escalates one alert instead of
    flooding the feed with duplicates.
    """

    name: str = "detector"

    def __init__(self, config: Config) -> None:
        self.config = config
        self._last_fired: Dict[str, datetime] = {}

    @abc.abstractmethod
    def on_event(self, event: AuthEvent) -> List[Signal]:
        ...

    def reset(self) -> None:
        self._last_fired.clear()

    def _cooldown_ok(self, key: str, ts: datetime) -> bool:
        last = self._last_fired.get(key)
        if last is not None and (ts - last).total_seconds() < self.config.detector_cooldown_seconds:
            return False
        self._last_fired[key] = ts
        return True
