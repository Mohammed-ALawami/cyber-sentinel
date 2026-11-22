"""The detection pipeline: raw log line in, explained alerts out.

Used identically by the HTTP app, the replay CLI and the evaluation
harness, so measured results describe the same code the demo runs.
"""
from __future__ import annotations

from typing import Callable, Dict, List, Optional

from .alerts import AlertEngine
from .config import Config
from .detectors import default_detectors
from .ingestion import parse_line
from .models import AuthEvent, event_from_row
from .storage import Storage


class Pipeline:
    def __init__(self, storage: Storage, config: Optional[Config] = None) -> None:
        self.config = config or Config()
        self.storage = storage
        self.detectors = default_detectors(self.config)
        self.alerts = AlertEngine(self.config)
        self.ingested = 0
        self.skipped = 0
        # Optional sync callbacks. The HTTP layer uses them to broadcast
        # over websockets; both fire after the row is persisted.
        self.on_alert: Optional[Callable[[Dict], None]] = None
        self.on_event: Optional[Callable[[Dict], None]] = None

    def rebuild_from_storage(self, limit: int = 200_000) -> int:
        """Rebuild detector memory from persisted events after a restart.

        Events are replayed through the detectors with their signals
        DISCARDED: the alerts those old events produced already exist in the
        database, so re-raising them would duplicate open alerts. Cooldown
        markers set during the rebuild also stop a re-ingested old log from
        alerting twice. Bounded to the most recent `limit` events.
        """
        rows = self.storage.iter_events_ascending(limit)
        for row in rows:
            ev = event_from_row(row)
            for det in self.detectors:
                det.on_event(ev)
        return len(rows)

    def reset(self) -> None:
        """Wipe all synthetic demo data and return every detector to fresh."""
        self.storage.reset()
        for det in self.detectors:
            det.reset()
        self.alerts.reset()
        self.ingested = 0
        self.skipped = 0

    def ingest_line(self, line: str) -> List[Dict]:
        ev = parse_line(line, self.config.assumed_year)
        if ev is None:
            self.skipped += 1
            return []
        return self.ingest_event(ev)

    def ingest_lines(self, lines: List[str]) -> List[Dict]:
        fired: List[Dict] = []
        for line in lines:
            fired.extend(self.ingest_line(line))
        return fired

    def ingest_event(self, ev: AuthEvent) -> List[Dict]:
        row_id = self.storage.add_event(ev)
        self.ingested += 1
        if self.on_event:
            self.on_event({"id": row_id, "ts": ev.ts.isoformat(),
                           "kind": ev.kind.value, "user": ev.user,
                           "source_ip": ev.source_ip, "host": ev.host,
                           "method": ev.method, "raw": ev.raw})
        fired: List[Dict] = []
        for det in self.detectors:
            for sig in det.on_event(ev):
                alert, created = self.alerts.absorb(sig)
                alert_id = self.storage.upsert_alert(alert)
                alert.id = alert_id
                self.storage.add_signal(alert_id, sig)
                if not created and self.storage.alert_status(alert_id) != "open":
                    # Reopen policy: NEW activity on a triaged alert puts it
                    # back in the open queue instead of updating it silently
                    # under acknowledged/resolved. Documented in the README.
                    self.storage.set_alert_status(alert_id, "open")
                record = self.storage.get_alert(alert_id)
                fired.append({"alert": record, "created": created})
                if self.on_alert:
                    self.on_alert(record)
        return fired
