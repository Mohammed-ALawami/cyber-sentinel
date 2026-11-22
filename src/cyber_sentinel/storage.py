"""SQLite persistence. Stdlib sqlite3 on purpose: v1 has three tables and
no relational complexity worth an ORM. WAL mode lets the dashboard read
while ingestion writes."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional

from .alerts import Alert
from .models import AuthEvent, Signal

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  kind TEXT NOT NULL,
  user TEXT,
  source_ip TEXT,
  host TEXT,
  method TEXT,
  raw TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL,
  title TEXT NOT NULL,
  score INTEGER NOT NULL,
  severity TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  signal_count INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'open'
);
CREATE TABLE IF NOT EXISTS signals(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  alert_id INTEGER NOT NULL REFERENCES alerts(id),
  detector TEXT NOT NULL,
  title TEXT NOT NULL,
  explanation TEXT NOT NULL,
  points INTEGER NOT NULL,
  ts TEXT NOT NULL,
  evidence TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_signals_alert ON signals(alert_id);
"""


class Storage:
    def __init__(self, path: str = ":memory:") -> None:
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(_SCHEMA)
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    # ---- events ----
    def add_event(self, ev: AuthEvent) -> int:
        cur = self.db.execute(
            "INSERT INTO events(ts, kind, user, source_ip, host, method, raw)"
            " VALUES(?,?,?,?,?,?,?)",
            (ev.ts.isoformat(), ev.kind.value, ev.user, ev.source_ip,
             ev.host, ev.method, ev.raw))
        self.db.commit()
        return int(cur.lastrowid)

    def recent_events(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        rows = self.db.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset)).fetchall()
        return [dict(r) for r in rows]

    def iter_events_ascending(self, limit: int = 200_000) -> List[Dict]:
        """The most recent `limit` events in chronological (insertion) order.

        Used to rebuild detector memory after a restart. Bounded so a huge
        database does not make startup slow; see README for the tradeoff.
        """
        rows = self.db.execute(
            "SELECT * FROM (SELECT * FROM events ORDER BY id DESC LIMIT ?)"
            " ORDER BY id", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def reset(self) -> None:
        """Delete ALL stored synthetic demo data (events, alerts, signals).

        Only reachable through the explicit demo-reset endpoint/button.
        """
        self.db.executescript(
            "DELETE FROM signals; DELETE FROM alerts; DELETE FROM events;")
        self.db.commit()

    def event_count(self) -> int:
        return int(self.db.execute("SELECT COUNT(*) c FROM events").fetchone()["c"])

    # ---- alerts ----
    def upsert_alert(self, alert: Alert) -> int:
        if alert.id is None:
            cur = self.db.execute(
                "INSERT INTO alerts(key, title, score, severity, summary,"
                " first_seen, last_seen, signal_count) VALUES(?,?,?,?,?,?,?,?)",
                (alert.key, alert.title, alert.score, alert.severity,
                 alert.summary(), alert.first_seen.isoformat(),
                 alert.last_seen.isoformat(), len(alert.signals)))
            self.db.commit()
            return int(cur.lastrowid)
        self.db.execute(
            "UPDATE alerts SET score=?, severity=?, summary=?, last_seen=?,"
            " signal_count=? WHERE id=?",
            (alert.score, alert.severity, alert.summary(),
             alert.last_seen.isoformat(), len(alert.signals), alert.id))
        self.db.commit()
        return alert.id

    def add_signal(self, alert_id: int, sig: Signal) -> int:
        cur = self.db.execute(
            "INSERT INTO signals(alert_id, detector, title, explanation,"
            " points, ts, evidence) VALUES(?,?,?,?,?,?,?)",
            (alert_id, sig.detector, sig.title, sig.explanation, sig.points,
             sig.ts.isoformat(), json.dumps(list(sig.evidence))))
        self.db.commit()
        return int(cur.lastrowid)

    def list_alerts(self, limit: int = 50, offset: int = 0,
                    status: Optional[str] = None) -> List[Dict]:
        if status is not None:
            rows = self.db.execute(
                "SELECT * FROM alerts WHERE status=?"
                " ORDER BY last_seen DESC LIMIT ? OFFSET ?",
                (status, limit, offset)).fetchall()
        else:
            rows = self.db.execute(
                "SELECT * FROM alerts ORDER BY last_seen DESC LIMIT ? OFFSET ?",
                (limit, offset)).fetchall()
        return [dict(r) for r in rows]

    def set_alert_status(self, alert_id: int, status: str) -> bool:
        """Triage an alert: open -> acknowledged -> resolved (reopen allowed).

        Deliberately a small, permissive triage state, not a strict ticket
        workflow; the allowed values are enforced by the API layer. Returns
        False when the alert does not exist.
        """
        cur = self.db.execute("UPDATE alerts SET status=? WHERE id=?",
                              (status, alert_id))
        self.db.commit()
        return cur.rowcount > 0

    def alert_status(self, alert_id: int) -> Optional[str]:
        row = self.db.execute("SELECT status FROM alerts WHERE id=?",
                              (alert_id,)).fetchone()
        return None if row is None else str(row["status"])

    def get_alert(self, alert_id: int) -> Optional[Dict]:
        row = self.db.execute("SELECT * FROM alerts WHERE id=?",
                              (alert_id,)).fetchone()
        if row is None:
            return None
        alert = dict(row)
        sig_rows = self.db.execute(
            "SELECT * FROM signals WHERE alert_id=? ORDER BY ts",
            (alert_id,)).fetchall()
        alert["signals"] = [
            {**dict(s), "evidence": json.loads(s["evidence"])} for s in sig_rows]
        return alert

    def alert_count(self) -> int:
        return int(self.db.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"])

    def stats(self) -> Dict:
        by_sev = {r["severity"]: r["c"] for r in self.db.execute(
            "SELECT severity, COUNT(*) c FROM alerts GROUP BY severity")}
        by_status = {r["status"]: r["c"] for r in self.db.execute(
            "SELECT status, COUNT(*) c FROM alerts GROUP BY status")}
        top = self.db.execute(
            "SELECT key, MAX(score) s FROM alerts GROUP BY key"
            " ORDER BY s DESC LIMIT 5").fetchall()
        return {
            "events": self.event_count(),
            "alerts": self.alert_count(),
            "alerts_by_severity": by_sev,
            "alerts_by_status": by_status,
            "top_risk_sources": [{"key": r["key"], "score": r["s"]} for r in top],
        }
