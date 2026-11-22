"""Core data model for Cyber Sentinel.

Everything here is framework-free on purpose: the same objects flow through
the replay tool, the evaluation harness and the FastAPI app.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Tuple


class EventKind(str, Enum):
    AUTH_FAILED = "auth_failed"    # wrong password for an existing user
    INVALID_USER = "invalid_user"  # attempt against a user that does not exist
    AUTH_SUCCESS = "auth_success"
    OTHER = "other"                # parsed sshd line we do not classify further


@dataclass(frozen=True)
class AuthEvent:
    ts: datetime
    kind: EventKind
    user: Optional[str]
    source_ip: Optional[str]
    host: str
    method: Optional[str]
    raw: str

    @property
    def is_failure(self) -> bool:
        return self.kind in (EventKind.AUTH_FAILED, EventKind.INVALID_USER)


@dataclass(frozen=True)
class Signal:
    """One detector firing once, carrying its own explanation and evidence.

    `points` is a rule-based weight, never a probability. `key` names the
    blamed entity (normally a source IP) and decides which alert absorbs it.
    """
    detector: str
    title: str
    explanation: str
    points: int
    ts: datetime
    evidence: Tuple[str, ...] = ()
    key: str = ""


SEVERITY_BANDS = (
    (85, "critical"),
    (60, "high"),
    (30, "medium"),
    (1, "low"),
    (0, "info"),
)


def severity_for(score: int) -> str:
    for minimum, name in SEVERITY_BANDS:
        if score >= minimum:
            return name
    return "info"


def event_from_row(row: Dict) -> AuthEvent:
    """Rebuild an AuthEvent from a stored events-table row (for state rebuilds)."""
    return AuthEvent(
        ts=datetime.fromisoformat(row["ts"]),
        kind=EventKind(row["kind"]),
        user=row["user"],
        source_ip=row["source_ip"],
        host=row["host"] or "",
        method=row["method"],
        raw=row["raw"],
    )
