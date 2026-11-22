"""Parse OpenSSH/sshd syslog lines into AuthEvents.

Only well-known sshd message shapes are classified; anything else yields an
OTHER event or None, so callers can count skipped lines instead of guessing.
Syslog timestamps carry no year, so the caller supplies the year the data
belongs to (Config.assumed_year for replayed data).
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import List, Optional, Tuple

from .models import AuthEvent, EventKind

_PREFIX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hms>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)

_FAILED_INVALID = re.compile(r"^Failed password for invalid user (?P<user>\S+) from (?P<ip>\S+) port \d+")
_FAILED = re.compile(r"^Failed password for (?P<user>\S+) from (?P<ip>\S+) port \d+")
_ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port \d+")

_MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


def parse_line(line: str, year: int) -> Optional[AuthEvent]:
    m = _PREFIX.match(line.strip())
    if not m:
        return None
    month = _MONTHS.get(m["month"])
    if month is None:
        return None
    try:
        ts = datetime.strptime(
            f"{year} {month} {m['day']} {m['hms']}", "%Y %m %d %H:%M:%S")
    except ValueError:
        return None
    msg, host = m["msg"], m["host"]
    raw = line.rstrip("\n")

    for pattern, kind in ((_FAILED_INVALID, EventKind.INVALID_USER),
                          (_FAILED, EventKind.AUTH_FAILED)):
        mm = pattern.match(msg)
        if mm:
            return AuthEvent(ts, kind, mm["user"], mm["ip"], host, "password", raw)

    mm = _ACCEPTED.match(msg)
    if mm:
        return AuthEvent(ts, EventKind.AUTH_SUCCESS, mm["user"], mm["ip"], host, mm["method"], raw)

    return AuthEvent(ts, EventKind.OTHER, None, None, host, None, raw)


def parse_lines(lines: List[str], year: int) -> Tuple[List[AuthEvent], int]:
    """Parse many lines. Returns (events, skipped_count)."""
    events: List[AuthEvent] = []
    skipped = 0
    for line in lines:
        if not line.strip():
            continue
        ev = parse_line(line, year)
        if ev is None:
            skipped += 1
        else:
            events.append(ev)
    return events, skipped
