"""Built-in replay scenarios: synthetic syslog streams with known answers.

Every scenario is fully synthetic: invented users on one invented host, and
RFC 5737 documentation address ranges (203.0.113.x, 198.51.100.x) that can
never belong to real machines. Scenarios exist so detection quality can be
MEASURED against known ground truth, and so the demo can run anywhere with
no real server, no real logs and no real attacks.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

HOST = "srv-demo-01"

# RFC 5737 ranges reserved for documentation: unreachable in the real world.
ATTACK_NET = "203.0.113."
SITE_NET = "198.51.100."

# One healthy machine's cast of users and their usual addresses.
USERS = {
    "mohamed": SITE_NET + "11",
    "sara": SITE_NET + "12",
    "omar": SITE_NET + "13",
    "laila": SITE_NET + "14",
    "deploy": SITE_NET + "15",
    "admin": SITE_NET + "50",
    "root": SITE_NET + "60",
}

Event = Tuple[datetime, str]


@dataclass
class Scenario:
    name: str
    description: str
    lines: List[str]
    times: List[datetime]
    attack_start: Optional[datetime]
    expected_detectors: List[str]
    unexpected_detectors: List[str] = field(default_factory=list)


def _render(events: List[Event], seed: int = 7) -> Tuple[List[str], List[datetime]]:
    events = sorted(events, key=lambda e: e[0])
    lines: List[str] = []
    times: List[datetime] = []
    for i, (t, msg) in enumerate(events):
        lines.append(f"{t.strftime('%b')} {t.day} {t.strftime('%H:%M:%S')} "
                     f"{HOST} sshd[{2200 + i}]: {msg}")
        times.append(t)
    return lines, times


def _failed(user: str, ip: str, rng: random.Random) -> str:
    return f"Failed password for {user} from {ip} port {rng.randint(40000, 60999)} ssh2"


def _invalid(user: str, ip: str, rng: random.Random) -> str:
    return f"Failed password for invalid user {user} from {ip} port {rng.randint(40000, 60999)} ssh2"


def _accepted(user: str, ip: str, rng: random.Random) -> str:
    return f"Accepted password for {user} from {ip} port {rng.randint(40000, 60999)} ssh2"


def _ordinary_logins(events: List[Event], rng: random.Random, day_start: datetime,
                     rounds: int = 4, with_slips: bool = True) -> None:
    """Background noise: known users logging in from their usual addresses,
    with the occasional single typo'd password (never enough to alert)."""
    for user, ip in USERS.items():
        if user == "root":
            continue  # root does not log in over ssh on a healthy box
        t = day_start + timedelta(minutes=rng.randint(0, 20))
        for _ in range(rounds):
            t += timedelta(minutes=rng.randint(20, 55))
            if with_slips and rng.random() < 0.12:
                events.append((t - timedelta(seconds=15), _failed(user, ip, rng)))
            events.append((t, _accepted(user, ip, rng)))


def _benign_day() -> Scenario:
    rng = random.Random(42)
    start = datetime(2026, 11, 22, 8, 0, 0)
    events: List[Event] = []
    _ordinary_logins(events, rng, start)
    lines, times = _render(events)
    return Scenario(
        name="benign_day",
        description="A normal morning: staff log in from their usual addresses, "
                    "a few typos, nothing hostile. Any alert here is a false positive.",
        lines=lines, times=times, attack_start=None, expected_detectors=[])


def _brute_force_admin() -> Scenario:
    rng = random.Random(43)
    start = datetime(2026, 11, 22, 8, 0, 0)
    events: List[Event] = []
    _ordinary_logins(events, rng, start, rounds=3)
    ip = ATTACK_NET + "7"
    t = start + timedelta(hours=2, minutes=15)
    attack_start = None
    for i in range(40):
        t += timedelta(seconds=4)
        if attack_start is None:
            attack_start = t  # first attack log line, not a moment before it
        user = "root" if i % 7 == 0 else "admin"
        events.append((t, _failed(user, ip, rng)))
    lines, times = _render(events)
    return Scenario(
        name="brute_force_admin",
        description="40 rapid failed logins against admin/root from one unknown "
                    "address in under three minutes.",
        lines=lines, times=times, attack_start=attack_start,
        expected_detectors=["brute_force"])


def _breach_chain() -> Scenario:
    rng = random.Random(44)
    start = datetime(2026, 11, 22, 8, 0, 0)
    events: List[Event] = []
    _ordinary_logins(events, rng, start, rounds=4)  # admin builds history from .50
    ip = ATTACK_NET + "9"
    t = start + timedelta(hours=3, minutes=5)
    attack_start = None
    for _ in range(30):
        t += timedelta(seconds=4)
        if attack_start is None:
            attack_start = t
        events.append((t, _failed("admin", ip, rng)))
    t += timedelta(seconds=6)
    events.append((t, _accepted("admin", ip, rng)))  # the attempt that gets in
    lines, times = _render(events)
    return Scenario(
        name="breach_chain",
        description="Brute force against admin, then a SUCCESS from the same new "
                    "address. One alert should escalate through both signals.",
        lines=lines, times=times, attack_start=attack_start,
        expected_detectors=["brute_force", "new_source"])


def _password_spray() -> Scenario:
    rng = random.Random(45)
    start = datetime(2026, 11, 22, 8, 0, 0)
    events: List[Event] = []
    _ordinary_logins(events, rng, start, rounds=3)
    ip = ATTACK_NET + "21"
    t = start + timedelta(hours=3)
    attack_start = None
    targets = ["admin", "root", "mohamed", "sara", "omar", "laila", "test", "git"]
    for user in targets:
        t += timedelta(seconds=12)
        if attack_start is None:
            attack_start = t
        events.append((t, _failed(user, ip, rng)))
    lines, times = _render(events)
    return Scenario(
        name="password_spray",
        description="One address tries single passwords against eight different "
                    "accounts - too few per account for a brute-force counter.",
        lines=lines, times=times, attack_start=attack_start,
        expected_detectors=["password_spray"],
        unexpected_detectors=["brute_force"])


def _off_hours_root() -> Scenario:
    rng = random.Random(46)
    start = datetime(2026, 11, 22, 20, 30, 0)
    events: List[Event] = []
    ip = USERS["root"]
    for minute in (10, 40, 65):  # normal evening maintenance from the usual address
        events.append((start + timedelta(minutes=minute), _accepted("root", ip, rng)))
    late = datetime(2026, 11, 23, 3, 12, 0)
    events.append((late, _accepted("root", ip, rng)))
    lines, times = _render(events)
    return Scenario(
        name="off_hours_root",
        description="root logs in from its usual address at 03:12. Same address, "
                    "wrong hour: a weak signal worth a low-score alert, not a siren.",
        lines=lines, times=times, attack_start=late,
        expected_detectors=["off_hours"],
        unexpected_detectors=["new_source"])


def _slow_and_steady() -> Scenario:
    rng = random.Random(47)
    start = datetime(2026, 11, 22, 8, 0, 0)
    events: List[Event] = []
    _ordinary_logins(events, rng, start, rounds=2)
    ip = ATTACK_NET + "30"
    t = start + timedelta(hours=1)
    attack_start = None
    for _ in range(8):  # spaced so the sliding window never fills
        t += timedelta(seconds=80)
        if attack_start is None:
            attack_start = t
        events.append((t, _failed("admin", ip, rng)))
    lines, times = _render(events)
    return Scenario(
        name="slow_and_steady",
        description="Failed logins spaced 80 seconds apart stay under the burst "
                    "window. The long-horizon detector is expected to catch this; "
                    "the burst detector is expected NOT to.",
        lines=lines, times=times, attack_start=attack_start,
        expected_detectors=["slow_brute"],
        unexpected_detectors=["brute_force"])


_BUILDERS = {
    "benign_day": _benign_day,
    "brute_force_admin": _brute_force_admin,
    "breach_chain": _breach_chain,
    "password_spray": _password_spray,
    "off_hours_root": _off_hours_root,
    "slow_and_steady": _slow_and_steady,
}


def build_scenarios() -> Dict[str, Scenario]:
    return {name: builder() for name, builder in _BUILDERS.items()}


SCENARIOS = build_scenarios()
