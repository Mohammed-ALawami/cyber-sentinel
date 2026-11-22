"""Boundary behavior: window edges across restarts, cooldown edges, the
rebuild bound, cross-run alert grouping, and future-dated lines."""
from datetime import datetime, timedelta

from cyber_sentinel.config import Config
from cyber_sentinel.pipeline import Pipeline
from cyber_sentinel.scenarios import SCENARIOS
from cyber_sentinel.storage import Storage

T0 = datetime(2026, 11, 22, 10, 0, 0)
IP = "203.0.113.7"


def fail_line(ts, ip=IP, user="admin"):
    return (f"{ts.strftime('%b')} {ts.day} {ts.strftime('%H:%M:%S')} srv sshd[2201]: "
            f"Failed password for {user} from {ip} port 51234 ssh2")


def test_window_edge_across_restart():
    # 9 failures spread over 280s, restart, 10th at +295s: still inside the
    # 300s window of the newest line -> fires.
    st = Storage(":memory:")
    p1 = Pipeline(st)
    for i in range(9):
        p1.ingest_line(fail_line(T0 + timedelta(seconds=i * 35)))
    p2 = Pipeline(st)
    p2.rebuild_from_storage()
    assert p2.ingest_line(fail_line(T0 + timedelta(seconds=295))), "inside window: must fire"

    # Same setup, but the 10th lands at +400s: the earliest failures aged out.
    st2 = Storage(":memory:")
    q1 = Pipeline(st2)
    for i in range(9):
        q1.ingest_line(fail_line(T0 + timedelta(seconds=i * 35)))
    q2 = Pipeline(st2)
    q2.rebuild_from_storage()
    assert q2.ingest_line(fail_line(T0 + timedelta(seconds=400))) == [], \
        "after the window slid, one more failure must NOT fire"


def test_cooldown_boundary():
    st = Storage(":memory:")
    p = Pipeline(st)
    for i in range(10):
        p.ingest_line(fail_line(T0 + timedelta(seconds=i * 4)))  # fires at ~+36s
    cool = Config().detector_cooldown_seconds
    # A fresh burst ending 1s before the cooldown expires: suppressed.
    base = T0 + timedelta(seconds=36 + cool - 1 - 40)
    for i in range(10):
        fired = p.ingest_line(fail_line(base + timedelta(seconds=i * 4)))
    assert fired == [], "inside cooldown: suppressed"
    # A fresh burst ending after the cooldown expired: fires again (on its
    # first line, since the previous burst is still inside the window).
    base2 = T0 + timedelta(seconds=36 + cool + 10)
    fired_any = []
    for i in range(10):
        fired_any.extend(p.ingest_line(fail_line(base2 + timedelta(seconds=i * 4))))
    assert fired_any, "after cooldown: fires again"


def test_rebuild_bound_relearns_only_newest_events():
    st = Storage(":memory:")
    p1 = Pipeline(st)
    for i in range(9):
        p1.ingest_line(fail_line(T0 + timedelta(seconds=i * 4)))
    p2 = Pipeline(st)
    learned = p2.rebuild_from_storage(limit=5)
    assert learned == 5
    fired = p2.ingest_line(fail_line(T0 + timedelta(seconds=40)))
    assert fired == [], "only 5 of 9 were relearned, so the 10th must not fire"


def test_same_ip_merges_within_grouping_window_only():
    st = Storage(":memory:")
    p = Pipeline(st)
    p.ingest_lines(SCENARIOS["brute_force_admin"].lines)
    p.ingest_lines(SCENARIOS["brute_force_admin"].lines)  # same attack, again
    assert st.alert_count() == 1, "same IP within 15 min continues one alert"
    p.ingest_lines(SCENARIOS["breach_chain"].lines)       # different attack IP
    keys = {a["key"] for a in st.list_alerts(limit=10)}
    assert st.alert_count() == 2 and keys == {"203.0.113.7", "203.0.113.9"}, \
        "distinct source IPs get distinct alerts"


def test_future_dated_line_shifts_window_then_recovers():
    # A line dated far in the future becomes the newest timestamp: older
    # real lines age out (documented behavior, detectors trust event time).
    st = Storage(":memory:")
    p = Pipeline(st)
    for i in range(9):
        p.ingest_line(fail_line(T0 + timedelta(seconds=i * 4)))
    p.ingest_line(fail_line(T0 + timedelta(days=2)))     # bad clock / bad data
    fired = p.ingest_line(fail_line(T0 + timedelta(seconds=40)))
    assert fired == [], "the 9 old lines aged out behind the future timestamp"
    fired = []
    base = T0 + timedelta(days=2)
    for i in range(9):                                    # 10 at the new timeframe
        fired = p.ingest_line(fail_line(base + timedelta(seconds=i * 4)))
    assert fired, "detection follows event time and recovers"
