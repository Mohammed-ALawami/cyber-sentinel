"""Detector memory must survive a restart: the app rebuilds sliding windows
and known-address baselines from the events already stored, without
re-raising alerts that already exist."""
from datetime import datetime, timedelta

from cyber_sentinel.pipeline import Pipeline
from cyber_sentinel.storage import Storage

T0 = datetime(2026, 11, 22, 10, 0, 0)
IP = "203.0.113.7"
HOME = "198.51.100.11"


def fail_line(ts, user="admin", ip=IP):
    return (f"{ts.strftime('%b')} {ts.day} {ts.strftime('%H:%M:%S')} srv sshd[2201]: "
            f"Failed password for {user} from {ip} port 51234 ssh2")


def ok_line(ts, user="sara", ip=HOME):
    return (f"{ts.strftime('%b')} {ts.day} {ts.strftime('%H:%M:%S')} srv sshd[2201]: "
            f"Accepted password for {user} from {ip} port 52200 ssh2")


def restart(storage):
    """A brand-new pipeline over the same storage, as after a process restart."""
    p = Pipeline(storage)
    p.rebuild_from_storage()
    return p


def test_brute_force_window_survives_restart():
    st = Storage(":memory:")
    p1 = Pipeline(st)
    for i in range(9):
        assert p1.ingest_line(fail_line(T0 + timedelta(seconds=i * 4))) == []

    p2 = restart(st)
    fired = p2.ingest_line(fail_line(T0 + timedelta(seconds=40)))
    assert fired, "the 10th failure inside the rebuilt window must fire"


def test_new_source_baseline_survives_restart():
    st = Storage(":memory:")
    p1 = Pipeline(st)
    for i in range(3):
        p1.ingest_line(ok_line(T0 + timedelta(minutes=i)))

    p2 = restart(st)
    fired = p2.ingest_line(ok_line(T0 + timedelta(minutes=5), ip="203.0.113.9"))
    assert fired, "baseline learned before the restart must carry over"
    assert fired[0]["alert"]["signals"]


def test_restart_does_not_duplicate_existing_alerts():
    st = Storage(":memory:")
    p1 = Pipeline(st)
    lines = [fail_line(T0 + timedelta(seconds=i * 4)) for i in range(12)]
    p1.ingest_lines(lines)
    assert st.alert_count() == 1

    p2 = restart(st)
    fired = p2.ingest_lines(lines)  # same log re-ingested (e.g. re-uploaded file)
    assert fired == [], "cooldowns learned during rebuild must suppress duplicates"
    assert st.alert_count() == 1
