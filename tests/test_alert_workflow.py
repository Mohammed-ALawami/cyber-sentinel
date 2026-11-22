"""Alert triage workflow: status transitions, filtering, validation."""
from fastapi.testclient import TestClient

from cyber_sentinel.app import app
from cyber_sentinel.scenarios import SCENARIOS


def _raise_alert(client) -> int:
    r = client.post("/api/ingest", json={"lines": SCENARIOS["brute_force_admin"].lines})
    assert r.status_code == 200 and r.json()["alerts_fired"] >= 1
    alerts = client.get("/api/alerts").json()
    assert alerts
    return alerts[0]["id"]


def test_alert_status_roundtrip():
    with TestClient(app) as client:
        client.post("/api/demo/reset")
        alert_id = _raise_alert(client)

        alert = client.get(f"/api/alerts/{alert_id}").json()
        assert alert["status"] == "open"

        for status in ("acknowledged", "resolved", "open"):
            r = client.post(f"/api/alerts/{alert_id}/status", json={"status": status})
            assert r.status_code == 200
            assert r.json() == {"id": alert_id, "status": status}
            assert client.get(f"/api/alerts/{alert_id}").json()["status"] == status


def test_status_filter():
    with TestClient(app) as client:
        client.post("/api/demo/reset")
        alert_id = _raise_alert(client)
        client.post(f"/api/alerts/{alert_id}/status", json={"status": "resolved"})

        resolved = client.get("/api/alerts?status=resolved").json()
        assert any(a["id"] == alert_id for a in resolved)
        assert all(a["status"] == "resolved" for a in resolved)

        open_alerts = client.get("/api/alerts?status=open").json()
        assert all(a["status"] == "open" for a in open_alerts)
        assert not any(a["id"] == alert_id for a in open_alerts)


def test_status_validation_errors():
    with TestClient(app) as client:
        client.post("/api/demo/reset")
        alert_id = _raise_alert(client)

        r = client.post(f"/api/alerts/{alert_id}/status", json={"status": "bogus"})
        assert r.status_code == 400
        r = client.post("/api/alerts/999999/status", json={"status": "resolved"})
        assert r.status_code == 404
        r = client.get("/api/alerts?status=bogus")
        assert r.status_code == 400


def test_new_activity_reopens_triaged_alert():
    """A signal landing on an acknowledged/resolved alert returns it to the
    open queue instead of updating it silently."""
    with TestClient(app) as client:
        client.post("/api/demo/reset")
        alert_id = _raise_alert(client)
        client.post(f"/api/alerts/{alert_id}/status", json={"status": "resolved"})
        assert client.get(f"/api/alerts/{alert_id}").json()["status"] == "resolved"
        assert not client.get("/api/alerts?status=open").json()

        # New activity from the same source inside the grouping window must
        # reopen the SAME alert, not vanish under its resolved state. The
        # brute-force detector's cooldown was consumed by the first burst, so
        # the new activity is a successful login on the breached account from
        # the attacking address: admin has a success baseline in the scenario,
        # the address is unknown to that account, and 11:10 stays inside the
        # 15-minute grouping window of the last failure (~10:15).
        key = client.get(f"/api/alerts/{alert_id}").json()["key"]
        ip = key.split("->")[-1].strip() if "->" in key else key
        line = f"Nov 22 10:25:00 srv-demo-01 sshd[9999]: Accepted password for admin from {ip} port 44338 ssh2"
        r = client.post("/api/ingest", json={"lines": [line]})
        assert r.status_code == 200
        assert r.json()["alerts_fired"] >= 1, "new_source signal must fire"
        after = client.get(f"/api/alerts/{alert_id}").json()
        assert after["status"] == "open", after
        assert "new source" in after["summary"]
        assert any(a["id"] == alert_id for a in client.get("/api/alerts?status=open").json())


def test_post_restart_new_activity_opens_new_alert_keeps_triage():
    """Grouping memory is per session (documented limitation): after a
    restart, new activity from a source with a triaged alert opens a NEW
    open alert; the old alert keeps its triage status."""
    import tempfile

    from cyber_sentinel.pipeline import Pipeline
    from cyber_sentinel.storage import Storage

    with tempfile.TemporaryDirectory() as td:
        path = f"{td}/s.db"
        st = Storage(path)
        pipe = Pipeline(st)
        fired = pipe.ingest_lines(SCENARIOS["brute_force_admin"].lines)
        old_id = fired[0]["alert"]["id"]
        st.set_alert_status(old_id, "resolved")
        st.close()

        st2 = Storage(path)  # simulated restart: fresh in-memory grouping
        pipe2 = Pipeline(st2)
        pipe2.rebuild_from_storage()
        pipe2.ingest_lines([
            "Nov 22 10:25:00 srv-demo-01 sshd[9999]: Accepted password "
            "for admin from 203.0.113.7 port 44338 ssh2"])
        alerts = st2.list_alerts()
        assert len(alerts) == 2, alerts
        old = st2.get_alert(old_id)
        new = st2.get_alert(2)
        assert old["status"] == "resolved", "old triage status must be kept"
        assert new["status"] == "open" and "new source" in new["summary"]
        st2.close()


def test_status_survives_restart_and_stats_report_counts():
    """Triage state lives in the DB; a restart (fresh storage handle on the
    same file) keeps it. Stats expose per-status counts."""
    import tempfile

    from cyber_sentinel.pipeline import Pipeline
    from cyber_sentinel.storage import Storage

    with tempfile.TemporaryDirectory() as td:
        path = f"{td}/s.db"
        st = Storage(path)
        pipe = Pipeline(st)
        fired = pipe.ingest_lines(SCENARIOS["brute_force_admin"].lines)
        alert_id = fired[0]["alert"]["id"]
        assert st.set_alert_status(alert_id, "acknowledged") is True
        st.close()

        st2 = Storage(path)  # simulated restart on the same DB file
        assert st2.get_alert(alert_id)["status"] == "acknowledged"
        by_status = st2.stats()["alerts_by_status"]
        assert by_status.get("acknowledged") == 1
        # Unknown alert id is reported, not silently ignored.
        assert st2.set_alert_status(999999, "resolved") is False
        st2.close()
