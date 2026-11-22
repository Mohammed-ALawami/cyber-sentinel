"""End-to-end: raw scenario lines through the HTTP API into explained alerts."""
from fastapi.testclient import TestClient

from cyber_sentinel.app import app
from cyber_sentinel.scenarios import SCENARIOS


def test_brute_force_scenario_end_to_end():
    with TestClient(app) as client:
        client.post("/api/demo/reset")  # shared app state: start clean
        assert client.get("/api/health").json()["status"] == "ok"

        sc = SCENARIOS["brute_force_admin"]
        r = client.post("/api/ingest", json={"lines": sc.lines})
        assert r.status_code == 200
        body = r.json()
        assert body["alerts_fired"] >= 1
        assert body["skipped_total"] == 0

        alerts = client.get("/api/alerts").json()
        assert alerts, "scenario must raise at least one alert"
        top = max(alerts, key=lambda a: a["score"])
        assert top["severity"] in ("medium", "high", "critical")

        detail = client.get(f"/api/alerts/{top['id']}").json()
        assert detail["signals"], "alert must carry its explaining signals"
        sig = detail["signals"][0]
        assert sig["detector"] == "brute_force"
        assert sig["points"] > 0 and sig["explanation"]
        assert sig["evidence"], "signal must keep raw evidence lines"

        stats = client.get("/api/stats").json()
        assert stats["events"] == len(sc.lines)
        assert stats["alerts"] >= 1

        assert client.get("/api/alerts/999999").status_code == 404
        scenarios = client.get("/api/scenarios").json()
        assert any(s["name"] == "benign_day" for s in scenarios)


def test_benign_noise_raises_nothing_over_api():
    from cyber_sentinel.pipeline import Pipeline
    from cyber_sentinel.storage import Storage

    pipe = Pipeline(Storage(":memory:"))
    fired = pipe.ingest_lines(SCENARIOS["benign_day"].lines)
    assert fired == [], f"benign scenario must stay quiet, got {fired}"


def test_demo_reset_endpoint_clears_synthetic_data():
    with TestClient(app) as client:
        client.post("/api/demo/reset")
        client.post("/api/ingest", json={"lines": SCENARIOS["brute_force_admin"].lines})
        assert client.get("/api/stats").json()["events"] > 0
        r = client.post("/api/demo/reset")
        assert r.status_code == 200 and r.json() == {"reset": True}
        stats = client.get("/api/stats").json()
        assert stats["events"] == 0 and stats["alerts"] == 0
