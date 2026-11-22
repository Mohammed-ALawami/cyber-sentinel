"""Cyber Sentinel HTTP app: ingestion API, live websocket, dashboard.

v1 serves a dependency-free dashboard from static/ - no build step. The
original wishlist mentioned React;
the honest v1 decision is to prove detection first, and this API is shaped
so a React front end can replace static/ later without backend changes.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Dict, List, Optional, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .pipeline import Pipeline
from .scenarios import SCENARIOS
from .storage import Storage

BASE_DIR = Path(__file__).resolve().parent.parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "static"
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = os.environ.get("CYBER_SENTINEL_DB", str(DATA_DIR / "sentinel.db"))

app = FastAPI(title="Cyber Sentinel", version="1.0.0",
              description="Defensive authentication-log monitoring on synthetic data.")
storage = Storage(DB_PATH)
pipeline = Pipeline(storage)

_loop: Optional[asyncio.AbstractEventLoop] = None
_ws_clients: Set[WebSocket] = set()
_replays: Dict[str, asyncio.Task] = {}


class IngestBody(BaseModel):
    lines: List[str]


ALERT_STATUSES = ("open", "acknowledged", "resolved")


class StatusBody(BaseModel):
    status: str


@app.on_event("startup")
async def startup() -> None:
    global _loop
    _loop = asyncio.get_running_loop()
    pipeline.on_event = lambda ev: _broadcast({"type": "event", "data": ev})
    pipeline.on_alert = lambda alert: _broadcast({"type": "alert", "data": alert})
    # Restore detector memory (sliding windows, known user/IP baselines,
    # cooldowns) from the events already stored, without re-raising alerts.
    pipeline.rebuild_from_storage()


def _broadcast(msg: dict) -> None:
    if _loop is not None and _ws_clients:
        _loop.create_task(_send_all(msg))


async def _send_all(msg: dict) -> None:
    dead = []
    for ws in list(_ws_clients):
        try:
            await ws.send_json(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _ws_clients.discard(ws)


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok", "events": storage.event_count(),
            "alerts": storage.alert_count()}


@app.get("/api/stats")
async def stats() -> dict:
    return storage.stats()


@app.get("/api/alerts")
async def list_alerts(limit: int = 50, offset: int = 0,
                      status: Optional[str] = None) -> List[dict]:
    if status is not None and status not in ALERT_STATUSES:
        return JSONResponse({"error": f"unknown status {status!r}"}, status_code=400)  # type: ignore[return-value]
    return storage.list_alerts(limit=min(limit, 200), offset=offset, status=status)


@app.post("/api/alerts/{alert_id}/status")
async def set_alert_status(alert_id: int, body: StatusBody) -> dict:
    """Triage an alert: open -> acknowledged -> resolved (reopen allowed).

    Triage state is local to this demo instance - there is no auth and no
    shared SOC backend; it exists to practice an analyst workflow.
    """
    if body.status not in ALERT_STATUSES:
        return JSONResponse({"error": f"unknown status {body.status!r}"}, status_code=400)  # type: ignore[return-value]
    if not storage.set_alert_status(alert_id, body.status):
        return JSONResponse({"error": "alert not found"}, status_code=404)  # type: ignore[return-value]
    _broadcast({"type": "alert_status", "data": {"id": alert_id, "status": body.status}})
    return {"id": alert_id, "status": body.status}


@app.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: int) -> dict:
    alert = storage.get_alert(alert_id)
    if alert is None:
        return JSONResponse({"error": "alert not found"}, status_code=404)  # type: ignore[return-value]
    return alert


@app.get("/api/events")
async def list_events(limit: int = 100, offset: int = 0) -> List[dict]:
    return storage.recent_events(limit=min(limit, 500), offset=offset)


@app.get("/api/scenarios")
async def list_scenarios() -> List[dict]:
    return [{"name": sc.name, "description": sc.description, "lines": len(sc.lines)}
            for sc in SCENARIOS.values()]


@app.post("/api/ingest")
async def ingest(body: IngestBody) -> dict:
    fired = pipeline.ingest_lines(body.lines[:5000])
    return {"accepted_lines": len(body.lines[:5000]),
            "ingested_total": pipeline.ingested,
            "skipped_total": pipeline.skipped,
            "alerts_fired": len(fired)}


@app.post("/api/replay/{name}")
async def replay(name: str, speed: float = 30.0) -> dict:
    sc = SCENARIOS.get(name)
    if sc is None:
        return JSONResponse({"error": f"unknown scenario {name!r}"}, status_code=404)  # type: ignore[return-value]
    if name in _replays and not _replays[name].done():
        return JSONResponse({"error": f"scenario {name!r} is already replaying"},
                            status_code=409)  # type: ignore[return-value]
    speed = min(max(speed, 0.1), 1000.0)

    async def pump() -> None:
        prev = None
        for line, t in zip(sc.lines, sc.times):
            if prev is not None:
                delay = min((t - prev).total_seconds() / speed, 1.0)
                if delay > 0:
                    await asyncio.sleep(delay)
            prev = t
            pipeline.ingest_line(line)

    _replays[name] = asyncio.create_task(pump())
    return {"started": name, "lines": len(sc.lines), "speed": speed}


@app.post("/api/demo/reset")
async def demo_reset() -> dict:
    """Delete ALL stored synthetic demo data and reset every detector.

    Explicitly user-initiated (the dashboard asks for confirmation). This is
    how repeated scenario replays stay predictable; it is destructive to the
    demo database by design and says so wherever it is exposed.
    """
    for task in _replays.values():
        task.cancel()
    _replays.clear()
    pipeline.reset()
    _broadcast({"type": "reset"})
    return {"reset": True}


@app.websocket("/ws")
async def ws(websocket: WebSocket) -> None:
    await websocket.accept()
    _ws_clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()  # we never read; just detect close
    except WebSocketDisconnect:
        pass
    finally:
        _ws_clients.discard(websocket)


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
