# Architecture

```mermaid
flowchart LR
    subgraph Sources
      R[Replay CLI / scenario button]
      F[auth.log-style file or pipe]
    end
    R -->|POST /api/ingest| P
    F -->|POST /api/ingest| P

    subgraph Pipeline["Detection pipeline (shared by app, CLI and evaluation)"]
      P[ingestion.py<br/>parse + classify] --> D1[brute_force]
      P --> D2[password_spray]
      P --> D3[slow_brute]
      P --> D4[new_source]
      P --> D5[off_hours]
      D1 & D2 & D3 & D4 & D5 --> A[alerts.py<br/>group by source IP<br/>explainable score]
    end

    A --> S[(SQLite<br/>events, alerts, signals)]
    P --> S
    A -->|websocket /ws| UI[Live dashboard<br/>static/ - zero build]
    S --> UI
    UI -->|POST /api/replay/:name| P

    E[eval_runner.py] -->|same Pipeline, in-memory| P
    E --> M[eval/report.md<br/>measured results]
```

## Design decisions worth explaining

- **One pipeline, three front doors.** The HTTP app, the replay CLI and the
  evaluation harness all drive the same `Pipeline` object, so measured
  results describe the exact code the demo runs.
- **Rules before ML.** Deterministic detectors with injectable thresholds are
  testable and explainable. An ML layer is on the roadmap and ships only with
  published precision/recall on labeled scenarios.
- **Escalation over noise.** A detector fires at most once per key per
  cooldown; signals on one source merge into a single alert whose score grows
  with each new *kind* of evidence.
- **Stdlib SQLite.** Three tables, no ORM, WAL mode so the dashboard can read
  while ingestion writes.
- **Zero-build UI.** Vanilla JS over REST + websocket. A React front end can
  replace `static/` without touching the API.
