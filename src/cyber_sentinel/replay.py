"""Replay CLI: stream a synthetic scenario into a running Cyber Sentinel
app, list scenarios, or print raw lines for piping.

This tool only generates and replays synthetic log lines. The only network
it touches is the target URL you give it - normally localhost.

    PYTHONPATH=src python -m cyber_sentinel.replay --list
    PYTHONPATH=src python -m cyber_sentinel.replay --scenario brute_force_admin --speed 30
    PYTHONPATH=src python -m cyber_sentinel.replay --scenario benign_day --stdout | head
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from typing import List, Optional

from .scenarios import SCENARIOS


def post_lines(target: str, lines: List[str]) -> dict:
    req = urllib.request.Request(
        target.rstrip("/") + "/api/ingest",
        data=json.dumps({"lines": lines}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Replay synthetic log scenarios.")
    parser.add_argument("--list", action="store_true", help="list scenarios and exit")
    parser.add_argument("--scenario", help="scenario name to replay")
    parser.add_argument("--target", default="http://127.0.0.1:8791",
                        help="running app URL (default http://127.0.0.1:8791)")
    parser.add_argument("--speed", type=float, default=30.0,
                        help="replay speed multiplier over the recorded timeline")
    parser.add_argument("--stdout", action="store_true",
                        help="print lines instead of posting them")
    args = parser.parse_args(argv)

    if args.list:
        for name, sc in SCENARIOS.items():
            print(f"{name:20s} {len(sc.lines):4d} lines  {sc.description}")
        return 0

    sc = SCENARIOS.get(args.scenario or "")
    if sc is None:
        parser.error(f"unknown scenario {args.scenario!r}; use --list")

    if args.stdout:
        print("\n".join(sc.lines))
        return 0

    speed = max(0.1, args.speed)
    sent, prev = 0, None
    chunk: List[str] = []
    chunk_t = None
    for line, t in zip(sc.lines, sc.times):
        if prev is not None:
            delay = min((t - prev).total_seconds() / speed, 2.0)
            if delay > 0:
                time.sleep(delay)
        prev = t
        chunk.append(line)
        chunk_t = t
        if len(chunk) >= 25:
            post_lines(args.target, chunk)
            sent += len(chunk)
            chunk = []
    if chunk:
        post_lines(args.target, chunk)
        sent += len(chunk)
    print(f"replayed {sent} lines of '{sc.name}' to {args.target} at {speed}x")
    return 0


if __name__ == "__main__":
    sys.exit(main())
