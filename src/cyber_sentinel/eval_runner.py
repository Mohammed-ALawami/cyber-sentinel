"""Evaluation harness: run every scenario through the real pipeline and
measure detection quality against the known answers.

Writes eval/report.json and eval/report.md and exits non-zero when any
expectation fails, so it can gate CI. Numbers in the README come from this
script's actual output - never typed by hand.

    PYTHONPATH=src python -m cyber_sentinel.eval_runner
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

from .config import Config
from .pipeline import Pipeline
from .scenarios import SCENARIOS, Scenario
from .storage import Storage


def run_scenario(sc: Scenario, config: Optional[Config] = None) -> Dict:
    pipe = Pipeline(Storage(":memory:"), config)
    pipe.ingest_lines(sc.lines)

    alerts = [pipe.storage.get_alert(a["id"]) for a in pipe.storage.list_alerts(limit=1000)]
    fired = {sig["detector"] for alert in alerts for sig in alert["signals"]}
    expected = set(sc.expected_detectors)
    unexpected = set(sc.unexpected_detectors)

    missing = expected - fired
    wrongly_fired = fired & unexpected
    if not expected:
        wrongly_fired = set(fired)  # benign scenario: every alert is a false positive

    time_to_detect: Optional[float] = None
    if sc.attack_start and expected & fired:
        first = min(
            sig["ts"] for alert in alerts for sig in alert["signals"]
            if sig["detector"] in expected)
        time_to_detect = (
            __import__("datetime").datetime.fromisoformat(first) - sc.attack_start
        ).total_seconds()

    max_score = max((a["score"] for a in alerts), default=0)
    top = max(alerts, key=lambda a: a["score"], default=None)
    passed = not missing and not wrongly_fired

    return {
        "scenario": sc.name,
        "description": sc.description,
        "lines": len(sc.lines),
        "ingested": pipe.ingested,
        "skipped_lines": pipe.skipped,
        "alerts_raised": len(alerts),
        "detectors_fired": sorted(fired),
        "expected_detectors": sorted(expected),
        "missing_detections": sorted(missing),
        "false_positive_detectors": sorted(wrongly_fired),
        "max_score": max_score,
        "top_alert_severity": top["severity"] if top else None,
        "time_to_detect_seconds": time_to_detect,
        "pass": passed,
    }


def run_all(config: Optional[Config] = None) -> List[Dict]:
    return [run_scenario(sc, config) for sc in SCENARIOS.values()]


def to_markdown(results: List[Dict]) -> str:
    lines = [
        "# Cyber Sentinel - measured detection results",
        "",
        "Produced by `python -m cyber_sentinel.eval_runner` against the built-in",
        "synthetic scenarios. Every number below is measured by running the real",
        "pipeline, not estimated.",
        "",
        "Definitions: *Time to detect* is the gap between the first attack log line",
        "and the moment the first expected signal fires (both from the recorded",
        "timestamps). A signal's own explanation quotes its internal window, which",
        "may be shorter than time-to-detect when the detector needs several lines",
        "before it fires.",
        "",
        "| Scenario | Lines | Alerts | Detectors fired | Max score | Time to detect | False positives | Result |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        ttd = f"{r['time_to_detect_seconds']:.0f}s" if r["time_to_detect_seconds"] is not None else "-"
        fired = ", ".join(r["detectors_fired"]) or "none"
        fps = ", ".join(r["false_positive_detectors"]) or "none"
        lines.append(
            f"| {r['scenario']} | {r['lines']} | {r['alerts_raised']} | {fired} "
            f"| {r['max_score']} | {ttd} | {fps} | {'PASS' if r['pass'] else 'FAIL'} |")
    lines += [
        "",
        "`slow_and_steady` is intentionally expected to raise nothing: it",
        "documents an evasion technique v1 does not catch (see README,",
        "Known limitations).",
        "",
    ]
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Measure Cyber Sentinel detection quality.")
    parser.add_argument("--out", default="eval", help="output directory for report files")
    args = parser.parse_args(argv)

    results = run_all()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(json.dumps(results, indent=2))
    (out_dir / "report.md").write_text(to_markdown(results))

    for r in results:
        status = "PASS" if r["pass"] else "FAIL"
        ttd = (f", detected in {r['time_to_detect_seconds']:.0f}s"
               if r["time_to_detect_seconds"] is not None else "")
        print(f"[{status}] {r['scenario']}: {r['alerts_raised']} alert(s), "
              f"max score {r['max_score']}{ttd}")
    failed = [r for r in results if not r["pass"]]
    print(f"\n{len(results) - len(failed)}/{len(results)} scenarios meet expectations. "
          f"Report: {out_dir / 'report.md'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
