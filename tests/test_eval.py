"""The evaluation harness itself is the acceptance gate: every built-in
scenario must meet its declared expectations."""
from cyber_sentinel.eval_runner import run_all, run_scenario
from cyber_sentinel.scenarios import SCENARIOS


def test_all_scenarios_meet_expectations():
    results = run_all()
    failed = [r["scenario"] for r in results if not r["pass"]]
    assert not failed, f"scenarios failing expectations: {failed}"


def test_breach_chain_escalates_one_alert():
    r = run_scenario(SCENARIOS["breach_chain"])
    assert set(r["detectors_fired"]) >= {"brute_force", "new_source"}
    assert r["alerts_raised"] == 1, "attack chain from one IP must stay one alert"
    assert r["time_to_detect_seconds"] is not None
