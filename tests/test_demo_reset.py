"""The explicit demo reset must make repeated scenario replays predictable."""
from cyber_sentinel.pipeline import Pipeline
from cyber_sentinel.scenarios import SCENARIOS
from cyber_sentinel.storage import Storage


def test_reset_returns_to_fresh_state():
    st = Storage(":memory:")
    p = Pipeline(st)
    lines = SCENARIOS["breach_chain"].lines

    fired_first = p.ingest_lines(lines)
    assert st.alert_count() == 1 and len(fired_first) == 2

    p.reset()
    assert st.event_count() == 0 and st.alert_count() == 0
    assert p.ingested == 0 and p.skipped == 0

    fired_second = p.ingest_lines(lines)
    assert st.alert_count() == 1
    assert len(fired_second) == len(fired_first), "replay after reset must match a fresh run"
