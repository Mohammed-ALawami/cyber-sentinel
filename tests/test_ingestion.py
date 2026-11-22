from cyber_sentinel.ingestion import parse_line, parse_lines
from cyber_sentinel.models import EventKind

YEAR = 2026


def test_failed_password():
    ev = parse_line(
        "Nov 22 09:15:04 srv sshd[2201]: Failed password for admin "
        "from 203.0.113.7 port 51234 ssh2", YEAR)
    assert ev is not None
    assert ev.kind is EventKind.AUTH_FAILED
    assert ev.user == "admin" and ev.source_ip == "203.0.113.7"
    assert ev.ts.year == YEAR and ev.ts.month == 11 and ev.ts.day == 22
    assert ev.is_failure


def test_invalid_user_is_a_failure():
    ev = parse_line(
        "Nov 22 09:15:04 srv sshd[2201]: Failed password for invalid user "
        "oracle from 203.0.113.7 port 51234 ssh2", YEAR)
    assert ev.kind is EventKind.INVALID_USER
    assert ev.user == "oracle" and ev.is_failure


def test_accepted():
    ev = parse_line(
        "Nov 22 10:02:11 srv sshd[2300]: Accepted publickey for sara "
        "from 198.51.100.12 port 52200 ssh2", YEAR)
    assert ev.kind is EventKind.AUTH_SUCCESS
    assert ev.method == "publickey" and not ev.is_failure


def test_unrelated_sshd_message_is_other():
    ev = parse_line(
        "Nov 22 10:02:12 srv sshd[2300]: Connection closed by 198.51.100.12 "
        "port 52200", YEAR)
    assert ev.kind is EventKind.OTHER


def test_garbage_is_skipped_not_guessed():
    assert parse_line("this is not a syslog line", YEAR) is None
    assert parse_line("Foo 22 10:00:00 srv sshd[1]: Accepted password for a "
                      "from 1.2.3.4 port 5 ssh2", YEAR) is None


def test_parse_lines_counts_skips():
    events, skipped = parse_lines([
        "Nov 22 09:00:00 srv sshd[1]: Failed password for admin from 203.0.113.7 port 1 ssh2",
        "",
        "garbage",
        "Nov 22 09:00:05 srv sshd[2]: Accepted password for sara from 198.51.100.12 port 2 ssh2",
    ], YEAR)
    assert len(events) == 2 and skipped == 1
