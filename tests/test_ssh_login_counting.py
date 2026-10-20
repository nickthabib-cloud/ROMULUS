"""One SSH login is one login: the journal "Accepted" line, the audit USER_LOGIN record and the
PAM USER_START session opening describe the same login; the rule reports logins, not records."""
from datetime import UTC, datetime, timedelta

from romulus.detect.host import SshLoginFromExternal
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv

T0 = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)


def auth(event_id, phase, *, ts):
    fields = {"auth.service": "sshd", "auth.phase": phase, "source.ip": "203.0.113.8", "user.name": "root"}
    return TypedEvent(id=event_id, family="auth", ts=ts, host="web1", outcome=Outcome.success,
                      fields={k: fv(v, f"{event_id}:{k}") for k, v in fields.items()},
                      raw=[RawRef(target="host-x", native_id=event_id)], normalizer="test@1")


def test_logins_are_counted_once_across_sources_and_session_openings_are_not_logins():
    events = []
    for i in range(3):
        ts = T0 + timedelta(minutes=10 * i)
        events += [auth(f"j{i}", "authentication", ts=ts), auth(f"l{i}", "login", ts=ts + timedelta(seconds=1)),
                   auth(f"s{i}", "session_open", ts=ts + timedelta(seconds=2))]
    rule = SshLoginFromExternal()
    rule.consume(events)
    match = rule.finalize()[0]
    assert match.claim.startswith("At least 3 successful SSH login(s) on web1")
    assert "3 sshd 'Accepted' journal record(s); 3 audit USER_LOGIN record(s)" in match.claim
    assert not any(e.get("auth.phase") == "session_open" for e in match.events)
    assert f"– {(T0 + timedelta(minutes=20, seconds=1)).isoformat()};" in match.claim   # range = counted records


def test_one_source_alone_still_counts_its_logins():
    rule = SshLoginFromExternal()
    rule.consume([auth("l0", "login", ts=T0), auth("s0", "session_open", ts=T0)])
    assert rule.finalize()[0].claim.startswith("At least 1 successful SSH login(s)")
