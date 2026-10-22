"""Mission-scale state of the host aggregates, tamper and indicator rules: per-key state does not grow with the
records read, citations are ids once staged, and budgets make coverage partial instead of growing."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect import host, tamper
from romulus.detect.indicators import Indicator, IndicatorMatch, IndicatorSet
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv

T0 = datetime(2024, 11, 4, 0, 0, tzinfo=UTC)
_n = 0


def ev(family, ts, outcome=Outcome.success, host_name="web1", **fields):
    global _n
    _n += 1
    return TypedEvent(id=f"b{_n:09d}", family=family, ts=ts, host=host_name, outcome=outcome,
                      fields={k.replace("__", "."): fv(v, f"b{_n}:{k}") for k, v in fields.items()},
                      raw=[RawRef(target="host-x", native_id=f"b{_n}", digest="d")], normalizer="test@1")


def drain(rule, batches):
    stage = {}
    for batch in batches:
        rule.consume(batch)
        stage.update({e.id: e for e in rule.drain_staged()})
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    return rule.finalize()


@pytest.mark.slow
def test_web_shape_hours_are_folded_and_the_routine_verdict_is_unchanged():
    """A web helper run every five minutes for three weeks: open clock hours stay a handful, citations are ids."""
    rule = host.WebServiceSpawnsInterpreter()
    batches = []
    for hour in range(24 * 21):
        start = T0 + timedelta(hours=hour)
        batches.append([ev("process_exec", start + timedelta(minutes=5 * k), process__user="www-data",
                           process__argv=["/bin/sh", "-c", "/usr/bin/zmc -m 1"], process__executable="/bin/dash")
                        for k in range(12)])
    peak = 0
    stage = {}
    for batch in batches:
        rule.consume(batch)
        stage.update({e.id: e for e in rule.drain_staged()})
        peak = max(peak, sum(len(h) for h in rule.hours.values()))
    assert peak <= 4 and rule.retained_events() == []
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    [m] = rule.finalize()
    assert m.proposed_lane == "context" and f"{12 * 24 * 21} times" in m.claim
    assert f"spread across {24 * 21} distinct hours" in m.claim


def test_external_ssh_logins_hold_twenty_citations_and_exact_counts():
    rule = host.SshLoginFromExternal()
    logins = [ev("auth", T0 + timedelta(minutes=i), auth__service="sshd", auth__phase="authentication",
                 source__ip="203.0.113.9", user__name="root") for i in range(500)]
    [m] = drain(rule, [logins[:250], logins[250:]])
    assert len(m.events) == 20 and "At least 500 successful SSH login(s)" in m.claim
    assert (T0 + timedelta(minutes=499)).isoformat() in m.claim
    assert all(isinstance(i, str) for store in rule.groups.values() for i in store.ids())


@pytest.mark.parametrize("cls, make", [
    (host.SshLoginFromExternal,
     lambda i: ev("auth", T0, auth__service="sshd", auth__phase="authentication", source__ip=f"203.0.113.{i}",
                  user__name="root")),
    (host.UnbackedExecutable,
     lambda i: ev("process_exec", T0, process__executable=f"/memfd:x{i} (deleted)", process__pid=i)),
    (host.WebServiceSpawnsInterpreter,
     lambda i: ev("process_exec", T0, process__user="www-data", process__argv=["/bin/sh", "-c", f"cmd{'x' * i}"],
                  process__executable="/bin/dash")),
])
def test_host_group_budgets_refuse_new_groups(monkeypatch, cls, make):
    monkeypatch.setattr(cls, "MAX_KEYS", 3)
    rule = cls()
    rule.consume([make(i) for i in range(1, 8)])
    assert rule.capped == 4 and any("4 record(s) not evaluated" in r for r in rule.limit_reasons())


def test_tamper_held_records_and_per_key_times_are_budgeted(monkeypatch):
    monkeypatch.setattr(tamper._TamperRule, "MAX_HELD", 3)
    monkeypatch.setattr(tamper._TamperRule, "TIMES_PER_KEY", 5)
    rule = tamper.SecurityOrLoggingServiceStop()
    stops = [ev("service_change", T0 + timedelta(minutes=i), service__name="auditd", service__job="stop",
                service__job_phase="done", service__scope="system", service__source="audit") for i in range(6)]
    starts = [ev("service_change", T0 + timedelta(minutes=i, seconds=30), service__name="auditd", service__job="start",
                 service__job_phase="done", service__scope="system", service__source="audit") for i in range(9)]
    rule.consume(stops + starts)
    assert len(rule.stops) == 3 and rule.capped == 3 and len(rule.starts[("web1", "auditd")]) == 5
    reasons = " ".join(rule.limit_reasons())
    assert "3 record(s) not evaluated" in reasons and "time list" in reasons


def test_indicator_groups_are_budgeted_and_cited_as_ids(monkeypatch):
    monkeypatch.setattr(IndicatorMatch, "MAX_KEYS", 2)
    listed = IndicatorSet([Indicator(id="IND-1", kind="domain", values=("bad.test",), label="test", source="unit",
                                     lane="lead", severity="medium", attack=())])
    rule = IndicatorMatch(listed)
    events = [ev("dns_query", T0 + timedelta(seconds=i), host_name="sensor", source__ip="10.0.0.5",
                 dns__question__name=f"h{i}.bad.test") for i in range(5)]
    out = drain(rule, [events])
    assert len(out) == 2 and rule.capped == 3
    assert all(isinstance(i, str) for store in rule.groups.values() for i in store.ids())
