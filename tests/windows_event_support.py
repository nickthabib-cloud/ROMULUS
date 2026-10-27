"""Compact typed Windows fixtures and staged-rule driver for event-rule regressions."""
from datetime import UTC, datetime, timedelta

from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from tests.windows_process_support import run

START = datetime(2026, 1, 2, 3, tzinfo=UTC)


def event(family, code, *, host="ws01", offset=0, native=None, outcome="success", **fields):
    native = native or f"{family}-{code}-{host}-{offset}"
    values = {"host.os.family": "windows", "event.code": code, **fields}
    return TypedEvent(id=native, family=family, ts=START + timedelta(seconds=offset), host=host,
                      outcome=Outcome(outcome), fields={name: fv(value, f"{native}:{name}")
                                                       for name, value in values.items()},
                      raw=[RawRef(target="windows", native_id=native)], normalizer="windows-ecs@4")


__all__ = ["START", "event", "run"]
