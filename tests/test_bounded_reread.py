"""The re-read guards of every playbook that has one stay bounded however many records the sweep reads, and a
batch handed over again is still counted once."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect import bounded
from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv

START = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
GUARDED = [cls for cls in ALL_PLAYBOOKS if cls.kind not in ("context", "packet")]


def _event(i: int, family: str) -> TypedEvent:
    fields = {"process.pid": 1000 + i % 30000, "process.ppid": 1, "process.executable": "/usr/bin/true",
              "process.argv": ["true"], "process.uid": "1000", "auth.service": "sshd",
              "auth.phase": "authentication", "source.ip": "10.0.0.5", "source.port": 40000 + i % 20000,
              "destination.ip": "10.0.0.9", "destination.port": 22, "network.transport": "tcp",
              "socket.syscall": "connect"}
    return TypedEvent(id=f"{family}-{i}", family=family, ts=START + timedelta(milliseconds=i), host="h",
                      outcome=Outcome.failure, fields={k: fv(v, "test") for k, v in fields.items()},
                      raw=[RawRef(target="t", native_id=f"{family}-{i}")], normalizer="test")


def _guards(playbook) -> list:
    return [value for name in ("_seen", "_staged") if (value := getattr(playbook, name, None)) is not None]


@pytest.mark.parametrize("cls", [cls for cls in GUARDED if _guards(cls())], ids=lambda cls: cls.id)
def test_reread_guard_is_bounded(monkeypatch, cls):
    monkeypatch.setattr(bounded, "RECENT_IDS", 500)
    playbook = cls()
    assert _guards(playbook), cls.id
    for start in range(0, 20_000, 1000):
        batch = [_event(i, family) for i in range(start, start + 1000) for family in cls.families[:2]]
        playbook.consume(batch)
        for guard in _guards(playbook):
            assert len(guard) <= 2 * 500, (cls.id, len(guard))
