"""Doctor: every check runs under a deadline, a hung or crashing check costs only itself, and the store checks are
read-only and bounded by a lock wait and their own deadline."""
import sqlite3
import threading
import time

import pytest

from romulus import doctor
from romulus.config import Settings
from romulus.doctor import Check, check_db, check_db_space, run_all
from romulus.store.db import make_engine, migrate


def _quiet(monkeypatch, **overrides):
    """Every check replaced by an instant OK, except the ones given."""
    names = {"check_es": "es.reachable", "check_linux_text_sources": "es.text_inventory",
             "check_site_networks": "site.internal_networks", "check_arkime": "arkime.reachable",
             "check_ollama": "ollama.reachable", "check_agent": "agent.provider",
             "check_triage_model": "triage.provider", "check_secret_lengths": "secrets.length",
             "check_secret_strength": "secrets.strength", "check_tshark": "tshark", "check_site": "site.collection",
             "check_db_space": "db.space", "check_mention_patterns": "mentions.patterns",
             # no targets in its data: whether a hunt would run the packet stage stays unknown, so Arkime and TShark
             # are judged as required
             "check_packet_scope": "packets.scope", "check_session_secret": "web.secret_key",
             "check_index_patterns": "es.index_patterns"}
    for function, name in names.items():
        monkeypatch.setattr(doctor, function, overrides.get(function, lambda *_a, _n=name, **_k: Check(_n, "ok")))
    monkeypatch.setattr(doctor, "check_arkime_auth", overrides.get("check_arkime_auth", lambda _s: None))
    monkeypatch.setattr(doctor, "check_paths", overrides.get("check_paths", lambda *_a: [Check("disk.free", "ok")]))
    monkeypatch.setattr(doctor, "check_db", overrides.get("check_db", lambda *_a: Check("db.integrity", "ok")))


def test_a_hanging_check_times_out_and_the_run_continues(tmp_path, monkeypatch):
    release = threading.Event()

    def hang(*_args, **_kwargs):
        release.wait(30)
        return Check("arkime.reachable", "ok", "too late")

    def hang_locally(*_args, **_kwargs):
        release.wait(30)
        return Check("site.collection", "ok", "too late")

    _quiet(monkeypatch, check_arkime=hang, check_site=hang_locally)
    seen = []
    started = time.monotonic()
    try:
        checks = run_all(Settings(home=tmp_path), check_seconds=0.3, on_check=seen.append)
    finally:
        release.set()
    assert time.monotonic() - started < 10
    by_name = {check.name: check for check in checks}
    # a source every hunt needs fails on a timeout; a local check warns; neither reads as OK
    assert by_name["arkime.reachable"].status == "fail"
    assert by_name["arkime.reachable"].detail.startswith("timed out after 0.3 s")
    assert by_name["arkime.reachable"].data["timed_out"] is True
    assert by_name["site.collection"].status == "warn"
    assert by_name["site.collection"].detail.startswith("timed out after 0.3 s")
    # the checks after them still ran, and each result was reported as it was known
    assert [check.name for check in checks][-4:] == ["site.collection", "mentions.patterns", "db.integrity",
                                                     "db.space"]
    assert by_name["tshark"].status == "ok" and by_name["db.space"].status == "ok"
    assert seen == checks


def test_a_check_that_raises_is_its_own_result_and_the_run_continues(tmp_path, monkeypatch):
    def broken(*_args, **_kwargs):
        raise subprocess_timeout()

    def subprocess_timeout():
        import subprocess
        return subprocess.TimeoutExpired(["tshark"], 20)

    _quiet(monkeypatch, check_tshark=broken,
           check_secret_strength=lambda *_a: (_ for _ in ()).throw(OSError("unreadable tree")))
    checks = {check.name: check for check in run_all(Settings(home=tmp_path), check_seconds=5)}
    assert checks["tshark"].status == "fail" and "TimeoutExpired" in checks["tshark"].detail
    assert checks["secrets.strength"].status == "warn" and "unreadable tree" in checks["secrets.strength"].detail
    assert checks["db.space"].status == "ok"


def test_every_check_has_a_deadline_and_the_override_applies_to_all(tmp_path):
    s = Settings(home=tmp_path)
    steps = doctor.doctor_steps(s)
    assert steps and all(0 < step.seconds <= 400 for step in steps)
    assert {step.name for step in steps if step.critical} == {
        "es.reachable", "arkime.reachable", "ollama.reachable", "agent.provider", "triage.provider", "tshark"}
    overridden = doctor.doctor_steps(s, check_seconds=7)
    assert {step.seconds for step in overridden if step.name != "db.integrity"} == {7}
    assert next(step for step in overridden if step.name == "db.integrity").seconds == 7 + doctor.DB_GRACE_SECONDS


def test_tshark_that_never_answers_fails_instead_of_raising(tmp_path, monkeypatch):
    import subprocess

    monkeypatch.setattr(doctor.shutil, "which", lambda _name: "/usr/bin/tshark")

    def slow(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(["tshark"], doctor.TSHARK_SECONDS)

    monkeypatch.setattr(doctor.subprocess, "run", slow)
    check = doctor.check_tshark(Settings(home=tmp_path))
    assert check.status == "fail" and f"within {doctor.TSHARK_SECONDS} s" in check.detail


def test_the_model_probe_calls_are_cut_short_but_the_timeout_warning_reads_the_configured_value(tmp_path, monkeypatch):
    from types import SimpleNamespace

    seen = []
    readiness = SimpleNamespace(state="ready", provider="openai_responses", model="m",
                                decision=SimpleNamespace(egress="local", host="model.invalid", basis="test"))
    monkeypatch.setattr(doctor, "agent_readiness", lambda *_a: readiness)

    def build(settings, **_kwargs):
        seen.append(settings.agent_timeout_seconds)
        return SimpleNamespace(probe=lambda: [("agent.reachable", "ok", "answered")])

    monkeypatch.setattr(doctor, "build_provider", build)
    s = Settings(home=tmp_path, agent_timeout_seconds=900, agent_effort="high")
    checks = {check.name: check for check in doctor.check_agent(s)}
    assert seen == [doctor.MODEL_PROBE_CALL_SECONDS] and s.agent_timeout_seconds == 900
    assert "agent.timeout" not in checks and checks["agent.reachable"].status == "ok"
    short = Settings(home=tmp_path, agent_timeout_seconds=30)
    doctor.check_agent(short)
    assert seen[-1] == 30


# ---- the store -------------------------------------------------------------------------------------------------

def _store(tmp_path) -> Settings:
    s = Settings(home=tmp_path)
    engine = make_engine(s.db_path)
    migrate(engine)
    engine.dispose()
    return s


def test_the_db_check_returns_ok_behind_a_held_write_transaction(tmp_path):
    s = _store(tmp_path)
    writer = sqlite3.connect(s.db_path, timeout=0)
    try:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("BEGIN IMMEDIATE")
        writer.execute("INSERT INTO audit_event (at, actor, action, detail) VALUES ('2026-01-01', 't', 'x', '{}')")
        started = time.monotonic()
        integrity, space = check_db(s), check_db_space(s)
        assert time.monotonic() - started < 5
    finally:
        writer.rollback()
        writer.close()
    assert integrity.status == "ok" and integrity.detail.endswith(": ok")
    assert space.status == "ok"


def test_the_db_check_under_an_exclusive_lock_returns_within_the_lock_wait(tmp_path, monkeypatch):
    s = _store(tmp_path)
    monkeypatch.setattr(doctor, "DB_BUSY_TIMEOUT_MS", 300)
    holder = sqlite3.connect(s.db_path, timeout=0)
    try:
        holder.execute("PRAGMA locking_mode=EXCLUSIVE")
        holder.execute("BEGIN EXCLUSIVE")
        holder.execute("INSERT INTO audit_event (at, actor, action, detail) VALUES ('2026-01-01', 't', 'x', '{}')")
        started = time.monotonic()
        integrity, space = check_db(s), check_db_space(s)
        elapsed = time.monotonic() - started
    finally:
        holder.rollback()
        holder.close()
    assert elapsed < 10
    assert integrity.status == "warn" and "lock" in integrity.detail and "not verified" in integrity.detail
    assert space.status == "warn" and "not verified" in space.detail


def test_the_integrity_check_stops_at_its_deadline(tmp_path, monkeypatch):
    s = _store(tmp_path)
    monkeypatch.setattr("romulus.store.db.INTEGRITY_DEADLINE_STEPS", 1)
    started = time.monotonic()
    check = check_db(s, seconds=0)
    assert time.monotonic() - started < 5
    assert check.status == "warn" and "did not finish within 0 s" in check.detail
    assert "not verified" in check.detail


def test_the_db_check_never_migrates_or_writes(tmp_path):
    s = _store(tmp_path)
    with sqlite3.connect(s.db_path) as connection:
        connection.execute("UPDATE alembic_version SET version_num = 'older'")
    connection.close()
    before = s.db_path.read_bytes()
    check = check_db(s)
    assert check.status == "warn" and "schema at older" in check.detail and "migrates it" in check.detail
    with sqlite3.connect(s.db_path) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchall() == [("older",)]
    connection.close()
    assert s.db_path.read_bytes() == before


def test_a_missing_store_is_not_created(tmp_path):
    s = Settings(home=tmp_path)
    assert check_db(s).status == "warn" and check_db_space(s).status == "ok"
    assert not s.db_path.exists()


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "x"])
def test_check_timeout_must_be_a_positive_number(value, capsys):
    from romulus import cli

    with pytest.raises(SystemExit) as stop:
        cli.main(["doctor", "--check-timeout", value])
    assert stop.value.code == 2 and "--check-timeout" in capsys.readouterr().err
