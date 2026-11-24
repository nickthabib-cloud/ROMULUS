"""Doctor: Arkime and TShark are required only when a hunt would run the packet stage (an Arkime session index in
ES_INDEX_PATTERNS, judged as a hunt judges it), and ROMULUS_SECRET_KEY is checked by the rule `romulus web` enforces,
which refuses a bad key with a message instead of a traceback."""
import secrets
import threading
from datetime import UTC, datetime

import pytest

from romulus import cli, doctor
from romulus.config import Settings
from romulus.doctor import Check, run_all
from romulus.errors import SourceError
from romulus.web import app as web

ARKIME_MAPPING = {"arkime_sessions3-x": {"mappings": {"properties": {
    "firstPacket": {"type": "date"}, "lastPacket": {"type": "date"},
    "network": {"properties": {"community_id": {"type": "keyword"}}},
    "source": {"properties": {"ip": {"type": "ip"}}}}}}}
REAL_CHECK_INDEX_PATTERNS = doctor.check_index_patterns
HOST_MAPPING = {"logs-host": {"mappings": {"properties": {
    "@timestamp": {"type": "date"}, "host": {"properties": {"name": {"type": "keyword"}}}}}}}


class FakeClient:
    def __init__(self, targets: dict[str, dict], fail: bool = False):
        self.targets, self.fail = targets, fail

    def resolve(self, pattern):
        if self.fail:
            raise SourceError("connection refused")
        prefix = pattern.rstrip("*")
        return sorted(name for name in self.targets if name.startswith(prefix))

    def mapping(self, target):
        return self.targets[target]


# ---------------------------------------------------------------- a hunt needs index patterns

def test_doctor_fails_without_index_patterns_as_a_hunt_refuses_to_start(tmp_path):
    from romulus.hunt.run import create_hunt

    s = Settings(home=tmp_path)
    check = doctor.check_index_patterns(s)
    assert check.status == "fail"
    with pytest.raises(ValueError) as refused:
        create_hunt(s, datetime(2026, 1, 1, tzinfo=UTC), datetime(2026, 1, 2, tzinfo=UTC), created_by="test")
    assert check.detail == str(refused.value)                      # the hunt's own words
    assert "es.index_patterns" in {step.name for step in doctor.doctor_steps(s)}
    ok = doctor.check_index_patterns(Settings(home=tmp_path, es_index_patterns=["logs-*"]))
    assert ok.status == "ok" and "logs-*" in ok.detail


def test_doctor_exits_1_on_empty_index_patterns_even_when_arkime_and_tshark_only_warn(tmp_path, monkeypatch):
    _quiet_with(monkeypatch, [], _arkime_down, _no_tshark)
    monkeypatch.setattr(doctor, "check_index_patterns", REAL_CHECK_INDEX_PATTERNS)
    checks = {check.name: check for check in run_all(Settings(home=tmp_path), check_seconds=5)}
    assert checks["es.index_patterns"].status == "fail"
    assert checks["arkime.reachable"].status == "warn" and checks["tshark"].status == "warn"


# ---------------------------------------------------------------- which targets the packet stage reads

def test_no_index_patterns_means_no_packet_stage(tmp_path):
    assert doctor.packet_targets(Settings(home=tmp_path)) == []


def test_an_arkime_session_index_is_a_packet_target_and_a_host_index_is_not(tmp_path):
    s = Settings(home=tmp_path, es_index_patterns=["arkime_sessions3-*", "logs-host*"])
    client = FakeClient({"arkime_sessions3-x": ARKIME_MAPPING, "logs-host": HOST_MAPPING})
    assert doctor.packet_targets(s, client) == ["arkime_sessions3-x"]
    s = Settings(home=tmp_path, es_index_patterns=["logs-host*"])
    assert doctor.packet_targets(s, client) == []


def test_an_unreadable_cluster_leaves_the_packet_stage_unknown(tmp_path):
    s = Settings(home=tmp_path, es_index_patterns=["arkime_sessions3-*"])
    assert doctor.packet_targets(s, FakeClient({}, fail=True)) is None


# ---------------------------------------------------------------- Arkime and TShark follow the packet stage

def _quiet_with(monkeypatch, scope_targets, arkime, tshark):
    """Every check an instant OK, except the packet scope (with these targets) and the Arkime and TShark checks."""
    for function in ("check_es", "check_linux_text_sources", "check_site_networks", "check_ollama", "check_agent",
                     "check_triage_model", "check_secret_lengths", "check_secret_strength", "check_site",
                     "check_db_space", "check_mention_patterns", "check_web_tls", "check_session_secret",
                     "check_index_patterns"):
        monkeypatch.setattr(doctor, function, lambda *_a, _n=function, **_k: Check(_n, "ok"))
    monkeypatch.setattr(doctor, "check_arkime_auth", lambda _s: None)
    monkeypatch.setattr(doctor, "check_paths", lambda *_a: [Check("disk.free", "ok")])
    monkeypatch.setattr(doctor, "check_db", lambda *_a: Check("db.integrity", "ok"))
    if scope_targets == "hang":
        release = threading.Event()
        monkeypatch.setattr(doctor, "check_packet_scope", lambda _s: release.wait(30) or Check("packets.scope", "ok"))
    else:
        monkeypatch.setattr(doctor, "check_packet_scope",
                            lambda _s: Check("packets.scope", "ok", "", {"targets": scope_targets}))
    monkeypatch.setattr(doctor, "check_arkime", arkime)
    monkeypatch.setattr(doctor, "check_tshark", tshark)


def _arkime_down(_s):
    return Check("arkime.reachable", "fail", "connection refused")


def _no_tshark(_s):
    return Check("tshark", "fail", "tshark not found")


def test_without_an_arkime_index_arkime_and_tshark_only_warn(tmp_path, monkeypatch):
    _quiet_with(monkeypatch, [], _arkime_down, _no_tshark)
    checks = {check.name: check for check in run_all(Settings(home=tmp_path), check_seconds=5)}
    for name in ("arkime.reachable", "tshark"):
        assert checks[name].status == "warn"
        assert "packet stage will be skipped" in checks[name].detail
        assert checks[name].data["packet_stage"] == "skipped"
    assert not any(check.status == "fail" for check in checks.values())     # doctor exits 0


def test_a_timed_out_arkime_check_only_warns_without_an_arkime_index(tmp_path, monkeypatch):
    release = threading.Event()

    def hang(_s):
        release.wait(30)
        return Check("arkime.reachable", "ok")

    _quiet_with(monkeypatch, [], hang, _no_tshark)
    try:
        checks = {check.name: check for check in run_all(Settings(home=tmp_path), check_seconds=0.3)}
    finally:
        release.set()
    assert checks["arkime.reachable"].status == "warn"
    assert checks["arkime.reachable"].detail.startswith("timed out after 0.3 s")


@pytest.mark.parametrize("scope_targets", [["arkime_sessions3-x"], None, "hang"])
def test_with_an_arkime_index_or_when_unknown_arkime_and_tshark_stay_critical(tmp_path, monkeypatch, scope_targets):
    _quiet_with(monkeypatch, scope_targets, _arkime_down, _no_tshark)
    checks = {check.name: check for check in run_all(Settings(home=tmp_path), check_seconds=0.5)}
    assert checks["arkime.reachable"].status == "fail" and checks["arkime.reachable"].detail == "connection refused"
    assert checks["tshark"].status == "fail" and checks["tshark"].detail == "tshark not found"


def test_the_scope_check_names_what_it_found(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "packet_targets", lambda _s: [])
    assert doctor.check_packet_scope(Settings(home=tmp_path)).data == {"targets": []}
    monkeypatch.setattr(doctor, "packet_targets", lambda _s: None)
    unknown = doctor.check_packet_scope(Settings(home=tmp_path))
    assert unknown.status == "warn" and unknown.data == {"targets": None}


# ---------------------------------------------------------------- ROMULUS_SECRET_KEY

BAD_KEYS = ["", "short", "# random 32+ chars; signs web sessions", "x" * 20 + " " + "y" * 20]


@pytest.mark.parametrize("key", BAD_KEYS)
def test_doctor_fails_a_key_the_web_ui_would_refuse(tmp_path, key):
    check = doctor.check_session_secret(Settings(home=tmp_path, secret_key=key))
    assert check.status == "fail" and "32+ characters" in check.detail
    assert (key == "") == ("is empty" in check.detail)
    if key:
        assert key not in check.detail


def test_doctor_accepts_a_random_key(tmp_path):
    key = secrets.token_urlsafe(32)
    check = doctor.check_session_secret(Settings(home=tmp_path, secret_key=key))
    assert check.status == "ok" and key not in check.detail


def test_doctor_runs_the_secret_key_check(tmp_path):
    assert "web.secret_key" in {step.name for step in doctor.doctor_steps(Settings(home=tmp_path))}


@pytest.mark.parametrize("key", BAD_KEYS)
def test_web_refuses_a_bad_key_with_a_message(tmp_path, monkeypatch, capsys, key):
    env = tmp_path / "web.env"
    env.write_text(f"ROMULUS_HOME={tmp_path}\nROMULUS_SECRET_KEY='{key}'\nROMULUS_WEB_BIND=127.0.0.1:8443\n",
                   encoding="utf-8")
    for name in ("ROMULUS_SECRET_KEY", "ROMULUS_WEB_BIND", "ROMULUS_WEB_TLS_CERT", "ROMULUS_WEB_TLS_KEY",
                 "ROMULUS_WEB_ALLOW_PLAINTEXT", "ROMULUS_WEB_TRUSTED_PROXIES"):
        monkeypatch.delenv(name, raising=False)
    import uvicorn
    started = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: started.append(kw))
    monkeypatch.setattr(web, "create_app", lambda s, env=None: object())
    assert cli.main(["--env-file", str(env), "web"]) == cli.EXIT_FAIL and not started
    err = capsys.readouterr().err
    assert err.startswith("romulus web: ") and "ROMULUS_SECRET_KEY" in err and "Traceback" not in err
