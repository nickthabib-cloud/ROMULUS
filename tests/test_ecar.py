"""Synthetic eCAR records from the public schema and CAR object vocabulary.

https://github.com/FiveDirections/OpTC-data/blob/master/ecar.md
https://github.com/FiveDirections/OpTC-data/blob/master/errata.md
https://github.com/FiveDirections/OpTC-data/blob/master/README.md
https://car.mitre.org/data_model/
"""
from copy import deepcopy
from datetime import UTC, datetime

import pytest

from romulus.evidence.ecar import (
    ECAR_NORMALIZER,
    EcarInputError,
    EcarSkip,
    is_ecar_source,
    normalization_notices,
    normalize_ecar,
)
from romulus.evidence.ecar_catalog import ECAR_ROWS

RECORD = "11111111-1111-4111-8111-111111111111"
PROCESS = "22222222-2222-4222-8222-222222222222"
ACTOR = "33333333-3333-4333-8333-333333333333"
ZERO = "00000000-0000-0000-0000-000000000000"


def ecar_hit(object_name="PROCESS", action="CREATE", properties=None, **values):
    source = {"id": RECORD, "hostname": "CLIENT.example.test", "objectID": PROCESS,
              "object": object_name, "action": action, "actorID": ACTOR,
              "pid": 420, "ppid": 210, "tid": 422, "principal": "EXAMPLE\\analyst",
              "timestamp": 1735689600123,
              "properties": properties if properties is not None else {
                  "image_path": r"C:\Windows\System32\cmd.exe", "command_line": "cmd.exe /c echo test",
                  "parent_image_path": r"C:\Windows\explorer.exe", "user": "EXAMPLE\\analyst"}}
    source.update(values)
    return {"_index": "synthetic-endpoint", "_id": "native-1", "_source": source}


@pytest.mark.parametrize("pair", ECAR_ROWS)
def test_catalog_rows_are_typed_or_explicitly_counted(pair):
    row = ECAR_ROWS[pair]
    hit = ecar_hit(*pair, properties={})
    assert row.support in {"documented", "expected"}
    if row.family is None:
        with pytest.raises(EcarSkip, match="not typed") as caught:
            normalize_ecar(hit)
        assert caught.value.families == ()
    else:
        event = normalize_ecar(hit)
        assert event.family == row.family
        assert event.host == "client"
        assert event.get("host.os.family") == "windows"
        assert event.normalizer == ECAR_NORMALIZER == "ecar@1"
        assert not any(event.has(name) for name in ("event.code", "event.channel", "event.provider"))
        assert event.get("ecar.object") == pair[0]
        assert event.get("ecar.action") == pair[1]


def test_process_paths_origins_and_fenced_parent():
    event = normalize_ecar(ecar_hit(properties={
        "image_path": r"\Device\HarddiskVolume1\Windows\System32\CMD.EXE",
        "parent_image_path": r"C:\Windows\explorer.exe", "command_line": "cmd.exe /c echo test",
        "user": "EXAMPLE\\analyst", "sid": "S-1-5-21-1-2-3-1001"}))
    assert event.get("process.executable_key") == r"\device\harddiskvolume1\windows\system32\cmd.exe"
    assert event.get("process.executable_key.device_path") is True
    assert event.fields["process.executable"].origin == "native-1:properties.image_path"
    assert event.get("process.entity_id") == "ecar:" + PROCESS
    assert event.get("process.id_kind") == "ecar"
    assert event.get("process.parent.entity_id") == "pid:client:210"
    assert event.get("process.parent.id_kind") == "fenced_pid"
    assert event.get("process.user") == "EXAMPLE\\analyst"
    assert event.ts == datetime(2025, 1, 1, 0, 0, 0, 123000, tzinfo=UTC)


def test_pipeline_time_wins_and_both_native_epoch_fields_work():
    hit = ecar_hit(timestamp_ms=1735689600123)
    hit["_source"].pop("timestamp")
    assert normalize_ecar(hit).ts.microsecond == 123000
    hit["_source"]["@timestamp"] = "2025-01-02T03:04:05Z"
    event = normalize_ecar(hit)
    assert event.ts == datetime(2025, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert event.get("ecar.timestamp_ms") == 1735689600123


@pytest.mark.parametrize("field,value", [("id", "bad"), ("hostname", ""), ("timestamp", True),
                                        ("timestamp", "bad"), ("properties", [])])
def test_malformed_identity_is_not_guessed(field, value):
    with pytest.raises(EcarInputError):
        normalize_ecar(ecar_hit(**{field: value}))


@pytest.mark.parametrize("value", [-1, 0, True, "bad"])
def test_unknown_or_malformed_process_pid_is_not_typed(value):
    event = normalize_ecar(ecar_hit(pid=value, ppid=value, tid=value, objectID=ZERO))
    assert not event.has("process.pid")
    assert not event.has("process.ppid")
    assert not event.has("process.parent.entity_id")
    assert not event.has("process.entity_id")


def test_event_identity_uses_record_uuid_not_process_object_or_native_id():
    hit = ecar_hit()
    event = normalize_ecar(hit)
    duplicate = deepcopy(hit)
    duplicate["_id"] = "another-copy"
    duplicate["_index"] = "another-index"
    assert normalize_ecar(duplicate).id == event.id
    different = deepcopy(hit)
    different["_source"]["id"] = "44444444-4444-4444-8444-444444444444"
    assert normalize_ecar(different).id != event.id
    assert event.raw[0].native_id == "native-1"
    conflicting_copy = ecar_hit("FILE", "CREATE", {"file_path": r"C:\Tools\synthetic.txt"})
    assert normalize_ecar(conflicting_copy).id == event.id


def test_flow_fields_actor_and_zeek_link():
    event = normalize_ecar(ecar_hit("FLOW", "START", {
        "image_path": r"C:\Tools\client.exe", "src_ip": "192.0.2.10", "src_port": "55000",
        "dest_ip": "198.51.100.20", "dest_port": "443", "direction": "outbound", "l4protocol": "TCP",
        "bro_id": "Csynthetic123"}))
    assert event.family == "net_socket"
    assert event.get("process.entity_id") == "ecar:" + ACTOR
    assert event.get("source.port") == 55000
    assert event.get("network.direction") == "egress"
    assert event.get("network.transport") == "tcp"
    assert event.get("zeek.uid") == "Csynthetic123"
    assert event.has("network.community_id")


def test_registry_key_value_boundary_and_native_data_type():
    event = normalize_ecar(ecar_hit("REGISTRY", "ADD", {
        "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "value": "Synthetic",
        "data": r"C:\Tools\app.exe", "type": "REG_SZ"}))
    assert event.get("registry.path_key").startswith("hkey_current_user\\")
    assert event.get("registry.value_name") == "Synthetic"
    assert event.get("registry.value") == r"C:\Tools\app.exe"
    assert event.get("registry.action") == "value_set"
    assert event.get("registry.value_type") == "REG_SZ"


def test_unknown_properties_have_bounded_scoped_notices_and_usable_fields_survive():
    hit = ecar_hit(properties={"image_path": r"C:\Tools\app.exe", "future_" + "x" * 2000: "secret"})
    event = normalize_ecar(hit)
    assert event.has("process.executable")
    notices = normalization_notices(hit["_source"])
    assert len(notices) == 1 and notices[0][1] == ("process_exec",)
    assert len(notices[0][0]) <= 256 and "secret" not in notices[0][0]


def test_unknown_object_action_is_counted_without_global_family_uncertainty():
    with pytest.raises(EcarSkip) as caught:
        normalize_ecar(ecar_hit("OTHER", "FUTURE", {}))
    assert caught.value.families == ()
    assert str(caught.value) == "eCAR unsupported object/action: not typed"


def test_schema_recognition_requires_structural_markers():
    assert is_ecar_source(ecar_hit()["_source"])
    assert not is_ecar_source({"object": "PROCESS", "action": "CREATE", "message": "hello"})


def test_user_session_never_invents_success_from_action():
    event = normalize_ecar(ecar_hit("USER_SESSION", "LOGIN", {"user": "EXAMPLE\\analyst"}))
    assert event.outcome.value == "unknown"
    assert event.get("auth.action") == "logon"
    assert event.get("auth.target_user") == "analyst"


@pytest.mark.parametrize("value", ["caf\u00e9", "lone\ud800surrogate"])
def test_raw_digest_matches_stored_source_and_dispatch_digest(value):
    from romulus.evidence.normalize import normalize_hits, raw_digest
    from romulus.evidence.raw_scrub import clean_source

    hit = ecar_hit(properties={"command_line": value})
    event = normalize_ecar(hit)
    assert event.raw[0].digest == raw_digest(hit["_source"])
    assert event.raw[0].digest == raw_digest(clean_source(hit["_source"]))
    dispatched, skips, errors = normalize_hits([hit])
    assert not skips and not errors and len(dispatched) == 1
    assert dispatched[0].raw[0].digest == event.raw[0].digest


def test_host_actor_uuid_does_not_claim_to_identify_a_process():
    event = normalize_ecar(ecar_hit("HOST", "START", {}))
    assert not event.has("process.entity_id")
    assert event.get("process.fence") == "boot"
