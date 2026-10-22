"""Pure baseline key extraction from authoritative typed fields."""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from romulus.baseline.spec import BASELINE_SPECS, SPEC_BY_ID, KeyContext, Pending
from romulus.detect.correlation import PidTable
from romulus.evidence.typed import Outcome, TypedEvent, fv
from scripts.archmap import violations

T0 = datetime(2026, 1, 2, 12, tzinfo=UTC)


def _event(
    family: str,
    *,
    event_id: str = "event-1",
    host: str | None = "web01",
    outcome: Outcome = Outcome.unknown,
    ts: datetime = T0,
    **fields,
) -> TypedEvent:
    return TypedEvent(
        id=event_id,
        family=family,
        ts=ts,
        host=host,
        outcome=outcome,
        fields={name: fv(value, f"fixture:{name}") for name, value in fields.items()},
        raw=[],
        normalizer="fixture@1",
    )


def _ctx(table: PidTable | None = None, service_accounts: frozenset[str] | None = None) -> KeyContext:
    args = {"pid_table": table or PidTable()}
    if service_accounts is not None:
        args["service_accounts"] = service_accounts
    return KeyContext(**args)


def test_registry_has_the_six_accepted_specs_and_metadata():
    assert [spec.id for spec in BASELINE_SPECS] == [
        "bl.ssh_tuple", "bl.exec_path", "bl.exec_pair", "bl.cmd_shape", "bl.ext_dest", "bl.svc_exec_rate",
    ]
    assert SPEC_BY_ID["bl.ssh_tuple"].families == ("auth",)
    assert SPEC_BY_ID["bl.exec_path"].scope == ("host", "account")
    assert SPEC_BY_ID["bl.exec_pair"].scope == "host"
    assert SPEC_BY_ID["bl.cmd_shape"].scope == "host"
    assert SPEC_BY_ID["bl.ext_dest"].scope == "internal_ip"
    assert SPEC_BY_ID["bl.ext_dest"].families == (
        "net_flow", "dns_query", "tls_session", "net_session",
    )
    assert SPEC_BY_ID["bl.svc_exec_rate"].bucket == "hour"
    assert {spec.id: spec.measure for spec in BASELINE_SPECS} == {
        "bl.ssh_tuple": "presence", "bl.exec_path": "prevalence", "bl.exec_pair": "prevalence",
        "bl.cmd_shape": "prevalence", "bl.ext_dest": "prevalence", "bl.svc_exec_rate": "rate",
    }
    assert all(spec.version == "1" and spec.key_version == "1" for spec in BASELINE_SPECS)


def test_key_id_is_scope_free_and_key_digest_is_scoped():
    event = _event(
        "process_exec", outcome=Outcome.success,
        **{"process.executable": "/bin/sh", "process.exec_file.path": "/bin/sh", "process.user": "www-data"},
    )
    by_host, by_account = SPEC_BY_ID["bl.exec_path"].keys(event, _ctx())
    material = 'bl.exec_path|1|{"exec_file_path":"/bin/sh","executable":"/bin/sh"}'
    assert by_host.key_id == by_account.key_id == hashlib.sha256(material.encode()).hexdigest()
    assert by_host.key_digest != by_account.key_digest
    assert (by_host.scope_kind, by_host.scope) == ("host", "host:web01")
    assert (by_account.scope_kind, by_account.scope) == ("account", "account:www-data")
    other_host = SPEC_BY_ID["bl.exec_path"].keys(event.model_copy(update={"host": "db01"}), _ctx())[0]
    assert other_host.key_id == by_host.key_id and other_host.key_digest != by_host.key_digest


def test_architecture_gate_rejects_baseline_imports_from_hunt_or_sources():
    found = violations({
        "romulus.baseline.spec": {"romulus.hunt.run", "romulus.sources.models"},
    })
    assert found == [
        "romulus.baseline.spec imports romulus.hunt.run (layer rule: baseline must not import hunt)",
        "romulus.baseline.spec imports romulus.sources.models (layer rule: baseline must not import sources)",
    ]


def test_ssh_tuple_emits_one_key_per_dimension_each_with_a_kind():
    event = _event(
        "auth", outcome=Outcome.success,
        **{"auth.service": "sshd", "source.ip": "192.0.2.19", "user.name": "Alice"},
    )
    keys = SPEC_BY_ID["bl.ssh_tuple"].keys(event, _ctx())
    assert [key.key for key in keys] == [
        {
            "host": "web01", "kind": "tuple", "source_ip": "192.0.2.19",
            "source_network": "192.0.2.0/24", "user": "Alice",
        },
        {"host": "web01", "kind": "host"},
        {"kind": "source_ip", "source_ip": "192.0.2.19"},
        {"kind": "source_network", "source_network": "192.0.2.0/24"},
        {"kind": "user", "user": "Alice"},
    ]
    assert {(key.scope_kind, key.scope) for key in keys} == {("site", "site")}
    assert len({key.key_id for key in keys}) == 5


def test_ssh_tuple_known_source_network_keeps_its_key_when_the_address_changes():
    spec = SPEC_BY_ID["bl.ssh_tuple"]
    fields = {"auth.service": "sshd", "user.name": "alice"}
    first = spec.keys(_event("auth", outcome=Outcome.success, **{**fields, "source.ip": "192.0.2.19"}), _ctx())
    second = spec.keys(_event("auth", outcome=Outcome.success, **{**fields, "source.ip": "192.0.2.77"}), _ctx())
    first_by, second_by = ({key.key["kind"]: key.key_digest for key in keys} for keys in (first, second))
    assert first_by["source_network"] == second_by["source_network"]
    assert first_by["user"] == second_by["user"]
    assert first_by["source_ip"] != second_by["source_ip"]


@pytest.mark.parametrize(
    "event",
    [
        _event("auth", host=None, outcome=Outcome.success,
               **{"auth.service": "sshd", "source.ip": "192.0.2.1", "user.name": "a"}),
        _event("auth", outcome=Outcome.success,
               **{"auth.service": "sshd", "source.ip": None, "user.name": "a"}),
        _event("auth", outcome=Outcome.success,
               **{"auth.service": "sshd", "source.ip": "192.0.2.1", "user.name": None}),
        _event("auth", outcome=Outcome.failure,
               **{"auth.service": "sshd", "source.ip": "192.0.2.1", "user.name": "a"}),
        _event("auth", outcome=Outcome.success,
               **{"auth.service": "sudo", "source.ip": "192.0.2.1", "user.name": "a"}),
    ],
)
def test_ssh_tuple_missing_or_failed_auth_never_keys(event):
    assert SPEC_BY_ID["bl.ssh_tuple"].keys(event, _ctx()) is None


def test_exec_path_preserves_paths_verbatim_and_emits_host_and_account_scopes():
    event = _event(
        "process_exec",
        outcome=Outcome.success,
        **{
            "process.executable": "/Opt/My App/Runner ",
            "process.exec_file.path": "/Opt/My App/Script.PY ",
            "process.user": "svc web",
        },
    )
    keys = SPEC_BY_ID["bl.exec_path"].keys(event, _ctx())
    assert [key.scope for key in keys] == ["host:web01", "account:svc web"]
    assert keys[0].key == {
        "exec_file_path": "/Opt/My App/Script.PY ", "executable": "/Opt/My App/Runner ",
    }


@pytest.mark.parametrize("missing", ["host", "process.executable", "process.exec_file.path", "process.user"])
def test_exec_path_missing_required_value_never_keys(missing):
    fields = {
        "process.executable": "/bin/sh", "process.exec_file.path": "/bin/sh", "process.user": "www-data",
    }
    host = "web01"
    if missing == "host":
        host = None
    else:
        fields[missing] = None
    event = _event("process_exec", host=host, outcome=Outcome.success, **fields)
    assert SPEC_BY_ID["bl.exec_path"].keys(event, _ctx()) is None


def test_exec_pair_uses_the_same_boot_parent_exec():
    table = PidTable()
    table.add(_event(
        "process_exec",
        event_id="parent",
        ts=T0 - timedelta(seconds=1),
        **{
            "process.pid": 100, "process.ppid": 1, "process.executable": "/usr/sbin/nginx",
            "host.boot.id": "boot-a",
        },
    ))
    child = _event(
        "process_exec",
        **{
            "process.pid": 101, "process.ppid": 100, "process.executable": "/bin/sh",
            "host.boot.id": "boot-a",
        },
    )
    keys = SPEC_BY_ID["bl.exec_pair"].keys(child, _ctx(table))
    assert len(keys) == 1
    assert keys[0].scope == "host:web01"
    assert keys[0].key == {"child_executable": "/bin/sh", "parent_executable": "/usr/sbin/nginx"}


def test_exec_pair_without_parent_exec_returns_pending_carry_in():
    child = _event("process_exec", **{"process.ppid": 100, "process.executable": "/bin/sh"})
    assert SPEC_BY_ID["bl.exec_pair"].keys(child, _ctx()) == Pending("web01", None, 100, T0)


def test_exec_pair_never_joins_a_parent_from_another_boot():
    table = PidTable()
    table.add(_event(
        "process_exec",
        event_id="old-parent",
        ts=T0 - timedelta(seconds=1),
        **{"process.pid": 100, "process.executable": "/old/parent", "host.boot.id": "boot-a"},
    ))
    child = _event(
        "process_exec",
        **{"process.ppid": 100, "process.executable": "/bin/sh", "host.boot.id": "boot-b"},
    )
    assert SPEC_BY_ID["bl.exec_pair"].keys(child, _ctx(table)) == Pending("web01", "boot-b", 100, T0)


@pytest.mark.parametrize("missing", ["host", "process.ppid", "process.executable"])
def test_exec_pair_missing_required_value_never_keys(missing):
    fields = {"process.ppid": 100, "process.executable": "/bin/sh"}
    host = "web01"
    if missing == "host":
        host = None
    else:
        fields[missing] = None
    assert SPEC_BY_ID["bl.exec_pair"].keys(_event("process_exec", host=host, **fields), _ctx()) is None


def test_command_shape_masks_variable_tokens_without_using_serialized_records():
    event = _event(
        "process_exec",
        **{
            "process.executable": "/usr/bin/tool",
            "process.argv": [
                "tool", "192.0.2.9:443", "--id=550e8400-e29b-41d4-a716-446655440000",
                "--hex=0xDEADBEEF", "deadbeef", "42", "12345678", "--port=8080", "[2001:db8::1]:53",
            ],
        },
    )
    keys = SPEC_BY_ID["bl.cmd_shape"].keys(event, _ctx())
    assert [(key.scope_kind, key.scope) for key in keys] == [("host", "host:web01")]
    assert keys[0].key == {
        "argv_shape": [
            "tool", "<ip>:<num>", "--id=<uuid>", "--hex=<hex>", "<hex>", "<num>",
            "<num>", "--port=<num>", "[<ip>]:<num>",
        ],
        "executable": "/usr/bin/tool",
    }


@pytest.mark.parametrize(
    "fields",
    [
        {"process.executable": "/bin/sh", "process.argv": ["sh"], "process.argv_complete": False},
        {"process.executable": "/bin/sh", "process.argv": None},
        {"process.executable": "/bin/sh", "process.argv": ["sh", None]},
        {"process.executable": None, "process.argv": ["sh"]},
    ],
)
def test_command_shape_incomplete_or_missing_argv_never_keys(fields):
    assert SPEC_BY_ID["bl.cmd_shape"].keys(_event("process_exec", **fields), _ctx()) is None


def _kinds(keys) -> dict[str, dict]:
    return {key.key["kind"]: key.key for key in keys}


def _digest(keys, kind: str) -> str:
    return next(key.key_digest for key in keys if key.key["kind"] == kind)


def test_external_destination_emits_one_key_per_dimension_with_canonical_v6_and_v4_mapped_addresses():
    spec = SPEC_BY_ID["bl.ext_dest"]
    ipv6 = spec.keys(_event(
        "net_flow", **{"source.ip": "fd00::10", "destination.ip": "2001:4860:4860::8888"},
    ), _ctx())
    assert {(key.scope_kind, key.scope) for key in ipv6} == {("internal_ip", "internal_ip:fd00::10")}
    assert _kinds(ipv6) == {
        "dest_ip": {"kind": "dest_ip", "dest_ip": "2001:4860:4860::8888"},
        "dest_network": {"kind": "dest_network", "dest_network": "2001:4860:4860::/48"},
    }
    mapped = spec.keys(_event(
        "net_session", **{"source.ip": "::ffff:10.1.2.3", "destination.ip": "::ffff:192.0.2.129"},
    ), _ctx())
    assert {key.scope for key in mapped} == {"internal_ip:10.1.2.3"}
    assert _kinds(mapped) == {
        "dest_ip": {"kind": "dest_ip", "dest_ip": "192.0.2.129"},
        "dest_network": {"kind": "dest_network", "dest_network": "192.0.2.0/24"},
    }


def test_external_destination_tls_emits_sni_and_registered_domain_keys():
    keys = SPEC_BY_ID["bl.ext_dest"].keys(_event(
        "tls_session",
        **{
            "source.ip": "10.0.0.4", "destination.ip": "198.51.100.9",
            "tls.client.server_name": "Api.Example.COM.",
        },
    ), _ctx())
    assert _kinds(keys) == {
        "dest_ip": {"kind": "dest_ip", "dest_ip": "198.51.100.9"},
        "dest_network": {"kind": "dest_network", "dest_network": "198.51.100.0/24"},
        "sni": {"kind": "sni", "sni": "api.example.com"},
        "registered_domain": {"kind": "registered_domain", "registered_domain": "example.com"},
    }


def test_known_sni_on_a_new_address_keeps_the_same_sni_key():
    spec = SPEC_BY_ID["bl.ext_dest"]
    fields = {"source.ip": "10.0.0.4", "tls.client.server_name": "api.example.com"}
    old = spec.keys(_event("tls_session", **{**fields, "destination.ip": "198.51.100.9"}), _ctx())
    new = spec.keys(_event("tls_session", **{**fields, "destination.ip": "203.0.113.7"}), _ctx())
    assert _digest(old, "sni") == _digest(new, "sni")
    assert _digest(old, "registered_domain") == _digest(new, "registered_domain")
    assert _digest(old, "dest_ip") != _digest(new, "dest_ip")


def test_same_domain_through_two_resolvers_gives_the_same_domain_key():
    spec = SPEC_BY_ID["bl.ext_dest"]
    fields = {"dns.type": "query", "source.ip": "10.0.0.4", "dns.question.name": "WWW.Example.CO.UK."}
    first = spec.keys(_event("dns_query", **{**fields, "destination.ip": "10.0.0.53"}), _ctx())
    second = spec.keys(_event("dns_query", **{**fields, "destination.ip": "8.8.8.8"}), _ctx())
    assert [key.key for key in first] == [{"kind": "registered_domain", "registered_domain": "example.co.uk"}]
    assert [key.key_digest for key in first] == [key.key_digest for key in second]
    assert first[0].scope == "internal_ip:10.0.0.4"


def test_dns_answer_scopes_the_client_not_the_resolver():
    keys = SPEC_BY_ID["bl.ext_dest"].keys(_event(
        "dns_query",
        **{"dns.type": "answer", "source.ip": "10.0.0.53", "destination.ip": "10.0.0.4",
           "dns.question.name": "example.com"},
    ), _ctx())
    assert [key.scope for key in keys] == ["internal_ip:10.0.0.4"]


@pytest.mark.parametrize(
    "fields",
    [
        {"source.ip": None, "destination.ip": "192.0.2.1"},
        {"source.ip": "10.0.0.1", "destination.ip": None},
        {"source.ip": "not-an-ip", "destination.ip": "192.0.2.1"},
        {"source.ip": "10.0.0.1", "destination.ip": "not-an-ip"},
    ],
)
def test_external_destination_missing_or_malformed_address_never_keys(fields):
    assert SPEC_BY_ID["bl.ext_dest"].keys(_event("net_flow", **fields), _ctx()) is None


def test_service_exec_rate_uses_configured_service_accounts_and_empty_key():
    spec = SPEC_BY_ID["bl.svc_exec_rate"]
    service = _event("process_exec", **{"process.user": "www-data"})
    keys = spec.keys(service, _ctx(service_accounts=frozenset({"www-data"})))
    assert len(keys) == 1 and keys[0].scope == 'host_account:{"account":"www-data","host":"web01"}'
    assert keys[0].key == {}
    assert spec.keys(_event("process_exec", **{"process.user": "alice"}), _ctx(
        service_accounts=frozenset({"www-data"}),
    )) is None
    assert spec.keys(_event("process_exec", **{"process.user": None}), _ctx()) is None


def test_key_digests_are_deterministic_across_repeated_extraction():
    event = _event(
        "process_exec",
        **{"process.executable": "/bin/tool", "process.argv": ["tool", "--port=1234"]},
    )
    first = SPEC_BY_ID["bl.cmd_shape"].keys(event, _ctx())[0]
    second = SPEC_BY_ID["bl.cmd_shape"].keys(event.model_copy(deep=True), _ctx())[0]
    assert first == second
