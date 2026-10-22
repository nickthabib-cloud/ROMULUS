"""Pure baseline key extraction from authoritative typed fields."""
from __future__ import annotations

import hashlib
import ipaddress
from datetime import UTC, datetime, timedelta

import pytest

from romulus.baseline.spec import (
    ARGV_SHAPE_MAX_CHARS,
    ARGV_SHAPE_MAX_TOKENS,
    BASELINE_SPECS,
    SPEC_BY_ID,
    KeyContext,
    Missing,
    NotApplicable,
    ParentLookup,
    Pending,
    canonical_json,
)
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


SSH = {"auth.service": "sshd", "source.ip": "192.0.2.1", "user.name": "a"}


@pytest.mark.parametrize(
    ("host", "outcome", "fields", "missing"),
    [
        (None, Outcome.success, {}, ("host",)),
        ("", Outcome.success, {}, ("host",)),
        ("web01", Outcome.success, {"source.ip": None}, ("source.ip",)),
        ("web01", Outcome.success, {"source.ip": "not-an-ip"}, ("source.ip",)),
        ("web01", Outcome.success, {"source.ip": 3232235777}, ("source.ip",)),
        ("web01", Outcome.success, {"user.name": None}, ("user.name",)),
        ("web01", Outcome.success, {"user.name": ["alice", "bob"]}, ("user.name",)),
        ("web01", Outcome.success, {"user.name": 1000}, ("user.name",)),
        ("web01", Outcome.success, {"auth.service": None}, ("auth.service",)),
        ("web01", Outcome.unknown, {}, ("outcome",)),
    ],
)
def test_ssh_tuple_absent_or_malformed_required_value_is_typed_missing(host, outcome, fields, missing):
    result = SPEC_BY_ID["bl.ssh_tuple"].keys(_event("auth", host=host, outcome=outcome, **{**SSH, **fields}), _ctx())
    assert isinstance(result, Missing) and result.fields == missing and result.reason


@pytest.mark.parametrize(
    ("outcome", "fields"),
    [
        (Outcome.failure, {}),
        (Outcome.success, {"auth.service": "sudo"}),
        # a known non-applicable value decides even when another required value is absent
        (Outcome.failure, {"source.ip": None}),
        (Outcome.unknown, {"auth.service": "su"}),
    ],
)
def test_ssh_tuple_failed_auth_and_other_services_are_not_applicable(outcome, fields):
    result = SPEC_BY_ID["bl.ssh_tuple"].keys(_event("auth", outcome=outcome, **{**SSH, **fields}), _ctx())
    assert isinstance(result, NotApplicable) and result.reason


def test_wrong_family_is_not_applicable():
    result = SPEC_BY_ID["bl.ssh_tuple"].keys(_event("process_exec", outcome=Outcome.success, **SSH), _ctx())
    assert isinstance(result, NotApplicable)


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


EXEC = {"process.executable": "/bin/sh", "process.exec_file.path": "/bin/sh", "process.user": "www-data"}


@pytest.mark.parametrize(
    ("host", "outcome", "fields", "missing"),
    [
        (None, Outcome.success, {}, ("host",)),
        ("web01", Outcome.success, {"process.executable": None}, ("process.executable",)),
        ("web01", Outcome.success, {"process.exec_file.path": None}, ("process.exec_file.path",)),
        ("web01", Outcome.success, {"process.user": None}, ("process.user",)),
        ("web01", Outcome.success, {"process.user": ["a", "b"]}, ("process.user",)),
        ("web01", Outcome.success, {"process.executable": ["/bin/sh"]}, ("process.executable",)),
        ("web01", Outcome.unknown, {}, ("outcome",)),
    ],
)
def test_exec_path_absent_or_malformed_required_value_is_typed_missing(host, outcome, fields, missing):
    event = _event("process_exec", host=host, outcome=outcome, **{**EXEC, **fields})
    result = SPEC_BY_ID["bl.exec_path"].keys(event, _ctx())
    assert isinstance(result, Missing) and result.fields == missing


def test_exec_path_failed_exec_is_not_applicable():
    event = _event("process_exec", outcome=Outcome.failure, **{**EXEC, "process.user": None})
    assert isinstance(SPEC_BY_ID["bl.exec_path"].keys(event, _ctx()), NotApplicable)


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


def test_exec_pair_without_parent_exec_returns_compact_pending_carry_in():
    child = _event("process_exec", event_id="child-1", host="Web01",
                   **{"process.ppid": 100, "process.executable": "/bin/sh"})
    # the host stays as recorded: a carry-in pid table is keyed on the recorded host
    assert SPEC_BY_ID["bl.exec_pair"].keys(child, _ctx()) == Pending(
        host="Web01", boot=None, ppid=100, ts=T0, event_id="child-1", child_executable="/bin/sh",
    )


def test_exec_pair_accepts_any_parent_lookup_exposing_only_lookup():
    class OneParent:
        """A bounded stand-in: the extractor may call nothing but lookup()."""

        def __init__(self):
            self.calls = []

        def lookup(self, host, pid, ts, boot=None):
            self.calls.append((host, pid, ts, boot))
            return (ts - 1, "/usr/sbin/cron", 1, "raw-1", boot)

    table = OneParent()
    child = _event("process_exec", **{"process.ppid": 7, "process.executable": "/bin/sh",
                                      "host.boot.id": "boot-a"})
    keys = SPEC_BY_ID["bl.exec_pair"].keys(child, KeyContext(pid_table=table))
    assert keys[0].key == {"child_executable": "/bin/sh", "parent_executable": "/usr/sbin/cron"}
    assert table.calls == [("web01", 7, T0.timestamp(), "boot-a")]
    assert isinstance(OneParent(), ParentLookup)


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
    assert SPEC_BY_ID["bl.exec_pair"].keys(child, _ctx(table)) == Pending(
        host="web01", boot="boot-b", ppid=100, ts=T0, event_id="event-1", child_executable="/bin/sh",
    )


@pytest.mark.parametrize(
    ("host", "fields", "missing"),
    [
        (None, {}, ("host",)),
        ("web01", {"process.ppid": None}, ("process.ppid",)),
        ("web01", {"process.ppid": "100"}, ("process.ppid",)),
        ("web01", {"process.ppid": True}, ("process.ppid",)),
        ("web01", {"process.ppid": -1}, ("process.ppid",)),
        ("web01", {"process.executable": None}, ("process.executable",)),
        ("web01", {"process.executable": 5}, ("process.executable",)),
    ],
)
def test_exec_pair_absent_or_malformed_required_value_is_typed_missing(host, fields, missing):
    event = _event("process_exec", host=host, **{"process.ppid": 100, "process.executable": "/bin/sh", **fields})
    result = SPEC_BY_ID["bl.exec_pair"].keys(event, _ctx())
    assert isinstance(result, Missing) and result.fields == missing


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
    ("host", "fields", "missing"),
    [
        ("web01", {"process.executable": "/bin/sh", "process.argv": ["sh"], "process.argv_complete": False},
         ("process.argv",)),
        ("web01", {"process.executable": "/bin/sh", "process.argv": None}, ("process.argv",)),
        ("web01", {"process.executable": "/bin/sh", "process.argv": []}, ("process.argv",)),
        ("web01", {"process.executable": "/bin/sh", "process.argv": "sh -c id"}, ("process.argv",)),
        ("web01", {"process.executable": "/bin/sh", "process.argv": ["sh", None]}, ("process.argv",)),
        ("web01", {"process.executable": None, "process.argv": ["sh"]}, ("process.executable",)),
        (None, {"process.executable": "/bin/sh", "process.argv": ["sh"]}, ("host",)),
    ],
)
def test_command_shape_incomplete_or_missing_argv_is_typed_missing(host, fields, missing):
    result = SPEC_BY_ID["bl.cmd_shape"].keys(_event("process_exec", host=host, **fields), _ctx())
    assert isinstance(result, Missing) and result.fields == missing


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
    ("family", "fields", "missing"),
    [
        ("net_flow", {"source.ip": None, "destination.ip": "192.0.2.1"}, ("source.ip",)),
        ("net_flow", {"source.ip": "10.0.0.1", "destination.ip": None}, ("destination.ip",)),
        ("net_flow", {"source.ip": "not-an-ip", "destination.ip": "192.0.2.1"}, ("source.ip",)),
        ("net_flow", {"source.ip": "10.0.0.1", "destination.ip": "not-an-ip"}, ("destination.ip",)),
        ("net_session", {"source.ip": ["10.0.0.1"], "destination.ip": "192.0.2.1"}, ("source.ip",)),
        ("tls_session", {"source.ip": "10.0.0.1", "destination.ip": "192.0.2.1",
                         "tls.client.server_name": ["a.example.com"]}, ("tls.client.server_name",)),
        ("tls_session", {"source.ip": "10.0.0.1", "destination.ip": "192.0.2.1",
                         "tls.client.server_name": 7}, ("tls.client.server_name",)),
        ("dns_query", {"dns.type": "query", "source.ip": None, "destination.ip": "10.0.0.53",
                       "dns.question.name": "example.com"}, ("source.ip",)),
        ("dns_query", {"dns.type": "query", "source.ip": "10.0.0.4", "destination.ip": "bogus",
                       "dns.question.name": "example.com"}, ("destination.ip",)),
        ("dns_query", {"dns.type": "query", "source.ip": "10.0.0.4", "destination.ip": "10.0.0.53"},
         ("dns.question.names", "dns.question.name")),
        ("dns_query", {"dns.type": "query", "source.ip": "10.0.0.4", "destination.ip": "10.0.0.53",
                       "dns.question.names": ["example.com", 7]}, ("dns.question.names",)),
    ],
)
def test_external_destination_absent_or_malformed_value_is_typed_missing(family, fields, missing):
    result = SPEC_BY_ID["bl.ext_dest"].keys(_event(family, **fields), _ctx())
    assert isinstance(result, Missing) and result.fields == missing


@pytest.mark.parametrize(
    ("family", "fields"),
    [
        # inbound scanner traffic: external source to an internal host
        ("net_flow", {"source.ip": "203.0.113.50", "destination.ip": "10.0.0.8"}),
        ("net_session", {"source.ip": "203.0.113.50", "destination.ip": "10.0.0.8"}),
        # east-west between internal hosts
        ("net_flow", {"source.ip": "10.0.0.4", "destination.ip": "10.0.0.8"}),
        ("tls_session", {"source.ip": "fd00::4", "destination.ip": "fd00::8",
                         "tls.client.server_name": "intranet.example"}),
        # transit between two external addresses
        ("net_flow", {"source.ip": "198.51.100.1", "destination.ip": "203.0.113.2"}),
        # multicast, broadcast and unspecified destinations are not external hosts
        ("net_flow", {"source.ip": "10.0.0.4", "destination.ip": "224.0.0.251"}),
        ("net_flow", {"source.ip": "10.0.0.4", "destination.ip": "255.255.255.255"}),
        ("net_flow", {"source.ip": "10.0.0.4", "destination.ip": "ff02::fb"}),
        ("net_flow", {"source.ip": "10.0.0.4", "destination.ip": "0.0.0.0"}),
        # an external source decides even when the destination is unreadable
        ("net_flow", {"source.ip": "203.0.113.50", "destination.ip": None}),
        # a DNS client outside the site asking a site resolver
        ("dns_query", {"dns.type": "query", "source.ip": "203.0.113.50", "destination.ip": "10.0.0.53",
                       "dns.question.name": "example.com"}),
        # a recorded DNS role that is neither question nor answer
        ("dns_query", {"dns.type": "update", "source.ip": "10.0.0.4", "destination.ip": "10.0.0.53",
                       "dns.question.name": "example.com"}),
        # a Suricata v1 answer resource record carries no question; its query record does
        ("dns_query", {"dns.type": "answer", "source.ip": "10.0.0.53", "destination.ip": "10.0.0.4"}),
    ],
)
def test_external_destination_wrong_direction_or_role_is_not_applicable(family, fields):
    result = SPEC_BY_ID["bl.ext_dest"].keys(_event(family, **fields), _ctx())
    assert isinstance(result, NotApplicable) and result.reason


def test_internal_network_test_is_a_context_seam():
    lab_nets = (ipaddress.ip_network("198.51.100.0/24"),)
    context = KeyContext(is_internal=lambda address: any(address in net for net in lab_nets))
    keys = SPEC_BY_ID["bl.ext_dest"].keys(
        _event("net_flow", **{"source.ip": "198.51.100.4", "destination.ip": "203.0.113.9"}), context,
    )
    assert {key.scope for key in keys} == {"internal_ip:198.51.100.4"}
    assert isinstance(SPEC_BY_ID["bl.ext_dest"].keys(
        _event("net_flow", **{"source.ip": "10.0.0.4", "destination.ip": "203.0.113.9"}), context,
    ), NotApplicable)


def test_service_exec_rate_keys_configured_service_accounts_with_an_empty_key():
    spec = SPEC_BY_ID["bl.svc_exec_rate"]
    service = _event("process_exec", **{"process.user": "www-data", "process.uid": "1001"})
    keys = spec.keys(service, _ctx(service_accounts=frozenset({"www-data"})))
    assert len(keys) == 1 and keys[0].scope == 'host_account:{"account":"www-data","host":"web01"}'
    assert keys[0].scope_kind == "host_account" and keys[0].key == {}


@pytest.mark.parametrize(("account", "uid"), [("postgres", "114"), ("jenkins", "998"), ("svc", 1), ("www-data", 33)])
def test_service_exec_rate_keys_system_range_accounts_by_typed_uid(account, uid):
    keys = SPEC_BY_ID["bl.svc_exec_rate"].keys(
        _event("process_exec", **{"process.user": account, "process.uid": uid}), _ctx(),
    )
    assert [key.scope for key in keys] == [f'host_account:{{"account":"{account}","host":"web01"}}']


def test_service_exec_rate_default_context_is_not_the_web_only_list():
    assert KeyContext().service_accounts == frozenset()
    assert KeyContext().system_uid_range == (1, 999)


@pytest.mark.parametrize(
    ("fields", "configured"),
    [
        ({"process.user": "alice", "process.uid": "1000"}, frozenset()),
        ({"process.user": "root", "process.uid": "0"}, frozenset()),
        ({"process.user": "root", "process.uid": "0"}, frozenset({"root"})),
        ({"process.user": "root"}, frozenset({"root"})),
        ({"process.user": "nobody", "process.uid": "65534"}, frozenset()),
    ],
)
def test_service_exec_rate_human_root_and_out_of_range_accounts_are_not_applicable(fields, configured):
    result = SPEC_BY_ID["bl.svc_exec_rate"].keys(_event("process_exec", **fields), _ctx(service_accounts=configured))
    assert isinstance(result, NotApplicable)


def test_service_exec_rate_uid_range_is_configurable():
    context = KeyContext(system_uid_range=(1, 499))
    result = SPEC_BY_ID["bl.svc_exec_rate"].keys(
        _event("process_exec", **{"process.user": "jenkins", "process.uid": "998"}), context,
    )
    assert isinstance(result, NotApplicable)


@pytest.mark.parametrize(
    ("host", "fields", "missing"),
    [
        (None, {"process.user": "postgres", "process.uid": "114"}, ("host",)),
        ("web01", {"process.user": None, "process.uid": "114"}, ("process.user",)),
        ("web01", {"process.user": ["postgres"], "process.uid": "114"}, ("process.user",)),
        ("web01", {"process.user": "postgres"}, ("process.uid",)),
        ("web01", {"process.user": "postgres", "process.uid": True}, ("process.uid",)),
        ("web01", {"process.user": "postgres", "process.uid": "abc"}, ("process.uid",)),
        ("web01", {"process.user": "postgres", "process.uid": "4294967295"}, ("process.uid",)),
    ],
)
def test_service_exec_rate_absent_or_malformed_identity_is_typed_missing(host, fields, missing):
    result = SPEC_BY_ID["bl.svc_exec_rate"].keys(_event("process_exec", host=host, **fields), _ctx())
    assert isinstance(result, Missing) and result.fields == missing


_COMPLETE = {
    ("bl.ssh_tuple", "auth"): (Outcome.success, SSH),
    ("bl.exec_path", "process_exec"): (Outcome.success, EXEC),
    ("bl.exec_pair", "process_exec"): (Outcome.unknown, {"process.ppid": 100, "process.executable": "/bin/sh"}),
    ("bl.cmd_shape", "process_exec"): (Outcome.unknown, {"process.executable": "/bin/sh", "process.argv": ["sh"]}),
    ("bl.ext_dest", "net_flow"): (Outcome.unknown, {"source.ip": "10.0.0.4", "destination.ip": "192.0.2.1"}),
    ("bl.ext_dest", "net_session"): (Outcome.unknown, {"source.ip": "10.0.0.4", "destination.ip": "192.0.2.1"}),
    ("bl.ext_dest", "tls_session"): (Outcome.unknown, {"source.ip": "10.0.0.4", "destination.ip": "192.0.2.1"}),
    ("bl.ext_dest", "dns_query"): (Outcome.unknown, {
        "source.ip": "10.0.0.4", "destination.ip": "10.0.0.53", "dns.question.name": "example.com",
        "dns.question.names": ["example.com"],
    }),
    ("bl.svc_exec_rate", "process_exec"): (Outcome.unknown, {"process.user": "postgres", "process.uid": "114"}),
}


def test_required_fields_are_accurate_per_event_kind():
    """Each family's required fields are exactly what the extractor needs: a complete event keys, and
    removing any one required field (every alternative of an any-of group) makes the event Missing."""
    pairs = {(spec.id, family) for spec in BASELINE_SPECS for family in spec.families}
    assert pairs == set(_COMPLETE)
    for (spec_id, family), (outcome, fields) in _COMPLETE.items():
        spec = SPEC_BY_ID[spec_id]
        assert set(spec.required_fields) == set(spec.families)
        complete = spec.keys(_event(family, outcome=outcome, **fields), _ctx())
        assert isinstance(complete, (list, Pending)), (spec_id, family, complete)
        for requirement in spec.required_fields[family]:
            group = requirement if isinstance(requirement, tuple) else (requirement,)
            reduced = {name: value for name, value in fields.items() if name not in group}
            result = spec.keys(_event(family, outcome=outcome, **reduced), _ctx())
            assert isinstance(result, Missing), (spec_id, family, group, result)
            assert set(result.fields) <= set(group), (spec_id, family, group, result)


def test_key_digests_are_deterministic_across_repeated_extraction():
    event = _event(
        "process_exec",
        **{"process.executable": "/bin/tool", "process.argv": ["tool", "--port=1234"]},
    )
    first = SPEC_BY_ID["bl.cmd_shape"].keys(event, _ctx())[0]
    second = SPEC_BY_ID["bl.cmd_shape"].keys(event.model_copy(deep=True), _ctx())[0]
    assert first == second


def test_ipv6_zone_ids_are_stripped_before_canonicalization():
    ssh = SPEC_BY_ID["bl.ssh_tuple"].keys(
        _event("auth", outcome=Outcome.success, **{**SSH, "source.ip": "FE80::1%eth0"}), _ctx(),
    )
    assert _kinds(ssh)["source_ip"] == {"kind": "source_ip", "source_ip": "fe80::1"}
    flow = SPEC_BY_ID["bl.ext_dest"].keys(
        _event("net_flow", **{"source.ip": "fe80::10%2", "destination.ip": "2001:db8::9%eth1"}), _ctx(),
    )
    assert {key.scope for key in flow} == {"internal_ip:fe80::10"}
    assert _kinds(flow)["dest_ip"] == {"kind": "dest_ip", "dest_ip": "2001:db8::9"}


def test_internationalized_names_become_punycode():
    keys = SPEC_BY_ID["bl.ext_dest"].keys(_event("tls_session", **{
        "source.ip": "10.0.0.4", "destination.ip": "198.51.100.9", "tls.client.server_name": "Bücher.Example.",
    }), _ctx())
    assert _kinds(keys)["sni"]["sni"] == "xn--bcher-kva.example"
    assert _kinds(keys)["registered_domain"]["registered_domain"] == "xn--bcher-kva.example"
    dns = SPEC_BY_ID["bl.ext_dest"].keys(_event("dns_query", **{
        "dns.type": "query", "source.ip": "10.0.0.4", "destination.ip": "10.0.0.53",
        "dns.question.name": "www.bücher.example",
    }), _ctx())
    assert [key.key["registered_domain"] for key in dns] == ["xn--bcher-kva.example"]


def test_an_unencodable_internationalized_name_is_missing():
    result = SPEC_BY_ID["bl.ext_dest"].keys(_event("tls_session", **{
        "source.ip": "10.0.0.4", "destination.ip": "198.51.100.9",
        "tls.client.server_name": "ü" * 70 + ".example",
    }), _ctx())
    assert isinstance(result, Missing) and result.fields == ("tls.client.server_name",)


def test_host_names_in_scopes_are_lower_case():
    exec_keys = SPEC_BY_ID["bl.exec_path"].keys(
        _event("process_exec", host="WEB01.Corp", outcome=Outcome.success, **EXEC), _ctx(),
    )
    assert exec_keys[0].scope == "host:web01.corp"
    rate = SPEC_BY_ID["bl.svc_exec_rate"].keys(
        _event("process_exec", host="DB01", **{"process.user": "postgres", "process.uid": "114"}), _ctx(),
    )
    assert rate[0].scope == 'host_account:{"account":"postgres","host":"db01"}'
    ssh = SPEC_BY_ID["bl.ssh_tuple"].keys(_event("auth", host="Web01", outcome=Outcome.success, **SSH), _ctx())
    assert _kinds(ssh)["host"] == {"kind": "host", "host": "web01"}


@pytest.mark.parametrize("sni", ["203.0.113.7", "2001:db8::7", "[2001:db8::7]"])
def test_an_ip_literal_sni_has_no_registered_domain(sni):
    keys = SPEC_BY_ID["bl.ext_dest"].keys(_event("tls_session", **{
        "source.ip": "10.0.0.4", "destination.ip": "198.51.100.9", "tls.client.server_name": sni,
    }), _ctx())
    assert set(_kinds(keys)) == {"dest_ip", "dest_network", "sni"}


@pytest.mark.parametrize("name", ["192.0.2.10", ".", "<root>"])
def test_a_dns_question_naming_no_domain_is_not_applicable(name):
    result = SPEC_BY_ID["bl.ext_dest"].keys(_event("dns_query", **{
        "dns.type": "query", "source.ip": "10.0.0.4", "destination.ip": "10.0.0.53", "dns.question.name": name,
    }), _ctx())
    assert isinstance(result, NotApplicable)


def test_identical_keys_within_one_event_are_counted_once():
    keys = SPEC_BY_ID["bl.ext_dest"].keys(_event("dns_query", **{
        "dns.type": "query", "source.ip": "10.0.0.4", "destination.ip": "10.0.0.53",
        "dns.question.names": ["a.example.com", "B.example.com.", "a.example.com"],
    }), _ctx())
    assert [key.key for key in keys] == [{"kind": "registered_domain", "registered_domain": "example.com"}]


def _dns(role: str, flow, **extra) -> TypedEvent:
    client, resolver = "10.0.0.4", "10.0.0.53"
    source, destination = (resolver, client) if role == "answer" else (client, resolver)
    fields = {"dns.type": role, "source.ip": source, "destination.ip": destination,
              "dns.question.name": "www.example.com", **extra}
    if flow is not None:
        fields["suricata.flow_id"] = flow
    return _event("dns_query", **fields)


def test_query_and_answer_of_one_dns_transaction_share_a_dedup_token():
    spec = SPEC_BY_ID["bl.ext_dest"]
    query, answer = spec.keys(_dns("query", 77), _ctx()), spec.keys(_dns("answer", 77), _ctx())
    assert [key.key_digest for key in query] == [key.key_digest for key in answer]
    assert [key.dedup_token for key in query] == [key.dedup_token for key in answer]
    assert query[0].dedup_token is not None
    other_flow = spec.keys(_dns("query", 78), _ctx())
    assert other_flow[0].dedup_token != query[0].dedup_token
    # a typed DNS id separates two transactions in one flow
    first_id = spec.keys(_dns("query", 77, **{"dns.id": 1}), _ctx())[0]
    second_id = spec.keys(_dns("query", 77, **{"dns.id": 2}), _ctx())[0]
    assert first_id.dedup_token != second_id.dedup_token
    # without a flow identity a query and an answer cannot be proven one transaction: each counts
    assert spec.keys(_dns("query", None), _ctx())[0].dedup_token is None


def test_records_of_one_flow_share_a_dedup_token_across_families():
    spec = SPEC_BY_ID["bl.ext_dest"]
    fields = {"source.ip": "10.0.0.4", "destination.ip": "198.51.100.9", "suricata.flow_id": 5}
    flow = spec.keys(_event("net_flow", **fields), _ctx())
    tls = spec.keys(_event("tls_session", **fields, **{"tls.client.server_name": "a.example.com"}), _ctx())
    assert _kinds(flow)["dest_ip"] == _kinds(tls)["dest_ip"]
    assert {key.dedup_token for key in flow} == {key.dedup_token for key in tls} != {None}
    community = spec.keys(_event("net_session", **{
        "source.ip": "10.0.0.4", "destination.ip": "198.51.100.9", "network.community_id": "1:abc=",
    }), _ctx())
    assert community[0].dedup_token is not None and community[0].dedup_token != flow[0].dedup_token


def test_argv_shape_is_bounded_and_the_overflow_is_hashed_and_marked():
    spec = SPEC_BY_ID["bl.cmd_shape"]

    def shape(argv):
        event = _event("process_exec", **{"process.executable": "/bin/tool", "process.argv": argv})
        return spec.keys(event, _ctx())[0]

    long_argv = ["tool", *[f"--opt-{index:04d}x" for index in range(1000)]]
    bounded = shape(long_argv)
    assert len(bounded.key["argv_shape"]) <= ARGV_SHAPE_MAX_TOKENS
    assert len(canonical_json(bounded.key)) < 2 * ARGV_SHAPE_MAX_CHARS
    kept = len(bounded.key["argv_shape"])
    assert bounded.key["argv_overflow"]["tokens"] == len(long_argv) - kept
    changed_tail = shape([*long_argv[:-1], "--different"])
    assert changed_tail.key_digest != bounded.key_digest
    assert changed_tail.key["argv_shape"] == bounded.key["argv_shape"]
    assert shape(list(long_argv)).key_digest == bounded.key_digest

    giant = shape(["python3", "-c", "x" * 100_000, "--flag"])
    assert giant.key["argv_shape"] == ["python3", "-c"]
    assert giant.key["argv_overflow"]["tokens"] == 2
    assert len(canonical_json(giant.key)) < 2 * ARGV_SHAPE_MAX_CHARS

    assert "argv_overflow" not in shape(["tool", "--port=1"]).key
