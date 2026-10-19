"""Indicator lists matched by field role: exact, typed, worded by where the value matched."""
from datetime import UTC, datetime

import pytest

from romulus.decide.policy import decide
from romulus.detect.indicators import IndicatorFileError, IndicatorMatch, indicator_dir, load_indicators
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv

T = datetime(2024, 11, 18, 14, 30, tzinfo=UTC)

LIST = """schema_version: 1
indicators:
  - {id: t.linpeas, kind: program_name, values: [linpeas.sh, linpeas], label: LinPEAS, severity: high, lane: high}
  - {id: t.hydra, kind: program_name, values: [hydra], label: Hydra, severity: high, lane: lead}
  - {id: t.ip, kind: ip, values: ["192.0.2.174"], label: C2 address, severity: high, lane: high}
  - {id: t.net, kind: cidr, values: ["198.51.100.0/24"], label: bad range, severity: medium, lane: lead}
  - {id: t.dom, kind: domain, values: [evil.example], label: bad domain, severity: high, lane: lead}
  - {id: t.ja3, kind: ja3, values: [DEADBEEF], label: implant TLS client, severity: high, lane: high}
"""


@pytest.fixture()
def rule(tmp_path):
    (tmp_path / "list.yaml").write_text(LIST, encoding="utf-8")
    return IndicatorMatch(load_indicators(tmp_path))


def exec_event(argv, exe, _id="e1", host="videoserver"):
    return TypedEvent(id=_id, family="process_exec", ts=T, host=host, outcome=Outcome.success,
                      fields={"process.argv": fv(argv, "fixture:argv"), "process.executable": fv(exe, "fixture:exe")},
                      raw=[RawRef(target="host", native_id=_id)], normalizer="fixture")


def net_event(family, _id="n1", **fields):
    return TypedEvent(id=_id, family=family, ts=T, host="sensor",
                      fields={k.replace("__", "."): fv(v, f"fixture:{k}") for k, v in fields.items()},
                      raw=[RawRef(target="net", native_id=_id)], normalizer="fixture")


def run(rule, *events):
    rule.consume(list(events))
    return rule.finalize()


# ---- program names: exact, by role -------------------------------------------------------------

def test_executed_program_name_is_an_observed_match_with_the_indicator_lane(rule):
    m = run(rule, exec_event(["/tmp/linpeas.sh"], "/tmp/linpeas.sh"))
    assert len(m) == 1 and m[0].proposed_lane == "high"
    assert "kernel-recorded executable is named 'linpeas.sh'" in m[0].claim
    assert "a renamed copy would not match" in m[0].claim


def test_interpreter_script_operand_is_matched_as_a_script(rule):
    m = run(rule, exec_event(["sh", "./linpeas.sh"], "/usr/bin/dash"))
    assert len(m) == 1 and m[0].claim_type == "script_content" and "script operand 'linpeas.sh'" in m[0].claim


@pytest.mark.parametrize("argv, exe", [
    (["grep", "-r", "linpeas", "/var/log/syslog"], "/usr/bin/grep"),         # searching for the name
    (["cat", "/opt/notes/linpeas.sh"], "/usr/bin/cat"),                       # reading a file of that name
])
def test_a_name_in_an_argument_is_a_mention_in_the_context_lane(rule, argv, exe):
    m = run(rule, exec_event(argv, exe))
    assert len(m) == 1 and "is a mention, not evidence that the tool ran" in m[0].claim
    assert decide(m[0], "h1").lane == "context"


@pytest.mark.parametrize("argv, exe", [
    (["apt-get", "install", "-y", "dehydrated"], "/usr/bin/apt-get"),        # v1 fired "hydra" on this
    (["cat", "/srv/linpeas.sh.txt"], "/usr/bin/cat"),                         # different basename
    (["/usr/bin/hydrate"], "/usr/bin/hydrate"),
    (["echo", "run linpeas.sh now"], "/usr/bin/echo"),                        # one argument, not the name
])
def test_substrings_and_lookalikes_never_match(rule, argv, exe):
    assert run(rule, exec_event(argv, exe)) == []


def test_name_match_is_case_insensitive_and_grouped(rule):
    m = run(rule, exec_event(["/tmp/LinPEAS.SH"], "/tmp/LinPEAS.SH", "a"),
            exec_event(["/tmp/LinPEAS.SH"], "/tmp/LinPEAS.SH", "b"))
    assert len(m) == 1 and m[0].claim.startswith("2 auditd exec record(s)")


# ---- network indicators ------------------------------------------------------------------------

def test_address_and_range_match_typed_address_fields(rule):
    m = run(rule, net_event("net_flow", "f1", source__ip="172.17.100.121", destination__ip="192.0.2.174"),
            net_event("net_flow", "f2", source__ip="198.51.100.7", destination__ip="10.0.0.1"))
    roles = sorted(x.group_key.split("|")[1] for x in m)
    assert roles == ["address:destination", "address:source"]


def test_domain_matches_at_a_label_boundary_only(rule):
    m = run(rule, net_event("dns_query", "d1", dns__question__name="a.b.evil.example."),
            net_event("dns_query", "d2", dns__question__name="notevil.example"))
    assert len(m) == 1 and "'a.b.evil.example'" in m[0].claim


def test_fingerprint_matches_list_valued_session_fields(rule):
    m = run(rule, net_event("net_session", "s1", tls__ja3=["deadbeef", "0123"]))
    assert len(m) == 1 and "JA3 client fingerprint deadbeef" in m[0].claim


# ---- lists -------------------------------------------------------------------------------------

@pytest.mark.parametrize("body, error", [
    ("schema_version: 2\nindicators: []\n", "schema_version"),
    ("schema_version: 1\nindicators:\n  - {id: a, kind: url, values: [x]}\n", "kind"),
    ("schema_version: 1\nindicators:\n  - {id: a, kind: ip, values: [999.1.1.1]}\n", "valid ip"),
    ("schema_version: 1\nindicators:\n  - {id: a, kind: program_name, values: [/tmp/x]}\n", "basenames"),
    (("schema_version: 1\nindicators:\n  - {id: a, kind: ip, values: [192.0.2.1]}\n"
     "  - {id: a, kind: ip, values: [192.0.2.2]}\n"), "duplicated"),
    ("schema_version: 1\nindicators:\n  - {id: a, kind: ip, values: []}\n", "non-empty"),
])
def test_malformed_lists_are_refused_not_ignored(tmp_path, body, error):
    (tmp_path / "bad.yaml").write_text(body, encoding="utf-8")
    with pytest.raises(IndicatorFileError, match=error):
        load_indicators(tmp_path)


def test_list_digest_changes_with_content_so_manifests_record_the_lists(tmp_path):
    (tmp_path / "a.yaml").write_text(LIST, encoding="utf-8")
    first = load_indicators(tmp_path).digest
    (tmp_path / "a.yaml").write_text(LIST.replace("hydra]", "hydra, medusa]"), encoding="utf-8")
    assert load_indicators(tmp_path).digest != first


def test_shipped_seed_list_loads():
    s = load_indicators(indicator_dir())
    assert s.files == ["tools.yaml"] and len(s.indicators) >= 15
    assert all(i.kind == "program_name" for i in s.indicators)


def test_no_lists_means_no_matches(tmp_path):
    rule = IndicatorMatch(load_indicators(tmp_path))
    assert run(rule, exec_event(["/tmp/linpeas.sh"], "/tmp/linpeas.sh")) == []
