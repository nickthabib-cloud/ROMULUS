"""Honesty where direction decides a negative.

A rule that only evaluates traffic in one direction (inside to outside, or across the boundary) skips the rest.
Under the default definition that direction is an assumption, so a record skipped (or judged by a looser or
stricter standard) for its direction alone cannot support `no_match_complete`: the cell is partial with the
named reason. Matches still fire. Under a configured definition the same records give a complete negative.
"""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.baseline.spec import BASELINE_SPECS, SPEC_BY_ID
from romulus.detect import flows, netdef, sessions, tls
from romulus.detect.netdef import DIRECTION_ASSUMED_REASON, SiteNetworks
from romulus.detect.registry import ALL_PLAYBOOKS, fresh_pack
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt import sweep as sweep_mod
from romulus.hunt.sweep import WINDOW_ROLLUP_PARTIAL, Sweep
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.sources.profile import contract_from_types
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

SITE = SiteNetworks.from_lists(["198.51.100.0/24", "10.0.0.0/8"], ["10.50.0.0/16"])
T0 = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
WINDOW = Window(start=T0, end=T0 + timedelta(minutes=5))
TARGET = "romulus-network-x"
AFFECTED = {"net.horizontal_sweep", "net.long_external_connection", "net.beaconing", "net.rare_client_fingerprint",
            "net.tls_self_signed_certificate_outbound", "net.tls_short_lived_or_new_certificate_outbound"}
_n = 0


def ev(family, ts=None, **fields):
    global _n
    _n += 1
    return TypedEvent(id=f"c{_n}", family=family, ts=ts or T0 + timedelta(seconds=_n % 200), host="sensor",
                      outcome=Outcome.unknown,
                      fields={k.replace("__", "."): fv(v, f"fixture{_n}:{k}") for k, v in fields.items()},
                      raw=[RawRef(target=TARGET, native_id=f"r{_n}")], normalizer="fixture")


def session(src, dst, *, transport="tcp", seconds=60, **extra):
    start = T0 + timedelta(seconds=10)
    return ev("net_session", ts=start, source__ip=src, destination__ip=dst, source__port=50000,
              destination__port=443, network__transport=transport, flow__start=start.isoformat(),
              flow__end=(start + timedelta(seconds=seconds)).isoformat(), network__community_id=f"1:x{_n}=",
              **extra)


def flow(src, dst):
    start = T0 + timedelta(seconds=20)
    return ev("net_flow", ts=start, source__ip=src, destination__ip=dst, source__port=40000, destination__port=22,
              network__transport="tcp", flow__start=start.isoformat(), flow__pkts_toclient=2,
              suricata__flow_id=_n)


def tls_record(src, dst, **extra):
    return ev("tls_session", source__ip=src, destination__ip=dst, **extra)


# ---- which rules are affected, and why --------------------------------------------------------------------

def test_the_direction_dependent_rules_are_exactly_these():
    flagged = {pb.id for pb in ALL_PLAYBOOKS if getattr(pb, "direction_dependent", False)}
    assert flagged == AFFECTED
    # each can write a complete negative, which is what the reason protects
    assert all(pb.assures_negative for pb in ALL_PLAYBOOKS if pb.id in AFFECTED)


WORDING = {"host.ssh_login_external_source", "host.interpreter_external_connection", "corr.process_network_link",
           "net.outbound_volume_asymmetry"}


def test_each_changed_rule_carries_a_new_version():
    # the six direction-dependent rules (coverage semantics) and the four whose claim or reason wording changed
    versions = {pb.id: pb.version for pb in ALL_PLAYBOOKS if pb.id in AFFECTED | WORDING}
    assert versions == {"net.horizontal_sweep": "5", "net.long_external_connection": "4", "net.beaconing": "4",
                        "net.rare_client_fingerprint": "4", "net.tls_self_signed_certificate_outbound": "3",
                        "net.tls_short_lived_or_new_certificate_outbound": "3",
                        "host.ssh_login_external_source": "5", "host.interpreter_external_connection": "5",
                        "corr.process_network_link": "5", "net.outbound_volume_asymmetry": "4"}


def test_bl_ext_dest_requires_a_configured_internal_network():
    assert SPEC_BY_ID["bl.ext_dest"].requires_configured_networks is True
    assert {spec.id for spec in BASELINE_SPECS if spec.requires_configured_networks} == {"bl.ext_dest"}


# ---- each affected rule counts only records skipped for their direction ------------------------------------

def _assumed(rule, events):
    rule.consume(events)
    return rule.direction_assumed


@pytest.mark.parametrize(("rule", "skipped", "not_skipped_for_direction"), [
    # inside to inside: not a boundary connection; a UDP or non-routable session is skipped whatever the direction
    (sessions.LongExternalConnection, session("10.0.0.5", "10.0.0.6"),
     [session("10.0.0.5", "10.0.0.6", transport="udp"), session("10.0.0.5", "224.0.0.9"),
      session("10.0.0.5", "203.0.113.9")]),
    # public to public: under the default both ends read as outside the site
    (sessions.LongExternalConnection, session("198.51.100.20", "203.0.113.9"), []),
    (sessions.Beaconing, session("10.0.0.5", "10.0.0.6"),
     [session("10.0.0.5", "203.0.113.9"), session("10.0.0.5", "255.255.255.255")]),
    (sessions.Beaconing, session("203.0.113.9", "10.0.0.5"), []),
    (sessions.RareClientFingerprint, tls_record("10.0.0.5", "10.0.0.6", tls__ja3="abc"),
     [tls_record("10.0.0.5", "10.0.0.6"), tls_record("10.0.0.5", "203.0.113.9", tls__ja3="abc")]),
    (tls.SelfSignedCertificateOutbound, tls_record("203.0.113.9", "10.0.0.5"),
     [tls_record("10.0.0.5", "203.0.113.9")]),
    (tls.ShortLivedOrNewCertificateOutbound, tls_record("10.0.0.5", "10.0.0.6"),
     [tls_record("10.0.0.5", "203.0.113.9")]),
    (flows.HorizontalSweep, flow("10.0.0.5", "203.0.113.9"), [flow("10.0.0.5", "10.0.0.6")]),
])
def test_only_records_skipped_or_judged_for_their_direction_are_counted(rule, skipped, not_skipped_for_direction):
    assert _assumed(rule(), not_skipped_for_direction) == 0
    assert _assumed(rule(), [skipped]) == 1
    netdef.install(SITE)
    assert _assumed(rule(), [skipped] + not_skipped_for_direction) == 0      # the site's own direction


def test_a_continuation_record_is_skipped_whatever_its_direction():
    later = ev("net_session", source__ip="10.0.0.5", destination__ip="10.0.0.6", network__protocols=["tls"],
               arkime__continuation=True, network__transport="tcp")
    assert _assumed(tls.SelfSignedCertificateOutbound(), [later]) == 0


# ---- through the sweep: cells, window rollup, matches -------------------------------------------------------

def _sweep(tmp_path, monkeypatch, events) -> Repo:
    def execute(client, intent, contract):
        now = datetime.now(UTC)
        if intent.kind == "histogram":
            return SearchOutcome(target=intent.target, fingerprint="h", started_at=now, ended_at=now,
                                 completeness=Completeness.complete, total=len(events), total_relation="eq",
                                 buckets=[{"key": WINDOW.start.isoformat(), "count": len(events)}])
        return SearchOutcome(target=intent.target, fingerprint="f", started_at=now, ended_at=now,
                             completeness=Completeness.complete, total=len(events), total_relation="eq",
                             returned=len(events), records=[{"_id": e.raw[0].native_id, "_index": TARGET,
                                                             "_source": {}} for e in events])

    monkeypatch.setattr(sweep_mod, "execute", execute)
    monkeypatch.setattr(sweep_mod, "normalize_hits", lambda hits, boots=None: (list(events), {}, []))
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"window": {"start": WINDOW.start.isoformat(), "end": WINDOW.end.isoformat()},
                            "targets": [TARGET], "pack": {"version": "test"}}, "digest", "test")
    repo.set_hunt_state("h1", "running")
    sweep = Sweep(repo, None, "h1", WINDOW, {TARGET: contract_from_types(TARGET, {"@timestamp": "date"})},
                  stage_dir=tmp_path)
    sweep.run_target(TARGET)
    sweep.finalize()
    return repo


def _cells(repo, rule_id):
    cells = [c for c in repo.rule_cells("h1", rule_id=rule_id) if c["state"] != "split"]
    return ({c["partition"]: c for c in cells if c["target"] == TARGET},
            next(c for c in cells if c["partition"] == "window"))


# internal-to-internal and inside-to-outside traffic that matches nothing: every affected rule evaluates it
NO_MATCH = [session("10.0.0.5", "10.0.0.6"), session("10.0.0.5", "203.0.113.9"),
            tls_record("10.0.0.5", "10.0.0.6", tls__ja3="abc"), tls_record("10.0.0.7", "10.0.0.6", tls__ja3="abc"),
            flow("10.0.0.5", "203.0.113.9"), flow("10.0.0.5", "10.0.0.6")]


def test_under_the_default_a_direction_skip_is_partial_with_the_named_reason(tmp_path, monkeypatch):
    repo = _sweep(tmp_path, monkeypatch, NO_MATCH)
    for rule_id in ("net.long_external_connection", "net.beaconing", "net.rare_client_fingerprint",
                    "net.horizontal_sweep", "net.tls_self_signed_certificate_outbound"):
        parts, window = _cells(repo, rule_id)
        assert parts and all(c["state"] == "evaluated_partial" for c in parts.values()), rule_id
        assert all(DIRECTION_ASSUMED_REASON in c["detail"]["reasons"] for c in parts.values()), rule_id
        assert window["state"] == "evaluated_partial", rule_id
        assert window["detail"]["reasons"] == [WINDOW_ROLLUP_PARTIAL, DIRECTION_ASSUMED_REASON], rule_id
    # a rule whose skip does not depend on direction is unchanged
    parts, window = _cells(repo, "net.port_scan")
    assert window["state"] in ("no_match_complete", "not_applicable_no_events")
    assert not any(DIRECTION_ASSUMED_REASON in c["detail"].get("reasons", []) for c in parts.values())


def test_under_a_configured_site_the_same_records_give_a_complete_negative(tmp_path, monkeypatch):
    netdef.install(SITE)
    repo = _sweep(tmp_path, monkeypatch, NO_MATCH)
    for rule_id in ("net.long_external_connection", "net.beaconing", "net.rare_client_fingerprint",
                    "net.horizontal_sweep", "net.tls_self_signed_certificate_outbound"):
        parts, window = _cells(repo, rule_id)
        assert all(DIRECTION_ASSUMED_REASON not in c["detail"]["reasons"] for c in parts.values()), rule_id
        assert window["state"] == "no_match_complete", (rule_id, window)


def test_matches_still_fire_under_the_default_and_the_cell_says_partial(tmp_path, monkeypatch):
    long = session("10.0.0.5", "203.0.113.9", seconds=2000)
    repo = _sweep(tmp_path, monkeypatch, [long, session("10.0.0.5", "10.0.0.6")])
    assert [c["rule_id"] for c in repo.candidates("h1")] == ["net.long_external_connection"]
    _parts, window = _cells(repo, "net.long_external_connection")
    assert window["state"] == "match_on_partial"
    assert DIRECTION_ASSUMED_REASON in window["detail"]["reasons"]


def test_every_pack_rule_starts_with_no_assumed_direction():
    assert all(pb.direction_assumed == 0 for pb in fresh_pack())
