"""net.zeek_alert: Zeek's intel and signature matches are reported, notices are judged by a sourced table of notice
types, a notice outside the table is a lead, and a weird is context, never a finding. Claims name Zeek and the record kind."""
import pytest

from romulus.catalog.attack import load_attack_bundle
from romulus.detect.dns import rcode
from romulus.detect.network import SuricataAlertStack
from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.detect.zeek_alerts import NOTICE_TYPES, ZeekAlerts
from romulus.evidence.normalize import normalize_hits
from tests.fixtures import zeek_logs as zl


def events(rows, shape="malcolm"):
    out, skips, errors = normalize_hits([zl.WRITERS[shape](row, f"z{i}") for i, row in enumerate(rows)])
    assert (skips, errors) == ({}, [])
    return out


def run(rows, shape="malcolm"):
    rule = ZeekAlerts()
    staged = {}
    rule.consume(events(rows, shape))
    staged.update({e.id: e for e in rule.drain_staged()})
    rule.bind_loader(lambda ids: [staged[i] for i in ids if i in staged])
    return rule, rule.finalize()


def notice(note: str, i: int = 0, **changes):
    return zl.NOTICE.with_(note=note, uid=f"CnoticeConn{i:06d}", **changes)


@pytest.mark.parametrize("shape", ["malcolm", "elastic", "security_onion"])
def test_an_intel_hit_is_reported_naming_the_indicator_where_and_the_list(shape):
    rule, [match] = run([zl.INTEL], shape)
    assert (match.proposed_lane, match.severity) == ("lead", "medium")
    assert match.claim.startswith("Zeek's intel framework matched indicator 'listed.example.test'")
    assert "seen in SSL::IN_SERVER_NAME" in match.claim
    if shape != "malcolm":                       # Malcolm merges the sources with its own: not read
        assert "synthetic-feed" in match.claim
    assert "Suricata" not in match.claim and rule.missing_required == 0 and rule.evaluated == 1


def test_a_signature_match_is_reported():
    _rule, [match] = run([zl.SIGNATURES])
    assert match.claim.startswith("Zeek's signature engine matched signature 'synthetic-sig-1'")
    assert (match.proposed_lane, match.severity) == ("lead", "medium")


@pytest.mark.parametrize("note", ["SSH::Login_By_Password_Guesser", "Scan::Port_Scan", "ATTACK::Credential_Access"])
def test_a_tabled_notice_is_reported_at_its_table_lane_with_its_source(note):
    _rule, [match] = run([notice(note)])
    entry = NOTICE_TYPES[note]
    assert (match.proposed_lane, match.severity) == (entry.lane, entry.severity)
    assert match.claim.startswith(f"Zeek raised notice {note} 1 raw reference(s) on traffic from {zl.CLIENT} to {zl.SERVER}")
    assert entry.source in match.claim
    assert any(", ".join(entry.attack) in note_text for note_text in match.notes)


def test_an_untabled_notice_is_a_lead_and_folds_address_pairs():
    rows = [notice("Site::Custom_Notice", i, src=f"10.0.0.{i + 1}", **{"id.orig_h": f"10.0.0.{i + 1}"})
            for i in range(3)]
    _rule, [match] = run(rows)
    assert (match.proposed_lane, match.severity) == ("lead", "low")
    assert "Zeek raised notice Site::Custom_Notice 3 raw reference(s)" in match.claim
    assert "across 3 address pair(s)" in match.claim and "not in ROMULUS's table" in match.claim


def test_a_weird_alone_is_context_never_a_finding():
    _rule, [match] = run([zl.WEIRD, zl.WEIRD.with_(uid="CweirdConn0000002")])
    assert (match.proposed_lane, match.severity) == ("context", "low")
    assert match.claim.startswith("Zeek logged weird 'bad_TCP_checksum' 2 raw reference(s)")


def test_the_rule_reads_only_zeek_alerts_and_the_suricata_stack_only_suricata_alerts():
    rows = [zl.NOTICE, zl.WEIRD, zl.SIGNATURES, zl.INTEL]
    zeek = events(rows)
    assert ZeekAlerts().scope_partition(zeek) == zeek
    assert SuricataAlertStack().scope_partition(zeek) == []
    rule, matches = run(rows)
    assert rule.evaluated == 4 and rule.missing_required == 0 and len(matches) == 4
    assert not any("Suricata" in m.claim for m in matches)


def test_the_table_and_the_rule_name_only_techniques_in_the_vendored_bundle():
    known = load_attack_bundle()
    ids = {t for entry in NOTICE_TYPES.values() for t in entry.attack} | set(ZeekAlerts.attack)
    for technique in ids:
        found = known.technique(technique)          # KeyError when the bundle has no such technique
        assert not getattr(found, "revoked", False) and not getattr(found, "deprecated", False), technique
    assert ZeekAlerts in ALL_PLAYBOOKS and all(entry.lane in ("high", "lead", "context")
                                               for entry in NOTICE_TYPES.values())


def test_correlation_names_zeek_alert_rows_by_provider_and_kind():
    from romulus.detect.correlation import ZEEK_ALERT_PREFIX, Net, _alert_words, alert_kind, alert_lane

    def net(cat, sev=None):
        return Net("n", "net_alert", "s", 0.0, None, "10.0.0.5", 1, "203.0.113.10", 443, None, sev, cat, "x")

    weird, suricata = net(f"{ZEEK_ALERT_PREFIX}weird"), net("Attempted Information Leak", 2)
    assert (alert_kind(weird), alert_kind(suricata)) == ("weird", "ids")
    assert alert_lane(weird) is None and alert_lane(suricata) == "lead"      # a Zeek row raises no lane here
    assert _alert_words({"ids": 1}) == "1 IDS alert(s)"
    assert _alert_words({"weird": 2}) == "2 Zeek weird records"
    assert _alert_words({"ids": 1, "notice": 1, "intel": 3}) == "1 IDS alert(s) and 3 Zeek intel matches and 1 Zeek notice"


def test_rcode_reads_the_generic_form_back():
    assert rcode("RCODE3") == "NXDOMAIN" and rcode("rcode0") == "NOERROR" and rcode("RCODE23") == "RCODE23"
    assert rcode("NXDOMAIN") == "NXDOMAIN" and rcode(3) == "NXDOMAIN"
