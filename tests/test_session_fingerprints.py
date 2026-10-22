"""Rare handshake fingerprints across both sensors, and Arkime's ssh-reverse-shell tag."""
from datetime import timedelta

import pytest

from romulus.detect.sessions import ArkimeSshReverseShellTag, RareClientFingerprint
from romulus.evidence.normalize import normalize_hits
from tests.test_network_normalizers import T0, arkime, eve


def events(*hits):
    evs, skips, errors = normalize_hits(list(hits))
    assert errors == [] and skips == {}, (errors, skips)
    return evs


def run(rule, *batches):
    stage = {}
    for batch in batches:
        rule.consume(batch)
        stage.update({e.id: e for e in rule.drain_staged()})
    rule.bind_loader(lambda ids: [stage[i] for i in ids if i in stage])
    return rule.finalize()


def suri(_id, event_type, block, *, src="172.17.100.121", dst="192.0.2.174", cid=None):
    return eve(_id, {"event_type": event_type, "src_ip": src, "dest_ip": dst, "community_id": cid or f"1:{_id}=",
                     event_type: block})


# ---- rare fingerprints -----------------------------------------------------------------------------------------

def test_every_value_of_a_list_valued_ja3_is_grouped_not_only_the_first():
    m = run(RareClientFingerprint(), events(arkime(tls={"ja3": ["aaa", "bbb"]})))
    assert sorted(x.group_key for x in m) == ["JA3|aaa", "JA3|bbb"]


@pytest.mark.parametrize("block,key,label", [
    ({"ja4": "t13d1516h2_8daaf6152771_02713d6af862"}, "JA4|t13d1516h2_8daaf6152771_02713d6af862",
     "JA4 client fingerprint"),
    ({"ja3s": {"hash": "F4FEBC55EA12B31AE17CFB7E614AFDA8"}}, "JA3S|f4febc55ea12b31ae17cfb7e614afda8",
     "JA3S server fingerprint")])
def test_suricata_ja4_and_ja3s_are_new_kinds(block, key, label):
    m = run(RareClientFingerprint(), events(suri("t1", "tls", block)))
    assert [x.group_key for x in m] == [key] and m[0].claim.startswith(label)
    assert m[0].proposed_lane == "context"


def test_ssh_client_software_from_suricata_is_quoted_and_context():
    m = run(RareClientFingerprint(), events(suri("h1", "ssh", {"client": {"software_version": "paramiko_3.4.0"}})))
    assert len(m) == 1 and m[0].claim.startswith("SSH client software string 'paramiko_3.4.0' appears on 1")
    assert m[0].proposed_lane == "context" and m[0].predicate[0].field == "ssh.client.software"


def test_arkime_unattributed_ssh_banners_are_not_client_software():
    assert run(RareClientFingerprint(), events(arkime(ssh={"version": ["ssh-2.0-paramiko_3.4.0"]}))) == []


def test_value_used_by_a_second_internal_address_on_the_other_sensor_is_not_rare():
    one = arkime(tls={"ja3": ["abc"]})
    other = suri("t2", "tls", {"ja3": {"hash": "ABC"}}, src="172.17.100.122")
    assert run(RareClientFingerprint(), events(one, other)) == []


def test_same_connection_on_both_sensors_counts_once():
    ark = arkime(tls={"ja3": ["abc"]})
    sur = suri("t3", "tls", {"ja3": {"hash": "abc"}}, cid="1:abc=")
    m = run(RareClientFingerprint(), events(ark, sur))
    assert len(m) == 1 and "appears on 1 connection(s)" in m[0].claim and len(m[0].events) == 2


def test_server_side_and_inbound_sessions_are_not_counted():
    inbound = suri("t4", "tls", {"ja3": {"hash": "abc"}}, src="192.0.2.174", dst="172.17.100.121")
    internal = suri("t5", "tls", {"ja3": {"hash": "abc"}}, dst="10.0.0.5")
    assert run(RareClientFingerprint(), events(inbound, internal)) == []


def test_malformed_fingerprint_is_counted_missing():
    rule = RareClientFingerprint()
    assert run(rule, events(arkime(tls={"ja3": [{"hash": "x"}]}))) == []
    assert rule.missing_required == 1


def test_fingerprint_on_a_record_with_a_non_ip_endpoint_is_missing():
    rule = RareClientFingerprint()
    assert run(rule, events(suri("t6", "tls", {"ja3": {"hash": "abc"}}, dst="sensor-name"))) == []
    assert (rule.evaluated, rule.missing_required) == (0, 1)


def test_many_connections_with_one_value_are_not_rare():
    hits = [arkime(_id=f"m{i}", tls={"ja3": ["abc"]}, network={"community_id": f"1:m{i}="}) for i in range(6)]
    assert run(RareClientFingerprint(), events(*hits)) == []


# ---- Arkime ssh-reverse-shell tag ------------------------------------------------------------------------------

def ssh_session(_id, tags, *, cid=None, first=T0, **kw):
    hit = arkime(_id=_id, tags=tags, protocol=["tcp", "ssh"], network={"community_id": cid or f"1:{_id}="}, **kw)
    hit["_source"]["destination"]["port"] = 22
    hit["_source"]["firstPacket"] = int(first.timestamp() * 1000)
    hit["_source"]["lastPacket"] = int(first.timestamp() * 1000) + 5000
    return hit


def test_reverse_shell_tag_is_a_high_severity_lead_worded_as_a_vendor_heuristic():
    rule = ArkimeSshReverseShellTag()
    m = run(rule, events(ssh_session("r1", ["ssh-reverse-shell"]),
                         ssh_session("r2", ["ssh-reverse-shell"], first=T0 + timedelta(minutes=5))))
    assert len(m) == 1 and (m[0].proposed_lane, m[0].severity) == ("lead", "high")
    assert "Arkime's heuristic tagged 2 session record(s) of 2 connection(s)" in m[0].claim
    assert "does not show that a shell ran" in m[0].claim
    assert m[0].predicate[0].field == "arkime.tags"
    assert rule.assures_negative is False and rule.positive_only_reason


@pytest.mark.parametrize("tags", [["ssh-reverse-shell-test"], ["reverse"], None, ["SSH"], "ssh-reverse"])
def test_other_or_partial_tags_do_not_match(tags):
    assert run(ArkimeSshReverseShellTag(), events(ssh_session("r3", tags))) == []


def test_tag_as_a_plain_string_matches():
    assert len(run(ArkimeSshReverseShellTag(), events(ssh_session("r4", "ssh-reverse-shell")))) == 1


def test_malformed_tags_are_missing():
    rule = ArkimeSshReverseShellTag()
    assert run(rule, events(ssh_session("r5", [{"tag": "ssh-reverse-shell"}]))) == []
    assert rule.missing_required == 1


def _pair(hit, src, dst):
    hit["_source"]["source"]["ip"], hit["_source"]["destination"]["ip"] = src, dst
    return hit


def test_tag_on_internal_admin_ssh_states_the_sessions_context_and_stays_a_lead():
    """Internal to internal, the announced software, the bytes and the untagged sessions of the same pair are
    stated so the analyst can weigh the heuristic; the lane does not move."""
    banners = {"version": ["SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"],
               "hassh": ["ec7378c1a92f5a8dde7e8b7a1ddf33d1"]}
    tagged = _pair(ssh_session("i1", ["ssh-reverse-shell"], ssh=banners), "10.1.0.5", "10.1.0.9")
    routine = [_pair(ssh_session(f"i{i + 2}", None, first=T0 + timedelta(minutes=10 + i)), "10.1.0.5", "10.1.0.9")
               for i in range(3)]
    [m] = run(ArkimeSshReverseShellTag(), events(tagged, *routine))
    assert (m.proposed_lane, m.severity) == ("lead", "high")
    assert "Both ends are internal addresses." in m.claim
    assert ("SSH software the two ends announced (self-reported; Arkime does not say which end sent which): "
            "'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10', 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13'") in m.claim
    assert "client HASSH ec7378c1a92f5a8dde7e8b7a1ddf33d1" in m.claim
    assert "900 bytes from the client and 4000 bytes from the server" in m.claim
    assert "Arkime recorded 3 other SSH connection(s) from 10.1.0.5 to 10.1.0.9 port 22 without the tag" in m.claim
    assert [e.id for e in m.events] == [e.id for e in events(tagged)]


def test_missing_byte_counts_are_said_to_be_not_recorded_never_zero():
    hit = ssh_session("b1", ["ssh-reverse-shell"])
    del hit["_source"]["source"]["bytes"]
    second = ssh_session("b2", ["ssh-reverse-shell"], cid="1:b1=", first=T0 + timedelta(minutes=1))
    del second["_source"]["destination"]["bytes"]
    [m] = run(ArkimeSshReverseShellTag(), events(hit, second))
    assert ("carry at least 900 bytes (not recorded on 1 record(s)) from the client and at least 4000 bytes (not "
            "recorded on 1 record(s)) from the server") in m.claim
    only = ssh_session("b4", ["ssh-reverse-shell"])
    del only["_source"]["source"]["bytes"], only["_source"]["destination"]["bytes"]
    [m] = run(ArkimeSshReverseShellTag(), events(only))
    assert "carry a byte count not recorded from the client and a byte count not recorded from the server" in m.claim
    assert " 0 bytes" not in m.claim


def test_tag_toward_a_public_address_says_so_and_untagged_pairs_are_never_reported():
    [m] = run(ArkimeSshReverseShellTag(), events(ssh_session("p1", ["ssh-reverse-shell"]),
                                                 ssh_session("p2", None, first=T0 + timedelta(minutes=1))))
    assert "The client 172.17.100.121 is internal and the server 192.0.2.174 is a public address." in m.claim
    assert "Arkime recorded 1 other SSH connection(s)" in m.claim
    assert run(ArkimeSshReverseShellTag(), events(ssh_session("p3", None))) == []
