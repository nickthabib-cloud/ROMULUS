"""Standalone Linux text scenario through retrieval, sweep, baselines, expansion and report.

Synthetic statements follow these public source formats:
Dovecot: https://github.com/dovecot/core/blob/main/src/login-common/client-common.c
Postfix: https://github.com/vdukhovni/postfix/blob/master/postfix/src/global/log_adhoc.c
OpenVPN: https://github.com/OpenVPN/openvpn/blob/release/2.6/src/openvpn/multi.c#L432-L474
https://github.com/OpenVPN/openvpn/blob/release/2.6/src/openvpn/socket.c#L2236-L2244
"""
from collections import Counter
from datetime import timedelta

from romulus.hunt import sweep as sw
from romulus.site import COLLECTION_SCHEMA, validate_site_content
from tests import throughput_fixture as tf

TEXT_TYPES = {**tf.HOST_TYPES, "message": "text", "event.original": "text",
              "data_stream.dataset": "keyword", "input.type": "keyword", "log.file.path": "keyword"}
FINDING_RULES = {"auth.password_guessing", "auth.success_new_source_after_failures", "mail.outbound_burst",
                 "vpn.concurrent_sessions_same_user_distinct_sources"}
UNKNOWN_REASON = "text line in no recognized format: custom.unknown"

# Fixed reference includes real text selection, scoped unknown-line coverage and writer caveats.
# Seeded by the rule estimate (run_stack(rank=False)) this reference moves only in the manifest (incident tactics
# now come from the vendored ATT&CK release) and, since sudo's privilege_use joined the text families, in the audit
# and rule cells: the unknown line also leaves host.telemetry_gap_after_tamper partial. This fixture has no confirmed
# finding, so evidence ranking adds no extra seed: its single anchor is the rule estimate's. The rule cells include the
# Zeek RPC coercion, internal RDP and RPC enumeration rules (not applicable here). Events, candidates, raw records and
# citations are unchanged (`test_the_text_stack_candidates_moved_only_by_rule_versions`). Evidence epoch 18
# rehashes the event ids (candidates 75b41997... at epoch 17); the rule cells add the SMB impact and service
# catalog rules (not applicable here).
# The connection-level remote-administration, RPC, Kerberos and directory rules and the remote-administration pair
# baseline add rule cells and tasks (not applicable or unmatched here), rule cards in the manifest, the sixth
# baseline spec in the snapshot plan and window hours, and the audit that records them; candidates, events,
# links, citations and the non-baseline semantic projection are unchanged.
# Every coverage cell then gains the rule's cost (records offered and rows selected; wall times are volatile): only
# rule-cell digests move.
# The mention sweep: stats and the sweep summary audit record gain the mention pool's coverage (the unknown line is
# offered to it, not scanned: tests load no shipped pattern), and the manifest gains its mentions section.
# Evidence version 21 rehashes the event ids; the new privilege-broker rules add cells, and host.kernel_module_load
# now reads a text family (kernel taint notices), so its cells follow the text partition's coverage.
# The network-to-host join adds its rule cells, its manifest card and its later pass's audit; it publishes nothing here.
# The mention scan reads each record's free-text fields by family and counts the records outside the sweep's
# selection: only the mention coverage in stats, the sweep summary audit and the manifest moved.
# The mentions view then states how its finding link is found (cited_by_scope): only the manifest digest moved.
# pack@65 (three new rules' cells and cards, tool UA v5, scan_burst v3) moves only rule_cells and the manifest;
# candidates, events and links are unchanged.
GOLDEN_TEXT_STACK = {'anchors': 'e23919dbbe190daf61b3494b7b21e344022b803a564803a6dadaa59988bdf81e',
 # Fleet member hosts staged as memberships add two ranking statements: only the audit's rank query count moved.
 # The ranking version rank@1 -> rank@2 (fleet member hosts keep the rule's evidence, timed by their own record) moves
 # only the version string in the rank audit rows and the manifest's ranking block: with the version set back, both
 # digests are the earlier ones.
 'audit': 'c64a0572905fed66e789221eb9255853fb69cb70a2cb8e5ecfd4c18c4d02dbb9',
 'baseline_counts': '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
 'baseline_hunt_exclusions': '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
 'baseline_observations': '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
 'baseline_scope_hours': '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
 'baseline_segments': '1b81635a62e727fcb94ea06feaee1010eeb2cd33ddf87629208179d6e1f9aa69',
 'baseline_snapshot': 'aa2a03261ede19b7643889b4212cd96408b23bb1720e586e28565aa881a5b1cb',
 'baseline_window_counts': '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
 'baseline_window_event_hours': 'dbbcb75b0e5ad202089e3eeaf84801202f5f1b8b3fcfb214f42edbdd7e007f47',
 'baseline_window_scope_hours': '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
 'candidates': 'ae43a582a37d78da56668235ab1894ff694078abb594432bd43a00d90e68a293',
 'entities': '9e629528fba70d33c17e231aabf743f914b553fe3bc737669e3b8c0e33da6183',
 'event_citations': '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
 'event_entities': '5cc7c7bb876d535b9b3d6ec7300995aa8056163c19d08e9fcf7497e56ac308d5',
 'events': 'f0d612c20f67d030a43e835b8ef639a78c824b51fff59c169d3d5219700de383',
 'expansion': 'dae7cbd7929a4cb94bb232a7343d4d70f62885a979b52714b87bd3641a92169b',
 'links': 'd9f0da030bf1447f35601910ec18eb012f4a55a0a8feef7262ab6e745319890e',
 'manifest': 'e60a748678a6f94d9152b606b02e2da93af8210d2a98e22326b4fd3329800a65',
 'raw': '64be31e697a32f93b1a71657560af514b2d430469cb3be19f44b8827985a7775',
 # host.account_or_group_change 7->8 moves only the rule cells (its version); every other digest is unchanged.
 'rule_cells': '094f3986c5b0f48114a2b7fd7812b1c8dc1fd2cb4347c1743e1c927d22ede220',
 'stats': '64faa1b65d116f9fcc177c6defc3028cdf13a8db34724ccdc2db10f58214eabc',
 'tasks': '31db5bad23dca3ba0a6c4114135053177ece1b46af44576b3198b8967c6762bb'}


def text_documents():
    """All source documents are invented; only two tests below consume this fixture."""
    builder = tf.Builder(19)

    def add(n, dataset, body, *, original=False):
        when = tf.T0 + timedelta(seconds=n)
        line = f"Nov 18 {when:%H:%M:%S} web1 {body}"
        return builder._doc("web1", when, dataset, line if original else None,
                            **({} if original else {"message": line}))

    for n in range(10):
        add(n, "custom.auth", "dovecot: imap-login: Disconnected (auth failed, 1 attempts): "
            "user=<alice>, method=PLAIN, rip=192.0.2.8, lip=10.0.0.10")
    add(15, "custom.auth", "dovecot: imap-login: Login: user=<alice>, "
        "method=PLAIN, rip=192.0.2.8, lip=10.0.0.10")
    for n in range(50):
        add(30+n, "custom.mail", f"postfix/smtp[42]: ABC{n:04d}: to=<person{n}@external.example>, "
            "relay=mx.external.example[192.0.2.25]:25, delay=1, dsn=2.0.0, status=sent (250 ok)", original=True)
    for n, body in [
        (100, "192.0.2.2:51234 [client1] Peer Connection Initiated with [AF_INET]192.0.2.2:51234"),
        (110, "client1/198.51.100.8:51235 [client1] Peer Connection Initiated with [AF_INET]198.51.100.8:51235"),
        (130, "client1/192.0.2.2:51234 SIGTERM[soft,remote-exit] received, client-instance exiting"),
        (140, "client1/198.51.100.8:51235 SIGTERM[soft,remote-exit] received, client-instance exiting"),
    ]:
        add(n, "custom.vpn", "openvpn[43]: " + body)
    builder._doc("web1", tf.T0+timedelta(seconds=150), "custom.unknown", "unrecognized application record")
    builder._doc("web1", tf.T0+timedelta(seconds=160), "custom.without_text", None,
                 application={"state": "healthy"})
    return {tf.HOST_TARGET: builder.host, tf.NETWORK_TARGET: [], tf.ARKIME_TARGET: []}


def _exists_fields(value):
    if isinstance(value, dict):
        if isinstance(value.get("exists"), dict):
            yield value["exists"].get("field")
        for item in value.values():
            yield from _exists_fields(item)
    elif isinstance(value, list):
        for item in value:
            yield from _exists_fields(item)


def run_text_stack(stage_dir, monkeypatch, *, reverse=False):
    """Use the shared stack unchanged; inject its source mappings, explicit site facts and request recorder."""
    docs = text_documents()
    if reverse:
        docs = {target: list(reversed(rows)) for target, rows in docs.items()}
    trace = []
    base_es, base_sweep = tf.MiniES, sw.Sweep
    site = validate_site_content({"schema": COLLECTION_SCHEMA, "mail_domains": ["internal.example"]})

    class RecordingES(base_es):
        def _search(self, target, body):
            response = super()._search(target, body)
            if target == tf.HOST_TARGET:
                trace.append((body.get("query", {}), [row["_id"] for row in response["hits"]["hits"]]))
            return response

    class ConfiguredSweep(base_sweep):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **{**kwargs, "site_facts": site})

    with monkeypatch.context() as patch:
        tf.patched_sizes(patch)
        patch.setattr(tf, "HOST_TYPES", TEXT_TYPES)
        patch.setattr(tf, "MiniES", RecordingES)
        patch.setattr(sw, "Sweep", ConfiguredSweep)
        snapshot = tf.run_stack(stage_dir, docs=docs)
    return snapshot, trace, docs


def _assert_text_result(snapshot, trace, docs):
    payload_ids = {row["_id"] for row in docs[tf.HOST_TARGET]
                   if row["_source"].get("message") or row["_source"].get("event", {}).get("original")}
    no_payload_ids = {row["_id"] for row in docs[tf.HOST_TARGET]} - payload_ids
    selected = {native_id for query, returned in trace
                if {"message", "event.original"} <= set(_exists_fields(query)) for native_id in returned}
    assert len(payload_ids) == 66 and len(no_payload_ids) == 1
    assert selected == payload_ids  # real query returned the unknown line and excluded the no-payload control
    assert selected.isdisjoint(no_payload_ids)
    assert snapshot["stats"]["records"] == 66 and snapshot["stats"]["events"] == 65
    assert snapshot["stats"]["skips"] == {UNKNOWN_REASON: 1}
    assert snapshot["stats"]["errors"] == 0 and not snapshot["stats"].get("rule_failures")
    assert Counter(event["family"] for event in snapshot["events"]) == {
        "auth": 11, "mail_message": 50, "vpn_session": 4,
    }
    assert {row["rule_id"] for row in snapshot["candidates"]} == FINDING_RULES
    assert len(snapshot["candidates"]) == 4
    assert Counter(row["lane"] for row in snapshot["candidates"]) == {"lead": 3, "high": 1}
    assert snapshot["manifest"]["findings"] and snapshot["anchors"] and snapshot["links"]
    events = {event["id"]: event for event in snapshot["events"]}
    raw_ids = {row["id"] for row in snapshot["raw"]}
    for candidate in snapshot["candidates"]:
        assert candidate["event_ids"]
        assert set(candidate["event_ids"]) <= set(events)
        assert all(events[event_id]["raw_ids"] and set(events[event_id]["raw_ids"]) <= raw_ids
                   for event_id in candidate["event_ids"])
    for rule_id in ("auth.password_guessing", "mail.outbound_burst"):
        cells = [row for row in snapshot["rule_cells"] if row["rule_id"] == rule_id]
        assert any(row["partition"] == "window" and row["state"] in {"evaluated_partial", "match_on_partial"}
                   for row in cells)
        assert any(row["target"] == tf.HOST_TARGET and row["partition"] != "window"
                   and row["state"] == "evaluated_partial" for row in cells)
        assert any(UNKNOWN_REASON in str(row["detail"]) for row in cells)
    # a rule that reads no text family (process_exec only) is not made partial by an unrecognized text line
    unrelated = [row for row in snapshot["rule_cells"] if row["rule_id"] == "host.masquerading_binary"]
    assert unrelated and not any(UNKNOWN_REASON in str(row["detail"]) for row in unrelated)
    assert not any(row["state"] in {"evaluated_partial", "match_on_partial", "executed_failed"} for row in unrelated)


def test_linux_text_whole_stack_retrieval_findings_and_partial_coverage(tmp_path, monkeypatch):
    snapshot, trace, docs = run_text_stack(tmp_path / "forward", monkeypatch)
    _assert_text_result(snapshot, trace, docs)
    assert tf.deterministic_golden_digests(snapshot) == GOLDEN_TEXT_STACK


def test_the_text_stack_candidates_moved_only_by_rule_versions(tmp_path, monkeypatch):
    snapshot, _trace, _docs = run_text_stack(tmp_path / "prior", monkeypatch)
    assert tf.deterministic_golden_digests(tf.with_prior_versions(snapshot))["candidates"] == (
        "ae43a582a37d78da56668235ab1894ff694078abb594432bd43a00d90e68a293")


def test_linux_text_whole_stack_snapshot_is_deterministic(tmp_path, monkeypatch):
    first, first_trace, first_docs = run_text_stack(tmp_path / "forward", monkeypatch)
    second, second_trace, second_docs = run_text_stack(tmp_path / "reversed", monkeypatch, reverse=True)
    _assert_text_result(first, first_trace, first_docs)
    _assert_text_result(second, second_trace, second_docs)
    # Input arrival order must not affect any persisted result or report field.
    assert tf.deterministic_golden_digests(first) == tf.deterministic_golden_digests(second)
