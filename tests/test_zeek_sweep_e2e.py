"""Zeek records through a real sweep, with the whole rule pack.

- The same traffic written as Zeek rows (Malcolm's layout) and as Suricata EVE records gives the same findings from
  the flow, DNS, HTTP, TLS and SSH rules, by rule, group, lane and severity: the rule-level twin tests, run through
  partition retrieval, normalization, deduplication, staging, publication and finalize.
- One Malcolm index holding Zeek conn, dns, http, ssl, kerberos, smb, dce_rpc, notice and intel rows beside Arkime
  sessions, Malcolm's Suricata rows and a Zeek log outside the catalog is swept with honest coverage: every row of a
  catalogued log becomes an event of its family, the uncatalogued log is not assessed (and no rule is partial for it),
  Zeek's intel hit is reported naming Zeek, and nothing is an error.
- A credential-bearing row cited by a real rule leaves no secret in the hunt store.
- One rule that raises fails only its own cells; the others publish, later partitions are read, and a failing store
  still ends the sweep.
"""
import sqlite3
from dataclasses import replace
from datetime import timedelta

import pytest

from romulus.detect.base import Match, Playbook
from romulus.hunt import sweep as sw
from romulus.sources.models import Window
from romulus.sources.profile import contract_from_types
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests import test_sweep as ts
from tests import test_zeek_flow_rules as fr
from tests import test_zeek_twins as tw
from tests.fixtures import zeek_factory as zf
from tests.fixtures import zeek_logs as zl

WINDOW = Window(start=ts.START, end=ts.START + timedelta(minutes=10))
CONTRACT_FIELDS = {"@timestamp": "date", "event.dataset": "keyword", "event.provider": "keyword"}
# The rules whose Zeek reading the twin tests establish rule by rule.
TWIN_RULES = {"net.port_scan", "net.horizontal_sweep", "net.dns_nxdomain_burst", "net.dns_subdomain_enumeration",
              "net.tool_user_agent_http", "net.tls_self_signed_certificate_outbound", "net.rare_client_fingerprint"}


def _repo(path=None):
    engine = make_engine(str(path) if path is not None else ":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": ["net"], "style": "broad", "original_input": {}, "window": {
        "start": WINDOW.start.isoformat(), "end": WINDOW.end.isoformat()}, "source_profiles": {},
        "ai_agent": {"requested": False}, "expansion": {"enabled": False}, "pack": {"version": "p"}, "normalizer": "n",
        "policy": "d", "model": {}, "romulus_version": "t"}, "d", "t")
    return repo


def sweep(monkeypatch, tmp_path, batches, *, pack=None, repo=None, name="stage"):
    """A real sweep of one network target whose partitions return `batches` in turn, with the whole rule pack (or
    `pack`), finalized."""
    pending = list(batches)
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: ts._complete(intent, pending.pop(0)))
    contract = contract_from_types("net", CONTRACT_FIELDS, role="network", os_family="unknown")
    repo = repo or _repo()
    run = sw.Sweep(repo, ts.FakeClient(), "h1", WINDOW, {"net": contract}, stage_dir=tmp_path / name)
    if pack is not None:
        run.pack = pack
        for playbook in run.pack:
            playbook.spill_dir, playbook.budget, playbook.window_start = tmp_path / name, run.budget, WINDOW.start
    run._profiles = {"net": {"role": "network", "datasets": {}}}
    step = (WINDOW.end - WINDOW.start) / len(batches)
    for i, batch in enumerate(batches):
        part = Window(start=WINDOW.start + step * i, end=WINDOW.start + step * (i + 1))
        run.run_partition("net", contract, [], part, est=len(batch), any_of=[])
    run.finalize()
    return repo, run


def findings(repo, rules=None) -> list[tuple]:
    return sorted((c["rule_id"], c["group_key"], c["lane"], c["severity"]) for c in repo.candidates("h1")
                  if rules is None or c["rule_id"] in rules)


# ---- twins through the sweep -----------------------------------------------------------------------------------------

def _traffic():
    """(Zeek hits in Malcolm's layout, Suricata EVE twins) of one capture: a port scan, a sweep of tcp/445, an NXDOMAIN
    burst under one domain, curl downloads, a self-signed TLS server and a paramiko SSH client."""
    scan = [fr.tcp(i, resp_h="10.0.1.20", resp_p=port, service=None, conn_state="REJ", history="Sr",
                   duration=0.001, orig_bytes=0, resp_bytes=0, orig_pkts=1, resp_pkts=1, orig_ip_bytes=44,
                   resp_ip_bytes=40) for i, port in enumerate(range(20, 50))]
    sweep445 = [fr.tcp(100 + i, resp_h=f"10.0.2.{i + 1}", resp_p=445, service=None, conn_state="S0", history="S",
                       duration=None, orig_bytes=0, resp_bytes=0, orig_pkts=1, resp_pkts=0, orig_ip_bytes=60,
                       resp_ip_bytes=0) for i in range(25)]
    zeek = [zf.malcolm(conn, f"zc{i}") for i, conn in enumerate(scan + sweep445)]
    eve = [fr.eve_twin(conn, f"sc{i}") for i, conn in enumerate(scan + sweep445)]
    dns = [tw.dns_transaction(i, f"x{i:04d}qz.example.org", rcode="NXDOMAIN") for i in range(80)]
    http = [tw.http_transaction(i, "curl/8.4.0", f"/drop/{i}.bin") for i in range(4)]
    tls = [tw.tls_session(i) for i in range(3)]
    ssh = [tw.ssh_session(i) for i in range(2)]
    zeek += [zl.WRITERS["malcolm"](row, f"zd{i}") for i, (row, _hits) in enumerate(dns)]
    eve += [h for _row, hits in dns for h in hits]
    for prefix, pairs in (("zh", http), ("zt", tls), ("zs", ssh)):
        zeek += [zl.WRITERS["malcolm"](row, f"{prefix}{i}") for i, (row, _hit) in enumerate(pairs)]
        eve += [hit for _row, hit in pairs]
    return zeek, eve


def test_zeek_rows_give_the_findings_their_suricata_twins_give_through_the_sweep(monkeypatch, tmp_path):
    zeek, eve = _traffic()
    from_zeek, zeek_run = sweep(monkeypatch, tmp_path, [zeek[: len(zeek) // 2], zeek[len(zeek) // 2:]], name="z")
    from_eve, _eve_run = sweep(monkeypatch, tmp_path, [eve[: len(eve) // 2], eve[len(eve) // 2:]], name="s")
    twins = findings(from_zeek, TWIN_RULES)
    assert twins == findings(from_eve, TWIN_RULES)
    assert {rule for rule, *_rest in twins} == TWIN_RULES - {"net.dns_subdomain_enumeration"}
    assert zeek_run.stats["errors"] == 0 and not sw.Sweep._unsupported_skips(zeek_run.stats["skips"])
    # the Zeek hunt's flow claims name Zeek
    claims = [c["claim"] for c in from_zeek.candidates("h1") if c["rule_id"] == "net.horizontal_sweep"]
    assert claims and all("Zeek conn record" in claim for claim in claims)


# ---- one Malcolm index holding every shipper's rows ------------------------------------------------------------------

def _uncatalogued_ics() -> dict:
    h = zf.malcolm(zf.Conn(uid="CopcuaConn000001", resp_p=4840, service="opcua"), "mx-opcua")
    h["_source"]["event"]["dataset"] = "opcua_binary"
    return h


def _mixed_index() -> list[dict]:
    rows = (zl.DNS, zl.HTTP, zl.SSL, zl.KERBEROS, zl.SMB_FILES, zl.SMB_CMD, zl.DCE_RPC, zl.NOTICE, zl.INTEL)
    return [*zf.malcolm_mixed_batch(), *(zl.WRITERS["malcolm"](row, f"mx-{row.log}") for row in rows), _uncatalogued_ics(),
            *zf.previous_shapes()["malcolm-suricata-dns"]]


def test_a_mixed_malcolm_index_is_swept_with_honest_coverage(monkeypatch, tmp_path):
    records = _mixed_index()
    repo, run = sweep(monkeypatch, tmp_path, [records])
    assert run.stats["errors"] == 0
    # every row is an event, a merged copy or a superseded interim row, except the log outside the catalog
    [(reason, count)] = run.stats["not_assessed_by_target"]["net"].items()
    assert reason == "dataset:opcua_binary is not normalized" and count == 1
    assert not sw.Sweep._unsupported_skips({k: v for k, v in run.stats["skips"].items() if k != reason})
    assert not any("unsupported" in str(item) for item in run.partial_reasons)
    cells = repo.rule_cells("h1")
    assert not any("unsupported_records" in reason for cell in cells for reason in (cell["detail"] or {}).get(
        "reasons", []))
    flow_cells = [c for c in cells if c["rule_id"] == "net.horizontal_sweep" and c["target"] == "net"]
    assert flow_cells and all(c["state"] != "executed_failed" for c in flow_cells)
    # the sensor's own intel hit is reported, naming Zeek
    intel = [c for c in repo.candidates("h1") if c["rule_id"] == "net.zeek_alert"]
    assert any("Zeek's intel framework" in c["claim"] for c in intel), [c["claim"] for c in intel]
    assert not any("Suricata raised" in c["claim"] for c in intel)


def test_the_mixed_index_s_families_are_all_read(monkeypatch, tmp_path):
    seen = []

    class Families(Playbook):
        id, version = "test.families", 1
        families = ("net_flow", "net_session", "dns_query", "http_tx", "tls_session", "kerberos_tx", "smb_tx",
                    "rpc_tx", "net_alert")

        def match(self, event):
            seen.append(event.family)
            self.evaluated += 1
            return []

    sweep(monkeypatch, tmp_path, [_mixed_index()], pack=[Families()])
    assert set(seen) == set(Families.families)


# ---- secrets ---------------------------------------------------------------------------------------------------------

PASSWORD = "Sup3r-Secret-Pa55"


def test_a_credential_row_cited_by_a_real_rule_leaves_no_secret_in_the_hunt_store(monkeypatch, tmp_path):
    """Four curl downloads, one of them sent with Basic credentials that Malcolm lifted to related.password and wrote
    into url.full: the tool user-agent rule cites the rows, so their raw records are stored, without the secret."""
    pairs = [tw.http_transaction(i, "curl/8.4.0", f"/drop/{i}.bin") for i in range(4)]
    hits = [zl.WRITERS["malcolm"](row, f"zh{i}") for i, (row, _hit) in enumerate(pairs)]
    source = hits[0]["_source"]
    source.setdefault("related", {})["password"] = [PASSWORD]
    source.setdefault("url", {}).update(password=PASSWORD, full=f"http://admin:{PASSWORD}@files.example.net/drop/0")
    repo, _run = sweep(monkeypatch, tmp_path, [hits], repo=_repo(tmp_path / "hunt.db"))
    assert any(c["rule_id"] == "net.tool_user_agent_http" for c in repo.candidates("h1"))
    stored = (tmp_path / "hunt.db").read_bytes()
    with sqlite3.connect(tmp_path / "hunt.db") as db:
        rows = [repr(row) for (table,) in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
                for row in db.execute(f'SELECT * FROM "{table}"')]
        raw = db.execute("SELECT source FROM raw_record WHERE native_id = 'zh0'").fetchone()
    assert raw is not None, "the credential row was cited and stored"
    assert PASSWORD.encode() not in stored and not any(PASSWORD in row for row in rows)


# ---- the rule guard --------------------------------------------------------------------------------------------------

class _Boom(Playbook):
    id, version = "test.boom", 1
    families = ("net_flow",)

    def match(self, event):
        raise KeyError("a defect in this rule")


class _BoomAtFinalize(Playbook):
    id, version, kind = "test.boom_finalize", 1, "aggregate"
    families = ("net_flow",)

    def match(self, event):
        self.evaluated += 1
        return []

    def finalize(self):
        raise ZeroDivisionError("a defect at finalize")


class _Every(Playbook):
    id, version = "test.every", 1
    families = ("net_flow",)

    def match(self, event):
        return [Match(self.id, f"flow {event.id}", "network_observation", [event], [], event.ts, "low", "context",
                      "low", event.entities(), group_key=event.id)]


def _flows(n: int, offset: int = 0) -> list[dict]:
    return [zf.malcolm(replace(zf.Conn(), uid=f"Cguard{offset + i:010d}", orig_p=40000 + offset + i),
                       f"g{offset + i}") for i in range(n)]


def test_a_rule_that_raises_fails_only_its_own_cells(monkeypatch, tmp_path):
    repo, run = sweep(monkeypatch, tmp_path, [_flows(3), _flows(3, 3)],
                      pack=[_Boom(), _BoomAtFinalize(), _Every()])
    cells = {(c["rule_id"], c["partition"]): c for c in repo.rule_cells("h1")}
    boom = [c for (rule, _p), c in cells.items() if rule == "test.boom"]
    assert len(boom) == 2 and all(c["state"] == "executed_failed" for c in boom)
    assert all("test.boom failed" in c["detail"]["error"] and "KeyError" in c["detail"]["error"] for c in boom)
    window = cells[("test.boom_finalize", "window")]
    assert window["state"] == "executed_failed" and "ZeroDivisionError" in window["detail"]["error"]
    # the other rule read both partitions and published every record
    every = [c for (rule, _p), c in cells.items() if rule == "test.every"]
    assert len(every) == 2 and all(c["state"] == "matched" and c["evaluated"] == 3 for c in every)
    assert len(repo.candidates("h1")) == 6
    assert set(run.stats["rule_failures"]) == {"test.boom", "test.boom_finalize"}
    assert sum("failed" in reason for reason in run.partial_reasons) == 2


def test_a_failing_store_still_ends_the_sweep(monkeypatch, tmp_path):
    class StoreFails(_Every):
        id = "test.store_fails"

        def match(self, event):
            raise sqlite3.OperationalError("disk I/O error")

    with pytest.raises(sqlite3.OperationalError):
        sweep(monkeypatch, tmp_path, [_flows(1)], pack=[StoreFails()])


def test_a_publishing_failure_during_consume_ends_the_sweep_and_is_not_the_rules(monkeypatch, tmp_path):
    def broken_publish(*args, **kwargs):
        raise ValueError("invalid adapter response")

    monkeypatch.setattr(sw, "publish_match", broken_publish)
    with pytest.raises(ValueError, match="invalid adapter response"):
        sweep(monkeypatch, tmp_path, [_flows(2)], pack=[_Every()])


def test_a_rule_that_raises_mid_batch_fails_only_itself(monkeypatch, tmp_path):
    class SecondRaises(_Every):
        id = "test.second_raises"
        seen = 0

        def match(self, event):
            self.seen += 1
            if self.seen == 2:
                raise KeyError("a defect on the second record")
            return super().match(event)

    repo, run = sweep(monkeypatch, tmp_path, [_flows(3)], pack=[SecondRaises(), _Every()])
    [cell] = [c for c in repo.rule_cells("h1") if c["rule_id"] == "test.second_raises" and c["partition"] != "window"]
    assert cell["state"] == "executed_failed" and "KeyError" in cell["detail"]["error"]
    assert {c["rule_id"] for c in repo.candidates("h1")} == {"test.every"}
    assert set(run.stats["rule_failures"]) == {"test.second_raises"}
