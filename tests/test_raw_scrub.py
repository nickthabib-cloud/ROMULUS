"""No credential a Zeek record carries is stored, in any shipper shape, and no lone surrogate ends a sweep.

A record a rule cites is stored whole, and the event stage keeps raw copies of what joining rules may cite. Every
credential the typed path withholds from a Zeek record (password columns, credential commands' arguments, IRC channel
keys, SNMP communities, LDAP simple-bind arguments and password filters, SQL password literals and their echoes, Redis
AUTH and replies, URI userinfo, Malcolm's related.password, url.password, url.full and post_password_*, the Zeek line a
shipper keeps in event.original or message) is masked in the stored copy by the same decisions, and a record's digest
is over that stored form, so a copy fetched again verifies against it. Every other record is stored as it was read.

The end-to-end cases run a real Sweep over every credential-bearing row in every shape that normalize_hits reads, with a
rule citing every event (stored through publish and save_evidence) and staging every event (the event stage's raw
table), then read every byte of the hunt database, the stage database, the report manifest and the captured logs.
"""
import json
import logging
import sqlite3
from datetime import timedelta

import pytest

from romulus.detect.base import Match, Playbook, pf
from romulus.evidence import surrogates
from romulus.evidence.normalize import normalize_hits, raw_digest
from romulus.evidence.raw_scrub import clean_source
from romulus.evidence.typed import NETWORK_OBSERVER_FAMILIES
from romulus.evidence.zeek import ORIGINAL_WITHHELD, STORED_SECRET, normalize_plain_zeek, scrub_zeek_source
from romulus.hunt import sweep as sw
from romulus.sources.models import Window
from romulus.sources.profile import contract_from_types
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests import test_sweep as ts
from tests import throughput_fixture as tf
from tests.fixtures import zeek_logs as zl

SECRET = zl.SECRET
# one document id per row (the fixture names variants of one log, such as irc and irc.dcc, by the log alone)
SECRET_ROWS = [(name, {**h, "_id": f"secret-{name}"}) for name, h in zl.secret_rows()]
SWEPT = [(name, h) for name, h in SECRET_ROWS if h["_index"] != zl.INDEX["plain"]]
PLAIN = [(name, h) for name, h in SECRET_ROWS if h["_index"] == zl.INDEX["plain"]]
# every shape a row of the fixture is written in
SHAPES = ("malcolm", "elastic", "security_onion", "plain")


def _shape(name: str) -> str:
    return next(shape for shape in SHAPES if f"-{shape}" in name)


# ---- the stored form ----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name,h", SECRET_ROWS, ids=[name for name, _ in SECRET_ROWS])
def test_a_credential_bearing_record_is_stored_without_its_secret(name, h):
    stored = clean_source(h["_source"])
    text = json.dumps(stored, ensure_ascii=False)
    assert SECRET not in text and "Hunter2" not in text
    assert stored != h["_source"]                                  # masked, so the record changed
    # scrubbing the stored form changes nothing, so its digest is the digest of what was read
    assert clean_source(stored) == stored
    assert raw_digest(stored) == raw_digest(h["_source"])
    events = ([normalize_plain_zeek(h, sensor=zl.SENSOR)] if h["_index"] == zl.INDEX["plain"]
              else normalize_hits([h])[0])
    assert events and all(ref.digest == raw_digest(h["_source"]) for e in events for ref in e.raw)


def test_every_shape_and_every_credential_log_is_covered():
    shapes = {_shape(name) for name, _ in SECRET_ROWS}
    assert shapes == set(SHAPES)
    logs = {name.split("-", 1)[0] for name, _ in SECRET_ROWS}
    assert {"http", "ftp", "socks", "snmp", "irc", "redis", "mysql", "postgresql", "ldap", "ldap_search",
            "software"} <= {log.split(".", 1)[0] for log in logs}


def test_records_of_no_zeek_shape_are_stored_as_they_were_read():
    docs = tf.build(1)
    for hits in docs.values():
        for h in hits[:2000]:
            assert clean_source(h["_source"]) is h["_source"]
            text = json.dumps(h["_source"], sort_keys=True, separators=(",", ":"))
            import hashlib
            assert raw_digest(h["_source"]) == hashlib.sha256(text.encode()).hexdigest()


def test_a_clean_zeek_record_is_stored_as_it_was_read():
    for log, row in zl.ROWS.items():
        if log == "snmp":                       # its base row carries a community
            continue
        for shape, h in zl.in_every_shape(row, "clean-").items():
            assert scrub_zeek_source(h["_source"]) is h["_source"], (log, shape)


def test_a_kept_line_that_is_not_json_is_withheld_whole():
    [(_name, h)] = [(name, h) for name, h in SECRET_ROWS if name == "ftp-security_onion"]
    source = {**h["_source"], "message": f"1731938400.1\tCxyz\t10.0.0.5\tPASS\t{SECRET}"}
    stored = scrub_zeek_source(source)
    assert stored["message"] == ORIGINAL_WITHHELD and SECRET not in json.dumps(stored)


def test_a_password_in_any_field_and_userinfo_in_any_uri_are_masked():
    [(_name, h)] = [(name, h) for name, h in SWEPT if name == "dns-malcolm-column"]
    source = json.loads(json.dumps(h["_source"]))
    source["zeek"]["dns"]["note"] = f"see https://alice:{SECRET}@files.example.test/x"
    source["zeek"]["dns"]["password"] = SECRET
    stored = scrub_zeek_source(source)
    assert SECRET not in json.dumps(stored)
    assert stored["zeek"]["dns"]["note"] == "see https://files.example.test/x"
    assert stored["zeek"]["dns"]["password"] == STORED_SECRET


# ---- end to end through a sweep ----------------------------------------------------------------------------------

class _CiteAll(Playbook):
    """Cites every network-observer event it reads (stored through publish) and stages it (the event stage)."""
    id = "test.cite_all"
    version = 1
    families = tuple(sorted(NETWORK_OBSERVER_FAMILIES))
    staged = True

    def __init__(self):
        super().__init__()
        self._pending = []

    def match(self, e):
        self._pending.append(e)
        predicate = [pf(e, name) for name in ("source.ip", "destination.ip") if e.has(name)]
        return [Match(self.id, f"cited {e.family} record", "network_observation", [e], predicate, e.ts, "low",
                      "lead", "low", e.entities(), group_key=e.id)]

    def drain_staged(self):
        out, self._pending = self._pending, []
        return out

    def drain_bounds(self):
        return [], []


def _file_repo(path):
    engine = make_engine(path)
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": ["net"], "style": "broad", "original_input": {}, "window": {
        "start": ts.START.isoformat(), "end": (ts.START + timedelta(minutes=5)).isoformat()},
        "source_profiles": {}, "agent_mode": "off", "expansion": {"enabled": False}, "pack": {"version": "p"},
        "normalizer": "n", "policy": "d", "model": {}, "romulus_version": "t"}, "d", "t")
    return repo, engine


def _bytes_of_database(path) -> bytes:
    """Every row of every table, and the file itself."""
    out = [path.read_bytes()]
    with sqlite3.connect(path) as db:
        for (table,) in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'"):
            for row in db.execute(f'SELECT * FROM "{table}"'):
                out.append(repr(row).encode("utf-8", "backslashreplace"))
    return b"\n".join(out)


def _sweep(monkeypatch, tmp_path, records, pack=None):
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: ts._complete(intent, records))
    contract = contract_from_types("net", {"@timestamp": "date", "event.dataset": "keyword"},
                                   role="network", os_family="unknown")
    window = Window(start=ts.START, end=ts.START + timedelta(minutes=5))
    repo, engine = _file_repo(tmp_path / "hunt.db")
    sweep = sw.Sweep(repo, ts.FakeClient(), "h1", window, {"net": contract}, stage_dir=tmp_path / "stage")
    sweep.pack = pack or [_CiteAll()]
    for playbook in sweep.pack:
        playbook.spill_dir, playbook.budget = tmp_path / "stage", sweep.budget
    sweep._profiles = {"net": {"role": "network", "datasets": {}}}
    return sweep, repo, engine, window, contract


def test_a_sweep_stores_no_secret_in_the_hunt_store_the_stage_the_report_or_the_logs(monkeypatch, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    records = [h for _name, h in SWEPT]
    sweep, repo, engine, window, contract = _sweep(monkeypatch, tmp_path, records)
    sweep.run_partition("net", contract, [], window, est=len(records), any_of=[])
    stage_bytes = _bytes_of_database(sweep._stage.path)
    candidates = repo.candidates("h1", ["lead"])
    # every credential-bearing row normalized and was cited, so each one's raw copy is stored
    assert candidates
    with sqlite3.connect(tmp_path / "hunt.db") as db:
        (stored_rows,) = db.execute("SELECT COUNT(*) FROM raw_record").fetchone()
    assert stored_rows == len(records)
    assert b"secret-" in stage_bytes and SECRET.encode() not in stage_bytes
    assert SECRET not in json.dumps(candidates, default=str)
    stored = _bytes_of_database(tmp_path / "hunt.db")
    assert b"secret-" in stored                                     # the cited records were stored
    assert SECRET.encode() not in stored and b"Hunter2" not in stored
    from romulus.report.manifest import build_manifest
    manifest = build_manifest(repo, "h1", "tester")
    assert manifest["findings"]
    assert SECRET not in json.dumps(manifest, default=str)
    assert SECRET not in caplog.text and "Hunter2" not in caplog.text
    sweep.close_stage()
    engine.dispose()


def test_each_stored_record_s_digest_is_its_stored_body_s_and_its_source_s(monkeypatch, tmp_path):
    records = [h for _name, h in SWEPT]
    sweep, _repo, engine, window, contract = _sweep(monkeypatch, tmp_path, records)
    sweep.run_partition("net", contract, [], window, est=len(records), any_of=[])
    by_key = {f"{h['_index']}/{h['_id']}": h["_source"] for h in records}
    with sqlite3.connect(tmp_path / "hunt.db") as db:
        rows = db.execute("SELECT target, native_id, digest, source FROM raw_record").fetchall()
    assert rows
    for target, native_id, digest, source in rows:
        body = json.loads(source)
        assert digest == raw_digest(body) == raw_digest(by_key[f"{target}/{native_id}"])
    sweep.close_stage()
    engine.dispose()


def test_plain_zeek_json_is_stored_without_its_secret(tmp_path):
    repo, engine = _file_repo(tmp_path / "hunt.db")
    events = [normalize_plain_zeek(h, sensor=zl.SENSOR) for _name, h in PLAIN]
    repo.save_evidence("h1", events, {f"{h['_index']}/{h['_id']}": h["_source"] for _name, h in PLAIN}, None)
    stored = _bytes_of_database(tmp_path / "hunt.db")
    assert b"secret-" in stored and SECRET.encode() not in stored
    engine.dispose()


# ---- lone surrogates ----------------------------------------------------------------------------------------------

def _surrogate_http(nid: str) -> dict:
    """A Malcolm Zeek http row whose user agent and URI carry a lone surrogate (a JSON "\\ud800" escape)."""
    [(_name, h)] = [(name, h) for name, h in SWEPT if name == "http-malcolm-column"]
    hit = json.loads(json.dumps(h))
    hit["_id"] = nid
    hit["_source"]["zeek"]["http"]["user_agent"] = "curl/8\ud800"
    hit["_source"]["zeek"]["http"]["uri"] = "/a\udfffb"
    return hit


def _surrogate_eve(nid: str) -> dict:
    """A Suricata EVE http record whose user agent, inside its EVE line, is a lone surrogate escape."""
    eve = {"timestamp": "2024-11-18T14:00:01.000000+0000", "event_type": "http", "src_ip": "10.0.0.5",
           "src_port": 51000, "dest_ip": "203.0.113.10", "dest_port": 80, "proto": "TCP", "flow_id": 7,
           "http": {"hostname": "example.test", "url": "/x", "http_user_agent": "agent\\ud800",
                    "http_method": "GET", "status": 200}}
    line = json.dumps(eve).replace("agent\\\\ud800", "agent\\ud800")
    return {"_index": "logs-suricata", "_id": nid, "_source": {
        "@timestamp": "2024-11-18T14:00:01Z", "host": {"name": "suricata-01"},
        "event": {"dataset": "suricata.eve.http", "original": line}}}


def test_a_lone_surrogate_is_replaced_and_named_on_the_event():
    found: dict[str, list[str]] = {}
    events, _skips, errors = normalize_hits([_surrogate_http("s1"), _surrogate_eve("s2")], malformed_text=found)
    assert errors == [] and len(events) == 2
    for event in events:
        text = json.dumps([e.model_dump(mode="json") for e in events], ensure_ascii=False)
        assert "\ud800" not in text and "\udfff" not in text
        assert any(note.startswith("text in ") and "U+FFFD" in note for note in event.caveats)
        event.model_dump_json()                                      # serializable
    zeek = next(e for e in events if e.family == "http_tx")
    assert zeek.get("user_agent.original") == "curl/8�"
    assert set(found) == {"zeek-malcolm-http/s1", "logs-suricata/s2"} or len(found) == 2
    assert {"zeek.http.user_agent", "zeek.http.uri"} <= set(found[next(k for k in found if k.endswith("/s1"))])
    assert "user_agent.original" in found[next(k for k in found if k.endswith("/s2"))]


def test_a_clean_record_gets_no_surrogate_caveat():
    events, _skips, _errors = normalize_hits([h for _name, h in SWEPT[:20]])
    assert not any(surrogates.MALFORMED_TEXT_CAVEAT.split("{")[0] in note for e in events for note in e.caveats)


class _CiteHttp(_CiteAll):
    id = "test.cite_http"
    families = ("http_tx",)


def test_a_surrogate_record_is_cited_stored_and_the_next_partition_is_still_read(monkeypatch, tmp_path):
    first, second = [_surrogate_http("s1"), _surrogate_eve("s2")], [_surrogate_http("s3")]
    batches = iter([first, second])
    sweep, repo, engine, window, contract = _sweep(monkeypatch, tmp_path, first, pack=[_CiteHttp()])
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: ts._complete(intent, next(batches)))
    half = window.start + (window.end - window.start) / 2
    sweep.run_partition("net", contract, [], Window(start=window.start, end=half), est=2, any_of=[])
    sweep.run_partition("net", contract, [], Window(start=half, end=window.end), est=1, any_of=[])
    candidates = repo.candidates("h1", ["lead"])
    assert len(candidates) == 3                                     # both partitions read, each record published
    with sqlite3.connect(tmp_path / "hunt.db") as db:
        sources = [json.loads(source) for (source,) in db.execute("SELECT source FROM raw_record")]
    # the Zeek rows held the surrogate in their own text; the EVE record holds only its escape, in its line
    zeek_rows = [s for s in sources if "zeek" in s]
    assert len(zeek_rows) == 2 and all("�" in json.dumps(s, ensure_ascii=False) for s in zeek_rows)
    sweep.close_stage()
    engine.dispose()


def test_the_store_and_the_stage_take_an_event_built_with_a_surrogate(tmp_path):
    """An event made outside normalize_hits (a rule's own) is cleaned where it is stored, never ending the write."""
    from romulus.hunt.stage import EventStage
    event = normalize_hits([_surrogate_http("s9")])[0][0]
    raw = event.model_copy(update={"host": "sensor\ud800"})
    repo, engine = _file_repo(tmp_path / "hunt.db")
    repo.save_evidence("h1", [raw], {}, None)
    stage = EventStage(tmp_path / "stage")
    stage.put([raw], {})
    [loaded] = stage.load([raw.id])
    assert loaded.host == "sensor�"
    stage.close()
    engine.dispose()
