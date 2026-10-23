"""Process-lineage links over execs of one pid at one instant.

`bash -c 'cat /etc/shadow'` execs twice in one pid at one instant: bash (audit serial n), then cat in place (serial
n+1). The process of the cat record is cat itself; its earlier image is bash; the parent's image is the sshd that
was running before either. A lookup that cannot decide (no serials, different programs at one instant) leaves the
link partial with the reason named: a lineage link is never complete over an unknown step.
"""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.correlation import PidTable
from romulus.detect.host import ExecLineage
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv
from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkWindow, Selection
from romulus.report.incidents import build_incident_graph
from tests.test_expansion_links import FakePivot, cases

T = datetime(2024, 11, 18, 15, 19, 35, 112000, tzinfo=UTC)
HOST = "videoserver"


def ev(event_id, family="process_exec", *, ts=T, host=HOST, **fields):
    return TypedEvent(
        id=event_id, family=family, ts=ts, host=host, outcome=Outcome.success,
        fields={name.replace("__", "."): fv(value, f"{event_id}:{name}") for name, value in fields.items()},
        raw=[RawRef(target="host-x", native_id=f"raw-{event_id}", digest="d")], normalizer="test@1",
    )


def lab_shape(serials=True, extra=()):
    """sshd (pid 60348) execs before the window's instant; pid 60718 execs bash, then cat, at one instant."""
    def serial(value):
        return {"audit__serial": value} if serials else {}

    sshd = ev("sshd", ts=T - timedelta(seconds=40), process__pid=60348, process__ppid=812,
              process__executable="/usr/sbin/sshd", process__argv=["/usr/sbin/sshd", "-D", "-R"],
              process__session_id=96, **serial(55100))
    bash = ev("bash", process__pid=60718, process__ppid=60348, process__executable="/usr/bin/bash",
              process__argv=["bash", "-c", "cat /etc/shadow"], process__session_id=96, **serial(55439))
    cat = ev("cat", process__pid=60718, process__ppid=60348, process__executable="/usr/bin/cat",
             process__argv=["cat", "/etc/shadow"], process__session_id=96, **serial(55440))
    stranger = ev("stranger", ts=T + timedelta(seconds=1), process__pid=70000, process__ppid=812,
                  process__executable="/usr/bin/true", process__session_id=7, **serial(55500))
    return sshd, bash, cat, stranger, *extra


def window():
    return LinkWindow(label="anchor ±5 min", start=T - timedelta(minutes=5), end=T + timedelta(minutes=5))


def lineage(anchor_event, events):
    anchor = LinkAnchor(finding_id="F-c8216463", ts=anchor_event.ts, host=anchor_event.host,
                        event_ids=[anchor_event.id], events=[anchor_event])
    return LinkFetcher(FakePivot(list(events)), T - timedelta(hours=1), T + timedelta(hours=1)).fetch(
        anchor, "process_lineage", window())


# --------------------------------------------------------------------------------------------- the exec store

def test_a_records_own_image_includes_the_record_and_the_parents_image_is_strictly_before():
    sshd, bash, cat, *_ = lab_shape()
    store = ExecLineage()
    for item in (sshd, bash, cat):
        store.observe(item)
    when = T.timestamp()

    assert store.latest(HOST, 60718, when, serial=55440, inclusive=True).event_id == "cat"     # itself
    assert store.latest(HOST, 60718, when, serial=55440).event_id == "bash"                    # before it
    assert store.latest(HOST, 60718, when, serial=55439, inclusive=True).event_id == "bash"


def test_an_unordered_instant_is_reported_ambiguous_not_absent():
    sshd, bash, cat, *_ = lab_shape(serials=False)
    table = PidTable()
    for item in (sshd, bash, cat):
        table.add(item)
    when = T.timestamp()

    found = table.image(HOST, 60718, when, inclusive=True)
    assert found.record is None and "ambiguous" in found.why and "pid 60718" in found.why and found.at == when
    found = table.image(HOST, 60719, when, inclusive=True)
    assert found.record is None and found.why is None                       # nothing recorded: not ambiguous
    found = table.image(HOST, 60718, when, serial=None, strict=True, exclude="cat")
    assert found.record.event_id == "bash" and found.why is None            # one other image at that instant
    assert table.lookup(HOST, 60718, when, inclusive=True) is None          # the tuple view stays None


# --------------------------------------------------------------------------------------------- the link

def test_lab_shape_with_serials_finds_bash_and_its_sshd_parent():
    sshd, bash, cat, stranger = lab_shape()

    result = lineage(cat, [sshd, bash, cat, stranger])

    assert result.status == "complete", result.reasons
    assert set(result.event_ids) == {"bash", "sshd"}


def test_lab_shape_context_edges_come_back():
    """The incident graph draws an observed edge from the anchor to every finding that cites a linked record: with
    bash and sshd linked again, the edges to the two context findings that cite them are back."""
    sshd, bash, cat, stranger = lab_shape()
    result = lineage(cat, [sshd, bash, cat, stranger])

    class Repo:
        def expansion_links(self, _hunt):
            return [{"id": result.id, "anchor_id": "F-c8216463", "link_type": result.link_type,
                     "window_label": result.window.label, "window_start": result.window.start,
                     "window_end": result.window.end, "strength": result.strength, "key": result.key,
                     "status": result.status, "event_ids": result.event_ids,
                     "evidence_ids": result.evidence_ids, "coverage": [], "reasons": result.reasons}]

        def expansion_anchors(self, _hunt):
            return []

    def finding(finding_id, rule_id, event_id, lane):
        return {"id": finding_id, "rule_id": rule_id, "lane": lane, "observed_at": T.isoformat(),
                "event_ids": [event_id], "entities": [["host", HOST, "host"]]}

    findings = [finding("F-c8216463", "host.credential_store_read", "cat", "urgent"),
                finding("F-13c895", "context.post_access_discovery", "bash", "lead"),
                finding("F-669380", "context.entry_point_promotion", "sshd", "high")]

    graph = build_incident_graph(Repo(), "h1", findings)

    edges = {(edge["from"], edge["to"], edge["style"]) for edge in graph["edges"]}
    assert ("F-c8216463", "F-13c895", "observed") in edges
    assert ("F-c8216463", "F-669380", "observed") in edges


def test_lab_shape_without_serials_is_never_complete_and_empty():
    """Without serials the order of bash and cat is unknown, but both are images of the one process (same pid,
    parent and session at one instant) and sshd is its parent either way: the link selects them."""
    sshd, bash, cat, stranger = lab_shape(serials=False)

    result = lineage(cat, [sshd, bash, cat, stranger])

    assert result.event_ids, "a lineage link is never complete over an unknown step with nothing selected"
    assert set(result.event_ids) == {"bash", "sshd"}
    assert result.status == "complete", result.reasons


def test_a_third_program_at_the_instant_without_serials_leaves_the_link_partial_with_the_reason():
    env = ev("env", process__pid=60718, process__ppid=60348, process__executable="/usr/bin/env",
             process__argv=["env", "cat", "/etc/shadow"], process__session_id=96)
    sshd, bash, cat, stranger, env = lab_shape(serials=False, extra=(env,))

    result = lineage(cat, [sshd, bash, cat, stranger, env])

    assert result.status == "partial"
    assert any(reason.startswith("lineage ambiguous at ") and "pid 60718" in reason for reason in result.reasons)
    assert "sshd" in result.event_ids                                       # what is known is still linked


def test_a_non_exec_anchor_at_an_unordered_instant_is_partial_with_the_reason():
    """The anchor is a file read by pid 60718 at the exec instant, without serials: which image read it is unknown."""
    sshd, bash, cat, stranger = lab_shape(serials=False)
    read = ev("read", "file_access", process__pid=60718, process__ppid=60348, process__session_id=96,
              file__path="/etc/shadow")

    result = lineage(read, [sshd, bash, cat, stranger])

    assert result.status == "partial"
    assert any("lineage ambiguous at " in reason and "pid 60718" in reason for reason in result.reasons)
    assert {"sshd", "bash", "cat"} <= set(result.event_ids)


def test_a_non_exec_anchor_with_its_serial_finds_its_image_and_is_complete():
    sshd, bash, cat, stranger = lab_shape()
    read = ev("read", "file_access", process__pid=60718, process__ppid=60348, process__session_id=96,
              file__path="/etc/shadow", audit__serial=55441)

    result = lineage(read, [sshd, bash, cat, stranger])

    assert result.status == "complete", result.reasons
    assert set(result.event_ids) == {"sshd", "bash", "cat"}


def test_an_anchor_whose_process_exec_is_not_retrieved_is_partial_not_an_empty_complete():
    sshd, _bash, _cat, stranger = lab_shape()
    read = ev("read", "file_access", process__pid=60718, process__ppid=60348, process__session_id=96,
              file__path="/etc/shadow", audit__serial=55441)

    result = lineage(read, [sshd, stranger])

    assert result.status == "partial"
    assert any("pid 60718" in reason and "no exec record" in reason for reason in result.reasons)
    assert result.event_ids == ["sshd"]                                    # its parent is still known


def test_a_descendant_of_an_unordered_instant_is_partial_with_the_reason():
    """From sshd's lineage: pid 60718 has bash and cat ordered by serial and an env exec at the same instant without
    one, so which image was the parent of its later child is unknown."""
    env = ev("env", process__pid=60718, process__ppid=60348, process__executable="/usr/bin/env",
             process__session_id=96)
    child = ev("child", ts=T + timedelta(seconds=2), process__pid=60800, process__ppid=60718,
               process__executable="/usr/bin/id", process__session_id=96)
    sshd, bash, cat, stranger, env, child = lab_shape(extra=(env, child))

    result = lineage(sshd, [sshd, bash, cat, stranger, env, child])

    assert result.status == "partial"
    assert any(reason.startswith("lineage ambiguous at ") and "pid 60718" in reason for reason in result.reasons)
    assert {"bash", "cat", "env"} <= set(result.event_ids)


def test_the_strict_parent_lookup_never_takes_the_childs_own_instant_image_with_a_higher_serial():
    """sshd re-execs at the child's instant with a higher serial: the child's parent is the image before it."""
    sshd, bash, cat, stranger = lab_shape()
    later = ev("sshd-later", process__pid=60348, process__ppid=812, process__executable="/usr/bin/other",
               process__session_id=96, audit__serial=55441)

    result = lineage(cat, [sshd, bash, cat, stranger, later])

    assert result.status == "complete", result.reasons
    assert "sshd" in result.event_ids and "sshd-later" not in result.event_ids


# --------------------------------------------------------------------------------------------- the invariant

@pytest.mark.parametrize("link_type", sorted(cases()))
def test_no_link_type_is_complete_when_its_selection_left_a_step_unknown(link_type, monkeypatch):
    """Whatever a link's typed selection is, a step it could not decide makes the link partial with the reason;
    the retrieval being complete never makes the link complete on its own."""
    anchor_event, linked = cases()[link_type]
    handler_name = {"process_lineage": "_lineage", "login_session": "_session", "network_flow": "_flow",
                    "flow_host_side": "_flow_host_side", "source_ip": "_source_ip", "account": "_account",
                    "host_after_anchor": "_host_after"}[link_type]
    original = getattr(LinkFetcher, handler_name)

    def unknown_step(self, anchor, window):
        key, strength, intents, retain, select, reason, coverage = original(self, anchor, window)

        def undecided(events):
            selected = select(events)
            chosen = selected.events if isinstance(selected, Selection) else list(selected)
            return Selection(chosen, ["a lookup returned unknown"])

        return key, strength, intents, retain, undecided, reason, coverage

    monkeypatch.setattr(LinkFetcher, handler_name, unknown_step)
    anchor = LinkAnchor(finding_id=f"finding-{link_type}", ts=anchor_event.ts, host=anchor_event.host,
                        event_ids=[anchor_event.id], events=[anchor_event])
    start = anchor_event.ts
    result = LinkFetcher(FakePivot([anchor_event, linked]), start, start + timedelta(minutes=10)).fetch(
        anchor, link_type, LinkWindow(label="w", start=start, end=start + timedelta(minutes=10)))

    assert result.status != "complete"
    if result.status != "unsupported":
        assert "a lookup returned unknown" in result.reasons


def test_a_non_exec_anchor_never_takes_another_processs_exec_of_its_pid():
    """A forked process that never execed reuses a pid an exited process execed with minutes earlier: the record's
    own parent (the attacker's bash) is the lineage, never the earlier holder's, and the link says why it is partial."""
    crond = ev("crond", ts=T - timedelta(minutes=4, seconds=1), process__pid=1200, process__ppid=1,
               process__executable="/usr/sbin/cron", process__session_id=5, audit__serial=99)
    cron = ev("cronjob", ts=T - timedelta(minutes=4), process__pid=4000, process__ppid=1200,
              process__executable="/usr/bin/logrotate", process__session_id=5, audit__serial=100)
    attacker = ev("attacker-bash", ts=T - timedelta(seconds=30), process__pid=3999, process__ppid=3000,
                  process__executable="/usr/bin/bash", process__session_id=77, audit__serial=900)
    write = ev("write", "file_change", process__pid=4000, process__ppid=3999, process__session_id=77,
               file__path="/etc/cron.d/x", audit__serial=1000)

    result = lineage(write, [crond, cron, attacker])

    assert "attacker-bash" in result.event_ids
    assert not {"crond", "cronjob"} & set(result.event_ids)
    assert result.status == "partial"
    assert any("forked without exec or the pid was reused" in reason for reason in result.reasons)


def test_a_daemon_reparented_to_init_never_takes_another_programs_exec_of_its_pid():
    """A double-forked payload orphaned to init (ppid 1, no session) reuses a pid an exited logrotate execed with:
    the program differs, so logrotate's lineage is never the payload's; the link is partial and says why."""
    crond = ev("crond", ts=T - timedelta(minutes=4, seconds=1), process__pid=1200, process__ppid=1,
               process__executable="/usr/sbin/cron", process__session_id=5, audit__serial=99)
    cron = ev("cronjob", ts=T - timedelta(minutes=4), process__pid=4000, process__ppid=1200,
              process__executable="/usr/bin/logrotate", process__session_id=5, audit__serial=100)
    connect = ev("connect", "net_socket", process__pid=4000, process__ppid=1,
                 process__executable="/usr/bin/python3", audit__serial=1000)

    result = lineage(connect, [crond, cron])

    assert not {"crond", "cronjob"} & set(result.event_ids)
    assert result.status == "partial"
    assert any("forked without exec or the pid was reused" in reason for reason in result.reasons)

