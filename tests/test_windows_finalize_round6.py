"""An unavailable parent-path child cannot cancel unrelated finalize work."""
import pytest

from romulus.detect.bounded import CitationUnavailable
from romulus.detect.windows_lineage import LureAppSpawnsCodeRunner
from tests.windows_process_support import security4688, security4689


@pytest.mark.parametrize("dirty", [False, True])
def test_parent_finalize_citation_failure_is_local_to_one_child(dirty):
    rule = LureAppSpawnsCodeRunner()
    image = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
    parent = security4688(image=image, command="winword.exe", pid=0x700, ppid=0x10, offset=0)
    children = [security4688(image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                            command=f"powershell.exe -NoLogo {n}", pid=0x800+n, ppid=0x700, offset=10+n) for n in range(2)]
    by_id = {item.id: item for item in [parent, *children]}
    rule.load = lambda ids: [by_id[key] for key in ids if key in by_id]
    if dirty:
        rule.consume([parent, *children])
        termination = security4689(image=image, pid=0x700, offset=5)
        by_id[termination.id] = termination
        rule.consume([termination])
    else:
        assert rule.consume(children) == []
        rule.consume([parent])
    rule.drain_staged()
    failed = min(children, key=lambda item: item.id)
    other = next(item for item in children if item.id != failed.id)

    def load(ids):
        if failed.id in ids:
            raise CitationUnavailable("injected unavailable child")
        return [by_id[key] for key in ids if key in by_id]

    rule.load = load
    matches = rule.finalize()
    assert any(other.id in {item.id for item in match.events} for match in matches), (
        [(match.claim, [item.id for item in match.events]) for match in matches],
        [value.reason() for value in rule.limits.values()], list(rule.lineage.dirty_ids()))
    assert "parent_children" in rule.limits
    assert failed.id in rule.limits["parent_children"].reason()
    rule.release_state()


def test_computed_deferred_hit_survives_a_fold_citation_failure(monkeypatch):
    rule = LureAppSpawnsCodeRunner()
    parent = security4688(image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                          command="winword.exe", pid=0x700, ppid=0x10, offset=0)
    child = security4688(image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                         command="powershell.exe -NoLogo", pid=0x800, ppid=0x700, offset=10)
    by_id = {event.id: event for event in (parent, child)}
    rule.load = lambda ids: [by_id[key] for key in ids if key in by_id]
    assert rule.consume([child]) == []
    rule.consume([parent])

    def unavailable(*args):
        raise CitationUnavailable("injected fold citation failure")

    monkeypatch.setattr(rule, "_fold", unavailable)
    matches = rule.finalize()
    assert len(matches) == 1
    assert child.id in {event.id for event in matches[0].events}
    assert any("Fleet correlation was incomplete" in note for note in matches[0].notes)
    rule.release_state()
