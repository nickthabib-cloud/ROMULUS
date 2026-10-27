"""Script view provenance and dynamic shared-disk ceilings."""
from romulus.detect.bounded import StateBudget
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.windows_reassembly import ScriptBlockAssembler
from tests.test_windows_evidence import _hit
from tests.test_windows_reassembly import _part


def test_normalizer_labels_single_and_fragment_views():
    for total, want in [(1, "single"), (2, "fragment")]:
        hit = _hit(4104, channel="Microsoft-Windows-PowerShell/Operational",
                   provider="Microsoft-Windows-PowerShell", data={
                       "ScriptBlockId": "11111111-1111-1111-1111-111111111111",
                       "MessageNumber": "1", "MessageTotal": str(total), "ScriptBlockText": "Get-Date"})
        [record], skips, errors = normalize_hits([hit])
        assert not skips and not errors
        assert record.get("script.view") == want
        assert record.fields["script.view"].origin


def test_assembler_marks_views_even_for_untyped_test_inputs(tmp_path):
    assembler = ScriptBlockAssembler(tmp_path)
    try:
        first = assembler.consume([_part(1, 2, "Invoke-")])
        assert [e.get("script.view") for e in first] == ["fragment"]
        last = assembler.consume([_part(2, 2, "Mimikatz")])
        assert [e.get("script.view") for e in last] == ["fragment", "joined"]
        assert last[-1].get("script.text") == "Invoke-Mimikatz"
    finally:
        assembler.close()


def test_checkpoint_refreshes_ceiling_after_other_store_grows(tmp_path):
    budget = StateBudget(tmp_path, disk_total=2_000_000, reserve=0)
    budget.free = lambda: 2_000_000
    assembler = ScriptBlockAssembler(tmp_path / "scripts", budget=budget)
    try:
        initial = assembler.db.execute("PRAGMA max_page_count").fetchone()[0]
        budget.free = lambda: 700_000
        assembler._checkpoint()
        reduced = assembler.db.execute("PRAGMA max_page_count").fetchone()[0]
        assert reduced < initial
        assert reduced * assembler._page <= assembler._size + budget.headroom() + assembler._page
    finally:
        assembler.close()
