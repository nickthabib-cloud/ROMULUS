from romulus.detect.windows_common import Undecided
from romulus.detect.windows_events import WindowsEventRule
from romulus.detect.windows_scripts import ScriptReflectiveLoad
from romulus.hunt.publish import publish_match
from tests.test_report import _repo_with_finding
from tests.test_windows_c_identity_review import native
from tests.test_windows_script_provenance_review import _publish, _script_candidate, _views


def test_unresolved_native_records_keep_distinct_instances():
    class Unknown(WindowsEventRule):
        id = "test.unresolved"
        title = "Unresolved native observation"
        families = ("auth",)

        def judge(self, event):
            raise Undecided("test_missing", "The native field is missing")

    rule = Unknown()
    first = native(4624, {"TargetUserName": "first"}, record=123)
    second = native(4624, {"TargetUserName": "second"}, record=124)
    [one] = rule.consume([first])
    [two] = rule.consume([second])
    assert [item.id for item in one.events] == [first.id]
    assert [item.id for item in two.events] == [second.id]


def test_sweep_reclaims_agent_script_ownership_but_keeps_original_discovery(tmp_path):
    repo, _ = _repo_with_finding()
    _, joined, raw = _views(tmp_path)
    first = _publish(repo, joined, raw)
    rule = ScriptReflectiveLoad()
    [match] = rule.consume([joined])
    publish_match(repo, "h1", rule, match, None, raw)
    row = _script_candidate(repo)
    assert row["id"] == first["id"]
    assert row["source_case_id"] is None
    assert row["source_anchor_id"] is None
    assert row["source_link_id"] is None
    assert row["gate_results"]["_evidence_view_origin"]["source_case_id"] == "case-1"
