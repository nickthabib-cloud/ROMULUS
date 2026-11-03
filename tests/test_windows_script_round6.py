"""Native script records exercise program starts without assuming successful execution."""
import base64

import pytest

from romulus.detect.powershell_tokens import read_event_script
from romulus.detect.windows_proxy import PowerShellEncodedOrCradle
from romulus.detect.windows_scripts import runs_code
from romulus.evidence.windows_reassembly import ScriptBlockAssembler
from tests.test_windows_script_round3 import native
from tests.test_windows_script_round5 import DOWNLOAD
from tests.test_windows_script_rules import RULES
from tests.windows_process_support import run, sysmon1

STARTS = [
    '& "$f"', '& "${f}"', '. "$f"', '& "$f" /S',
    'start $f', 'START $f',
    r'& C:\Temp\setup.exe', r'& .\setup.exe', r'C:\Temp\setup.exe /quiet',
    r'.\setup.exe /quiet', '& setup.msi', 'setup.exe /quiet',
    "& (Join-Path $env:TEMP 'setup.exe')", ". (Resolve-Path $f)",
    "& (Microsoft.PowerShell.Management\\Join-Path $env:TEMP 'setup.exe')",
    "$g='setup.msi'; & $g", "$g='setup.exe'; & $g", r"$g='C:\Temp\setup.exe'; & $g",
    '(New-Object -Com WScript.Shell).Exec($f)',
    '(New-Object -ComO WScript.Shell).Run($f)',
    '(New-Object -ComOb WScript.Shell).Exec($f)',
    '(New-Object -ComObj WScript.Shell).Run($f)',
    '(New-Object -ComObje WScript.Shell).Exec($f)',
    '(New-Object -ComObjec WScript.Shell).Run($f)',
    '(New-Object -ComObject WScript.Shell).Exec($f)',
    "(New-Object -ComObject 'Shell.Application').ShellExecute($f)",
    '$sh = New-Object -Com WScript.Shell; $sh.Run($f)',
    '$sh = New-Object -ComObject WScript.Shell; $sh.Exec($f)',
    '$sh = (New-Object -ComObject WScript.Shell); $sh.Run($f)',
    '$sh = New-Object -ComObject Shell.Application; $sh.ShellExecute($f)',
    '${sh} = New-Object -ComObject WScript.Shell; ${sh}.Exec($f)',
    r'.\123.exe /quiet', r'C:\Temp\123.exe', '123.exe /quiet',
    "& ((Join-Path $env:TEMP 'setup.exe'))", '& ((Resolve-Path $f))',
]

CONSTRUCTED_AFTER_PATH = [
    "& (Join-Path $env:TEMP 'unused' | Out-Null; $left + $right)",
    "& (Resolve-Path $input | Out-Null; $left + $right)",
    "& ((Join-Path $env:TEMP 'unused' | Out-Null; $left + $right))",
    "& ((Resolve-Path $input | Out-Null; $left + $right))",
    "& ((Join-Path $env:TEMP 'unused') + $unknown)",
    "& ((Resolve-Path $input) + $unknown)",
]

PATH_WITH_BACKGROUND = "& (Join-Path $env:TEMP 'unused' & $left + $right)"


@pytest.mark.parametrize('start', STARTS)
def test_native_requested_start_after_download_is_only_a_start_lead(start):
    observation = native(DOWNLOAD + start)
    [match] = RULES['download']().consume([observation])
    assert match.proposed_lane == 'lead'
    assert 'program-start/item-open request' in match.claim
    assert not RULES['obfuscated_execution']().consume([observation])
    assert not runs_code(read_event_script(observation))


@pytest.mark.parametrize('start', STARTS)
def test_native_requested_start_without_download_or_with_decode_stays_negative(start):
    assert not RULES['download']().consume([native(start)])
    assert not RULES['obfuscated_execution']().consume([native(start)])
    assert not RULES['decode_evaluation']().consume([native('[Convert]::FromBase64String($data); ' + start)])


@pytest.mark.parametrize('source', [
    '(New-Object -ComObject WScript.Shell).ShellExecute($f)',
    '(New-Object -ComObject Shell.Application).Run($f)',
    '(New-Object -ComObject Shell.Application).Exec($f)',
    '$sh = New-Object -ComObject WScript.Shell; $sh.ShellExecute($f)',
    '$sh = New-Object -ComObject Shell.Application; $sh.Exec($f)',
    '$sh = New-Object -ComObject WScript.Shell; $sh = $other; $sh.Run($f)',
    '$sh = New-Object -ComObject WScript.Shell; $sh += $other; $sh.Run($f)',
    '$sh = New-Object -ComObject WScript.Shell; $sh++; $sh.Run($f)',
    '$sh = New-Object -ComObject WScript.Shell; Clear-Variable sh; $sh.Run($f)',
    '$sh = New-Object -ComObject WScript.Shell; & Set-Variable sh $other; $sh.Run($f)',
    '$sh = New-Object -ComObject WScript.Shell; { $sh.Run($f) }',
    'Write-Output New-Object -ComObject WScript.Shell; $sh.Run($f)',
    '(New-Object -ComputerName WScript.Shell).Run($f)',
    '$sh = New-Object -ComObject Other.Shell; $sh.Run($f)',
    'Write-Output "& $f"', "Write-Output 'start $f'", r'Write-Output C:\Temp\setup.exe',
    'Get-Date && $f', 'Get-Date && "$f"', 'Get-Date && ($x + $y)',
    r"& 'Microsoft.PowerShell.Utility\Write-Output' $f",
    r'Microsoft.PowerShell.Utility\Write-Output $f',
])
def test_native_inert_or_invalid_start_shapes_do_not_create_download_leads(source):
    observation = native(DOWNLOAD + source)
    assert not RULES['download']().consume([observation])
    assert not RULES['obfuscated_execution']().consume([observation])


def test_native_module_qualified_literal_is_a_constructed_command_not_a_path():
    target = r"& ($env:Unset + 'Microsoft.PowerShell.Utility\Write-Output') 1"
    observation = native(DOWNLOAD + target)
    [match] = RULES['download']().consume([observation])
    assert match.proposed_lane == 'lead'
    assert 'program-start/item-open request' not in match.claim
    [obfuscated] = RULES['obfuscated_execution']().consume([observation])
    assert obfuscated.proposed_lane == 'lead'
    assert not read_event_script(observation).starts_program


@pytest.mark.parametrize('target', CONSTRUCTED_AFTER_PATH)
def test_native_path_command_does_not_exempt_a_later_constructed_target(target):
    observation = native(DOWNLOAD + target)
    [match] = RULES['download']().consume([observation])
    assert match.proposed_lane == 'lead'
    assert 'program-start/item-open request' not in match.claim
    [obfuscated] = RULES['obfuscated_execution']().consume([observation])
    assert obfuscated.proposed_lane == 'lead'
    assert runs_code(read_event_script(observation))
    assert not read_event_script(observation).starts_program


def test_native_path_command_does_not_exempt_an_ampersand_separated_expression():
    observation = native(DOWNLOAD + PATH_WITH_BACKGROUND)
    [match] = RULES['download']().consume([observation])
    assert match.proposed_lane == 'lead'
    assert 'program-start/item-open request' not in match.claim
    [obfuscated] = RULES['obfuscated_execution']().consume([observation])
    assert obfuscated.proposed_lane == 'lead'
    assert runs_code(read_event_script(observation))


@pytest.mark.parametrize('target', [r'Get-Date && .\setup.exe', 'Get-Date && & "$f"'])
def test_native_chain_still_recognizes_an_explicit_start(target):
    [match] = RULES['download']().consume([native(DOWNLOAD + target)])
    assert match.proposed_lane == 'lead'
    assert 'program-start/item-open request' in match.claim


@pytest.mark.parametrize('start', STARTS)
def test_native_joined_download_and_requested_start_publish_once(tmp_path, start):
    assembler = ScriptBlockAssembler(tmp_path)
    try:
        rule = RULES['download']()
        first = assembler.consume([native(DOWNLOAD, number=1, total=2)])
        assert not rule.consume(first)
        second = assembler.consume([native(start, number=2, total=2, record=2)])
        [match] = rule.consume(second)
        assert match.proposed_lane == 'lead'
        assert match.events[0].get('script.view') == 'joined'
        assert not rule.consume(second)
    finally:
        assembler.close()


def test_native_download_and_start_in_separate_blocks_remain_block_local():
    observations = [native(DOWNLOAD, block='download', record=1), native('start $f', block='start', record=2)]
    assert not RULES['download']().consume(observations)


def test_native_start_alias_arguments_distinguish_recorded_download_behavior():
    rule = RULES['download']()
    observations = [native(DOWNLOAD + 'start $first', block='first', record=1),
                    native(DOWNLOAD + 'start $second', block='second', record=2)]
    matches = rule.consume(observations)
    assert len(matches) == 2
    assert len({match.group_key for match in matches}) == 2


@pytest.mark.parametrize('start', STARTS)
def test_native_encoded_download_and_start_keep_lead_through_fleet_publication(start):
    encoded = base64.b64encode((DOWNLOAD + start).encode('utf-16le')).decode()
    observations = [sysmon1(image=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
        command='powershell.exe -enc ' + encoded, guid=index + 10) for index in range(4)]
    matches = run(PowerShellEncodedOrCradle(), observations)
    assert matches and all(match.proposed_lane == 'lead' for match in matches)
    assert any(match.group_key for match in matches)
