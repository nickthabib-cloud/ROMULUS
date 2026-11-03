"""Native synthetic regressions for recorded PowerShell start requests."""
import pytest

from romulus.detect.powershell_tokens import read_event_script
from romulus.detect.windows_scripts import runs_code
from tests.test_windows_script_round3 import native
from tests.test_windows_script_rules import RULES

DOWNLOAD = 'Invoke-WebRequest $url -OutFile $f; '
STARTS = [
    r"& ($env:TEMP + '\setup.exe') /quiet",
    r'& "$env:TEMP\setup.exe"', '& $f', '. $f',
    r". ($PSScriptRoot + '\Common.ps1')",
    r"& ($PSCommandPath + '\setup.exe')",
    r"& ($env:TEMP + '\tools' + '\setup.exe')",
    r"& (($env:TEMP) + ('\tools' + '\setup.exe'))",
    r"& ($env:TEMP + '\tools' + $env:ARCH + '\setup.exe')",
    r"& 'C:\Temp\setup.exe'", r'. "C:\Temp\setup.ps1"',
    r"& 'setup.exe'", r'& "setup.exe"',
    '[Diagnostics.Process]::Start($f)', '[System.Diagnostics.Process]::Start($f)',
    '(New-Object -ComObject WScript.Shell).Run($f)',
    "(New-Object -ComObject 'WScript.Shell').ShellExecute($f)",
]


@pytest.mark.parametrize('start', STARTS)
def test_native_download_and_ordinary_start_request_is_a_lead(start):
    observation = native(DOWNLOAD + start)
    [match] = RULES['download']().consume([observation])
    assert match.proposed_lane == 'lead'
    assert 'program-start/item-open request' in match.claim
    assert 'data flow and execution are unverified' in match.claim
    assert not RULES['obfuscated_execution']().consume([observation])
    assert not runs_code(read_event_script(observation))


@pytest.mark.parametrize('start', STARTS)
def test_native_start_alone_and_decode_plus_start_do_not_imply_download_or_evaluation(start):
    observation = native(start)
    assert not RULES['download']().consume([observation])
    assert not RULES['obfuscated_execution']().consume([observation])
    assert not RULES['decode_evaluation']().consume([native('[Convert]::FromBase64String($data); ' + start)])


@pytest.mark.parametrize('target', [
    "& ($env:A + 'b')", "& ('b' + $env:A)", "& ($env:A + $env:B)",
    "& ($PSScriptRoot + 'b')", "& ($PSCommandPath + 'b')", "& ($x + 'b')",
    r"& ($env:A + '\tools' + 'b')", r"& ('\tools' + $env:A)",
])
def test_native_nonpath_construction_keeps_obfuscation_and_download_leads(target):
    observation = native(DOWNLOAD + target)
    [match] = RULES['obfuscated_execution']().consume([observation])
    assert match.proposed_lane == 'lead'
    [download] = RULES['download']().consume([observation])
    assert download.proposed_lane == 'lead'
    assert 'program-start/item-open request' not in download.claim
    assert runs_code(read_event_script(observation))
    [decoded] = RULES['decode_evaluation']().consume([native('[Convert]::FromBase64String($data); ' + target)])
    assert decoded.proposed_lane == 'lead'


@pytest.mark.parametrize('mention', [
    "'[Diagnostics.Process]::Start($f)'",
    '# [Diagnostics.Process]::Start($f)', '[Diagnostics.Process]::Start',
    "Write-Output '(New-Object -ComObject WScript.Shell).Run($f)'",
    '(New-Object -ComObject WScript.Shell).Run',
    '(New-Object -ComObject WScript.Shell).ShellExecute',
    '(New-Object -ComObject Other.Shell).Run($f)',
    "Write-Output 'WScript.Shell'; $unrelated.Run($f)",
    'Write-Output WScript.Shell; $unrelated.ShellExecute($f)',
    '[Unrelated.Process]::Start($f)',
    "& 'Get-Date'", '& Get-Date',
    "& 'Start-ProcessNot'", 'Write-Output $f',
])
def test_native_download_with_inert_or_unrelated_start_name_stays_negative(mention):
    assert not RULES['download']().consume([native(DOWNLOAD + mention)])


def test_native_download_without_a_start_request_stays_negative():
    assert not RULES['download']().consume([native(DOWNLOAD)])


@pytest.mark.parametrize('source', [
    r"& ($env:SystemRoot + '\System32\cscript.exe') //nologo x.vbs",
    r". ($PSScriptRoot + '\Common.ps1')", ". (Join-Path $PSScriptRoot 'Common.ps1')",
    "& $tools['git'] status", '& $steps[0] -Verbose', '& $MyInvocation.MyCommand.Path',
    'foreach ($s in $scripts) { & $s.FullName }',
    r"Import-Module ($Env:SMS_ADMIN_UI_PATH.Substring(0,$Env:SMS_ADMIN_UI_PATH.Length-5) + '\ConfigurationManager.psd1')",
    ("Configuration Web { Node localhost { WindowsFeature IIS { Ensure='Present'; Name='Web-Server' } } }\n"
     r"Web -OutputPath ($PSScriptRoot + '\mof')"),
    r'& "$PSScriptRoot\x.ps1" @PSBoundParameters', '& (Get-Command *Update-Help*)',
    '& ([scriptblock]::Create($code))',
    r'Get-ChildItem "$PSScriptRoot\*.ps1" | ForEach-Object { . $_.FullName }',
])
def test_native_administrative_controls_remain_free_of_obfuscation(source):
    assert not RULES['obfuscated_execution']().consume([native(source)])
