"""Native telemetry regressions for bounded static PowerShell start requests."""
import base64
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from romulus.detect.powershell_tokens import read_event_script
from romulus.detect.windows_proxy import PowerShellEncodedOrCradle
from romulus.detect.windows_scripts import runs_code
from tests.test_windows_script_round3 import native
from tests.test_windows_script_round5 import DOWNLOAD
from tests.test_windows_script_rules import RULES
from tests.windows_process_support import run, sysmon1

STARTS = [
    f'{name}{suffix} {args}'
    for name, args in [
        ('cmd', '/c $f'), ('cmd', '/k $f'), ('cmd', '/c start $f'),
        ('msiexec', '/i $f'), ('msiexec', '/package $f'),
        ('rundll32', '$f,Start'), ('regsvr32', '/s $f'),
        ('powershell', '-File $f'), ('powershell', '-Command $f'),
        ('pwsh', '-File $f'), ('pwsh', '-Command $f'),
        ('wscript', '$f'), ('cscript', '//nologo $f'), ('mshta', '$f'),
    ] for suffix in ('', '.exe')
] + [
    '& ($f)', '& (Get-Item $f)', '& (gi $f)', '& (Get-Item $f).FullName',
    '& (Convert-Path $f)', '& ($env:ComSpec) /c $f',
    'Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=$f}',
    'Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $f',
    "([wmiclass]'win32_process').Create($f)", 'Start-Job -FilePath $f',
    '(New-Object -C WScript.Shell).Run($f)', '(New-Object -Co WScript.Shell).Exec($f)',
    '(New-Object -ComObject:WScript.Shell).Run($f)',
    '(New-Object -Strict -ComObject WScript.Shell.1).Run($f)',
    "([Activator]::CreateInstance([type]::GetTypeFromProgID('WScript.Shell'))).Run($f)",
    'Set-Variable sh (New-Object -ComObject WScript.Shell); $sh.Run($f)',
    '$global:sh=New-Object -ComObject WScript.Shell; $global:sh.Run($f)',
    '$script:sh=New-Object -ComObject WScript.Shell; $script:sh.Run($f)',
    '[object]$sh=New-Object -ComObject WScript.Shell; $sh.Run($f)',
    '($sh=New-Object -ComObject WScript.Shell); $sh.Run($f)',
    r"& '.\Install-Update'", r". '.\Install-Update'", r"& '..\Install-Update'",
    r"& 'tools\Install-Update'", r"& 'dir\Install-Update'",
]


@pytest.mark.parametrize('source', STARTS)
def test_native_extended_start_is_download_only_lead(source):
    event = native(DOWNLOAD + source)
    rule = RULES['download']()
    [match] = rule.consume([event])
    assert match.proposed_lane == 'lead'
    assert 'program-start/item-open request' in match.claim
    assert not runs_code(read_event_script(event))
    assert not RULES['download']().consume([native(source)])
    assert not RULES['decode_evaluation']().consume([native('[Convert]::FromBase64String($data); ' + source)])


@pytest.mark.parametrize('middle', [
    'Start-Sleep 1;', '$other=3;', '$sh;', 'Write-Output $sh;',
    'if ($f) {', 'try {', '& {', 'Get-Item $f | ForEach-Object {',
])
def test_native_receiver_survives_commands_reads_and_nested_blocks(middle):
    for prefix in (DOWNLOAD, '', '[Convert]::FromBase64String($data); '):
        source = '$sh=New-Object -ComObject WScript.Shell; ' + prefix + middle + '$sh.Run($f)'
        source += ' }' if middle.endswith('{') else ''
        event = native(source)
        matches = RULES['download']().consume([event])
        if prefix == DOWNLOAD:
            [match] = matches
            assert match.proposed_lane == 'lead'
        else:
            assert not matches
        assert not RULES['decode_evaluation']().consume([event])


@pytest.mark.parametrize('write', [
    '$sh=$other', '[object]$sh=$other', '($sh=$other)', '$sh+=$other', '$sh-=$other',
    '$sh*=$other', '$sh/=$other', '$sh%=$other', '$sh++', '$sh--', '++$sh', '--$sh',
    'Set-Variable sh $other', 'Clear-Variable -Name sh', 'Remove-Variable sh',
    "& 'Set-Variable' sh $other", '$global:sh=$other', '$script:sh=$other',
    'Set-Variable -Name sh -Value $other -Scope global',
    'Set-Variable -Scope Global -Name sh -Value $other',
    'Remove-Variable -Scope Script -Name sh', 'Clear-Variable global:sh',
    'Set-Variable -Value $other -Name sh', 'Clear-Variable -Name:sh',
    'Set-Variable -Value ($other) -Name sh',
    'Remove-Variable other,sh', '$sh,$other=$null',
])
def test_native_exact_receiver_write_invalidates(write):
    source = DOWNLOAD + '$sh=New-Object -ComObject WScript.Shell; ' + write + '; $sh.Run($f)'
    assert not RULES['download']().consume([native(source)])


@pytest.mark.parametrize('source', [
    'cmd /?', 'msiexec /?', 'msiexec /x $f', 'rundll32', 'regsvr32 /s',
    "& 'cmd.exe'", '& powershell.exe -File',
    'powershell -Version 7', 'pwsh -Version 7', 'wscript //nologo', 'cscript //nologo', 'mshta',
    'Start-Job -ScriptBlock { Get-Date }',
    'Invoke-CimMethod -ClassName Win32_Service -MethodName Create',
    'Invoke-WmiMethod -Class Win32_Process -Name GetOwner',
    "([wmiclass]'win32_service').Create($f)",
    '$sh=New-Object -ComObject WScript.Shell | Out-Null; $sh.Run($f)',
    '(New-Object -ComputerName WScript.Shell).Run($f)',
    '(New-Object -ComObject WScript.Shell).ShellExecute($f)',
    '(New-Object -ComObject Shell.Application).Run($f)',
])
def test_native_invalid_start_grammar_stays_quiet(source):
    assert not RULES['download']().consume([native(DOWNLOAD + source)])


def test_native_join_path_module_call_is_constructed_evaluation():
    event = native(DOWNLOAD + "& (Join-Path 'Module' 'Verb-Noun')")
    [match] = RULES['download']().consume([event])
    assert 'program-start/item-open request' not in match.claim
    assert runs_code(read_event_script(event))
    assert RULES['obfuscated_execution']().consume([event])


@pytest.mark.parametrize('directory', ['Module', 'module', 'MODULE', 'tools', 'Tools', 'TOOLS', 'dir', 'DIR'])
def test_native_ambiguous_relative_directory_case_does_not_change_start(directory):
    source = "& '" + directory + "\\Install-Update'"
    [match] = RULES['download']().consume([native(DOWNLOAD + source)])
    assert 'program-start/item-open request' in match.claim
    assert not RULES['download']().consume([native(source)])
    assert not RULES['decode_evaluation']().consume([native('[Convert]::FromBase64String($data); ' + source)])


@pytest.mark.parametrize('module', ['Microsoft.PowerShell.Utility', 'microsoft.powershell.utility',
                                   'MICROSOFT.POWERSHELL.UTILITY'])
def test_native_namespaced_module_case_remains_command(module):
    assert not RULES['download']().consume([native(DOWNLOAD + "& '" + module + "\\Write-Output' $f")])


@pytest.mark.parametrize('source', STARTS)
def test_native_encoded_extended_start_finalizes_as_lead(source):
    encoded = base64.b64encode((DOWNLOAD + source).encode('utf-16le')).decode()
    observations = [sysmon1(image=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                           command='powershell.exe -enc ' + encoded, guid=i+500) for i in range(4)]
    matches = run(PowerShellEncodedOrCradle(), observations)
    assert matches and all(m.proposed_lane == 'lead' for m in matches)


@pytest.mark.parametrize('source', [
    '$sh=New-Object -ComObject WScript.Shell; $shell=$other; $sh.Run($f)',
    '$sh=New-Object -ComObject WScript.Shell; Clear-Variable shell; $sh.Run($f)',
    '$sh=New-Object -ComObject WScript.Shell; $sh + $other; $sh.Run($f)',
    '$sh=New-Object -ComObject WScript.Shell; $sh=$other; $sh=New-Object -C WScript.Shell; $sh.Run($f)',
    'Set-Variable -Value (New-Object -C WScript.Shell) -Name sh; $sh.Run($f)',
])
def test_native_receiver_rebinding_and_other_name_writes_keep_exact_facts(source):
    [match] = RULES['download']().consume([native(DOWNLOAD + source)])
    assert match.proposed_lane == 'lead'
    assert not RULES['download']().consume([native(source)])
    assert not RULES['decode_evaluation']().consume([native('[Convert]::FromBase64String($data); ' + source)])


def test_native_nested_wmi_create_reading_has_linear_cost():
    # the child runs this file as a script, so it needs the repository root to import the `tests` package
    root = str(Path(__file__).resolve().parents[1])
    env = {**os.environ, 'PYTHONPATH': os.pathsep.join(p for p in (root, os.environ.get('PYTHONPATH')) if p)}
    child = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--wmi-cost-probe'],
                           capture_output=True, text=True, timeout=20, check=False, env=env)
    assert child.returncode == 0, child.stdout + child.stderr
    timings = json.loads(child.stdout)
    assert timings[-1]['seconds'] < 2
    assert timings[-1]['seconds'] <= 8 * max(timings[0]['seconds'], .03)


if __name__ == '__main__' and '--wmi-cost-probe' in sys.argv:
    timings = []
    for count in (2000, 8000):
        source = DOWNLOAD + '(' * count + "[wmiclass]'win32_process'" + ').Create($f)' * count
        event = native(source)
        started = time.perf_counter()
        [match] = RULES['download']().consume([event])
        assert match.proposed_lane == 'lead'
        timings.append({'count': count, 'seconds': time.perf_counter() - started})
    print(json.dumps(timings))
