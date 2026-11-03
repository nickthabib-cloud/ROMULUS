"""Nonexecuting constant interpretation is bounded and tied to actual invocation sites."""
import time

import pytest

from romulus.detect.powershell_tokens import read_event_script, read_script
from tests.windows_event_support import event


@pytest.mark.parametrize('source,command', [
    ('. ‘Invoke-Mimikatz’', 'invoke-mimikatz'),
    ('i\'e\'x $payload', 'iex'),
    ('& ("{1}{0}" -f "katz","Invoke-Mimi")', 'invoke-mimikatz'),
    ('.( "{1}{0}" –f "x","ie") $payload', 'iex'),
    ('& ([char]73+[char]69+[char]88) $payload', 'iex'),
    ('& (-join [char[]](73,69,88)) $payload', 'iex'),
    ('& ([char[]](73,69,88) –join "") $payload', 'iex'),
    ('& ([string]::Join("", @("i","e","x"))) $payload', 'iex'),
    ('$x="i"+"ex"; & $x $payload', 'iex'),
    ('$x="{1}{0}" -f "x","ie"; & ${x} $payload', 'iex'),
    ('& (gcm iex) $payload', 'iex'),
    ('& (Get-Command Invoke-Expression) $payload', 'invoke-expression'),
    ('function global:Invoke-Mimikatz {}', None),
    ('.\\Invoke-Mimikatz.ps1', 'invoke-mimikatz'),
])
def test_provable_constant_call_targets(source, command):
    parsed = read_script(source)
    if command:
        assert command in parsed.commands
    else:
        assert 'invoke-mimikatz' in parsed.definitions


@pytest.mark.parametrize('source', [
    "'a' + 'b'; & $p", "'a' + 'b'; Write-Output value", "Write-Output 'a'+'b'; & $p",
    'Write-Output hi 2>&1', "Write-Output '-f {0}'; & $p", '$x="i"+"ex"; $x=Get-Input; & $x',
    '$x="i"+"ex"; if ($condition) {$x="Get-Date"}; & $x',
])
def test_unrelated_expression_or_redirection_is_not_obfuscated_execution(source):
    assert not read_script(source).obfuscated_execution


@pytest.mark.parametrize('source', [
    '& ("i"+"ex") $payload', 'iex ("a"+"b")', 'Invoke-Expression ("{1}{0}" -f "b","a")',
    '$x="i"+"ex"; & $x $payload', 'i\'e\'x $payload',
    '$ExecutionContext.InvokeCommand.InvokeScript(("a"+"b"))',
])
def test_obfuscation_is_on_invoked_target_or_evaluated_argument(source):
    parsed = read_script(source)
    assert parsed.obfuscated_execution and parsed.obfuscation


@pytest.mark.parametrize('source,member', [
    ('$x.DownloadString.Invoke("https://example.test/x")', 'downloadstring'),
    ('$x.DownloadData.Invoke($uri)', 'downloaddata'),
    ('$ExecutionContext.InvokeCommand.InvokeScript($payload)', 'invokescript'),
    ('$response.GetResponseStream()', 'getresponsestream'),
])
def test_member_invoke_preserves_actual_named_member(source, member):
    assert member in read_script(source).members


@pytest.mark.parametrize('source', [
    '$ExecutionContext.InvokeCommand.InvokeScript($payload)', 'iex $payload',
    'Invoke-Expression $payload', '& (gcm iex) $payload',
])
def test_recorded_evaluators_expose_evaluates_code(source):
    assert read_script(source).evaluates_code


def test_constant_variable_and_format_strings_supply_whole_literals():
    parsed = read_script('$x="System.Management.Automation.{1}{0}" -f "Utils","Amsi"; '
                         '$w="am"+"siInitFailed"; [Ref].Assembly.GetType($x).GetField(${w}).SetValue($null,$true)')
    assert {'system.management.automation.amsiutils', 'amsiinitfailed'} <= parsed.literals
    assert {'gettype', 'getfield', 'setvalue'} <= parsed.members
    assert parsed.constant_folds


def test_reflection_wildcard_evidence_requires_code_not_quoted_mention():
    source = '[Ref].Assembly.GetTypes() | Where-Object {$_.Name -like "*iUtils"}; $t.GetField("amsiInitFailed").SetValue($null,$true)'
    assert read_script(source).reflection_filter
    assert not read_script('Write-Output \'Name -like "*iUtils" GetTypes GetField SetValue\'').reflection_filter


@pytest.mark.parametrize('source', ['Write-Output "("', "Write-Output ']'", "Write-Output '{'"])
def test_literal_brackets_do_not_mark_complete_source_partial(source):
    assert not read_script(source).partial


def test_nested_parentheses_preserve_outer_command_arguments():
    parsed = read_script('Set-ItemProperty -Path "HKLM:\\Software\\Policies\\X" -Name Enable -Value (0)')
    assert 'set-itemproperty' in parsed.arguments
    assert any('0' in arguments and '-value' in arguments for arguments in parsed.arguments['set-itemproperty'])
    assert '0' not in parsed.commands


def test_parameter_binding_values_stay_data_and_command_names_are_observed():
    payload = ('CommandInvocation(Write-Output): "Write-Output"\n'
               'ParameterBinding(Write-Output): name="InputObject"; value="Invoke-Mimikatz; iex $payload"\n'
               'CommandInvocation(Get-Date): "Get-Date"')
    observation = event('script_block', 4103, **{'script.text': payload})
    parsed = read_event_script(observation)
    assert parsed.commands == {'write-output'}
    assert not parsed.members and not parsed.evaluates_code
    assert parsed.partial and parsed.module_binding_data and parsed.module_bindings
    assert not parsed.arguments
    assert read_event_script(observation) is parsed


def test_module_payload_without_invocation_is_uncertain_not_executable():
    observation = event('script_block', 4103, **{'script.text': 'ParameterBinding(Write-Output): name="Object"; value="Invoke-Mimikatz"'})
    parsed = read_event_script(observation)
    assert not parsed.commands and parsed.partial


def test_module_binding_newlines_cannot_forge_command_invocations():
    text = ('CommandInvocation(Write-Output): "Write-Output"\n'
            'ParameterBinding(Write-Output): name="Object"; value="text\n'
            'CommandInvocation(Invoke-Mimikatz): "Invoke-Mimikatz"\n'
            'iex $payload\n"')
    parsed = read_event_script(event('script_block', 4103, **{'script.text': text}))
    assert parsed.commands == {'write-output'}
    assert parsed.partial and not parsed.evaluates_code


def test_module_bindings_cannot_invent_executable_command_arguments():
    text = ('CommandInvocation(Write-Output): "Write-Output"\n'
            'ParameterBinding(Set-ItemProperty): name="Path"; value="HKLM:\\Software\\Policies\\X"\n'
            'ParameterBinding(Set-ItemProperty): name="Name"; value="Enabled"\n'
            'ParameterBinding(Set-ItemProperty): name="Value"; value="0"')
    parsed = read_event_script(event('script_block', 4103, **{'script.text': text}))
    assert parsed.commands == {'write-output'} and not parsed.arguments


@pytest.mark.parametrize('intervening', ['Set-Variable x Get-Date', '& $unknown', '$x+=Get-Input', '$x++'])
def test_constant_variables_do_not_survive_possible_mutation(intervening):
    parsed = read_script('$x="i"+"ex"; ' + intervening + '; & $x $payload')
    assert 'iex' not in parsed.commands and not parsed.obfuscated_execution


def test_format_precedes_addition_in_constant_expressions():
    parsed = read_script('$x="x{0}" -f 1 + 2')
    assert 'x12' in parsed.literals and 'x3' not in parsed.literals


def test_unknown_format_or_call_lookup_is_never_guessed():
    assert 'iex' not in read_script('& (gcm i*x) $payload').commands
    assert 'iex' not in read_script('& ("{name}" -f "iex") $payload').commands


def test_constant_growth_and_large_malformed_inputs_are_bounded():
    source = '$x="a";' + '$x=$x+$x;' * 40
    started = time.perf_counter()
    assert not read_script(source).partial
    assert time.perf_counter() - started < 2
    started = time.perf_counter()
    assert read_script("']'::b()," * (1_048_576 // 9)).partial
    assert time.perf_counter() - started < 8


@pytest.mark.parametrize('source', [
    "$x=[char[]]'get-gpppassword'; $x[0]=[char]88; & (-join $x)",
    "$x=[char[]]'get-gpppassword'; $y=$x; $y[0]=[char]88; & (-join $x)",
    "$x=[char[]]'get-gpppassword'; $y=$x; $x[0]=[char]88; & (-join $y)",
    "${x}=[char[]]'get-gpppassword'; ${x}[0]=[char]88; & (-join ${x})",
    "$x=[char[]]'get-gpppassword'; $x.Item=88; & (-join $x)",
    "$x=[char[]]'get-gpppassword'; $x[0]+=1; & (-join $x)",
    "$x=[char[]]'get-gpppassword'; $x[0]++; & (-join $x)",
    "$x=[char[]]'get-gpppassword'; $x[0]--; & (-join $x)",
    "$x='get-gpppassword'; $x,$y='Get-Date','safe'; & $x",
    "$x='get-gpppassword'; $x,$y='Get-Date'; & $x",
    "$x=[char[]]'get-gpppassword'; $x.SetValue([char]88,0); & (-join $x)",
    "$x=[char[]]'get-gpppassword'; [Array]::Clear($x,0,1); & (-join $x)",
    "$x=[char[]]'get-gpppassword'; Unknown-Mutator ([ref]$x); & (-join $x)",
    "$x='get-gpppassword'; . $unknown; & $x",
    "$x='get-gpppassword'; . .\\Unknown-Mutator.ps1; & $x",
])
def test_unsupported_writes_and_unknown_mutators_invalidate_all_constant_aliases(source):
    parsed = read_script(source)
    assert 'get-gpppassword' not in parsed.commands


@pytest.mark.parametrize('source', [
    "$x='get-gpppassword'; & $x[0]", "$x='get-gpppassword'; & ${x}[0]",
    "& 'get-gpppassword'[0]", "$x='get-gpppassword'; & $x.Substring(1)",
])
def test_unresolved_index_or_member_target_never_invokes_the_constant_prefix(source):
    assert 'get-gpppassword' not in read_script(source).commands


@pytest.mark.parametrize('source', [
    "switch ($x) { Get-GppPassword { Write-Output 'matched' } }",
    "switch -Wildcard ($x) { Get-GppPassword { Write-Output 'matched' } default {} }",
    "switch ($x) { 'Get-GppPassword' {} }", "Mock Get-GppPassword {}",
    "Get-Help Get-GppPassword -Examples", "Get-Command Get-GppPassword",
])
def test_pattern_mock_and_help_arguments_are_mentions_not_tool_invocations(source):
    assert 'get-gpppassword' not in read_script(source).commands


def test_a_real_call_in_a_switch_action_is_still_an_invocation():
    assert 'get-gpppassword' in read_script("switch ($x) { safe { Get-GppPassword } }").commands


def test_mutated_array_join_target_retains_generic_obfuscation_without_tool_identity():
    parsed = read_script("$x=[char[]]'get-gpppassword'; $x[0]=[char]88; & (-join $x)")
    assert 'get-gpppassword' not in parsed.commands
    assert parsed.obfuscated_execution


def test_deep_balanced_groups_do_not_make_switch_role_cleanup_quadratic():
    source = '(' * 20_000 + ')' * 20_000 + '; Get-Date'
    started = time.perf_counter()
    parsed = read_script(source)
    assert 'get-date' in parsed.commands and parsed.partial
    assert time.perf_counter() - started < 1.2
