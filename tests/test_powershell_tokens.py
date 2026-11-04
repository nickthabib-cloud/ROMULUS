"""Lexical boundaries prevent data and comments from becoming executable tokens."""
import pytest

from romulus.detect.powershell_tokens import read_script


@pytest.mark.parametrize("text", [
    "# Invoke-Mimikatz\nGet-Date", "Write-Output 'Invoke-Mimikatz'", "$x = 'Invoke-Mimikatz'",
    "@{ FunctionsToExport = @('Invoke-Mimikatz'); Description = 'Assembly.Load' }",
    "<# Invoke-Mimikatz #> Get-Date", '@"\nInvoke-Mimikatz\n"@',
])
def test_data_and_comments_do_not_become_calls(text):
    assert "invoke-mimikatz" not in read_script(text).commands


@pytest.mark.parametrize("text", ["Invoke-Mimikatz", "& 'Invoke-Mimikatz'", "Inv`oke-Mimikatz"])
def test_exact_command_tokens_and_literal_call_operator(text):
    assert "invoke-mimikatz" in read_script(text).commands
    assert "invoke-mimikatz-extra" not in read_script(text).commands


def test_members_and_constant_obfuscation_are_read_without_execution():
    parsed = read_script("& ('Inv'+'oke-Mimikatz'); [Reflection.Assembly]::Load($bytes)")
    assert "invoke-mimikatz" in parsed.commands
    assert ("reflection.assembly", "load") in parsed.static_calls
    assert "concatenation" in parsed.obfuscation
    assert "load" not in read_script("Write-Output '[Reflection.Assembly]::Load($bytes)'").members


def test_unclosed_comment_string_and_nested_shapes_are_partial():
    assert read_script("<# missing").partial
    assert read_script("'missing").partial
    assert read_script("(" * 200 + "Get-Date").partial


def test_backtick_newline_is_continuation_not_command_boundary():
    parsed = read_script("Write-Output `\n Invoke-Mimikatz")
    assert "invoke-mimikatz" not in parsed.commands


@pytest.mark.parametrize("text", [
    'Write-Output "$(Invoke-Mimikatz)"',
    'Write-Output "$(Write-Output \'$(not-executable)\'; Invoke-Mimikatz)"',
    'Write-Output "$(Write-Output \'a)b\'; Invoke-Mimikatz)"',
    '@"\n$(Invoke-Mimikatz)\n"@',
])
def test_expandable_string_subexpression_calls_are_code(text):
    assert "invoke-mimikatz" in read_script(text).commands


@pytest.mark.parametrize("text", [
    '& ("{1}{0}" -f "katz","Invoke-Mimi")', '& (-join [char[]](73,69,88))',
])
def test_dynamic_invocation_is_recognized_without_running_it(text):
    parsed = read_script(text)
    assert parsed.dynamic_invocation and parsed.obfuscation
