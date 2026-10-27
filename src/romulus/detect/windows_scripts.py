"""Positive-only PowerShell script-content observations with revisable block identities."""
from __future__ import annotations

import hashlib
import json
import re

from romulus.detect.base import PredicateField
from romulus.detect.bounded import KeyedStore
from romulus.detect.powershell_tokens import lex, read_script
from romulus.detect.windows_cmdline import parse_powershell, split_argv
from romulus.detect.windows_events import WindowsEventRule, basename, signal
from romulus.evidence.windows_catalog import (
    LEGACY_POWERSHELL_CHANNEL,
    LEGACY_POWERSHELL_PROVIDER,
    POWERSHELL_CHANNEL,
    POWERSHELL_PROVIDER,
)

RESEARCH = (
    "https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_parsing",
    "https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging",
    "https://github.com/PowerShellMafia/PowerSploit",
    "https://github.com/PowerShell/PowerShell/tree/master/src/System.Management.Automation",
    "https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/defense_evasion_amsienable_key_mod",
)
SCRIPT_CLASSES = tuple((POWERSHELL_CHANNEL, POWERSHELL_PROVIDER, code) for code in (4103, 4104)) + tuple(
    (LEGACY_POWERSHELL_CHANNEL, LEGACY_POWERSHELL_PROVIDER, code) for code in (400, 403, 800))
EXECUTORS = {"iex", "invoke-expression"}
TOOLS = frozenset({
    "invoke-mimikatz", "invoke-kerberoast", "invoke-reflectivepeinjection", "invoke-shellcode",
    "invoke-dllinjection", "invoke-tokenmanipulation", "get-gpppassword", "get-keystrokes",
    "invoke-ninjacopy", "invoke-allchecks", "invoke-bloodhound", "invoke-amsibypass",
    "get-domainuser", "get-domaincomputer", "get-domaintrust", "get-domainpolicy",
    "get-netdomain", "get-netuser", "get-netcomputer", "invoke-userhunter", "find-localadminaccess",
    "get-netlocalgroupmember", "get-domainspnticket", "get-domainobjectacl", "add-domainobjectacl",
})


class ScriptRule(WindowsEventRule):
    families = ("script_block",)
    windows_event_classes = SCRIPT_CLASSES
    claim_type = "script_content"
    positive_only_reason = ("Script content describes recorded code, not successful execution; comments, dynamic "
                            "code, incomplete blocks and uncollected logging prevent any negative assurance.")
    research = RESEARCH
    benign = ("authorized administration, security testing, application deployment or recovery can use this code",)
    next_checks = ("inspect the complete raw block and parent process", "corroborate the requested action in host telemetry")
    required_fields = ("event.code",)
    evidence_view_field = "script.view"

    def __init__(self):
        super().__init__()
        self.views = KeyedStore(self, "script_views", self.HOT)

    def _owned_stores(self):
        return [*super()._owned_stores(), self.views]

    def consume(self, events):
        output = []
        # Prefer joined evidence in a batch; an earlier batch's fragment is revised in place.
        rank = {"joined": 2, "single": 1, "fragment": 0}
        for event in sorted(events, key=lambda e: (-rank.get(e.get("script.view"), 0), e.ts, e.id)):
            if event.family != "script_block" or not self.event_in_os_scope(event):
                continue
            if event.get("event.code") not in {4104, 4103, 400, 403, 800}:
                continue
            if not self._events_pre_scoped:
                self.os_applicable += 1
            self.evaluated += 1
            text = str(event.get("script.text") or "")
            parsed = read_script(text)
            if parsed.partial or event.get("script.complete") is False or event.get("script.truncated") is True:
                self.note_limit("script_partial", "Script text is partial or has unresolved lexical structure; "
                                "unevaluated portions and dynamic code remain unresolved")
            labels = self.shapes(event, parsed)
            for shape, description, fields in labels:
                block = str(event.get("script.block_id") or "").strip().casefold()
                key = (str(event.host).casefold(), block) if event.host and block else ("record", event.id)
                identity = hashlib.sha256(json.dumps((self.id, key, shape)).encode()).hexdigest()[:32]
                preference = rank.get(event.get("script.view"), 0)
                previous = self.views.get(identity)
                if previous is not None and preference <= previous:
                    continue
                hit = signal(event, shape, description, self.attack, ("script.block_id", "script.view", *fields))
                hit.predicate = [
                    PredicateField(item.field, {"shape": shape, "reading": description},
                                   item.origin + "#parsed:powershell-call-shapes")
                    if item.field == "script.text" else item for item in hit.predicate
                ]
                partial = (event.get("script.complete") is False or event.get("script.truncated") is True
                           or parsed.partial or event.get("script.view") == "fragment")
                if partial:
                    hit.text += "; partial script view: missing, truncated or lexically unresolved text may change context"
                hit.notes += (("Script content is not proof that the described action ran or succeeded. "
                               "The lexer does not execute dynamic expressions or resolve runtime aliases/variables."),)
                hit.notes += tuple(event.caveats)
                match = self.record_match(event, hit)
                match.group_key = identity
                match.raw_copies = self.raw_of(event)
                if previous is not None:
                    match.revision_reason = "A matching joined script view replaces the earlier fragment evidence"
                output.append(match)
                if not self.views.put(identity, preference):
                    self.note_limit("script_identity", "Disk budget refused script view deduplication; "
                                    "the positive was retained but later duplicate/revision handling is partial")
                self.views.trim()
        return output

    def finalize(self):
        return []

    def shapes(self, event, parsed):
        if self.test(event, parsed):
            return [(self.id, self.description, ("script.text",))]
        return []


class ScriptDownload(ScriptRule):
    id = "win.script_download"
    title = "PowerShell script contains a download cradle"
    attack = ("T1059.001", "T1105")
    description = "Recorded script contains a tokenized download and code-evaluation cradle"

    def test(self, event, p):
        downloads = bool(p.members & {"downloadstring", "downloaddata", "downloadfile"}
                         or p.commands & {"invoke-webrequest", "iwr", "wget", "curl", "invoke-restmethod", "irm",
                                          "start-bitstransfer"})
        return downloads and bool(p.commands & EXECUTORS or ("scriptblock", "create") in p.static_calls
                                  or ("system.management.automation.scriptblock", "create") in p.static_calls)


class ScriptReflectiveLoad(ScriptRule):
    id = "win.script_reflective_load"
    title = "PowerShell script contains a reflective assembly load"
    attack = ("T1620", "T1059.001")
    description = "Recorded script contains a Reflection.Assembly load call; in-memory loading is indicated by code only"

    def test(self, event, p):
        return bool(p.static_calls & {(name, method) for name in ("reflection.assembly", "system.reflection.assembly")
                                     for method in ("load", "loadfrom", "loadfile", "loadwithpartialname")})


class ScriptPInvoke(ScriptRule):
    id = "win.script_pinvoke"
    title = "PowerShell script contains native memory or delegate calls"
    attack = ("T1055", "T1059.001")
    description = "Recorded script contains native allocation, memory-write, delegate call or P/Invoke declaration shapes"

    def test(self, event, p):
        native = {"virtualalloc", "virtualallocex", "writeprocessmemory", "createremotethread",
                  "getdelegateforfunctionpointer"}
        if p.members & native:
            return True
        for args in p.arguments.get("add-type", []):
            if "-typedefinition" not in args:
                continue
            index = args.index("-typedefinition") + 1
            if index >= len(args):
                continue
            tokens, _partial = lex(args[index], csharp=True)
            words = {token.value for token in tokens if token.kind == "word"}
            if {"dllimport", "extern"} <= words and words & native:
                return True
        return False


class ScriptAmsiBypass(ScriptRule):
    id = "win.script_amsi_bypass"
    title = "PowerShell script contains AMSI bypass code"
    attack = ("T1685", "T1059.001")
    description = "Recorded script contains AMSI reflection or patching call shapes; bypass success is unresolved"

    def test(self, event, p):
        reflection = ("system.management.automation.amsiutils" in p.literals
                      and bool(p.literals & {"amsiinitfailed", "amsicontext", "amsisession"})
                      and {"gettype", "getfield", "setvalue"} <= p.members)
        patch = ("amsiscanbuffer" in p.literals and "getprocaddress" in p.members
                 and bool(p.members & {"virtualprotect", "copy", "writebyte", "writeint32"}))
        return reflection or patch


class ScriptEtwBypass(ScriptRule):
    id = "win.script_etw_bypass"
    title = "PowerShell script contains ETW bypass code"
    attack = ("T1685.001", "T1059.001")
    description = "Recorded script contains ETW provider modification or patching code; logging impact is unresolved"

    def test(self, event, p):
        reflection = ("system.management.automation.tracing.psetwlogprovider" in p.literals
                      and bool(p.literals & {"etwprovider", "m_enabled"})
                      and {"getfield", "setvalue"} <= p.members)
        patch = (bool(p.literals & {"etweventwrite", "nttraceevent"}) and "getprocaddress" in p.members
                 and bool(p.members & {"virtualprotect", "copy", "writebyte", "writeint32"}))
        return reflection or patch


class ScriptObfuscatedExecution(ScriptRule):
    id = "win.script_obfuscated_execution"
    title = "PowerShell script contains obfuscated evaluation"
    attack = ("T1027.010", "T1059.001")
    description = "Recorded script combines character, format, backtick or concatenation obfuscation with call/evaluation syntax"

    def test(self, event, p):
        return bool(p.obfuscation and (p.commands & EXECUTORS or p.commands & TOOLS
                                      or "create" in p.members or p.dynamic_invocation))


class ScriptOffensiveFunction(ScriptRule):
    id = "win.script_offensive_function"
    title = "PowerShell script contains an offensive or dual-use function"
    attack = ("T1059.001",)
    description = "Recorded script invokes or defines an exact offensive/dual-use function token; identity and use require review"

    def test(self, event, p):
        return bool((p.commands | p.definitions) & TOOLS)


class ScriptLsassAccess(ScriptRule):
    id = "win.script_lsass_access"
    title = "PowerShell script contains LSASS dump code"
    attack = ("T1003.001", "T1059.001")
    description = "Recorded script combines an LSASS process selection with a dump call; no credential read is established"

    def test(self, event, p):
        selects = any(set(args) & {"lsass", "lsass.exe"} for args in p.arguments.get("get-process", []))
        return selects and bool(p.commands & {"out-minidump", "get-processdump", "invoke-procdump"}
                                or "minidumpwritedump" in p.members)


class ScriptSamAccess(ScriptRule):
    id = "win.script_sam_access"
    title = "PowerShell script contains credential hive export code"
    attack = ("T1003.002", "T1003.004", "T1059.001")
    description = "Recorded script requests export of a SAM, SECURITY or SYSTEM registry hive; export success is unresolved"

    def test(self, event, p):
        for command in ("reg", "reg.exe"):
            for args in p.arguments.get(command, []):
                if len(args) >= 2 and args[0] in {"save", "export"} and args[1].rstrip("\\") in {
                    "hklm\\sam", "hklm\\security", "hklm\\system",
                    "hkey_local_machine\\sam", "hkey_local_machine\\security", "hkey_local_machine\\system",
                }:
                    return True
        return False


class ScriptDpapiAccess(ScriptRule):
    id = "win.script_dpapi_access"
    title = "PowerShell script contains DPAPI decryption code"
    attack = ("T1555", "T1059.001")
    description = "Recorded script calls DPAPI Unprotect; the protected data and credential content remain unverified"

    def test(self, event, p):
        return bool(p.static_calls & {("system.security.cryptography.protecteddata", "unprotect"),
                                     ("security.cryptography.protecteddata", "unprotect")} or
                    "cryptunprotectdata" in p.members)


class ScriptCredentialHarvest(ScriptRule):
    id = "win.script_credential_harvest"
    title = "PowerShell script contains credential prompt extraction code"
    attack = ("T1056.003", "T1059.001")
    description = "Recorded script combines Get-Credential, plaintext credential access and an output/transfer call"

    def test(self, event, p):
        return ("get-credential" in p.commands and "getnetworkcredential" in p.members
                and bool(p.commands & {"out-file", "set-content", "add-content", "invoke-webrequest",
                                       "invoke-restmethod", "export-csv"}))


def disables(p, suffix, name):
    for command in ("set-itemproperty", "new-itemproperty", "sp", "set"):
        for args in p.arguments.get(command, []):
            def argument(parameter, args=args):
                try:
                    return args[args.index(parameter) + 1]
                except (ValueError, IndexError):
                    return ""
            path = argument("-path") or argument("-literalpath")
            path = path.replace("/", "\\").rstrip("\\")
            if (re.fullmatch(r"(?:hklm:|hkcu:|registry::hkey_local_machine|registry::hkey_current_user)\\" +
                             re.escape(suffix), path)
                    and argument("-name") == name and argument("-value") in {"0", "0x0", "$false"}):
                return True
    return False


class ScriptLoggingDisable(ScriptRule):
    id = "win.script_logging_disable"
    title = "PowerShell script contains logging-disable code"
    attack = ("T1685.001", "T1059.001")
    description = "Recorded script writes a PowerShell logging policy to disabled; effective policy is unverified"

    def test(self, event, p):
        root = "software\\policies\\microsoft\\windows\\powershell\\"
        return any(disables(p, root + key, name) for key, name in (
            ("scriptblocklogging", "enablescriptblocklogging"), ("modulelogging", "enablemodulelogging"),
            ("transcription", "enabletranscripting")))


class ScriptAmsiDisable(ScriptRule):
    id = "win.script_amsi_disable"
    title = "PowerShell script contains Windows Script AMSI-disable code"
    attack = ("T1685", "T1059.001")
    description = "Recorded script writes Windows Script AmsiEnable policy to zero; this does not establish PowerShell AMSI state"

    def test(self, event, p):
        return disables(p, "software\\microsoft\\windows script\\settings", "amsienable")


class ScriptEncodedCommand(ScriptRule):
    id = "win.script_encoded_command"
    title = "PowerShell script record has a decoded encoded-command host launch"
    attack = ("T1027.010", "T1059.001")

    def shapes(self, event, parsed):
        line = str(event.get("script.host_application") or "")
        args = split_argv(line)
        if not args or basename(args[0]) not in {"powershell.exe", "powershell", "pwsh.exe", "pwsh"}:
            return []
        call = parse_powershell(args[1:])
        if call.source != "encodedcommand" or call.script is None or call.decode_error:
            return []
        text = "Recorded HostApplication contains a decoded UTF-16LE encoded-command script; execution outcome is unverified"
        if call.truncated:
            text += "; partial decode: encoded command exceeds the parser's retained prefix"
            self.note_limit("encoded_partial", "Encoded host command decode retained a prefix; remainder unresolved")
        return [(self.id, text, ("script.host_application",))]


class ScriptEngineV2(ScriptRule):
    id = "win.script_engine_v2"
    title = "PowerShell engine-start record reports version 2.0"
    attack = ("T1059.001", "T1685.001")

    def shapes(self, event, parsed):
        if event.get("event.code") == 400 and re.fullmatch(r"2\.0(?:\.\d+){0,2}", str(event.get("script.engine_version") or "")):
            return [(self.id, "Recorded engine-start version is PowerShell 2.0; downgrade intent and effective protections are unverified",
                     ("script.engine_version",))]
        return []


WINDOWS_SCRIPT_PLAYBOOKS = (
    ScriptDownload, ScriptReflectiveLoad, ScriptPInvoke, ScriptAmsiBypass, ScriptEtwBypass,
    ScriptObfuscatedExecution, ScriptOffensiveFunction, ScriptLsassAccess, ScriptSamAccess, ScriptDpapiAccess,
    ScriptCredentialHarvest, ScriptLoggingDisable, ScriptAmsiDisable, ScriptEncodedCommand, ScriptEngineV2,
)
