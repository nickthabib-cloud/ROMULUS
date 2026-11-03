"""Positive-only PowerShell script-content observations with revisable block identities."""
from __future__ import annotations

import hashlib
import json
import re

from romulus.detect.base import PredicateField
from romulus.detect.bounded import KeyedStore
from romulus.detect.powershell_tokens import lex, read_event_script
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
HIGH_TOOLS = frozenset({"invoke-mimikatz", "invoke-kerberoast", "invoke-reflectivepeinjection",
                        "invoke-shellcode", "invoke-dllinjection", "invoke-tokenmanipulation",
                        "get-gpppassword", "get-keystrokes", "invoke-ninjacopy"})
CONTENT_COMMANDS = TOOLS | EXECUTORS | {"get-process", "gps", "ps", "out-minidump", "reg", "reg.exe",
    "add-type", "get-credential", "out-file", "set-content", "add-content", "export-csv",
    "invoke-webrequest", "iwr", "wget", "curl", "invoke-restmethod", "irm", "start-bitstransfer",
    "set-itemproperty", "new-itemproperty", "sp", "get-command", "gcm",
    "start-process", "saps", "invoke-item", "ii"}


def runs_code(parsed):
    return bool(parsed.evaluates_code or parsed.commands & EXECUTORS
                or parsed.members & {'invokescript', 'newscriptblock'}
                or parsed.static_calls & {('scriptblock', 'create'),
                                          ('system.management.automation.scriptblock', 'create')})


def downloads(parsed):
    return bool(parsed.members & {'downloadstring', 'downloaddata', 'downloadfile', 'getresponsestream'}
                or {'send', 'open'} <= parsed.members and parsed.literals & {'msxml2.xmlhttp', 'microsoft.xmlhttp'}
                or parsed.commands & {'invoke-webrequest', 'iwr', 'wget', 'curl', 'invoke-restmethod', 'irm',
                                      'start-bitstransfer'})


def amsi_bypass(parsed):
    reflection = (('system.management.automation.amsiutils' in parsed.literals or parsed.reflection_filter)
                  and bool(parsed.literals & {'amsiinitfailed', 'amsicontext', 'amsisession'})
                  and bool(parsed.members & {'gettype', 'gettypes'}) and {'getfield', 'setvalue'} <= parsed.members)
    patch = ('amsiscanbuffer' in parsed.literals and 'getprocaddress' in parsed.members
             and bool(parsed.members & {'virtualprotect', 'copy', 'writebyte', 'writeint32'}))
    return reflection or patch


def add_type_words(parsed):
    cached = getattr(parsed, '_add_type_words', None)
    if cached is not None:
        return cached
    remaining, seen, words = 2_097_152, set(), set()
    for args in parsed.arguments.get('add-type', []):
        if '-typedefinition' not in args:
            continue
        position = args.index('-typedefinition') + 1
        if position >= len(args) or args[position] in seen:
            continue
        source = args[position]
        seen.add(source)
        if len(source) > remaining:
            parsed.partial = True
            parsed.limits.add('MAX_ADD_TYPE_CHARS=2097152')
            continue
        remaining -= len(source)
        inner_limits = set()
        tokens, _partial = lex(source, csharp=True, limits=inner_limits)
        for limit in inner_limits:
            if limit.startswith(('MAX_TOKENS=', 'MAX_READ_CHARS=')):
                parsed.partial = True
                parsed.limits.add('ADD_TYPE_' + limit)
        words.update(token.value for token in tokens if token.kind == 'word')
    parsed._add_type_words = words
    return words


class ScriptRule(WindowsEventRule):
    version = "4"
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
        self.block_views = KeyedStore(self, "script_blocks", self.HOT)
        self.content_views = KeyedStore(self, "script_content", self.HOT)
        self.unresolved = 0
        self.folded_views = 0

    def _owned_stores(self):
        return [*super()._owned_stores(), self.views, self.block_views, self.content_views]

    def _proof(self, event, parsed):
        if self.id == "win.script_encoded_command":
            return {"host_command": str(event.get("script.host_application") or "").strip()}
        if self.id == "win.script_engine_v2":
            return {"engine": event.get("script.engine_version")}
        cached = getattr(parsed, '_proof', None)
        if cached is not None:
            return cached
        arguments, remaining, retained, total, digest = {}, 32768, 0, 0, hashlib.sha256()
        for name, rows in parsed.arguments.items():
            if name not in CONTENT_COMMANDS:
                continue
            for row in rows:
                kept = []
                digest.update(name.encode())
                for value in row:
                    total += 1
                    digest.update(len(value).to_bytes(8, 'big'))
                    digest.update(value.encode())
                    if retained < 256 and len(value) <= remaining:
                        kept.append(value)
                        remaining -= len(value)
                        retained += 1
                if kept:
                    arguments.setdefault(name, []).append(tuple(kept))
        def bounded(values):
            retained_values, room, checksum = [], 32768, hashlib.sha256()
            for value in sorted(values):
                text = value if isinstance(value, str) else json.dumps(value)
                checksum.update(len(text).to_bytes(8, 'big'))
                checksum.update(text.encode())
                if len(retained_values) < 256 and len(text) <= room:
                    retained_values.append(value)
                    room -= len(text)
            return retained_values, {'total_values': len(values), 'omitted_values': len(values)-len(retained_values),
                                     'digest': checksum.hexdigest()}
        constants, constant_summary = bounded(parsed.literals)
        members, member_summary = bounded(parsed.members)
        member_literals, member_literal_summary = bounded(parsed.member_literals)
        static_calls, static_summary = bounded(parsed.static_calls)
        proof = {"commands": sorted(parsed.commands & CONTENT_COMMANDS),
                "arguments": arguments, 'argument_summary': {'total_values': total,
                    'omitted_values': total-retained, 'digest': digest.hexdigest()},
                "definitions": sorted(parsed.definitions & TOOLS), "members": members,
                "static_calls": static_calls, "constants": constants,
                'member_literals': member_literals, 'member_literal_summary': member_literal_summary,
                'constant_summary': constant_summary, 'member_summary': member_summary, 'static_summary': static_summary,
                "obfuscation": sorted(parsed.obfuscation)}
        parsed._proof = proof
        return proof

    def _lane(self, event, parsed, complete):
        if not complete:
            return "lead"
        if self.id in {"win.script_amsi_bypass", "win.script_etw_bypass", "win.script_lsass_access"}:
            return "high"
        if self.id == "win.script_offensive_function" and parsed.commands & HIGH_TOOLS:
            return "high"
        if self.id == "win.script_sam_access" and any(
            len(args) > 1 and args[0] in {'save', 'export'} and args[1].rstrip("\\") in {"hklm\\sam", "hklm\\security",
                "hkey_local_machine\\sam", "hkey_local_machine\\security"}
            for name in ("reg", "reg.exe") for args in parsed.arguments.get(name, [])):
            return "high"
        return "lead"

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
            parsed = read_event_script(event)
            add_type_words(parsed)
            if not event.get("script.text") and self.id not in {"win.script_encoded_command", "win.script_engine_v2"}:
                self.missing_required += 1
                self.note_limit("script_text", "This record has no script source text; content rules cannot judge it", 1)
                continue
            if event.get("event.code") == 4103:
                self.note_coverage("module_binding", "Module logs expose invocation names; bound parameter values are "
                                   "data, not complete script source")
            complete = (event.get("script.complete") is True and event.get("script.truncated") is not True
                        and not parsed.partial and event.get("script.view") in {"joined", "single"})
            block = str(event.get("script.block_id") or "").strip().casefold()
            block_key = (str(event.host or "").casefold(), block) if block else None
            prior_block = self.block_views.get(block_key) if block_key else None
            if block_key and not complete and prior_block is None:
                self.unresolved += 1
                self.block_views.put(block_key, {"identity": None, "open": True})
            elif block_key and complete and prior_block and prior_block["open"]:
                self.unresolved -= 1
                prior_block["open"] = False
                self.block_views.put(block_key, prior_block)
            if parsed.partial or event.get("script.truncated") is True:
                reasons = sorted(parsed.limits)
                if event.get('script.truncated') is True:
                    reasons.append('script.truncated')
                self.note_limit("script_partial", "Script reading is partial: " + ', '.join(reasons))
                for reason in reasons:
                    self.note_limit('script_partial:' + reason, 'Script reading is partial: ' + reason)
            labels = self.shapes(event, parsed)
            correction = False
            if not labels and complete and prior_block and prior_block["identity"]:
                old = self.views.get(prior_block["identity"])
                if old is not None and not old.get("confirmed"):
                    correction = True
                    labels = [(self.id, ("Complete recorded code places the earlier fragment token in comment, data "
                               "or argument context; the partial observation is retained as a lead for review"),
                               ("script.text",))]
            for shape, description, fields in labels:
                proof = self._proof(event, parsed)
                content = hashlib.sha256(json.dumps(proof, sort_keys=True).encode()).hexdigest()
                content_key = ((event.host or event.id, content, block_key) if not complete and block_key
                               else (event.host or event.id, content))
                identity = self.content_views.get(content_key)
                if correction:
                    identity = prior_block["identity"]
                elif identity is None:
                    identity = (prior_block["identity"] if prior_block and prior_block["identity"] else
                                hashlib.sha256(json.dumps((self.id, block_key or content_key, shape)).encode()).hexdigest()[:32])
                    self.content_views.put(content_key, identity)
                preference = 2 * rank.get(event.get("script.view"), 0) + int(complete)
                if complete and not correction:
                    preference += 10
                previous = self.views.get(identity)
                if block_key:
                    self.block_views.put(block_key, {"identity": identity, "open": not complete})
                if previous is not None and preference <= previous["preference"]:
                    self.folded_views += 1
                    continue
                hit = signal(event, shape, description, self.attack, ("script.block_id", "script.view", *fields),
                             lane=self._lane(event, parsed, complete) if not correction else "lead",
                             content=json.dumps(proof, sort_keys=True))
                hit.severity = "high" if hit.lane == "high" else "medium"
                hit.predicate = [
                    PredicateField(item.field, {"shape": shape, "reading": description,
                                               "content_digest": content,
                                               "calls": sorted(parsed.commands & CONTENT_COMMANDS),
                                               "definitions": sorted(parsed.definitions & TOOLS)},
                                   item.origin + "#parsed:powershell-call-shapes")
                    if item.field == "script.text" else item for item in hit.predicate
                ]
                origin = (event.fields.get("script.text") or event.fields["event.code"]).origin
                hit.predicate.append(PredicateField("script.view_quality", preference, origin + "#parsed:view-quality"))
                if not complete:
                    hit.text += "; partial script view: missing, truncated or lexically unresolved text may change context"
                hit.notes += (("Script content is not proof that the described action ran or succeeded. "
                               "The lexer does not execute dynamic expressions or resolve runtime aliases/variables."),)
                hit.notes += tuple(event.caveats)
                omitted = proof.get('argument_summary', {}).get('omitted_values', 0)
                if omitted:
                    hit.notes += (f'Bounded proof omits {omitted} argument values; full source remains cited.',)
                if parsed.limits:
                    hit.notes += ('Script reading limits: ' + ', '.join(sorted(parsed.limits)),)
                if parsed.fold_evidence_truncated:
                    hit.notes += ('Fold evidence list truncated at 256; this evidence-list cap does not determine script completeness.',)
                    self.note_coverage('script_fold_evidence', 'Fold evidence list truncated at 256')
                match = self.record_match(event, hit)
                match.group_key = identity
                match.raw_copies = self.raw_of(event)
                if previous is not None:
                    match.revision_reason = "A matching joined script view replaces the earlier fragment evidence"
                output.append(match)
                if not self.views.put(identity, {"preference": preference, "confirmed": complete and not correction}):
                    self.note_limit("script_identity", "Disk budget refused script view deduplication; "
                                    "the positive was retained but later duplicate/revision handling is partial")
                self.views.trim()
                self.block_views.trim()
                self.content_views.trim()
        return output

    def finalize(self):
        if self.unresolved:
            self.note_limit("script_partial", f"{self.unresolved} script blocks have unresolved fragment context")
        if self.folded_views:
            self.note_coverage("script_folding", f"{self.folded_views} additional equivalent content views were folded; "
                               "this is not a count of successful executions")
        return []

    def shapes(self, event, parsed):
        if self.test(event, parsed):
            return [(self.id, self.description, ("script.text",))]
        return []


class ScriptDownload(ScriptRule):
    id = "win.script_download"
    title = "PowerShell script contains download and evaluation or start requests"
    attack = ("T1059.001", "T1105")
    description = "Recorded script combines a download with a code-running call; runtime data flow and execution are unverified"
    start_requests = frozenset({'start-process', 'saps', 'invoke-item', 'ii'})

    def test(self, event, p):
        return downloads(p) and (runs_code(p) or bool(p.commands & self.start_requests))

    def shapes(self, event, parsed):
        labels = super().shapes(event, parsed)
        if labels and not runs_code(parsed):
            return [(self.id, ("Recorded script combines a download with a program-start/item-open request; "
                     "data flow and execution are unverified"), ("script.text",))]
        return labels


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
        words = add_type_words(p)
        return bool({'dllimport', 'extern'} <= words and words & native)


class ScriptAmsiBypass(ScriptRule):
    id = "win.script_amsi_bypass"
    title = "PowerShell script contains AMSI bypass code"
    attack = ("T1685", "T1059.001")
    description = "Recorded script contains AMSI reflection or patching call shapes; bypass success is unresolved"

    def test(self, event, p):
        return amsi_bypass(p)


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
        return bool(getattr(p, "obfuscated_execution", False))


class ScriptDecodeEvaluation(ScriptRule):
    id = "win.script_decode_evaluation"
    version = "3"
    title = "PowerShell script contains decoding followed by code evaluation"
    attack = ("T1140", "T1059.001")
    description = "Recorded code combines Base64/decompression reading and a code-evaluation call; runtime data flow is unverified"

    def test(self, event, p):
        decompress = (bool(p.static_calls & {(name, "new") for name in
                      ("io.compression.gzipstream", "system.io.compression.gzipstream",
                       "io.compression.deflatestream", "system.io.compression.deflatestream")})
                      or any(any(value in {"system.io.compression.gzipstream", "io.compression.gzipstream",
                                            "system.io.compression.deflatestream", "io.compression.deflatestream"}
                                 for value in args) for args in p.arguments.get("new-object", [])))
        return ("frombase64string" in p.members or decompress) and runs_code(p)


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
    description = "Recorded script combines an LSASS process selection with dump API and invocation syntax; execution and data flow are unverified"

    def test(self, event, p):
        selects = any(set(args) & {"lsass", "lsass.exe"}
                      for name in ("get-process", "gps", "ps") for args in p.arguments.get(name, []))
        reflection = ('invoke' in p.members and bool(p.member_literals & {('getmethod', 'minidumpwritedump'),
                                                                         ('getprocaddress', 'minidumpwritedump')}))
        return selects and bool(p.commands & {"out-minidump", "get-processdump", "invoke-procdump"}
                                or "minidumpwritedump" in p.members or reflection)


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
    description = "Recorded script combines a credential prompt with plaintext credential access; use and output are unresolved"

    def test(self, event, p):
        return bool(('get-credential' in p.commands or 'promptforcredential' in p.members)
                    and 'getnetworkcredential' in p.members)


def disables(p, suffix, name):
    for command in ("reg", "reg.exe"):
        for args in p.arguments.get(command, []):
            if len(args) < 2 or args[0] != "add":
                continue
            path = args[1].replace("/", "\\").rstrip("\\")
            if path not in {"hklm\\" + suffix, "hkcu\\" + suffix,
                            "hkey_local_machine\\" + suffix, "hkey_current_user\\" + suffix}:
                continue
            try:
                if (args[args.index("/v") + 1] == name and args[args.index("/t") + 1] == "reg_dword"
                        and args[args.index("/d") + 1] in {"0", "0x0"}):
                    return True
            except (ValueError, IndexError):
                continue
    for command in ("set-itemproperty", "new-itemproperty", "sp"):
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
    ScriptDecodeEvaluation,
)
