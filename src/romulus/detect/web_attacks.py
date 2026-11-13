"""Bounded HTTP attack grammars and disk-backed, positive-only observations.

The patterns are a small, independently implemented adaptation of OWASP CRS
grammars, not a WAF or a complete CRS implementation. Tool markers adapt
Sigma's suspicious user-agent rule and the tools' own documented identifiers;
source, author and licence details are in content/network/web_attacks_sources.json
and accompany affected findings.
"""
from __future__ import annotations

import hashlib
import html
import json
import re
from datetime import UTC
from ipaddress import ip_address
from typing import ClassVar
from urllib.parse import unquote_to_bytes, urlsplit

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.bounded import StateExhausted, register_store
from romulus.detect.netdef import DIRECTION_ASSUMED_REASON, current
from romulus.detect.network_producers import HTTP_OBSERVATIONS, ZEEK_AND_SURICATA, rule_reads
from romulus.detect.site_roles import address_member
from romulus.detect.zeek_rate_state import ZeekWindowRule
from romulus.evidence.typed import fv
from romulus.evidence.zeek_credentials import strip_uri_userinfo
from romulus.hunt.citations import COMPACT_CITATION_NOTE, compact_event, expand_event

MAX_URI = 16_384            # characters of one request target that are inspected
MAX_UA = 2_048              # characters of one user-agent value that are inspected
MAX_RECORD_TEXT = 65_536    # characters (and, at one each, repeated values) inspected per record
MAX_CITATION = 24_576
CITED_VALUES = 8            # values of a longer typed list kept in a cited example: the ones that matched
CITED_CHARS = 2_048         # characters of one value kept in a cited example
FLUSH_ROWS = 256            # folded observations written to disk in one statement
# Leads kept for single (source, destination, class) pairs: the first five sources seen at one destination, and the
# first five destinations seen from one source, each get their own lead. A handful can be read one by one; past it
# the same class against the same endpoint is one event (a scan, or a crowd of scanners) and is reported as one
# roll-up whose member list holds every address.
PAIR_LEADS = 5
MEMBERS_NAMED = 10          # members named in a roll-up's claim and entities; the member list holds every one
REFUSED_GROUPS = 4_096      # pairs given a live lead of their own while detection state cannot grow
URI_FIELDS = ("url.original", "url.path", "url.query")
_FIELDS = ("source.ip", "destination.ip", "observer.name", "observer.product", *URI_FIELDS,
           "http.request.method", "http.response.status_code", "user_agent.original", "user.name")
_CRS = "https://github.com/coreruleset/coreruleset"
_SIGMA = "https://github.com/SigmaHQ/sigma/blob/master/rules/web/webserver_generic/web_susp_useragents.yml"
_SIGMA_HACKTOOL = "https://github.com/SigmaHQ/sigma/blob/master/rules/web/proxy_generic/proxy_ua_hacktool.yml"
_ATTRIBUTION = ("User-agent markers adapted from Sigma 'Suspicious User-Agents Related To Recon Tools', "
                "by Nasreddine Bencherchali (Nextron Systems) and Tim Shelton, DRL-1.1: " + _SIGMA
                + "; and from Sigma 'Hack Tool User Agent', by Florian Roth (Nextron Systems), DRL-1.1: "
                + _SIGMA_HACKTOOL + "; further markers are the tools' own published identifiers.")
_UNCERTAIN = ("Network metadata shows request shapes only; exploitation, application execution and "
              "authentication success are not established, including for 2xx or redirect responses.")
_MASKING = ("Request bodies are not inspected. In retained examples a query or path parameter loses its value when "
            "its name has a credential word as one of its parts (password, secret, token, key, signature, session, "
            "auth, credential, one-time code, pin, code and their usual spellings); the whole query is omitted "
            "instead when encoded delimiters or HTML entities make the end of such a value ambiguous; and URI "
            "userinfo is removed. A secret under another name, or written into the path itself, is not recognised "
            "and is retained.")
_CLASSES = {
    "sql_injection": "SQL injection grammar",
    "cross_site_scripting": "cross-site scripting grammar",
    "path_traversal_lfi": "path traversal, local-file inclusion or sensitive-file request grammar",
    "remote_file_inclusion": "remote-file inclusion grammar",
    "command_injection": "OS command injection grammar",
    "template_injection": "server-side template or expression injection grammar",
    "exploit_tool": "known exploit, scanning or brute-force tool user-agent marker",
}

# ---- decoding ------------------------------------------------------------------------------------------------------

_PERCENT_U = re.compile(r"%[uU]([0-9a-fA-F]{4})")
# UTF-8 forms longer than the shortest one for their code point. A decoder that accepts them reads a character its
# filters did not see, which is their only use in a request.
_OVERLONG = re.compile(rb"[\xc0\xc1][\x80-\xbf]|\xe0[\x80-\x9f][\x80-\xbf]|\xf0[\x80-\x8f][\x80-\xbf]{2}")
_OVERLONG_PATH = frozenset("/.\\")


def _decode(value, bound, *, fold=True):
    """The text the grammars read, the named reasons its inspection is partial, and whether a path separator or dot
    arrived overlong-encoded.

    Plus signs become spaces, then at most two percent-decoding passes, then HTML entities, then case folding. A
    `%` that does not start an escape is a literal. `%uXXXX` is the code point. Overlong UTF-8 is read as the
    character it encodes. Bytes that are not UTF-8 are replaced (reason `utf8`) and a value longer than `bound` is
    read up to it (reason `length`); both are inspected, never refused.
    """
    if not isinstance(value, str):
        return None, {"shape"}, False
    issues, evasive = set(), False
    if len(value) > bound:
        value = value[:bound]
        issues.add("length")
    text = value.replace("+", " ")
    for _pass in range(2):
        if "%" not in text:
            break
        text = _PERCENT_U.sub(lambda found: chr(int(found.group(1), 16)), text)
        try:
            data = text.encode("utf-8")
        except UnicodeEncodeError:
            data = text.encode("utf-8", "replace")
            issues.add("utf8")
        data = unquote_to_bytes(data)
        data, plain = _shortest_forms(data)
        evasive = evasive or not _OVERLONG_PATH.isdisjoint(plain)
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("utf-8", "replace")
            issues.add("utf8")
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        text = text.encode("utf-8", "replace").decode("utf-8")
        issues.add("utf8")
    text = html.unescape(text)
    return (text.casefold() if fold else text), issues, evasive


def _shortest_forms(data):
    """Bytes with every overlong form replaced by the character it encodes, and those characters."""
    seen = []

    def shortest(found):
        raw = found.group()
        if len(raw) == 2:
            point = (raw[0] & 0x1F) << 6 | raw[1] & 0x3F
        elif len(raw) == 3:
            point = (raw[1] & 0x3F) << 6 | raw[2] & 0x3F
        else:
            point = (raw[1] & 0x3F) << 12 | (raw[2] & 0x3F) << 6 | raw[3] & 0x3F
        seen.append(chr(point))
        return seen[-1].encode("utf-8", "replace")

    return _OVERLONG.sub(shortest, data), seen


# ---- grammars ------------------------------------------------------------------------------------------------------
# Every unbounded-looking gap carries an explicit bound, so no expression backtracks over a request-sized span.

_COMMENT = re.compile(r"/\*[^*]{0,128}(?:\*(?!/)[^*]{0,128}){0,4}\*/")
# MySQL runs the body of /*!50000 ... */, so the body is kept and only the comment markers go.
_VERSIONED = re.compile(r"/\*!(?:[0-9]{5})?([^*]{0,128})\*/")
# What follows SELECT in a statement rather than in prose: `*`, `(`, a variable, NULL, a quoted literal, a number
# that ends the list item, or a column or function name followed by `,`, `(` or FROM.
_OPERAND = (r"(?:[*(@'\"]|null\b|[0-9]{1,12}(?:\s{0,8}(?:[,;)#&]|--|/\*|$)|\s{1,8}from\b)"
            r"|[a-z_][a-z_0-9.$]{0,63}(?:\s{0,8}[,(]|\s{1,8}from\b))")
_SQL = re.compile("|".join((
    r"\bunion\s{1,32}(?:(?:all|distinct)\s{1,32})?select\s{1,32}(?:(?:all|distinct)\s{1,32})?" + _OPERAND,
    # A statement after a closing quote or a statement separator. Each verb needs the words that make it a
    # statement (INSERT INTO, UPDATE x SET, DELETE FROM, DROP TABLE x), so a quoted phrase that only starts with
    # the verb ("select committee", 'insert coin', "Update profile") is not one.
    r"['\";]\s{0,16}(?:select\s{1,32}" + _OPERAND
    + r"|insert\s{1,16}into\s{1,16}[a-z_`\[\"]"
    r"|update\s{1,16}[a-z_][a-z_0-9.$]{0,63}\s{1,16}set\s{1,16}[a-z_`\[]"
    r"|delete\s{1,16}from\s{1,16}[a-z_`\[\"]"
    r"|drop\s{1,16}(?:table|database|schema|view|index|user|procedure|function)\s{1,16}[a-z_`\[\"]"
    r"|having\s{1,16}[^\s=<>'\"]{1,32}\s{0,8}[=<>]"
    r"|(?:exec|execute)\s{1,16}(?:master\.|xp_|sp_)"
    r"|declare\s{1,16}@)",
    # A boolean clause after a closing quote: ' or 1=1, ' or 'a'='a, ') or ('1'='1, 'or'1'='1
    (r"['\"]\s{0,8}\){0,4}\s{0,16}(?:or|and)(?:\s{1,16}|(?=['\"(]))\({0,4}\s{0,8}"
    r"(?:[0-9]{1,12}|['\"][^'\"]{0,64}['\"])\s{0,8}(?:[=<>]|like\b|in\b|between\b)"),
    # ... and one that compares a column: ' or name like '%admin%'
    (r"['\"]\s{0,8}\){0,4}\s{0,16}(?:or|and)\s{1,16}[a-z_][a-z_0-9.]{0,63}\s{0,8}"
    r"(?:=|<>|!=|\s(?:like|in)\b)\s{0,8}['\"(0-9]"),
    # A tautology needs no quote: 1 or 1=1, 1 AND 4321=4321, 1) and (8=8. The two numbers must be equal.
    r"(?:^|[\s)'\"=])(?:or|and)\s{1,16}\({0,4}\s{0,8}(?P<same>[0-9]{1,12})\s{0,8}=\s{0,8}(?P=same)(?![0-9])",
    # A quote that closes the application's string, then a comment that discards the rest: admin'--, admin'#
    r"[a-z0-9_)]'\s{0,8}(?:--|#)(?=[\s&]|$)",
    # Column counting: ' order by 5--, 1 order by 10#
    r"(?:['\")]\s{0,16}|[0-9]\s{1,16})order\s{1,16}by\s{1,16}[0-9]{1,4}\s{0,8}(?:--|[#,)&]|/\*|$)",
    r"\bwaitfor\s{1,16}delay\s{1,16}['\"0-9]",
    (r"\binformation_schema\s{0,4}\.\s{0,4}(?:tables|columns|schemata|routines|views|triggers|processlist|statistics"
    r"|key_column_usage|table_constraints|user_privileges|schema_privileges|character_sets|collations|plugins"
    r"|engines|partitions|files)\b"),
    r"\b(?:extractvalue|updatexml)\s{0,8}\(\s{0,8}[0-9a-z'\"(@]",
    r"\bxp_cmdshell\b",
    # Timing functions as calls in a statement: sleep(5) closed and followed by SQL, not "sleep(8) hours".
    r"\bsleep\s{0,8}\(\s{0,8}[0-9]{1,6}(?:\.[0-9]{1,3})?\s{0,8}\)\s{0,8}(?:--|[#),;&|]|/\*|$|(?:and|or)\b)",
    r"\bbenchmark\s{0,8}\(\s{0,8}[0-9]{3,12}\s{0,8},",
    r"\bpg_sleep\s{0,8}\(\s{0,8}[0-9]",
)))
# An HTML event-handler attribute is separated from what precedes it (whitespace, `/` or a closing quote), so a
# URL parameter such as ?online=1 inside an attribute value is not one.
_XSS = re.compile(
    r"<\s{0,8}script(?:[\s/>]|$)"
    r"|<[a-z][a-z0-9]{0,15}(?=[\s/])[^>]{0,256}[\s/\"']on[a-z]{3,32}\s{0,8}=\s{0,8}[^=\s>]"
    # An attribute value closed early, then a handler holding script: " onmouseover="alert(1)
    r"|['\"][\s/]{1,8}on[a-z]{3,32}\s{0,8}=\s{0,8}['\"]?\s{0,8}"
    r"(?:alert|confirm|prompt|eval|fetch|import|javascript:|document\.|window\.|location\b)"
    r"|\bjavascript\s{0,8}:\s{0,8}(?:alert|eval|confirm|prompt)\s{0,8}\(")
# Operating-system and credential files that a web application has no reason to be asked for by path.
_LFI = re.compile(
    r"(?:^|[=/\\:])(?:etc/(?:passwd|shadow|hosts|group|issue|fstab|crontab|sudoers|resolv\.conf)"
    r"|proc/(?:self|[0-9]{1,7})/(?:environ|cmdline|maps|status)|proc/version"
    r"|(?:windows|winnt)[/\\](?:win\.ini|system\.ini"
    r"|system32[/\\](?:config[/\\]sam|drivers[/\\]etc[/\\]hosts|cmd\.exe))"
    r"|boot\.ini)(?=[\s&#?\x00]|$)"
    # Files a web root holds by accident: environment files, repository metadata, key and password files.
    r"|(?:^|[=/\\])(?:\.env(?:\.[a-z0-9_-]{1,16})?|\.git/(?:config|head|index)|\.aws/credentials|\.htpasswd"
    r"|\.ssh/(?:id_[a-z0-9]{2,8}|authorized_keys)|\.svn/entries)(?=[\s&#?\x00]|$)"
    # Stream wrappers given as a parameter value: they read or run something other than the named page.
    r"|=(?:php://(?:filter|input)|expect://|phar://|zip://|data://text/plain|file://)"
    # Traversal spellings no client produces: path-parameter traversal (/..;/) and doubled dots that survive one
    # removal of "../" (....//).
    r"|(?:^|[=/\\])\.\.;/|\.{4}[/\\]{2}")
_LFI_TARGET = re.compile(
    r"(?:^|[/\\])(?:[a-z0-9_.-]{0,48}config[a-z0-9_.-]{0,16}\.(?:php|inc|ini|xml|ya?ml|json|js)|web\.config"
    r"|\.[a-z][a-z0-9_.-]{0,31}|[a-z0-9_.-]{1,48}\.(?:log|bak|old|sql|key|pem|ini|conf|cnf))$")
# A parameter whose value is a remote URL. Whether it is an inclusion is decided in `_remote_inclusion`.
_RFI_PARAM = re.compile(
    r"(?:^|[?&])(?P<key>include|require|inc|mosconfig_absolute_path|page|file|path|template|doc|document|root)"
    r"(?:\[[^\]=&]{0,16}\])?=(?P<url>(?:https?|ftps?)://[^\s&#\x00]{1,16384}+)(?P<nul>\x00)?(?=[\s&#]|$)")
_RFI_CALL = re.compile(r"\b(?:include|require)(?:_once)?\s{0,8}\(\s{0,8}['\"]?(?:https?|ftps?)://")
# Parameters named after the include statement itself: any remote URL in them is reported.
_RFI_DIRECTIVES = frozenset({"include", "require", "inc", "mosconfig_absolute_path"})
# For the other file-like parameters a remote URL is ordinary (a proxy, a viewer, a redirect), so one more sign is
# needed. An include payload has to reach the victim as source text, so it is served under an extension the
# attacker's own server does not execute: these, not .php, .jsp or .aspx.
_RFI_TEXT_EXTENSIONS = re.compile(r"\.(?:txt|inc|dat|tmp)$")
_INTEGER_HOST = re.compile(r"(?:0x[0-9a-f]{8}|[0-9]{8,10})$")

# Commands seen in injection payloads. A name alone is not a command: see `_COMMAND`.
_COMMANDS = (
    "cat", "tac", "head", "tail", "more", "less", "nl", "id", "whoami", "uname", "hostname", "pwd", "ls", "dir",
    "type", "echo", "printf", "sleep", "timeout", "ping", "nslookup", "dig", "curl", "wget", "tftp", "ftp", "nc",
    "ncat", "netcat", "telnet", "bash", "sh", "zsh", "ksh", "dash", "ash", "busybox", "cmd", "cmd.exe",
    "powershell", "powershell.exe", "pwsh", "python", "python2", "python3", "perl", "php", "ruby", "node", "lua",
    "certutil", "bitsadmin", "mshta", "rundll32", "regsvr32", "wmic", "net", "systeminfo", "tasklist", "ipconfig",
    "ifconfig", "netstat", "ps", "env", "printenv", "set", "chmod", "rm", "touch", "mkdir", "mkfifo", "cp", "mv",
    "kill", "base64", "xxd", "tar", "find", "grep", "awk", "sed", "sudo", "crontab", "nohup",
)
# Names that are not also ordinary field names, list items or language codes, so they count without an operand.
_BARE_COMMANDS = ("whoami", "uname", "ifconfig", "ipconfig", "systeminfo", "printenv", "tasklist", "netstat")
# Commands that do something with no operand (and echo, whose operand is any word): the ones a probe appends to a
# complete value. The rest of the list needs an operand to be read as a command.
_VALUE_COMMANDS = ("id", "ls", "dir", "pwd", "ps", "env", "hostname", "echo", "printf", *_BARE_COMMANDS)


def _names(words):
    return "(?:" + "|".join(re.escape(word) for word in sorted(words, key=len, reverse=True)) + ")"


_BIN = r"(?:/(?:usr/)?(?:local/)?s?bin/)?"
_END = r"(?=$|[\s;&|`)<>])"
_SEPARATOR = r"(?:[;|\n]|&&)"
# An operand: a flag, a path, a number, a quoted or expanded word, a redirect, or a URL.
_ARGUMENT = r"\s{1,8}(?:-{1,2}[a-z0-9]|[/~.$'\"<>\\0-9*]|[a-z]:[/\\]|(?:https?|ftp|tftp)://)"
_ARGUMENT_STRICT = r"\s{1,8}(?:-{1,2}[a-z]|/[a-z]|[~$'\"<>]|(?:https?|ftp|tftp)://)"
_SUBSTITUTION = (
    r"\$\(\s{0,16}" + _BIN + _names(_COMMANDS) + r"(?=[\s)])"                       # $(command ...)
    + r"|(?<=\S)`\s{0,8}" + _BIN + _names(_COMMANDS) + r"(?=[\s`])[^`]{0,128}`"     # value`command`
    + r"|\(\)\s{0,8}\{[^}]{0,32}\}\s{0,8};")                                        # () { :; }; (Shellshock)
# A delimiter followed by a name is a list (fields=name;id, titles=Dog|Cat). It is a command when the name has an
# operand, when the name is unambiguous, or when the delimiter follows a complete value (a digit, `=`, a closing
# quote or bracket: 127.0.0.1;id) rather than a word and the command needs no operand.
_COMMAND = re.compile(
    _SEPARATOR + r"\s{0,16}" + _BIN + _names(_COMMANDS) + _ARGUMENT
    + "|" + _SEPARATOR + r"\s{0,16}" + _BIN + _names(_BARE_COMMANDS) + _END
    + "|" + r"(?<=[0-9=)\]'\"])" + _SEPARATOR + r"\s{0,16}" + _BIN + _names(_VALUE_COMMANDS) + _END
    # A decoded `&` that starts a command with an operand and no `=`: 127.0.0.1&ping -c 5 10.0.0.1
    + "|" + r"&\s{0,8}" + _BIN + _names(_COMMANDS) + _ARGUMENT_STRICT + r"[^=&]{0,128}(?=&|$)"
    + "|" + _SUBSTITUTION)
# A user agent is punctuated with `;` and version numbers, so only an explicit operand or substitution counts.
_COMMAND_UA = re.compile(
    _SEPARATOR + r"\s{0,16}" + _BIN + _names(_COMMANDS) + _ARGUMENT_STRICT + "|" + _SUBSTITUTION)
# Arithmetic probes multiply or add (7*7, 7+7, 7*'7'); `-` and `/` between numbers are dates and ranges.
_TEMPLATE = re.compile(
    r"(?:\{\{|[$#]\{|<%)[^{}<>]{0,128}(?:[0-9]\s{0,8}[*+]\s{0,8}['\"]?[0-9]|__[a-z][a-z0-9_]{0,30}__"
    r"|\b(?:config|request|self|cycler|joiner|namespace|lipsum)\s{0,8}[.(\[])[^{}<>]{0,128}(?:\}\}|\}|%>)"
    r"|\{\{\s{0,8}config\s{0,8}\}\}"
    r"|\$\{\s{0,4}(?:jndi\s{0,4}:|\$\{)"                          # a JNDI lookup, or a lookup nested to hide one
    r"|\bjava\.lang\.(?:runtime|processbuilder)\b|\bgetruntime\s{0,4}\(\s{0,4}\)\s{0,4}\.\s{0,4}exec\b"
    r"|#_memberaccess\b")

# (name, marker after a token boundary, ATT&CK technique). The order is the bit order of the stored marker set.
_VULNERABILITY_SCAN, _WORDLIST_SCAN, _BLOCK_SCAN, _BRUTE_FORCE = "T1595.002", "T1595.003", "T1595.001", "T1110"
_TOKEN_END = r"(?=$|[/\s;)])"
_TOOLS = (
    ("sqlmap", "sqlmap" + _TOKEN_END, _VULNERABILITY_SCAN),
    ("Nikto", "nikto" + _TOKEN_END, _VULNERABILITY_SCAN),
    ("commix", "commix" + _TOKEN_END, _VULNERABILITY_SCAN),
    ("Nuclei", "nuclei" + _TOKEN_END, _VULNERABILITY_SCAN),
    ("Hydra", "hydra" + _TOKEN_END, _BRUTE_FORCE),
    ("Medusa", r"(?:medusa" + _TOKEN_END + r"|teh forest lobster|i'm not mozilla, i'm ming mong"
               r"|mozilla/1\.22 \(compatible; msie 10\.0; windows 3\.1\))", _BRUTE_FORCE),
    ("Nmap Scripting Engine", "nmap scripting engine", _VULNERABILITY_SCAN),
    ("gobuster", "gobuster" + _TOKEN_END, _WORDLIST_SCAN),
    ("DirBuster", r"dirbuster(?=$|[-/\s;)])", _WORDLIST_SCAN),
    ("dirb", "dirb" + _TOKEN_END, _WORDLIST_SCAN),
    ("Wfuzz", "wfuzz" + _TOKEN_END, _WORDLIST_SCAN),
    ("ffuf", r"(?:fuzz faster u fool|ffuf" + _TOKEN_END + ")", _WORDLIST_SCAN),
    ("feroxbuster", "feroxbuster" + _TOKEN_END, _WORDLIST_SCAN),
    ("WPScan", "wpscan" + _TOKEN_END, _VULNERABILITY_SCAN),
    ("WhatWeb", "whatweb" + _TOKEN_END, _VULNERABILITY_SCAN),
    ("Recon-ng", "recon-ng" + _TOKEN_END, _VULNERABILITY_SCAN),
    ("masscan", "(?:ivre-)?masscan" + _TOKEN_END, _BLOCK_SCAN),
    ("zgrab", "zgrab" + _TOKEN_END, _BLOCK_SCAN),
    ("Nessus", "nessus" + _TOKEN_END, _VULNERABILITY_SCAN),
    ("OpenVAS", r"openvas(?=$|[-/\s;)])", _VULNERABILITY_SCAN),
    ("Acunetix", r"acunetix(?=$|[-/\s;)])", _VULNERABILITY_SCAN),
    ("w3af", r"w3af(?=$|[./\s;)])", _VULNERABILITY_SCAN),
    ("Arachni", "arachni" + _TOKEN_END, _VULNERABILITY_SCAN),
    ("ZAP", r"(?:zap/|owasp[ _-]zap\b)", _VULNERABILITY_SCAN),
    ("Havij", "havij" + _TOKEN_END, _VULNERABILITY_SCAN),
    ("sqlninja", "sqlninja" + _TOKEN_END, _VULNERABILITY_SCAN),
    ("DotDotPwn", "dotdotpwn" + _TOKEN_END, _VULNERABILITY_SCAN),
    ("ZmEu", "zmeu" + _TOKEN_END, _VULNERABILITY_SCAN),
    ("Morfeus", "morfeus fucking scanner", _VULNERABILITY_SCAN),
    ("Webshag", "webshag" + _TOKEN_END, _VULNERABILITY_SCAN),
    ("Grendel-Scan", "grendel-scan" + _TOKEN_END, _VULNERABILITY_SCAN),
    ("Vega", "vega/", _VULNERABILITY_SCAN),
)
_TOOL = re.compile(r"(?:^|[\s(/;,\[])(?:" + "|".join(f"(?P<t{index}>{marker})"
                                                      for index, (_name, marker, _id) in enumerate(_TOOLS)) + ")")

# ---- authentication paths and credential names ---------------------------------------------------------------------

# A path segment that names a sign-in endpoint, ending at `/`, an extension, a path parameter (`;`) or the end.
_AUTH = re.compile(
    r"(?:^|/)(?:login|logon|signin|sign-in|sign_in|signon|sign-on|sso|authenticate|auth|token|logincheck"
    r"|wp-login\.php|xmlrpc\.php|auth\.owa|j_security_check|session|sessions|administrator|phpmyadmin)"
    r"(?:/|\.[a-z]{1,5}|;|$)")
_ACCOUNT_KEYS = frozenset({"user", "username", "user_name", "login", "email", "account", "log", "j_username",
                           "uname", "userid"})
# The password half of a login query pair. Tokens and keys accompany every request of a signed-in client, so
# on a path that is not a sign-in endpoint only a password field marks a request as an attempt.
_PASSWORD_KEYS = frozenset({"password", "passwd", "pwd", "pass", "pw", "j_password"})

# Parameter names are split into parts at every character that is not a letter or digit, at lower-to-upper case
# changes, and between letters and digits (txtPassword, user[password], X-Amz-Signature, password1). A name is a
# credential name when one whole part is a credential word, starts with a credential stem followed by a listed
# ending, or ends with one of the compound words written without a separator. A credential word inside an unrelated
# word (monkey, author, passenger) is not a match.
_KEY_PARTS = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")
_CREDENTIAL_PART = re.compile(
    r"(?:pass(?:word|wd|wort|phrase|code|key)?s?|pwd?|pswd?|secrets?|tokens?|keys?|sig|sign|signed|signature"
    r"|sess|session(?:s|id|key)?|sessid|sid|auth|authn|authz|authori[sz]ation|authentication|authenticity"
    r"|creds?|credentials?|otp|totp|hotp|mfa|pin|pincode|code|jwt|bearer|hmac|nonce"
    r"|[a-z]{1,24}(?:password|passwd|secret|token|sessid|sessionid|signature|credentials?)"
    r"|(?:api|private|access|license|master|encryption|app|client|user|auth|session|signing)key)$")


def _credential_name(name):
    return any(_CREDENTIAL_PART.match(part.casefold()) for part in _KEY_PARTS.findall(name))


def _peers(event):
    try:
        return tuple(str(ip_address(event.get(name))) for name in ("source.ip", "destination.ip"))
    except (ValueError, TypeError):
        return None


def _form_value(value):
    """An account label uses ordinary form decoding, not attack normalization."""
    try:
        if len(value) > MAX_URI:
            return None
        return unquote_to_bytes(value.replace("+", " ")).decode("utf-8", "replace")
    except (UnicodeError, TypeError):
        return None


def _management(rule, source):
    return address_member(source, getattr(getattr(rule, "site_facts", None), "management_hosts", ()))


def _host_of(authority):
    """The host of a URL authority: no userinfo, no port, brackets removed, an address in its canonical form."""
    host = authority.rsplit("@", 1)[-1]
    if host.startswith("["):
        host = host[1:].partition("]")[0]
    elif host.count(":") == 1:
        host = host.partition(":")[0]
    try:
        return str(ip_address(host)), True
    except ValueError:
        return host, bool(_INTEGER_HOST.match(host))


_ABSOLUTE = re.compile(r"[a-z][a-z0-9+.-]{0,15}://")


def _target(value, session):
    """A request target's own host (when it carries one) and its path. An Arkime session URI is host-prefixed."""
    head = value.split("?", 1)[0]
    if _ABSOLUTE.match(head):
        authority, _slash, rest = head.split("://", 1)[1].partition("/")
        return _host_of(authority)[0], "/" + rest
    if session and not head.startswith("/"):
        authority, slash, rest = head.partition("/")
        return _host_of(authority)[0], slash + rest
    if head.startswith("//"):
        authority, _slash, rest = head[2:].partition("/")
        return _host_of(authority)[0], "/" + rest
    return "", head


def _climb(path):
    """How many levels a path goes above where it starts; an in-root a/../b does not."""
    depth = lowest = 0
    for component in path.replace("\\", "/").split("/"):
        if component == "..":
            depth -= 1
            lowest = min(lowest, depth)
        elif component not in {"", "."}:
            depth += 1
    return -lowest


def _traversal(value, path):
    # The request path: any step above the root. A client resolves dot segments before it sends a request, so one
    # that arrives is deliberate.
    if ".." not in value:
        return False
    if ".." in path and _climb(path):
        return True
    # A parameter value is a path of its own. One or two levels up are ordinary relative links (next=../home,
    # src=../../img/a.png); three or more leave any site layout, and fewer count when they end at a configuration,
    # hidden, log, key or backup file.
    for part in value.partition("?")[2].split("&"):
        candidate = part.partition("=")[2]
        if ".." not in candidate:
            continue
        climbed = _climb(candidate)
        if climbed >= 3 or climbed and _LFI_TARGET.search(candidate.rstrip("\x00 ")):
            return True
    return False


def _remote_inclusion(value, own):
    for found in _RFI_PARAM.finditer(value):
        url = found.group("url")
        host, literal = _host_of(url.split("://", 1)[1].split("/", 1)[0].split("?", 1)[0])
        # A URL on the requested server itself is not remote: nothing is fetched from another party. Its path is
        # still read by the local-file grammars.
        if host in own:
            continue
        if (found.group("key") in _RFI_DIRECTIVES or literal or found.group("nul") is not None
                or url.endswith("?") or _RFI_TEXT_EXTENSIONS.search(url.split("?", 1)[0])):
            return True
    return bool(_RFI_CALL.search(value))


def _sql(value):
    if "/*" in value:
        value = _COMMENT.sub(" ", _VERSIONED.sub(r" \1 ", value))
    return bool(_SQL.search(value))


def _classes(value, *, own=frozenset(), session=False, evasive=False):
    """The request-target classes one decoded value matches."""
    matches = set()
    if _sql(value):
        matches.add("sql_injection")
    if _XSS.search(value):
        matches.add("cross_site_scripting")
    host, path = _target(value, session)
    if evasive or _traversal(value, path) or _LFI.search(value):
        matches.add("path_traversal_lfi")
    if "://" in value and _remote_inclusion(value, own | {host} if host else own):
        matches.add("remote_file_inclusion")
    if _COMMAND.search(value):
        matches.add("command_injection")
    if _TEMPLATE.search(value):
        matches.add("template_injection")
    return matches


def _agent_classes(value):
    """The classes one decoded user-agent value matches, and its tool markers as a bit set."""
    tools = 0
    for found in _TOOL.finditer(value):
        tools |= 1 << int(found.lastgroup[1:])
    matches = {"exploit_tool"} if tools else set()
    if _sql(value):
        matches.add("sql_injection")
    if _XSS.search(value):
        matches.add("cross_site_scripting")
    if _COMMAND_UA.search(value):
        matches.add("command_injection")
    if _TEMPLATE.search(value):
        matches.add("template_injection")
    return matches, tools


def _tool_names(tools):
    return [name for index, (name, _marker, _id) in enumerate(_TOOLS) if tools >> index & 1]


def _tool_attack(tools):
    found = [technique for index, (_name, _marker, technique) in enumerate(_TOOLS) if tools >> index & 1]
    return tuple(dict.fromkeys(found)) or (_VULNERABILITY_SCAN,)


# ---- retained examples ---------------------------------------------------------------------------------------------

_REDACTED_QUERY = "[redacted:credential-query]"
# Spellings that can put a parameter delimiter inside a value once decoded (an encoded `%`, `&`, `;`, `=`, `?` or
# `#`, or an HTML entity). With one of them present, where a credential's value ends is not known from the raw text.
_AMBIGUOUS_QUERY = re.compile(r"%(?:25|26|3b|3d|3f|23)|&#|&[a-z0-9]{1,10};", re.IGNORECASE)
_PARAMETER_START = re.compile("[?#]")


def _has_credential_key(text):
    """Whether any parameter of a query or fragment (split at `&`, `;`, `?` and `#`) has a credential name."""
    for part in re.split("[&;?#]", text):
        name, equals, _value = part.partition("=")
        if not equals or not name:
            continue
        name = name[:256]
        if _credential_name(name) or "%" in name and _credential_name(_decode(name, 256, fold=False)[0]):
            return True
    return False


def _mask_query(query, decoded_query):
    """A query (and fragment) without its credential values. Each parameter whose name, decoded, is a credential
    name keeps the name and loses the value, so the rest of the request stays readable. When a value's end is
    ambiguous the whole of it is omitted instead."""
    if _AMBIGUOUS_QUERY.search(query):
        credential = _has_credential_key(query) or _has_credential_key(decoded_query)
        return _REDACTED_QUERY if credential else query
    kept = []
    for part in re.split("([&?#])", query):
        name, equals, _value = part.partition("=")
        kept.append(name + "=[redacted]" if equals and _has_credential_key(part) else part)
    return "".join(kept)


def _mask_path_parameters(path):
    """A path whose `name=value` pieces with credential names have their values masked. A piece is what `;` or
    `&` delimits inside one segment: path parameters (/app;jsessionid=...) and parameters written into the path."""
    if "=" not in path:
        return path
    segments = []
    for segment in path.split("/"):
        kept = []
        for piece in re.split("([;&])", segment) if "=" in segment else (segment,):
            name, equals, _value = piece.partition("=")
            kept.append(name + "=[redacted]" if equals and _has_credential_key(piece) else piece)
        segments.append("".join(kept))
    return "/".join(segments)


def _redact_uri(value):
    """Keep request evidence without retaining recognised credential values (see `_MASKING`)."""
    if not isinstance(value, str):
        return value
    value = value[:MAX_URI].encode("utf-8", "replace").decode("utf-8")
    clipped = len(value) > CITED_CHARS
    decoded = _decode(value, MAX_URI, fold=False)[0]
    # The path ends at the first `?` or `#`; everything after it is parameters (query and fragment alike).
    found, decoded_found = _PARAMETER_START.search(value), _PARAMETER_START.search(decoded)
    path, lead, parameters = (value[:found.start()], found.group(), value[found.end():]) if found else (value, "", "")
    if lead:
        parameters = _mask_query(parameters, decoded[decoded_found.end():] if decoded_found else decoded)
    path = _mask_path_parameters(path)
    plain_path = _decode(path, MAX_URI, fold=False)[0]
    if _mask_path_parameters(plain_path) != plain_path:
        # A credential piece that only appears once decoded cannot be masked in the raw spelling.
        path = "[redacted:encoded-path-parameters]"
    retained = strip_uri_userinfo(path + lead + parameters)[0]
    if strip_uri_userinfo(_decode(retained, MAX_URI, fold=False)[0])[1]:
        # Userinfo that only appears once decoded: drop the part that holds it.
        path_only = strip_uri_userinfo(path)[0]
        if lead and not strip_uri_userinfo(_decode(path_only, MAX_URI, fold=False)[0])[1]:
            retained = path_only + lead + _REDACTED_QUERY
        else:
            return "[redacted:encoded-URI-credentials]"
    if clipped:
        retained = retained[:CITED_CHARS] + "[truncated]"
    return retained


def _view(event, hits=None):
    """The bounded, masked copy of a record that a finding cites."""
    hits = hits or {}
    fields = {}
    for name in _FIELDS:
        if not event.has(name):
            continue
        fact = event.fields[name]
        value, origin = fact.value, fact.origin
        if len(origin) > 1024:
            continue
        values = value if isinstance(value, list) else [value]
        if any(not isinstance(item, (str, int)) or isinstance(item, bool) for item in values):
            continue
        if len(values) > CITED_VALUES:
            # A long list is cited by the values that matched; the native reference still names the whole record.
            values = list(hits.get(name, ()))[:CITED_VALUES]
            if not values:
                continue
            origin += "#matched-values-only"
        if name in URI_FIELDS:
            changed = [_redact_uri(item) for item in values]
            if changed != values:
                origin += "#masked-or-truncated"
        else:
            changed = [item[:CITED_CHARS] + "[truncated]" if isinstance(item, str) and len(item) > CITED_CHARS
                       else item for item in values]
            if changed != values:
                origin += "#truncated"
        kept = changed if isinstance(value, list) else changed[0]
        fields[name] = fact if kept == value and origin == fact.origin else fv(kept, origin)
    raw = [ref for ref in event.raw[:3] if len(ref.target) <= 1024 and len(ref.native_id) <= 4096 and len(ref.digest) <= 256]
    return event.model_copy(update={"fields": fields, "raw": raw,
                                    "caveats": [COMPACT_CITATION_NOTE,
                                                ("HTTP citation retains bounded fields; recognised credential "
                                                "values in the request target are masked.")]})


_PARTIAL_INPUT = {
    "length": "a value longer than its inspected bound was read up to that bound",
    "shape": "a value of an unexpected shape was not read",
    "text": "the record's total text bound was reached and its later values were not read",
    "utf8": "bytes that are not UTF-8 were replaced before inspection",
}


def _when(rank):
    return rank.partition("|")[0] if rank else "an unrecorded time"


class WebAttacks(Playbook):
    id, title, version = "network.web_attacks", "Attack-associated HTTP request shapes", "2"
    families = ("http_tx", "net_session")
    required_fields = ("source.ip", "destination.ip")
    kind, claim_type, anchor_class = "aggregate", "aggregate_observation", "network_observation"
    severity, lane = "medium", "lead"
    assures_negative = False
    positive_only_reason = "Finite request grammars and tool markers cannot exclude web attacks; encrypted or absent requests and bodies are not inspected."
    # Exploitation attempts against a server; tool markers carry the technique of what the tool does.
    attack = ("T1190", _VULNERABILITY_SCAN, _WORDLIST_SCAN, _BLOCK_SCAN, _BRUTE_FORCE)
    uses_site_facts = True
    state_slice = "strong"
    benign = (
        "Authorized vulnerability testing can use the same request grammars and tool identifiers.",
        ("Search text or a document that holds a complete statement or payload (a query for \"1 or 1=1\", a SQL "
        "tutorial's UNION SELECT with a column list) matches as the payload would."),
        ("A page editor or preview that carries HTML with event-handler attributes, or markdown inline code that "
        "directly follows `=` or a word (`=`id``), in a request target."),
        "A delimiter list whose item follows a number and is a command name (titles=Windows 10|Dir).",
        "An application that includes remote text files by design (page=https://other-site/readme.txt).",
        "A template placeholder holding arithmetic on literals ({{2+2}}) left unexpanded in a link.",
    )
    next_checks = ("Verify the target application and authorization, then inspect application and host evidence.",)
    card: ClassVar[dict] = {
        "behavior": title,
        "telemetry": ("Zeek/Suricata HTTP transactions (http_tx: url.original or url.path/url.query, "
                      "user_agent.original, http.hostname) and Arkime sessions (net_session: unordered url.path and "
                      "user_agent.original lists); present in the lab profile for all three producers."),
        "fidelity": "Bounded syntax-based observations of a request, not successful exploitation or independent request counts.",
        "license": "Apache-2.0 (OWASP CRS grammar concepts) and DRL-1.1 (Sigma user-agent markers, attributed in findings)",
        "thresholds": (f"{MAX_URI} characters per request target, {MAX_UA} per user agent and {MAX_RECORD_TEXT} per "
                       f"record are inspected; {PAIR_LEADS} leads per endpoint and class before a roll-up"),
        "benign_and_cost": " ".join(benign) + " Each costs one lead per source, destination and class, or one roll-up.",
        "query_cost": "One streaming family sweep; exact disk-backed folds written once per batch.",
        "next_pivot": next_checks[0],
        "adds": "The only rule that reads HTTP request targets and user agents for attack syntax; IDS alerts cover "
                "only what a sensor's signatures name.",
        "research_basis": _CRS + "; " + _SIGMA + "; " + _SIGMA_HACKTOOL
                          + "; content/network/web_attacks_sources.json",
        "retrieval": "Only typed request targets and user-agent values; omissions remain unresolved.",
        "lanes": ("Every class stays lead, including 2xx and declared management sources. Roll-ups stay lead. "
                  "Severity medium: a request that succeeded would give a foothold on one application, and nothing "
                  "in the request shows that it did."),
        "grouping": f"The first {PAIR_LEADS} sources at a destination and the first {PAIR_LEADS} destinations of a "
                    "source keep their own leads; beyond that one roll-up per (destination, class) lists the "
                    "sources and one per (source, class) lists the destinations, with exact member counts.",
    }

    def __init__(self):
        super().__init__()
        self._ready = False
        self._account = None
        self._tables = set()
        self._fold_refused = False
        self._refused_keys = set()         # at most REFUSED_GROUPS pair keys
        self._refused_classes = set()      # at most one entry per class

    _SCHEMA = (
        ("web_seen", ("k TEXT NOT NULL,id BLOB NOT NULL,rank TEXT,values_n INTEGER,session_n INTEGER,tools INTEGER,"
                     "partial INTEGER,payload BLOB,src TEXT,dst TEXT,cls TEXT,p TEXT,q TEXT,PRIMARY KEY(k,id)")),
        # One row per (source, destination, class). `p` and `q` are the two roll-ups the pair belongs to and
        # `p_ord`, `q_ord` its arrival position in each; `own` marks a pair that keeps a lead of its own.
        ("web_groups", ("k TEXT PRIMARY KEY,src TEXT,dst TEXT,cls TEXT,p TEXT,q TEXT,p_ord INTEGER,q_ord INTEGER,"
                       "own INTEGER,n INTEGER,values_n INTEGER,session_n INTEGER,tools INTEGER,partial_n INTEGER,"
                       "first_rank TEXT,last_rank TEXT,first_event BLOB,last_event BLOB")),
        # One row per roll-up: its exact member count and, once it has more members than keep their own leads,
        # its earliest and latest witness.
        ("web_fans", ("g TEXT PRIMARY KEY,prim INTEGER,members INTEGER,rolled INTEGER,first_rank TEXT,"
                     "last_rank TEXT,first_event BLOB,last_event BLOB")),
    )
    # One INSERT atomically records the identity, the pair's counters and witnesses, both roll-ups' member counts
    # and witnesses. A refused write cannot inflate counts or lose old rows.
    _STATEMENTS = (
        "CREATE INDEX IF NOT EXISTS web_p ON web_groups(p,k)",
        "CREATE INDEX IF NOT EXISTS web_q ON web_groups(q,k)",
        ("CREATE TRIGGER IF NOT EXISTS web_member AFTER INSERT ON web_groups BEGIN "
        "INSERT INTO web_fans VALUES(NEW.p,1,1,0,NULL,NULL,NULL,NULL) ON CONFLICT(g) DO UPDATE SET members=members+1; "
        "INSERT INTO web_fans VALUES(NEW.q,0,1,0,NULL,NULL,NULL,NULL) ON CONFLICT(g) DO UPDATE SET members=members+1; "
        "UPDATE web_groups SET p_ord=(SELECT members FROM web_fans WHERE g=NEW.p),"
        "q_ord=(SELECT members FROM web_fans WHERE g=NEW.q) WHERE k=NEW.k; "
        f"UPDATE web_groups SET own=(p_ord<={PAIR_LEADS} AND q_ord<={PAIR_LEADS}),"
        f"first_event=CASE WHEN p_ord<={PAIR_LEADS} AND q_ord<={PAIR_LEADS} THEN first_event END WHERE k=NEW.k; END"),
        ("CREATE TRIGGER IF NOT EXISTS web_fold AFTER INSERT ON web_seen BEGIN "
        "INSERT INTO web_groups VALUES(NEW.k,NEW.src,NEW.dst,NEW.cls,NEW.p,NEW.q,0,0,0,1,NEW.values_n,NEW.session_n,"
        "NEW.tools,NEW.partial,NEW.rank,NEW.rank,NEW.payload,NULL) "
        "ON CONFLICT(k) DO UPDATE SET n=n+1,values_n=values_n+NEW.values_n,session_n=session_n+NEW.session_n,"
        "tools=tools|NEW.tools,partial_n=partial_n+NEW.partial,"
        "last_event=CASE WHEN NOT own THEN NULL WHEN NEW.rank>last_rank THEN NEW.payload "
        "WHEN NEW.rank<first_rank AND last_event IS NULL THEN first_event ELSE last_event END,"
        "first_event=CASE WHEN NOT own THEN NULL WHEN NEW.rank<first_rank THEN NEW.payload ELSE first_event END,"
        "first_rank=min(first_rank,NEW.rank),last_rank=max(last_rank,NEW.rank); "
        "UPDATE web_fans SET "
        "last_event=CASE WHEN last_rank IS NULL OR NEW.rank>last_rank THEN NEW.payload ELSE last_event END,"
        "first_event=CASE WHEN first_rank IS NULL OR NEW.rank<first_rank THEN NEW.payload ELSE first_event END,"
        "first_rank=CASE WHEN first_rank IS NULL OR NEW.rank<first_rank THEN NEW.rank ELSE first_rank END,"
        "last_rank=CASE WHEN last_rank IS NULL OR NEW.rank>last_rank THEN NEW.rank ELSE last_rank END "
        f"WHERE g IN (NEW.p,NEW.q) AND members>{PAIR_LEADS}; "
        "UPDATE web_seen SET rank=NULL,payload=NULL,src=NULL,dst=NULL,cls=NULL,p=NULL,q=NULL "
        "WHERE k=NEW.k AND id=NEW.id; END"),
    )

    def _db(self):
        spill = self.spill()
        if not self._ready:
            if self._account is None:
                self._account = self.state_budget().account(self.id + ":fold", strong=True)
                register_store(self, spill)
            reason = self.state_budget().new_key_reason(self._account)
            if reason:
                raise StateExhausted(reason)
            for name, columns in self._SCHEMA:
                if name not in self._tables:
                    spill.table(name, columns)
                    self._tables.add(name)
            for statement in self._STATEMENTS:
                spill.write(statement, [()], account=self._account)
            self._ready = True
        return spill

    # -- inspection ------------------------------------------------------------------------------------------------

    def _inspect(self, event, destination):
        """One record's matched classes (with the count of distinct matching values), tool markers, the named
        reasons its inspection is partial, whether it held any inspectable text, and the raw values that matched."""
        session = event.family == "net_session"
        found, hits, issues, tools = {}, {}, set(), 0
        own = {destination}
        hostnames = event.get("http.hostname")
        for name in (hostnames if isinstance(hostnames, list) else [hostnames])[:16]:
            if isinstance(name, str) and len(name) <= 260:
                own.add(_host_of(name.casefold())[0])
        own = frozenset(own)
        # Every value is charged against one per-record character budget (a repeat costs one), so the work one
        # record can ask for is bounded however long its lists are.
        remaining, present, raw_seen, decoded_seen = MAX_RECORD_TEXT, False, set(), set()
        for field in (*URI_FIELDS, "user_agent.original"):
            raw = event.get(field)
            if raw is None:
                continue
            present = True
            if isinstance(raw, list) and not session:
                issues.add("shape")
                continue
            agent = field == "user_agent.original"
            limit = MAX_UA if agent else MAX_URI
            for value in raw if isinstance(raw, list) else (raw,):
                if remaining <= 0:
                    issues.add("text")
                    break
                if not isinstance(value, str):
                    issues.add("shape")
                    remaining -= 1
                    continue
                if (agent, value) in raw_seen:
                    remaining -= 1
                    continue
                raw_seen.add((agent, value))
                bound = min(limit, remaining)
                if len(value) > bound:
                    issues.add("length" if bound == limit else "text")
                decoded, problems, evasive = _decode(value[:bound], bound)
                issues |= problems
                remaining -= max(1, min(len(value), bound))
                if (agent, decoded) in decoded_seen:
                    continue
                decoded_seen.add((agent, decoded))
                if field == "url.query" and not decoded.startswith("?"):
                    decoded = "?" + decoded          # a separately typed query is parameters, not a path
                if agent:
                    classes, marked = _agent_classes(decoded)
                    tools |= marked
                else:
                    classes = _classes(decoded, own=own, session=session, evasive=evasive)
                if classes and len(hits.setdefault(field, [])) < CITED_VALUES:
                    hits[field].append(value)
                for name in classes:
                    found[name] = found.get(name, 0) + 1
        return found, tools, issues, present, hits

    def consume(self, events):
        pending = []
        try:
            for event in events:
                if event.family not in self.families or not rule_reads(event, HTTP_OBSERVATIONS) or not self.event_in_os_scope(event):
                    continue
                if not self._events_pre_scoped:
                    self.os_applicable += 1
                peers = _peers(event)
                if peers is None:
                    self.missing_required += 1
                    continue
                found, tools, issues, present, hits = self._inspect(event, peers[1])
                if issues:
                    named = sorted(issues)
                    self.refuse("web_input:" + "+".join(named), "HTTP request inspection is partial ("
                                + ", ".join(named) + "): " + "; ".join(_PARTIAL_INPUT[name] for name in named))
                if not present:
                    self.missing_required += 1
                    continue
                if not issues:
                    self.evaluated += 1
                if not found:
                    continue
                blob = None
                if len(event.id) <= 1024 and (event.host is None or len(event.host) <= 1024):
                    blob = compact_event(_view(event, hits))
                    if len(blob) > MAX_CITATION:
                        blob = None
                if blob is None:
                    self.note_limit("web_citation", "A known HTTP grammar match exceeded the bounded citation size; its positive count is retained")
                identity = hashlib.sha256(event.id.encode("utf-8", "replace")).digest()[:16]
                rank = event.ts.astimezone(UTC).isoformat(timespec="microseconds") + "|" + identity.hex()
                sides = tuple(self._inside(address) for address in peers)
                for name, values in sorted(found.items()):
                    primary, secondary = self._roll_ups(*peers, name, *sides)
                    pending.append(("|".join((*peers, name)), identity, rank, values,
                                    int(event.family == "net_session"), tools if name == "exploit_tool" else 0,
                                    int(bool(issues)), blob, *peers, name, primary, secondary))
                if len(pending) >= FLUSH_ROWS:
                    yield from self._flush(pending)
            yield from self._flush(pending)
        finally:
            if pending:
                # An error ended the batch early: keep what was already inspected. Finalize publishes from the fold;
                # if this write is refused, coverage counts the records and no finding can be handed back from here.
                for _match in self._flush(pending, publish=False):
                    pass

    @staticmethod
    def _inside(address):
        return current().is_internal(ip_address(address))

    @staticmethod
    def _roll_ups(source, destination, name, source_inside, destination_inside):
        """The pair's primary and secondary roll-up. A roll-up holds members of one side of the site boundary,
        because an internal member is one of the hunt's machines and an outside member is not.

        The primary roll-up is always published once it has more members than keep their own leads. It is the one
        anchored on the site's own endpoint when exactly one endpoint is internal (the roll-ups a site can have are
        then bounded by its own addresses, however many outside addresses take part), and the destination's
        otherwise. The secondary roll-up is published only for a pair the primary one does not cover.
        """
        fleet = f"fleet|{destination}|{name}|{'in' if source_inside else 'out'}"      # members: the sources
        sweep = f"sweep|{source}|{name}|{'in' if destination_inside else 'out'}"      # members: the destinations
        return (sweep, fleet) if source_inside and not destination_inside else (fleet, sweep)

    # -- the fold --------------------------------------------------------------------------------------------------

    def _flush(self, pending, *, publish=True):
        if not pending:
            return
        rows = list(pending)
        pending.clear()
        keys = list(dict.fromkeys(row[0] for row in rows))
        try:
            spill = self._db()
            reason = self.state_budget().new_key_reason(self._account)
            if reason:
                raise StateExhausted(reason)
            known = set()
            for offset in range(0, len(keys), 500):
                chunk = keys[offset:offset + 500]
                known.update(key for (key,) in spill.db.execute(
                    f"SELECT k FROM web_groups WHERE k IN ({','.join('?' * len(chunk))})", chunk))
            spill.write("INSERT OR IGNORE INTO web_seen VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", rows, account=self._account)
            witness = {row[0]: len(row[7] or b"") for row in rows}
            self.state_budget().charge(self._account, sum(len(row[0]) + 160 for row in rows) + sum(
                3 * len(key) + 320 + 2 * witness[key] for key in keys if key not in known))
        except StateExhausted as error:
            yield from self._refused(rows, error)
            return
        if not publish:
            return
        for key in keys:
            if key not in known:
                yield from self._publish_new(key)

    def _refused(self, rows, error):
        """Detection state could not grow: every matching record is still covered by a published lead, once per
        pair up to a stated number of pairs and once per class beyond it, and coverage says what was not folded."""
        self._fold_refused = True
        whole = {row[1] for row in rows if not row[6]}        # records not already counted as partly inspected
        self.refuse("web_state", f"HTTP fold is incomplete; matching live evidence remains a lead: {error}",
                    records=len(whole))
        for key, _identity, _rank, values, session, tools, partial, blob, _src, _dst, name, _p, _q in rows:
            if key in self._refused_keys:
                continue
            if len(self._refused_keys) < REFUSED_GROUPS:
                self._refused_keys.add(key)
                yield self._pair(key, 1, values, session, tools, partial, blob, None, final=False)
            elif name not in self._refused_classes:
                self._refused_classes.add(name)
                yield self._overflow(name, blob)

    def _publish_new(self, key):
        db = self._spill.db
        row = db.execute("SELECT p,q,p_ord,q_ord,own,n,values_n,session_n,tools,partial_n,first_event,last_event "
                         "FROM web_groups WHERE k=?", (key,)).fetchone()
        if row is None:
            return
        primary, secondary, p_ord, _q_ord, own, *counts = row
        if own:
            yield self._pair(key, *counts, final=False)
        elif p_ord > PAIR_LEADS:
            if p_ord == PAIR_LEADS + 1:
                yield self._roll_up(primary, final=False)
        elif not db.execute("SELECT rolled FROM web_fans WHERE g=?", (secondary,)).fetchone()[0]:
            try:
                self._spill.write("UPDATE web_fans SET rolled=1 WHERE g=?", [(secondary,)], account=self._account)
            except StateExhausted as error:
                self.note_limit("web_roll_up_mark", f"A roll-up's publication mark could not be kept, so it may "
                                                    f"be published again with the same identity: {error}")
            yield self._roll_up(secondary, final=False)

    # -- findings --------------------------------------------------------------------------------------------------

    def _notes(self, name, tools, sessions, partial_records, lower):
        notes = [_UNCERTAIN, "Counts deduplicate canonical event identities, not independent requests across sensors or re-indexing.",
                 "At most two representative event citations are retained; exact retained counts are independent of citation sampling.",
                 _MASKING]
        if sessions:
            notes.append(f"{sessions} counted observation(s) are Arkime sessions with unordered lists; "
                         "URI, user-agent, method and status values cannot be paired and do not count individual requests.")
        if name == "exploit_tool":
            notes.append(_ATTRIBUTION)
            notes.append("Tool identifiers may be customized or spoofed; their absence does not exclude the tool.")
        else:
            notes.append("Grammar reference: OWASP CRS contributors, Apache-2.0; bounded adaptation, not complete CRS coverage.")
        if partial_records:
            notes.append(f"{partial_records} of the counted record(s) were only partly inspected (a length or text "
                         "bound, or bytes that are not UTF-8); further matching values in them are possible.")
        if lower:
            notes.append("Retained fold coverage is partial; counts are lower bounds for observed activity.")
        return notes

    def _events(self, *blobs):
        events = []
        for blob in blobs:
            if blob is not None:
                event = expand_event(blob)
                if not events or events[0].id != event.id:
                    events.append(event)
        return events

    def _attack(self, name, tools):
        return _tool_attack(tools) if name == "exploit_tool" else ("T1190",)

    def _pair(self, key, count, values, sessions, tools, partial_records, first, last, *, final):
        source, destination, name = key.split("|")
        events = self._events(first, last)
        lower = self._fold_refused
        qualifier = "At least " if lower or not final else ""
        markers = f" Markers: {', '.join(_tool_names(tools))}." if name == "exploit_tool" and tools else ""
        claim = (f"{qualifier}{count} recorded HTTP observation(s) from {source} to {destination} "
                 f"contain {_CLASSES[name]} ({values} distinct inspected value(s) after decoding/case folding)."
                 + markers)
        notes = self._notes(name, tools, sessions, partial_records, lower)
        if _management(self, source):
            notes.append("The source is a site-declared management host; authorized scanning is possible and the observation remains a lead.")
        return Match(self.id, claim, self.claim_type, events,
                     [pf(event, field) for event in events for field in event.fields],
                     events[-1].ts if events else None, self.severity, "lead", "medium",
                     entities=[("ip", source, "src"), ("ip", destination, "dst")], notes=notes, group_key=key,
                     bounded_revision=True, revision_reason="Final retained HTTP observation counts" if final else "",
                     citation_unavailable=not events,
                     aggregate_summary={"record_count": count, "matching_values": values, "session_count": sessions,
                                        "count_complete": int(final and not lower and not partial_records)},
                     attack=self._attack(name, tools))

    def _overflow(self, name, blob):
        events = self._events(blob)
        claim = (f"HTTP observations containing {_CLASSES[name]} were recorded after detection state could no longer "
                 f"grow, from more source and destination pairs than the {REFUSED_GROUPS} that kept a lead of their "
                 f"own; those pairs are not individually retained and one of their records is cited.")
        notes = [*self._notes(name, 0, 0, 0, True),
                 "Coverage names the records that were not folded; a larger state budget keeps every pair."]
        return Match(self.id, claim, self.claim_type, events,
                     [pf(event, field) for event in events for field in event.fields],
                     events[-1].ts if events else None, self.severity, "lead", "medium",
                     entities=list(dict.fromkeys(item for event in events for item in event.entities())),
                     notes=notes, group_key=f"unfolded|{name}", bounded_revision=True,
                     citation_unavailable=not events,
                     aggregate_summary={"record_count": 1, "matching_values": 1, "session_count": 0,
                                        "count_complete": 0}, attack=self._attack(name, 0))

    def _members(self, column, member, group):
        for (address,) in self._spill.db.execute(
                f"SELECT {member} FROM web_groups WHERE {column}=? ORDER BY k", (group,)):
            yield address, ""

    def _roll_up(self, group, *, final):
        db = self._spill.db
        role, anchor, name, side = group.split("|")
        prim, first, last = db.execute(
            "SELECT prim,first_event,last_event FROM web_fans WHERE g=?", (group,)).fetchone()
        column, member = ("p" if prim else "q"), ("src" if role == "fleet" else "dst")
        members, records, values, sessions, partial_records, earliest, latest = db.execute(
            f"SELECT count(*),sum(n),sum(values_n),sum(session_n),sum(partial_n),min(first_rank),max(last_rank) "
            f"FROM web_groups WHERE {column}=?", (group,)).fetchone()
        tools = 0
        if name == "exploit_tool":
            for (marked,) in db.execute(f"SELECT DISTINCT tools FROM web_groups WHERE {column}=?", (group,)):
                tools |= marked or 0
        top = db.execute(f"SELECT {member},n FROM web_groups WHERE {column}=? ORDER BY n DESC,{member} LIMIT ?",
                         (group, MEMBERS_NAMED)).fetchall()
        events = self._events(first, last)
        lower = self._fold_refused
        least = "at least " if lower or not final else ""
        where = "internal" if side == "in" else "outside"
        listed = "; ".join(f"{address} ({count})" for address, count in top)
        more = f"; and {members - len(top)} more (the finding's member list holds every one)" if members > len(top) else ""
        markers = f" Markers: {', '.join(_tool_names(tools))}." if tools else ""
        span = f"{_when(earliest)} – {_when(latest)}"
        if role == "fleet":
            claim = (f"{least}{members} distinct {where} source address(es) sent {least}{records} recorded HTTP "
                     f"observation(s) containing {_CLASSES[name]} to {anchor} ({span}; {values} distinct inspected "
                     f"value(s) after decoding/case folding).{markers} The sources with the most observations: "
                     f"{listed}{more}.")
            entities = [("ip", anchor, "dst"), *(("ip", address, "src") for address, _count in top)]
        else:
            claim = (f"{anchor} sent {least}{records} recorded HTTP observation(s) containing {_CLASSES[name]} to "
                     f"{least}{members} distinct {where} destination address(es) ({span}; {values} distinct "
                     f"inspected value(s) after decoding/case folding).{markers} The destinations with the most "
                     f"observations: {listed}{more}.")
            entities = [("ip", anchor, "src"), *(("ip", address, "dst") for address, _count in top)]
        notes = self._notes(name, tools, sessions, partial_records, lower)
        notes.append(f"This finding stands for every {'source' if role == 'fleet' else 'destination'} in its member "
                     f"list; the first {PAIR_LEADS} pairs of an endpoint also keep leads of their own. Its two "
                     "citations are the earliest and latest records kept for the group.")
        if not current().configured:
            notes.append(DIRECTION_ASSUMED_REASON)
        management = getattr(getattr(self, "site_facts", None), "management_hosts", ())
        if management and role == "sweep" and address_member(anchor, management):
            notes.append("The source is a site-declared management host; authorized scanning is possible and the "
                         "observation remains a lead.")
        elif management and role == "fleet":
            declared = sum(address_member(address, management) for address, _ in self._members(column, member, group))
            if declared:
                notes.append(f"{declared} of the source address(es) are site-declared management hosts; authorized "
                             "scanning is possible and the observation remains a lead.")
        # Internal members are the hunt's own machines, so they are published as the hosts the finding stands for:
        # the ranking then counts them exactly as it counts the internal endpoint of each per-pair lead this
        # roll-up replaces. Outside members are never hosts: they are staged as `ip` entities.
        return Match(self.id, claim, self.claim_type, events,
                     [pf(event, field) for event in events for field in event.fields],
                     events[-1].ts if events else None, self.severity, "lead", "medium", entities=entities,
                     notes=notes, group_key=group, bounded_revision=True,
                     revision_reason="Final retained HTTP observation counts" if final else "",
                     citation_unavailable=not events, fleet_hosts=self._members(column, member, group),
                     fleet_host_count=members, fleet_hosts_complete=final and not lower,
                     fleet_member_kind="host" if side == "in" else "external_address",
                     aggregate_summary={"member_count": members, "record_count": records, "matching_values": values,
                                        "session_count": sessions,
                                        "count_complete": int(final and not lower and not partial_records)},
                     attack=self._attack(name, tools))

    def finalize(self):
        if not self._ready:
            return
        db = self._spill.db
        for key, *counts in db.execute(
                "SELECT k,n,values_n,session_n,tools,partial_n,first_event,last_event FROM web_groups "
                "WHERE own=1 ORDER BY k"):
            yield self._pair(key, *counts, final=True)
        for group, prim in db.execute("SELECT g,prim FROM web_fans WHERE members>? ORDER BY g", (PAIR_LEADS,)):
            # A secondary roll-up is published when one of its pairs has neither its own lead nor a primary roll-up.
            if prim or db.execute("SELECT 1 FROM web_groups WHERE q=? AND q_ord>? AND p_ord<=? LIMIT 1",
                                  (group, PAIR_LEADS, PAIR_LEADS)).fetchone():
                yield self._roll_up(group, final=True)

    def finalize_fallback(self, reason):
        self.note_limit("web_finalize", "HTTP fold finalization is partial: " + reason)
        return self.finalize()


_STATUS_KEY = "#status"       # suffix of the window key that counts the same attempts by response status
_STATUSES_NAMED = 6


class WebLoginBurst(ZeekWindowRule):
    id, title, version = "network.web_login_burst", "Repeated attempts at a web authentication path", "2"
    families, producers = ("http_tx",), ZEEK_AND_SURICATA
    required_fields = ("source.ip", "destination.ip", "http.request.method", "http.response.status_code")
    citation_fields = _FIELDS
    # Twenty counted requests from one source address to one path on one server inside five minutes. The reasoning
    # does not depend on a network. One person typing credentials submits a few times a minute, and account-lockout
    # settings (commonly three to ten failures) stop one account well short of twenty, so twenty is beyond what a
    # person's retries produce, while any guessing tool passes it within seconds. What the number cannot separate
    # is many people behind one address (NAT, a proxy, a single sign-on portal, a health check): the claim therefore
    # states the response-status mix of the window and the lane stays lead. Guessing slower than this, spread over
    # many sources, or visible only as failure statuses on other paths is not counted.
    seconds, threshold, per_sensor = 300, 20, True
    severity, lane, attack = "medium", "lead", ("T1110",)
    uses_site_facts = True
    benign = (("Shared NAT, proxies, sign-on portals, broken clients, token refreshes and authorized testing can "
              "generate repeated requests to an authentication path; the response-status mix separates most of them."),)
    next_checks = ("Compare application authentication outcomes and account evidence; HTTP status alone cannot prove success.",)
    card: ClassVar[dict] = {
        "behavior": title,
        "telemetry": ("Zeek or Suricata HTTP transactions (http_tx: url.original or url.path, http.request.method, "
                      "http.response.status_code, optional user.name); present in the lab profile for both. Arkime "
                      "lists are excluded: their methods and statuses cannot be paired with a request."),
        "fidelity": ("Requests shaped as authentication attempts: at a sign-in path, every answered POST and every "
                     "401/403/429; on any path, a request carrying an account and a password parameter. Positive-only."),
        "benign_and_cost": benign[0] + " One lead per source, destination, path and sensor.",
        "query_cost": "Disk-backed five-minute window with late replay.",
        "next_pivot": next_checks[0],
        "research_basis": "MITRE ATT&CK T1110 (Brute Force); an original rate rule with no imported detection content.",
        "license": "original",
        "thresholds": "20 attempt references in 300 seconds from one source to one path on one server, per sensor",
        "adds": "The only rate over web sign-in requests; host authentication rules need the server's own logs.",
        "retrieval": "Typed request path, method, response status and peers; absent body/account stays unknown.",
        "lanes": ("Lead at 20 attempt references in 300 seconds; no promotion from network status. Severity medium: "
                  "a guessed password gives one account on one application."),
    }

    def __init__(self):
        super().__init__()
        self._emitting = None

    def compact(self, event):
        return super().compact(_view(event))

    def select(self, event):
        peers = _peers(event)
        if not peers:
            return None
        value = event.get("url.original") or event.get("url.path")
        decoded, issues, _evasive = _decode(value, MAX_URI, fold=False)
        if decoded is None:
            self.refuse("web_login_input", "Web-login request inspection is partial: the request target is not text")
            return None
        if "length" in issues:
            self.note_limit("web_login_length", "A request target longer than the inspected bound was read up to it")
        try:
            parsed = urlsplit(decoded)
            raw_parts = urlsplit(value[:MAX_URI])
        except ValueError:
            self.refuse("web_login_shape", "Web-login request target has an invalid URL shape")
            return None
        # Path parameters (;jsessionid=...) vary per request and are not part of the endpoint; a credential written
        # into a segment (/token=.../login) is masked before the path becomes a key.
        path = _mask_path_parameters("/".join(segment.split(";", 1)[0] for segment in parsed.path.split("/")))
        method, status = event.get("http.request.method"), event.get("http.response.status_code")
        if not isinstance(method, str) or not isinstance(status, int) or isinstance(status, bool):
            self.missing_required += 1
            return None
        method = method.casefold()
        account = event.get("user.name")
        if not isinstance(account, str) or not account or len(account) > 256:
            account = ""
        # Query boundaries precede decoding. Encoded '&' and '=' belong to
        # an account value, not to new parameters or truncated identities.
        query = raw_parts.query
        if not query and event.has("url.query"):
            query = event.get("url.query")
            if not isinstance(query, str) or len(query) > MAX_URI:
                self.refuse("web_login_query", "Web-login account inspection is partial: query shape or length")
                query = ""
        query_account = password = credential = False
        for part in query.split("&"):
            key, equals, raw_value = part.partition("=")
            key = _form_value(key)
            if not equals or not key:
                continue
            if raw_value:
                password = password or key.casefold() in _PASSWORD_KEYS
                credential = credential or _credential_name(key)
            if key.casefold() in _ACCOUNT_KEYS:
                value = _form_value(raw_value)
                if value and len(value) <= 256:
                    query_account = True
                    if not account:
                        account = value
        if _AUTH.search(path.casefold()):
            # At a sign-in path: every answered POST (a failed login is answered 200, 302, 401, 422 and more,
            # depending on the application), every refusal status, and a query that carries the credentials.
            counted = method == "post" or status in (401, 403, 429) or query_account and (password or credential)
        else:
            counted = query_account and password
        if not counted:
            return None
        member = hashlib.sha256(account.encode("utf-8", "replace")).hexdigest() if account else "unknown-account"
        sensor = event.get("observer.name")
        sensor = sensor if isinstance(sensor, str) and len(sensor) <= 256 else "unknown-sensor"
        return (*peers, sensor, path[:1024]), member, "attempt"

    # -- the response-status mix of a window -----------------------------------------------------------------------
    # The same attempts are counted a second time under a companion key whose members are response statuses. The
    # window engine keeps that key's window exactly as it keeps the first, on disk, so the mix of the peak window
    # costs one small read however many attempts the window holds.

    def _forward(self, key, event, member, role, weight):
        status = event.get("http.response.status_code")
        if role == "attempt" and isinstance(status, int):
            try:
                self.rows.advance(key + _STATUS_KEY, event, str(status), "attempt", weight)
            except StateExhausted as error:
                self.note_limit("web_login_statuses", f"The response-status mix of a window could not be kept: {error}")
        yield from super()._forward(key, event, member, role, weight)

    def _record_episode(self, key, event, total, distinct, role, member, decision, **options):
        body, old = super()._record_episode(key, event, total, distinct, role, member, decision, **options)
        if body.get("peak_ts") == event.ts.timestamp() and body.get("total") == total:
            rows = self.rows.store().db.execute(
                "SELECT member,n FROM members WHERE k=? ORDER BY n DESC,member", (key + _STATUS_KEY,)).fetchall()
            body["status_mix"] = [[status, count] for status, count in rows[:_STATUSES_NAMED]]
            body["status_rest"] = [len(rows[_STATUSES_NAMED:]), sum(count for _status, count in rows[_STATUSES_NAMED:])]
        return body, old

    def _emit_episode(self, key, *, body=None, **options):
        if body is None:
            row = self.rows.store().db.execute("SELECT body FROM episodes WHERE k=?", (key,)).fetchone()
            if row is None:
                return None
            body = json.loads(row[0])
        self._emitting = body
        try:
            return super()._emit_episode(key, body=body, **options)
        finally:
            self._emitting = None

    def _statuses(self, total_refs):
        body = self._emitting
        if not body or body.get("total") != total_refs or not body.get("status_mix"):
            return " The response statuses of that window were not retained."
        named = body["status_mix"]
        others, other_records = body.get("status_rest") or (0, 0)
        records = sum(count for _status, count in named) + other_records
        text = ", ".join(f"{count} answered {status}" for status, count in named)
        if others:
            text += f", and {other_records} answered {others} other status value(s)"
        return f" Of the {records} record(s) in that window, {text}."

    def describe(self, event, total_refs, distinct_members, role):
        notes = [
            _UNCERTAIN,
            ("No status is read as a failed or a successful login: an application may answer a wrong password with "
            "200 (the form again), a redirect, 401, 403 or 422, and a right one with a redirect or 200. The status "
            "mix shows whether the window held one repeated answer (guessing against one application) or the varied "
            "answers of many users."),
            ("Counted: at a sign-in path, every answered POST, every 401, 403 or 429, and a request whose query "
            "carries an account with a credential parameter; on any path, a request whose query carries both an "
            "account and a password parameter. Other requests are not counted."),
            ("Twenty attempt references in five minutes is beyond one person's retries and below any tool's rate; "
            "many users behind one address can also reach it. Counts are per sensor and path."),
            "Account labels are counted across repeated or distinct users when available; unknown accounts share one unknown bucket. Request bodies are unavailable.",
            _MASKING,
        ]
        if _management(self, event.get("source.ip")):
            notes.append("The source is a site-declared management host; the observation remains a lead.")
        target = event.get("url.original") or event.get("url.path")
        path = ""
        if isinstance(target, str) and not target.startswith("["):
            try:
                path = _mask_path_parameters(
                    "/".join(segment.split(";", 1)[0] for segment in urlsplit(target).path.split("/")))[:256]
            except ValueError:
                path = ""
        where = f"path {path}" if path else "one path"
        return "lead", (f"Source {event.get('source.ip')} has {total_refs} HTTP authentication-attempt raw "
                        f"references to {event.get('destination.ip')} at {where} in five minutes "
                        f"({distinct_members} account-label bucket(s), including unknown when absent)."
                        + self._statuses(total_refs)), tuple(notes)


WEB_ATTACK_PLAYBOOKS = (WebAttacks, WebLoginBurst)
