"""Bounded HTTP attack grammars and disk-backed, positive-only observations.

The patterns are a small, independently implemented adaptation of OWASP CRS
grammars, not a WAF or a complete CRS implementation. Tool markers also adapt
Sigma's suspicious user-agent rule; source, author and licence details are in
content/network/web_attacks_sources.json and accompany affected findings.
"""
from __future__ import annotations

import hashlib
import html
import re
from datetime import UTC
from ipaddress import ip_address
from typing import ClassVar
from urllib.parse import unquote_to_bytes, urlsplit

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.bounded import StateExhausted, register_store
from romulus.detect.network_producers import HTTP_OBSERVATIONS, ZEEK_AND_SURICATA, rule_reads
from romulus.detect.zeek_rate_state import ZeekWindowRule
from romulus.evidence.typed import fv
from romulus.hunt.citations import COMPACT_CITATION_NOTE, compact_event, expand_event

MAX_URI = 16_384
MAX_UA = 2_048
MAX_VALUES = 128
MAX_RECORD_TEXT = 65_536
MAX_CITATION = 24_576
URI_FIELDS = ("url.original", "url.path", "url.query")
_FIELDS = ("source.ip", "destination.ip", "observer.name", "observer.product", *URI_FIELDS,
           "http.request.method", "http.response.status_code", "user_agent.original", "user.name")
_CRS = "https://github.com/coreruleset/coreruleset"
_SIGMA = "https://github.com/SigmaHQ/sigma/blob/master/rules/web/webserver_generic/web_susp_useragents.yml"
_ATTRIBUTION = ("User-agent markers adapted from Sigma 'Suspicious User-Agents Related To Recon Tools', "
                "by Nasreddine Bencherchali (Nextron Systems) and Tim Shelton, DRL-1.1: " + _SIGMA)
_UNCERTAIN = ("Network metadata shows request shapes only; exploitation, application execution and "
              "authentication success are not established, including for 2xx or redirect responses.")
_CLASSES = {
    "sql_injection": "SQL injection grammar",
    "cross_site_scripting": "cross-site scripting grammar",
    "path_traversal_lfi": "path traversal or local-file inclusion grammar",
    "remote_file_inclusion": "remote-file inclusion grammar",
    "command_injection": "OS command injection grammar",
    "template_injection": "server-side template injection grammar",
    "exploit_tool": "known exploit or reconnaissance tool user-agent marker",
}

# Bounded token gaps avoid backtracking over arbitrary request-sized expressions.
_COMMENT = re.compile(r"/\*[^*]{0,128}(?:\*(?!/)[^*]{0,128}){0,4}\*/")
_SQL = re.compile(
    r"\bunion\s{1,32}(?:(?:all|distinct)\s{1,32})?select\s{1,32}(?:[0-9*(@]|[a-z_][a-z_0-9.]{0,63}\b)"
    r"|['\"]\s{0,16};?\s{0,16}(?:select|union|having|insert|update|delete|drop)\s{1,32}\S"
    r"|['\"]\s{0,16}(?:or|and)\s{1,16}(?:[0-9]{1,12}|['\"][^'\"]{0,64}['\"])\s{0,8}[=<>]"
    r"|\b(?:sleep|benchmark|pg_sleep)\s{0,8}\(\s{0,8}[0-9]"
)
_XSS = re.compile(r"<\s{0,8}script(?:[\s/>]|$)|<(?:img|svg|body|iframe|input|video|audio)\b[^>]{0,512}"
                  r"\bon[a-z]{3,32}\s{0,8}=\s{0,8}[^=\s]|\bjavascript\s{0,8}:\s{0,8}(?:alert|eval|confirm|prompt)\s{0,8}\(")
_LFI = re.compile(r"(?:^|[=/\\])(?:etc/(?:passwd|shadow)|proc/self/(?:environ|cmdline)|"
                  r"(?:[a-z]:)?[/\\]?windows[/\\](?:win\.ini|system32[/\\]config[/\\]sam))(?:[\s&#?]|$)")
_RFI = re.compile(r"(?:^|[?&])(?:include|require|mosconfig_absolute_path)=(?:https?|ftps?)://[^\s&#]{1,512}"
                  r"|(?:^|[?&])(?:file|page|template|path)="
                  r"(?:https?|ftps?)://[^\s&#]{1,512}(?:\.php[0-9]?|\.phtml|\.jsp|\.asp[x]?)(?:\?|[&#]|$)"
                  r"|\binclude\s{0,8}\(\s{0,8}['\"]?(?:https?|ftps?)://")
_COMMAND = re.compile(r"(?:[;|`\r\n]|&&|\$\()\s{0,16}(?:/(?:usr/)?bin/)?"
                      r"(?:cat|id|whoami|uname|curl|wget|bash|sh|cmd(?:\.exe)?|powershell(?:\.exe)?|"
                      r"pwsh|nc|netcat|ping|nslookup|certutil|python[23]?|perl|php)"
                      r"(?=$|[\s;&|`)/<>])")
_TEMPLATE = re.compile(r"(?:\{\{|\$\{|<%)[^{}<>]{0,128}(?:[0-9]\s{0,8}[*+/-]\s{0,8}[0-9]|"
                       r"__[a-z_]{1,32}__|\b(?:config|request|self|cycler|joiner|namespace)\s{0,8}[.(])"
                       r"[^{}<>]{0,128}(?:\}\}|\}|%>)")
_TOOL = re.compile(r"(?:^|[\s(/;])(?:sqlmap|nikto|commix|nuclei)(?=$|[/\s;)])")
_AUTH = re.compile(r"(?:^|/)(?:login|logon|signin|sign-in|sign_in|authenticate|wp-login\.php|"
                   r"j_security_check|session|sessions)(?:/|\.[a-z]{1,5}|$)")
_BAD_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")
_SECRET_KEYS = frozenset({"password", "passwd", "pwd", "pass", "token", "access_token", "refresh_token",
                         "id_token", "api_key", "apikey", "secret", "client_secret", "authorization", "auth"})
_ACCOUNT_KEYS = frozenset({"user", "username", "user_name", "login", "email", "account"})
_SECRET_PARAMETER = re.compile(r"(?:^|[?&#;])(?:" + "|".join(sorted(_SECRET_KEYS)) + r")\s{0,8}=")


def _decode(value, bound, *, fold=True):
    if not isinstance(value, str):
        return None, "shape"
    if len(value) > bound:
        return None, "length"
    try:
        value.encode("utf-8", "strict")
        value = value.replace("+", " ")
        for pass_number in range(2):
            if "%" not in value:
                break
            if pass_number == 0 and _BAD_PERCENT.search(value):
                return None, "percent"
            value = unquote_to_bytes(value).decode("utf-8", "strict")
    except UnicodeError:
        # Strict decoding rejects overlong UTF-8, surrogates and invalid bytes.
        return None, "utf8"
    value = html.unescape(value)
    return value.casefold() if fold else value, None


def _peers(event):
    try:
        return tuple(str(ip_address(event.get(name))) for name in ("source.ip", "destination.ip"))
    except (ValueError, TypeError):
        return None


def _form_value(value):
    """An account label uses ordinary form decoding, not attack normalization."""
    try:
        if len(value) > MAX_URI or _BAD_PERCENT.search(value):
            return None
        return unquote_to_bytes(value.replace("+", " ")).decode("utf-8", "strict")
    except (UnicodeError, TypeError):
        return None


def _management(rule, source):
    return source in getattr(getattr(rule, "site_facts", None), "management_hosts", ())


def _above_root(value):
    # A path component '..' matters; isolated punctuation and an in-root a/../b
    # navigation do not. Query values are independently rooted file paths.
    path = value.split("?", 1)[0]
    if "://" in path:
        try:
            path = urlsplit(value).path
        except ValueError:
            return False
    paths = [path, *(part.partition("=")[2] for part in value.split("&"))]
    for candidate in paths:
        depth = 0
        for component in candidate.replace("\\", "/").split("/"):
            if component == "..":
                if depth == 0:
                    return True
                depth -= 1
            elif component not in {"", "."}:
                depth += 1
    return False


def _classes(value):
    matches = set()
    sql = _COMMENT.sub(" ", value) if "/*" in value else value
    if _SQL.search(sql):
        matches.add("sql_injection")
    if _XSS.search(value):
        matches.add("cross_site_scripting")
    if (".." in value and _above_root(value)) or _LFI.search(value):
        matches.add("path_traversal_lfi")
    if _RFI.search(value):
        matches.add("remote_file_inclusion")
    if _COMMAND.search(value):
        matches.add("command_injection")
    if _TEMPLATE.search(value):
        matches.add("template_injection")
    return matches


def _redact_uri(value):
    """Keep request evidence without retaining recognised credential values."""
    if not isinstance(value, str):
        return value
    decoded, error = _decode(value, MAX_URI, fold=False)
    if error:
        return "[unavailable: invalid or oversized HTTP text]"
    # Encoded or HTML delimiters can be part of a credential's value. Once any
    # sensitive key is recognised, omit the whole query rather than splitting
    # a decoded value into seemingly harmless new parameters.
    sensitive = (_SECRET_PARAMETER.search(value.casefold())
                 or _SECRET_PARAMETER.search(decoded.casefold()))
    retained = value
    if sensitive:
        prefix, separator, _query = value.partition("?")
        retained = prefix + "?[redacted:credential-query]" if separator else "[redacted:credential-query]"
    try:
        parsed = urlsplit(retained)
        decoded_parts = urlsplit(decoded)
    except ValueError:
        return "[unavailable: malformed HTTP target]"
    if parsed.netloc and "@" in parsed.netloc:
        authority = parsed.netloc.rsplit("@", 1)[1]
        retained = retained.replace(parsed.netloc, "[redacted]@" + authority, 1)
    elif decoded_parts.netloc and "@" in decoded_parts.netloc:
        # An encoded authority is ambiguous in the retained raw spelling.
        return "[redacted:encoded-URI-credentials]"
    return retained


def _view(event):
    fields = {}
    for name in _FIELDS:
        if not event.has(name):
            continue
        fact = event.fields[name]
        value = fact.value
        values = value if isinstance(value, list) else [value]
        # This is a citation bound only; classification already examined its
        # separate bounded input. Native references keep omitted facts traceable.
        if len(values) > MAX_VALUES or len(fact.origin) > 1024:
            continue
        if any(isinstance(item, str) and len(item) > MAX_URI for item in values):
            continue
        if any(not isinstance(item, (str, int)) or isinstance(item, bool) for item in values):
            continue
        if name in URI_FIELDS:
            changed = [_redact_uri(item) for item in values]
            redacted = changed if isinstance(value, list) else changed[0]
            fields[name] = fv(redacted, fact.origin + ("#redacted:credential-query" if redacted != value else ""))
        else:
            fields[name] = fact
    raw = [ref for ref in event.raw[:3] if len(ref.target) <= 1024 and len(ref.native_id) <= 4096 and len(ref.digest) <= 256]
    return event.model_copy(update={"fields": fields, "raw": raw,
                                    "caveats": [COMPACT_CITATION_NOTE,
                                                "HTTP citation retains bounded fields; recognised credential query values are masked."]})


class WebAttacks(Playbook):
    id, title = "network.web_attacks", "Attack-associated HTTP request shapes"
    families = ("http_tx", "net_session")
    required_fields = ("source.ip", "destination.ip")
    kind, claim_type, anchor_class = "aggregate", "aggregate_observation", "network_observation"
    severity, lane = "medium", "lead"
    assures_negative = False
    positive_only_reason = "Finite request grammars and tool markers cannot exclude web attacks; encrypted or absent requests and bodies are not inspected."
    attack = ("T1190",)
    uses_site_facts = True
    state_slice = "strong"
    benign = ("Authorized vulnerability testing can use the same request grammars and tool identifiers.",)
    next_checks = ("Verify the target application and authorization, then inspect application and host evidence.",)
    card: ClassVar[dict] = {
        "behavior": title, "telemetry": "Zeek/Suricata HTTP transactions and Arkime typed URI/UA lists",
        "fidelity": "Bounded syntax-based observations, not successful exploitation or independent request counts.",
        "benign_and_cost": benign[0], "query_cost": "One streaming family sweep; exact disk-backed folds.",
        "next_pivot": next_checks[0], "research_basis": _CRS + "; " + _SIGMA,
        "retrieval": "Only typed request targets and user-agent values; omissions remain unresolved.",
        "lanes": "Every class stays lead, including 2xx and declared management sources.",
    }

    def __init__(self):
        super().__init__()
        self._ready = False
        self._account = None
        self._tables = set()

    def _db(self):
        spill = self.spill()
        if not self._ready:
            if self._account is None:
                self._account = self.state_budget().account(self.id + ":fold", strong=True)
                register_store(self, spill)
            reason = self.state_budget().new_key_reason(self._account)
            if reason:
                raise StateExhausted(reason)
            for name, columns in (
                ("web_seen", "k TEXT,id TEXT,rank TEXT,values_n INTEGER,session_n INTEGER,payload BLOB,PRIMARY KEY(k,id)"),
                ("web_groups", ("k TEXT PRIMARY KEY,n INTEGER,values_n INTEGER,session_n INTEGER,"
                 "first_rank TEXT,last_rank TEXT,first_event BLOB,last_event BLOB")),
            ):
                if name not in self._tables:
                    spill.table(name, columns)
                    self._tables.add(name)
            # One INSERT atomically records the identity, counter and two
            # witnesses. A refused write cannot inflate counts or lose old rows.
            spill.write("CREATE TRIGGER web_fold AFTER INSERT ON web_seen BEGIN "
                        "INSERT INTO web_groups VALUES(NEW.k,1,NEW.values_n,NEW.session_n,NEW.rank,NEW.rank,NEW.payload,NEW.payload) "
                        "ON CONFLICT(k) DO UPDATE SET n=n+1,values_n=values_n+NEW.values_n,session_n=session_n+NEW.session_n,"
                        "first_event=CASE WHEN NEW.rank<first_rank THEN NEW.payload ELSE first_event END,"
                        "last_event=CASE WHEN NEW.rank>last_rank THEN NEW.payload ELSE last_event END,"
                        "first_rank=min(first_rank,NEW.rank),last_rank=max(last_rank,NEW.rank); "
                        "UPDATE web_seen SET payload=NULL WHERE k=NEW.k AND id=NEW.id; END", [()], account=self._account)
            self._ready = True
        return spill

    def consume(self, events):
        for event in events:
            if event.family not in self.families or not rule_reads(event, HTTP_OBSERVATIONS) or not self.event_in_os_scope(event):
                continue
            if not self._events_pre_scoped:
                self.os_applicable += 1
            peers = _peers(event)
            if peers is None:
                self.missing_required += 1
                continue
            found, seen, issues = {}, set(), set()
            remaining, count, present = MAX_RECORD_TEXT, 0, False
            for field in (*URI_FIELDS, "user_agent.original"):
                raw = event.get(field)
                if raw is None:
                    continue
                present = True
                values = raw if isinstance(raw, list) else (raw,)
                if event.family == "http_tx" and isinstance(raw, list):
                    issues.add("shape")
                    continue
                available = min(len(values), MAX_VALUES - count)
                if available < len(values):
                    issues.add("values")
                count += available
                for index in range(available):
                    value = values[index]
                    bound = min(MAX_UA if field == "user_agent.original" else MAX_URI, remaining)
                    decoded, error = _decode(value, bound)
                    if error:
                        issues.add(error)
                        continue
                    remaining -= len(value)
                    distinct_key = (field == "user_agent.original", decoded)
                    if distinct_key in seen:
                        continue
                    seen.add(distinct_key)
                    classes = {"exploit_tool"} if field == "user_agent.original" and _TOOL.search(decoded) else set()
                    if field != "user_agent.original":
                        classes = _classes(decoded)
                    for name in classes:
                        found[name] = found.get(name, 0) + 1
            if issues:
                self.refuse("web_input", "HTTP request inspection is partial (" + ", ".join(sorted(issues))
                            + "): URI length, total text, value counts, percent encoding and strict utf8 are bounded")
            if not present:
                self.missing_required += 1
                continue
            if not issues:
                self.evaluated += 1
            if not found:
                continue
            blob = None
            if len(event.id) <= 1024 and (event.host is None or len(event.host) <= 1024):
                blob = compact_event(_view(event))
                if len(blob) > MAX_CITATION:
                    blob = None
            if blob is None:
                self.note_limit("web_citation", "A known HTTP grammar match exceeded the bounded citation size; its positive count is retained")
            refused = bool(issues)
            for name, matches in sorted(found.items()):
                key = "|".join((*peers, name))
                try:
                    spill = self._db()
                    identity = hashlib.sha256(event.id.encode()).hexdigest()
                    before = spill.db.execute("SELECT n FROM web_groups WHERE k=?", (key,)).fetchone()
                    if spill.db.execute("SELECT 1 FROM web_seen WHERE k=? AND id=?", (key, identity)).fetchone():
                        continue
                    reason = self.state_budget().new_key_reason(self._account)
                    if reason:
                        raise StateExhausted(reason)
                    rank = event.ts.astimezone(UTC).isoformat(timespec="microseconds") + "|" + identity
                    spill.write("INSERT OR IGNORE INTO web_seen VALUES(?,?,?,?,?,?)",
                                [(key, identity, rank, matches, int(event.family == "net_session"), blob)], account=self._account)
                    self.state_budget().charge(self._account, len(key) + 160 + (2 * len(blob) if blob and before is None else 0))
                    if before is None:
                        yield self._match(key, 1, matches, int(event.family == "net_session"), blob, blob, final=False)
                except StateExhausted as error:
                    self.refuse("web_state", f"HTTP fold is incomplete; matching live evidence remains a lead: {error}",
                                records=0 if refused else 1)
                    refused = True
                    yield self._match(key, 1, matches, int(event.family == "net_session"), blob, blob, final=False)

    def _match(self, key, count, values, sessions, first, last, *, final):
        source, destination, name = key.split("|")
        events = []
        for blob in (first, last):
            if blob is not None:
                event = expand_event(blob)
                if not events or events[0].id != event.id:
                    events.append(event)
        partial = bool(self.capped)
        qualifier = "At least " if partial or not final else ""
        claim = (f"{qualifier}{count} recorded HTTP observation(s) from {source} to {destination} "
                 f"contain {_CLASSES[name]} ({values} distinct inspected value(s) after decoding/case folding).")
        notes = [_UNCERTAIN, "Counts deduplicate canonical event identities, not independent requests across sensors or re-indexing.",
                 "At most two representative event citations are retained; exact retained counts are independent of citation sampling.",
                 "Request bodies are not inspected. Sensitive query values are masked in retained examples."]
        if sessions:
            notes.append(f"{sessions} counted observation(s) are Arkime sessions with unordered lists; "
                         "URI, user-agent, method and status values cannot be paired and do not count individual requests.")
        if _management(self, source):
            notes.append("The source is a site-declared management host; authorized scanning is possible and the observation remains a lead.")
        if name == "exploit_tool":
            notes.append(_ATTRIBUTION)
            notes.append("Tool identifiers may be customized or spoofed; their absence does not exclude the tool.")
        else:
            notes.append("Grammar reference: OWASP CRS contributors, Apache-2.0; bounded adaptation, not complete CRS coverage.")
        if partial:
            notes.append("Inspection or retained fold coverage is partial; counts are lower bounds for observed activity.")
        return Match(self.id, claim, self.claim_type, events,
                     [pf(event, field) for event in events for field in event.fields],
                     events[-1].ts if events else None, self.severity, "lead", "medium",
                     entities=[("ip", source, "src"), ("ip", destination, "dst")], notes=notes, group_key=key,
                     bounded_revision=True, revision_reason="Final retained HTTP observation counts" if final else "",
                     citation_unavailable=not events,
                     aggregate_summary={"record_count": count, "matching_values": values, "session_count": sessions,
                                        "count_complete": int(final and not partial)}, attack=self.attack)

    def finalize(self):
        if self._ready:
            for row in self._spill.db.execute("SELECT k,n,values_n,session_n,first_event,last_event FROM web_groups ORDER BY k"):
                yield self._match(*row, final=True)

    def finalize_fallback(self, reason):
        self.note_limit("web_finalize", "HTTP fold finalization is partial: " + reason)
        return self.finalize()


class WebLoginBurst(ZeekWindowRule):
    id, title = "network.web_login_burst", "Repeated attempts at a web authentication path"
    families, producers = ("http_tx",), ZEEK_AND_SURICATA
    required_fields = ("source.ip", "destination.ip", "http.request.method", "http.response.status_code")
    citation_fields = _FIELDS
    # Twenty requests in five minutes exceeds an ordinary person's few retries,
    # but NAT, automated clients and authorized testing still require review.
    seconds, threshold, per_sensor = 300, 20, True
    severity, lane, attack = "medium", "lead", ("T1110",)
    uses_site_facts = True
    benign = ("Shared NAT, broken clients and authorized testing can generate repeated authentication attempts.",)
    next_checks = ("Compare application authentication outcomes and account evidence; HTTP status alone cannot prove success.",)
    card: ClassVar[dict] = {
        "behavior": title, "telemetry": "Zeek or Suricata HTTP transactions; Arkime lists excluded",
        "fidelity": "401/403 responses or 200 POST/explicit credential-bearing GET attempts at authentication paths, positive-only.",
        "benign_and_cost": benign[0], "query_cost": "Disk-backed five-minute window with late replay.",
        "next_pivot": next_checks[0], "research_basis": _CRS,
        "retrieval": "Typed request path, method, response status and peers; absent body/account stays unknown.",
        "lanes": "Lead at 20 attempt references in 300 seconds; no promotion from network status.",
    }

    def compact(self, event):
        return super().compact(_view(event))

    def select(self, event):
        peers = _peers(event)
        if not peers:
            return None
        value = event.get("url.original") or event.get("url.path")
        decoded, error = _decode(value, MAX_URI, fold=False)
        if error:
            self.refuse("web_login_input", "Web-login request inspection is partial: " + error)
            return None
        try:
            parsed = urlsplit(decoded)
            raw_parts = urlsplit(value)
        except ValueError:
            self.refuse("web_login_input", "Web-login request target has an invalid URL shape")
            return None
        if not _AUTH.search(parsed.path.casefold()):
            return None
        method, status = event.get("http.request.method"), event.get("http.response.status_code")
        if not isinstance(method, str) or not isinstance(status, int) or isinstance(status, bool):
            self.missing_required += 1
            return None
        method = method.casefold()
        if status not in (401, 403) and not (status == 200 and method in {"get", "post"}):
            return None
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
        query_account = credential = False
        for part in query.split("&"):
            key, equals, raw_value = part.partition("=")
            key = _form_value(key)
            if not equals or not key:
                continue
            if key.casefold() in _SECRET_KEYS and raw_value:
                credential = True
            if key.casefold() in _ACCOUNT_KEYS:
                value = _form_value(raw_value)
                if value and len(value) <= 256:
                    query_account = True
                    if not account:
                        account = value
        if status == 200 and method == "get" and not (query_account and credential):
            return None
        member = hashlib.sha256(account.encode()).hexdigest() if account else "unknown-account"
        sensor = event.get("observer.name")
        sensor = sensor if isinstance(sensor, str) and len(sensor) <= 256 else "unknown-sensor"
        return (*peers, sensor, parsed.path), member, "attempt"

    def describe(self, event, total_refs, distinct_members, role):
        notes = [
            _UNCERTAIN,
            "401/403 are HTTP failure responses, not necessarily failed credentials; 200 POST or explicit credential-bearing GET remains an attempt because a re-served login form cannot be distinguished.",
            "Twenty attempt references in five minutes is a review heuristic; counts are per sensor and authentication path.",
            "Account labels are counted across repeated or distinct users when available; unknown accounts share one unknown bucket. Request bodies are unavailable.",
        ]
        if _management(self, event.get("source.ip")):
            notes.append("The source is a site-declared management host; the observation remains a lead.")
        return "lead", (f"Source {event.get('source.ip')} has {total_refs} HTTP failure-or-attempt raw references "
                         f"to {event.get('destination.ip')}'s authentication path in five minutes "
                         f"({distinct_members} account-label bucket(s), including unknown when absent)."), tuple(notes)


WEB_ATTACK_PLAYBOOKS = (WebAttacks, WebLoginBurst)
