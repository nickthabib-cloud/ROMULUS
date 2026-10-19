"""Network and web-access playbooks (Suricata EVE, Apache access). Aggregates are exact counts
accumulated across every partition, so bursts spanning partition boundaries are not lost."""
from __future__ import annotations

from collections import defaultdict

from romulus.detect.base import Match, Playbook, pf
from romulus.evidence.typed import TypedEvent

TOOL_UA_PREFIXES = ("curl/", "wget/", "python-requests/", "python-urllib/", "go-http-client/", "libwww-perl/",
                    "powershell", "nmap", "sqlmap", "nikto", "fuzz faster u fool", "gobuster", "dirbuster")
EXAMPLE_LIMIT = 20


def _registered(name: str) -> str:
    parts = name.lower().rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else name.lower()


class _Grouped(Playbook):
    kind = "aggregate"
    claim_type = "aggregate_observation"

    def __init__(self):
        super().__init__()
        self.groups: dict[tuple, list[TypedEvent]] = defaultdict(list)
        self.counts: dict[tuple, int] = defaultdict(int)
        self.extra: dict[tuple, dict] = defaultdict(lambda: defaultdict(set))
        self._first: dict[tuple, object] = {}
        self._last: dict[tuple, object] = {}

    def keep(self, key: tuple, e: TypedEvent):
        """Exact count for every record; retain up to EXAMPLE_LIMIT cited examples per group."""
        self.counts[key] += 1
        if len(self.groups[key]) < EXAMPLE_LIMIT:
            self.groups[key].append(e)
        self._first[key] = min(self._first.get(key, e.ts), e.ts)
        self._last[key] = max(self._last.get(key, e.ts), e.ts)

    def span(self, key) -> str:
        return f"{self._first[key].isoformat()} – {self._last[key].isoformat()}"


class SuricataAlertStack(_Grouped):
    id = "net.suricata_alert_stack"
    title = "IDS alert signature observed between a source and destination"
    families = ("net_alert",)
    required_fields = ("alert.signature", "alert.severity", "source.ip", "destination.ip")
    severity, lane = "medium", "lead"
    attack = ()
    benign = ("signature false positives; scanners and crawlers on internet-facing services",)
    next_checks = ("ip_sessions for the source", "http_requests to the destination in the same minutes",
                   "entity_timeline of the destination host after the first alert")

    version = "2"

    def consume(self, events):
        """Group by (source, destination, category, severity); signatures are listed inside the group so a
        scanner triggering hundreds of signatures is one item, not hundreds."""
        for e in self.applicable(events):
            key = (e.get("source.ip"), e.get("destination.ip"), e.get("alert.category"), e.get("alert.severity"))
            self.keep(key, e)
            sigs = self.extra[key]["sigs"]
            if len(sigs) < 2000:
                sigs.add((e.get("alert.signature_id"), e.get("alert.signature")))
            tech = e.get("alert.mitre_technique_id")
            if tech:
                self.extra[key]["tech"].update(tech if isinstance(tech, list) else [tech])
        return []

    def finalize(self):
        out = []
        for key, evs in self.groups.items():
            src, dst, cat, sev = key
            n = self.counts[key]
            sigs = sorted(self.extra[key]["sigs"], key=lambda s: str(s[1]))
            if cat == "Not Suspicious Traffic" or sev == 3:
                lane, severity = "context", "low"
            elif sev == 1:
                lane, severity = "high", "high"
            else:
                lane, severity = "lead", "medium"
            names = "; ".join(f"{s[1]} (sid {s[0]})" for s in sigs[:3])
            more = f" and {len(sigs) - 3} more" if len(sigs) > 3 else ""
            claim = (f"Suricata raised {n} '{cat}' alert(s) at severity {sev} across {len(sigs)} distinct signature(s) "
                     f"for traffic from {src} to {dst} ({self.span(key)}): {names}{more}. IDS alerts are signature "
                     f"matches, not proof of successful exploitation.")
            e0 = evs[0]
            m = Match(self.id, claim, self.claim_type, evs, [pf(e0, "alert.signature"), pf(e0, "alert.severity"),
                                                            pf(e0, "source.ip"), pf(e0, "destination.ip")],
                      e0.ts, severity, lane, "medium", e0.entities(), group_key=f"{src}|{dst}|{cat}|{sev}")
            if self.extra[key]["tech"]:
                m.notes.append(f"signature metadata ATT&CK: {sorted(self.extra[key]['tech'])[:8]}")
            m.notes.append(f"signatures: {[s[0] for s in sigs[:50]]}")
            out.append(m)
        return out


class WebScanBurst(_Grouped):
    id = "web.scan_burst"
    title = "High-volume error-heavy web requests from one source"
    families = ("http_access",)
    required_fields = ("source.ip", "http.response.status_code", "url.original")
    severity, lane = "medium", "lead"
    attack = ("T1595.002", "T1595.003")
    benign = ("authorized vulnerability scans, search-engine crawlers, broken client loops",)
    next_checks = ("http_requests from the source with 2xx status after the burst",
                   "ids_alerts for the source", "entity_timeline of the web host after the burst")
    MIN_REQUESTS, MIN_ERROR_RATIO = 200, 0.5

    def consume(self, events):
        for e in self.applicable(events):
            key = (e.host, e.get("source.ip"))
            self.keep(key, e)
            try:
                st = int(e.get("http.response.status_code"))
            except (TypeError, ValueError):
                self.evaluated -= 1
                self.missing_required += 1
                continue
            ex = self.extra[key]
            if st >= 400:
                ex["errors"].add(e.id)
            if len(ex["urls"]) < 5000:
                ex["urls"].add(e.get("url.original"))
            ua = e.get("user_agent.original")
            if ua and len(ex["uas"]) < 10:
                ex["uas"].add(ua)
        return []

    def finalize(self):
        out = []
        for key, evs in self.groups.items():
            n = self.counts[key]
            errs = len(self.extra[key]["errors"])
            if n < self.MIN_REQUESTS or errs / n < self.MIN_ERROR_RATIO:
                continue
            host, src = key
            uas = sorted(self.extra[key]["uas"])
            claim = (f"{n} HTTP requests to {host} from {src} ({self.span(key)}), {errs} ({errs / n:.0%}) with "
                     f"4xx/5xx responses across {len(self.extra[key]['urls'])}+ distinct URLs.")
            m = Match(self.id, claim, self.claim_type, evs, [pf(evs[0], "source.ip")], evs[0].ts, self.severity,
                      self.lane, "high", evs[0].entities(), group_key=f"{host}|{src}")
            if uas:
                m.notes.append("user-agent strings seen (self-reported, not proof of tool): " + "; ".join(uas[:5]))
            out.append(m)
        return out


class DnsSubdomainEnumeration(_Grouped):
    id = "net.dns_subdomain_enumeration"
    title = "Many distinct subdomains of one domain queried by one source"
    families = ("dns_query",)
    required_fields = ("source.ip", "dns.question.name")
    severity, lane = "medium", "lead"
    attack = ("T1590.002",)
    benign = ("resolvers forwarding for many clients, CDN-heavy browsing, mail servers",)
    next_checks = ("ip_sessions for the source", "web.scan_burst or ids_alerts from the same source")
    MIN_DISTINCT = 100

    def consume(self, events):
        for e in self.applicable(events):
            if e.get("dns.type") not in (None, "query"):
                # answers/other record types are not evaluated by this rule: they must not count toward a
                # complete negative (an answer-only capture still carries the enumeration)
                self.evaluated -= 1
                self.missing_required += 1
                continue
            if not isinstance(e.get("dns.question.name"), str):
                self.evaluated -= 1
                self.missing_required += 1
                continue
            key = (e.get("source.ip"), _registered(e.get("dns.question.name")))
            self.keep(key, e)
            names = self.extra[key]["names"]
            if len(names) <= self.MIN_DISTINCT * 50:
                names.add(e.get("dns.question.name").lower())
        return []

    def finalize(self):
        out = []
        for key, evs in self.groups.items():
            distinct = len(self.extra[key]["names"])
            if distinct < self.MIN_DISTINCT:
                continue
            src, dom = key
            claim = (f"{src} issued {self.counts[key]} DNS queries for {distinct} distinct names under '{dom}' "
                     f"({self.span(key)}).")
            out.append(Match(self.id, claim, self.claim_type, evs, [pf(evs[0], "source.ip"),
                                                                     pf(evs[0], "dns.question.name")],
                             evs[0].ts, self.severity, self.lane, "medium", evs[0].entities(),
                             group_key=f"{src}|{dom}"))
        return out


class ToolUserAgentHttp(_Grouped):
    """Positive-only (ADR-004): the user agent is self-reported, attacker-controlled text, so its absence
    proves nothing; the prefix list also cannot see tools whose agent string does not start with the name."""
    id = "net.tool_user_agent_http"
    version = "2"
    assures_negative = False
    title = "HTTP requests whose user agent begins with a known command-line tool name"
    families = ("http_tx",)
    required_fields = ("source.ip", "destination.ip", "user_agent.original")
    severity, lane = "low", "lead"
    attack = ("T1105",)
    benign = ("health checks, package managers, monitoring scripts",)
    next_checks = ("process executions on the source host at the same time", "file_transfer for what was fetched")

    def consume(self, events):
        for e in self.applicable(events):
            ua = e.get("user_agent.original")
            if not isinstance(ua, str):
                self.evaluated -= 1
                self.missing_required += 1
                continue
            ua = ua.lower()
            if not ua.startswith(TOOL_UA_PREFIXES):
                continue
            key = (e.get("source.ip"), e.get("destination.ip"), e.get("http.hostname"), ua.split(" ")[0])
            self.keep(key, e)
            if len(self.extra[key]["urls"]) < 50:
                self.extra[key]["urls"].add(e.get("url.original"))
        return []

    def finalize(self):
        out = []
        for key, evs in self.groups.items():
            src, dst, hostname, ua = key
            urls = sorted(u for u in self.extra[key]["urls"] if u)
            claim = (f"{self.counts[key]} HTTP request(s) from {src} to {dst} (Host: {hostname}) with user agent "
                     f"'{ua}' ({self.span(key)}); URLs include {urls[:3]}. The user agent is self-reported.")
            out.append(Match(self.id, claim, self.claim_type, evs, [pf(evs[0], "user_agent.original"),
                                                                     pf(evs[0], "source.ip")],
                             evs[0].ts, self.severity, self.lane, "medium", evs[0].entities(),
                             group_key=f"{src}|{dst}|{ua}"))
        return out


class PortScan(_Grouped):
    id = "net.port_scan"
    title = "One source contacted many distinct ports on one destination"
    families = ("net_flow",)
    required_fields = ("source.ip", "destination.ip", "destination.port")
    severity, lane = "medium", "lead"
    attack = ("T1046", "T1595.001")
    benign = ("authorized vulnerability scanners, monitoring systems, some service discovery",)
    next_checks = ("ids_alerts for the source", "web.scan_burst / http_requests from the source afterwards",
                   "ip_sessions for the source across the network")
    MIN_PORTS = 25

    def consume(self, events):
        for e in self.applicable(events):
            key = (e.get("source.ip"), e.get("destination.ip"))
            self.keep(key, e)
            ports = self.extra[key]["ports"]
            if len(ports) < 70000:
                try:
                    ports.add(int(e.get("destination.port")))
                except (TypeError, ValueError):
                    self.missing_required += 1
        return []

    def finalize(self):
        out = []
        for key, evs in self.groups.items():
            ports = self.extra[key]["ports"]
            if len(ports) < self.MIN_PORTS:
                continue
            src, dst = key
            sample = sorted(ports)[:12]
            claim = (f"{self.counts[key]} flow record(s) from {src} to {dst} covering {len(ports)} distinct destination "
                     f"ports ({self.span(key)}); e.g. {sample}.")
            out.append(Match(self.id, claim, self.claim_type, evs, [pf(evs[0], "source.ip"),
                                                                     pf(evs[0], "destination.ip")],
                             evs[0].ts, self.severity, self.lane, "high", evs[0].entities(),
                             group_key=f"{src}|{dst}"))
        return out


NETWORK_PLAYBOOKS = [SuricataAlertStack, WebScanBurst, DnsSubdomainEnumeration, ToolUserAgentHttp, PortScan]
