"""Zeek's own alerts: intel matches, signature matches, notices and weirds (net_alert records with alert.provider
"zeek").

What Zeek's frameworks say, and how much each statement is worth:
- intel (base/frameworks/intel/main.zeek): a value Zeek saw in traffic is on an indicator list the sensor loaded. The
  match is the sensor's own; every one is reported (lead), naming the indicator, where Zeek saw it and the lists.
- signatures (base/frameworks/signatures/main.zeek): a site-written signature matched. Every match is reported (lead).
- notice (base/frameworks/notice/main.zeek): a script concluded something. A notice type is judged by the table below,
  each entry sourced to the Zeek (or package) script that raises it; a notice type outside the table is a
  low-severity lead, named, never dropped.
- weird (base/frameworks/notice/weird.zeek): a protocol violation or parsing anomaly. Alone it is context, never a
  finding: weirds are routine on real networks (checksums, truncation, unusual but legal traffic). The exception is
  the shape of IDS evasion or crafted probes (overlapping or inconsistent fragments, all-flags TCP), which is a lead.

Every claim names the provider and the kind of record ("Zeek's intel framework matched", "Zeek raised notice"). The rule
is positive-only: the absence of a Zeek alert says nothing, so no negative is ever claimed. Groups are exact counts
with bounded examples (the shared grouped-alert machinery of romulus.detect.network): intel, signature and tabled
notice items per (kind, name, source, destination); untabled notices and weirds per (kind, name) across every
address pair, so a weird-heavy sensor gives one context item per weird name.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from romulus.detect.base import Match, pf
from romulus.detect.citing import bound_note, citation_group, more
from romulus.detect.network import _Grouped, _values
from romulus.detect.site_roles import address_member
from romulus.evidence.typed import TypedEvent

ZEEK = "zeek"
MESSAGE_CHARS = 200             # a quoted message is cut here (Zeek messages can carry attacker-controlled text)
MESSAGES_HELD = 3               # distinct messages kept per group
# Weirds that are the shape of IDS evasion or crafted probes rather than offload, truncation or legal oddities:
# overlapping or inconsistent IP fragments (the reassembly ambiguity evasion relies on) and all-flags TCP packets.
EVASION_WEIRDS = frozenset({"fragment_overlap", "fragment_inconsistency", "fragment_size_inconsistency",
                            "excessively_small_fragment", "TCP_Christmas"})
PAIRS_HELD = 64                 # distinct address pairs kept per pairless group (untabled notices, weirds)
PAIRS_NAMED = 5


@dataclass(frozen=True)
class NoticeType:
    """What one Zeek notice type means, the lane it gets, and the script that raises it."""
    meaning: str
    lane: str
    severity: str
    attack: tuple[str, ...]
    source: str


_SCAN = "policy/misc/scan.zeek"
_SSH_BRUTE = "policy/protocols/ssh/detect-bruteforcing.zeek"
_FTP_BRUTE = "policy/protocols/ftp/detect-bruteforcing.zeek"
_SQLI = "policy/protocols/http/detect-sqli.zeek"
_HEARTBLEED = "policy/protocols/ssl/heartbleed.zeek"
_BZAR = "github.com/mitre-attack/bzar scripts/bzar_dce-rpc_consts.zeek and bzar_smb_main.zeek"
_ETERNAL = "github.com/0xl3x1/zeek-EternalSafety scripts/main.zeek (shipped with Malcolm)"

# Zeek notice types with a judgement. Documentation for each script: https://docs.zeek.org/en/current/scripts/<source>.html
# for Zeek's own; the package's repository for the others. ATT&CK ids are Enterprise 20.0 (checked against the bundle).
NOTICE_TYPES: dict[str, NoticeType] = {
    "Scan::Port_Scan": NoticeType("one host contacted many ports of another host", "lead", "medium",
                                  ("T1046",), _SCAN),
    "Scan::Address_Scan": NoticeType("one host contacted many hosts on one port", "lead", "medium",
                                     ("T1046", "T1018"), _SCAN),
    "SSH::Password_Guessing": NoticeType("a host failed SSH logins at a password-guessing rate", "lead", "high",
                                         ("T1110.001",), _SSH_BRUTE),
    "SSH::Login_By_Password_Guesser": NoticeType("a host Zeek had marked as an SSH password guesser then logged in "
                                                 "(by Zeek's heuristic)", "high", "high", ("T1110.001", "T1021.004"),
                                                 _SSH_BRUTE),
    "FTP::Bruteforcing": NoticeType("a host failed FTP logins at a password-guessing rate", "lead", "high",
                                    ("T1110.001",), _FTP_BRUTE),
    "FTP::Site_Exec_Success": NoticeType("an FTP SITE EXEC command succeeded", "high", "high", ("T1059",),
                                         "policy/protocols/ftp/detect.zeek"),
    "HTTP::SQL_Injection_Attacker": NoticeType("a host sent requests matching SQL injection patterns at a rate",
                                               "lead", "medium", ("T1190",), _SQLI),
    "HTTP::SQL_Injection_Victim": NoticeType("a host received requests matching SQL injection patterns at a rate",
                                             "lead", "medium", ("T1190",), _SQLI),
    "Heartbleed::SSL_Heartbeat_Attack": NoticeType("a TLS heartbeat request shaped like a Heartbleed attempt", "lead",
                                                   "medium", ("T1190",), _HEARTBLEED),
    "Heartbleed::SSL_Heartbeat_Attack_Success": NoticeType("a TLS heartbeat response larger than its request (a "
                                                           "Heartbleed read that the server answered)", "high",
                                                           "high", ("T1190",), _HEARTBLEED),
    "Heartbleed::SSL_Heartbeat_Odd_Length": NoticeType("a TLS heartbeat with an inconsistent length", "lead",
                                                       "medium", ("T1190",), _HEARTBLEED),
    "Heartbleed::SSL_Heartbeat_Many_Requests": NoticeType("many TLS heartbeat requests on one connection", "lead",
                                                          "medium", ("T1190",), _HEARTBLEED),
    "TeamCymruMalwareHashRegistry::Match": NoticeType("a transferred file's hash is in Team Cymru's malware hash "
                                                      "registry", "high", "high", ("T1105",),
                                                      "policy/frameworks/files/detect-MHR.zeek"),
    "Software::Vulnerable_Version": NoticeType("a host announced software at a version the site lists as vulnerable",
                                               "lead", "low", ("T1190",), "policy/frameworks/software/vulnerable.zeek"),
    "DNS::External_Name": NoticeType("a name in a local zone resolved to an address outside the local networks",
                                     "lead", "low", ("T1071.004",), "policy/protocols/dns/detect-external-names.zeek"),
    "ProtocolDetector::Protocol_Found": NoticeType("a protocol was found on a port not registered for it", "lead",
                                                   "low", ("T1571",), "policy/frameworks/dpd/detect-protocols.zeek"),
    "ProtocolDetector::Server_Found": NoticeType("a server for a protocol was found on a port not registered for it",
                                                 "lead", "low", ("T1571",),
                                                 "policy/frameworks/dpd/detect-protocols.zeek"),
    "Intel::Notice": NoticeType("an intel indicator marked for notices was seen", "lead", "medium", (),
                                "policy/frameworks/intel/do_notice.zeek"),
    "Signatures::Sensitive_Signature": NoticeType("a signature marked sensitive matched", "lead", "medium", (),
                                                  "base/frameworks/signatures/main.zeek"),
    "Signatures::Multiple_Signatures": NoticeType("one host triggered several different signatures", "lead",
                                                  "medium", (), "base/frameworks/signatures/main.zeek"),
    "Signatures::Multiple_Sig_Responders": NoticeType("one signature matched against many responders", "lead",
                                                      "medium", (), "base/frameworks/signatures/main.zeek"),
    "Signatures::Count_Signature": NoticeType("a signature matched a counted number of times", "lead", "medium", (),
                                              "base/frameworks/signatures/main.zeek"),
    "SSL::Invalid_Server_Cert": NoticeType("a server certificate failed validation", "context", "low", (),
                                           "policy/protocols/ssl/validate-certs.zeek"),
    "SSL::Certificate_Expired": NoticeType("a server presented an expired certificate", "context", "low", (),
                                           "policy/protocols/ssl/expiring-certs.zeek"),
    "SSL::Weak_Key": NoticeType("a server certificate has a weak key", "context", "low", (),
                                "policy/protocols/ssl/weak-keys.zeek"),
    "SSL::Old_Version": NoticeType("a TLS session used an old protocol version", "context", "low", (),
                                   "policy/protocols/ssl/weak-keys.zeek"),
    "SSL::Weak_Cipher": NoticeType("a TLS session used a weak cipher", "context", "low", (),
                                   "policy/protocols/ssl/weak-keys.zeek"),
    "CaptureLoss::Too_Much_Loss": NoticeType("the sensor estimated capture loss above its threshold (what it did not "
                                             "see was not searched)", "context", "low", (),
                                             "policy/misc/capture-loss.zeek"),
    "Weird::Activity": NoticeType("a weird marked for notices", "context", "low", (),
                                  "base/frameworks/notice/weird.zeek"),
    # MITRE's BZAR package: DCE-RPC and SMB activity mapped to ATT&CK tactics
    "ATTACK::Lateral_Movement": NoticeType("an SMB write to an administrative share (BZAR)", "lead", "high",
                                           ("T1021.002", "T1570"), _BZAR),
    "ATTACK::Lateral_Movement_Extracted_File": NoticeType("a file written to an administrative share and extracted "
                                                          "(BZAR)", "lead", "high", ("T1021.002", "T1570"), _BZAR),
    "ATTACK::Lateral_Movement_and_Execution": NoticeType("a file written to an administrative share and then a "
                                                         "remote execution call on the same host (BZAR)", "high",
                                                         "high", ("T1021.002", "T1569.002"), _BZAR),
    "ATTACK::Execution": NoticeType("a remote execution RPC call (service control or task scheduler, BZAR)", "lead",
                                    "high", ("T1569.002", "T1053.005"), _BZAR),
    "ATTACK::Persistence": NoticeType("a remote persistence RPC call (BZAR)", "lead", "high", ("T1053.005",), _BZAR),
    "ATTACK::Credential_Access": NoticeType("a directory replication or credential RPC call (BZAR)", "high", "high",
                                            ("T1003.006",), _BZAR),
    "ATTACK::Defense_Evasion": NoticeType("a remote event log clearing RPC call (BZAR)", "high", "high",
                                          ("T1685.005",), _BZAR),
    "ATTACK::Discovery": NoticeType("a remote account or share enumeration RPC call (BZAR)", "lead", "medium",
                                    ("T1087.002", "T1135"), _BZAR),
    "EternalSafety::EternalBlue": NoticeType("SMB traffic shaped like the EternalBlue exploit", "high", "high",
                                             ("T1210",), _ETERNAL),
    "EternalSafety::EternalSynergy": NoticeType("SMB traffic shaped like the EternalSynergy exploit", "high", "high",
                                                ("T1210",), _ETERNAL),
    "EternalSafety::EternalRomance": NoticeType("SMB traffic shaped like the EternalRomance exploit", "high", "high",
                                                ("T1210",), _ETERNAL),
    "EternalSafety::EternalChampion": NoticeType("SMB traffic shaped like the EternalChampion exploit", "high", "high",
                                                 ("T1210",), _ETERNAL),
    "EternalSafety::DoublePulsar": NoticeType("SMB traffic shaped like the DoublePulsar implant's control channel",
                                              "high", "high", ("T1210",), _ETERNAL),
}
KIND_WORDS = {"intel": ("intel match", "intel matches"), "signature": ("signature match", "signature matches"),
              "notice": ("notice", "notices"), "weird": ("weird record", "weird records")}


def zeek_alert(event: TypedEvent) -> bool:
    """A net_alert record Zeek's frameworks wrote (its provider field says so)."""
    return event.family == "net_alert" and event.get("alert.provider") == ZEEK


def _text(value) -> str | None:
    values = [v for v in _values(value) if isinstance(v, str) and v.strip()]
    return values[0].strip() if values else None


def _quoted(text: str) -> str:
    text = text if len(text) <= MESSAGE_CHARS else text[:MESSAGE_CHARS] + "..."
    return "'" + text.replace("'", "’") + "'"


class ZeekAlerts(_Grouped):
    """Zeek's intel and signature matches, notices judged by a sourced table of notice types, and weirds as
    context."""
    id = "net.zeek_alert"
    version = "3"
    uses_site_facts = True
    title = "Zeek intel match, signature match or notice"
    families = ("net_alert",)
    required_fields = ()
    severity, lane = "medium", "lead"
    attack = tuple(sorted({t for notice in NOTICE_TYPES.values() for t in notice.attack}))
    assures_negative = False
    positive_only_reason = ("the rule reports what Zeek's frameworks concluded; a sensor that raised nothing has not "
                            "shown that nothing happened, so no negative is claimed")
    benign = ("intel lists that include shared hosting or content-delivery addresses",
              "site signatures written broadly", "vulnerability scanners triggering scan and injection notices",
              "weirds from checksum offload, truncation and unusual but legal traffic")
    next_checks = ("the connection's other Zeek records by uid (conn, http, files)",
                   "the source host's process for the connection",
                   "for intel: the list entry and its source; for notices: the script's threshold at the site")
    card: ClassVar[dict] = {
        "behavior": "Zeek's intel framework matched a listed value, its signature engine matched a site signature, "
                    "or a Zeek script raised a notice; notices are judged by a table of notice types, each sourced "
                    "to the script that raises it, a notice type outside the table is a lead, and a weird is "
                    "context unless it has the shape of IDS evasion or a crafted probe",
        "telemetry": "Zeek intel, signatures, notice and weird logs as net_alert with alert.provider zeek "
                     "(alert.kind, alert.signature, alert.message, intel.indicator, intel.seen_where, "
                     "intel.sources, source and destination addresses), in each shipper shape Zeek is read from",
        "fidelity": "the sensor's own conclusions, read from typed fields: an intel match is a list membership, a "
                    "notice is a script's heuristic. Positive-only",
        "benign_and_cost": "broad lists and signatures, scanners, routine weirds. One item per (kind, name, source, "
                           "destination) for intel, signature and tabled notices; one per name for untabled notices "
                           "and weirds",
        "query_cost": "none beyond the sweep",
        "next_pivot": "the connection's other Zeek records by uid, and the owning process",
        "adds": "net.suricata_alert_stack reads Suricata's alerts only; this rule reads Zeek's",
        "research_basis": "Zeek script documentation for each notice type (docs.zeek.org/en/current/scripts/...), "
                          "MITRE BZAR for ATTACK:: notices, zeek-EternalSafety for EternalSafety:: notices; ATT&CK "
                          "Enterprise 20.0",
        "retrieval": "the sweep retrieves every record of the network targets in each partition, a superset of what "
                     "this evaluator reads",
        "lanes": "intel and signature matches lead; tabled notices at their table lane (high only where the notice "
                 "states a completed step: a login after guessing, a successful Heartbleed read, a malware hash, "
                 "remote execution or replication calls, exploit-shaped SMB); untabled notices lead at low "
                 "severity; evasion-shaped weirds lead at low severity; other weirds context",
    }

    def scope_partition(self, events: list[TypedEvent]) -> list[TypedEvent]:
        return [event for event in super().scope_partition(events) if zeek_alert(event)]

    @staticmethod
    def _key(e: TypedEvent) -> tuple | None:
        kind = e.get("alert.kind")
        src, dst = e.get("source.ip"), e.get("destination.ip")
        if kind == "intel":
            name = _text(e.get("intel.indicator"))
        elif kind in ("signature", "notice", "weird"):
            name = _text(e.get("alert.signature"))
        else:
            return None
        if name is None:
            return None
        if kind == "weird" or (kind == "notice" and name not in NOTICE_TYPES):
            return (kind, name, "", "")
        return (kind, name, src or "", dst or "")

    def consume(self, events):
        for e in self.applicable([event for event in events if zeek_alert(event)]):
            key = self._key(e)
            if key is None:
                self.evaluated -= 1
                self.missing_required += 1      # no name to report it by: counted, never a clean evaluation
                continue
            state = self.keep(key, e)
            if state is None:
                continue
            state.count += len({ref.key for ref in e.raw}) - 1
            message = _text(e.get("alert.message"))
            messages = state.bag("messages")
            if message is not None and len(messages) < MESSAGES_HELD:
                messages.add(message)
            if key[2:] == ("", ""):
                pairs = state.bag("pairs")
                pair = (str(e.get("source.ip") or "?"), str(e.get("destination.ip") or "?"))
                if pair in pairs or len(pairs) < PAIRS_HELD:
                    pairs.add(pair)
                else:
                    state.extra["pairs_capped"] = True
                self.name(state, "pairs", pair, e, PAIRS_NAMED)
            if key[0] == "intel":
                for name, field in (("where", "intel.seen_where"), ("sources", "intel.sources"),
                                    ("types", "intel.indicator_type")):
                    bag = state.bag(name)
                    for value in _values(e.get(field)):
                        if isinstance(value, str) and value and len(bag) < 16:
                            bag.add(value)
        return []

    @staticmethod
    def judged(key: tuple) -> tuple[str, str]:
        """(lane, severity) of a group."""
        kind, name = key[0], key[1]
        if kind in ("intel", "signature"):
            return "lead", "medium"
        if kind == "notice" and name in NOTICE_TYPES:
            notice = NOTICE_TYPES[name]
            return notice.lane, notice.severity
        if kind == "notice":
            return "lead", "low"      # an untabled notice may come from a site's exploit or CVE package
        if kind == "weird" and name in EVASION_WEIRDS:
            return "lead", "low"
        return "context", "low"

    def site_decision(self, key):
        lane, severity = self.judged(key)
        notes = ()
        # The default BZAR Credential_Access table consists of DRSUAPI replication calls.
        # This is still the sensor script's heuristic, never independent proof of replication.
        if key[:2] == ('notice', 'ATTACK::Credential_Access'):
            controllers = getattr(getattr(self, 'site_facts', None), 'domain_controller_addresses', ())
            if not controllers:
                notes = ('domain controller addresses not declared; the notice remains high',)
            elif address_member(key[2], controllers) and address_member(key[3], controllers):
                lane, severity = 'lead', 'medium'
                notes = (('Traffic between declared domain controllers can be routine replication; '
                          'the BZAR DRSUAPI notice remains a review lead.'),)
        return lane, severity, notes

    def finalize(self):
        out = []
        for key, state in self.reported():
            with citation_group(self, out, key, state):
                out.append(self._match(key, state))
        return out

    def _match(self, key: tuple, state) -> Match:
        kind, name, src, dst = key
        lane, severity, policy_notes = self.site_decision(key)
        evs, missing, context = self.cite(state)
        n = state.count
        span = self.span(state)
        between = f" on traffic from {src or 'an unrecorded source'} to {dst or 'an unrecorded destination'}" \
            if (src, dst) != ("", "") or kind in ("intel", "signature") or name in NOTICE_TYPES else ""
        messages = sorted(state.bag("messages"))
        said = f" Zeek's message: {'; '.join(_quoted(m) for m in messages)}." if messages else ""
        notes = list(policy_notes)
        if kind == "intel":
            where = ", ".join(sorted(state.bag("where"))) or "a place not recorded"
            types = ", ".join(sorted(state.bag("types")))
            lists = ", ".join(sorted(state.bag("sources")))
            claim = (f"Zeek's intel framework matched indicator {_quoted(name)}"
                     + (f" ({types})" if types else "") + f" {n} time(s){between} ({span}), seen in {where}"
                     + (f"; the indicator came from {lists}" if lists else "") + "."
                     + " An intel match says the value is on a list the sensor loaded, not that the traffic was "
                       "malicious.")
        elif kind == "signature":
            claim = (f"Zeek's signature engine matched signature {_quoted(name)} {n} time(s){between} ({span})."
                     + said + " A signature match is a pattern in the traffic, not proof of what it did.")
        elif kind == "notice" and name in NOTICE_TYPES:
            notice = NOTICE_TYPES[name]
            claim = (f"Zeek raised notice {name} {n} time(s){between} ({span}): by its script ({notice.source}), "
                     f"{notice.meaning}." + said + " A notice is the conclusion of a Zeek script's heuristic.")
            if notice.attack:
                notes.append(f"ATT&CK context: {', '.join(notice.attack)}")
        else:
            pairs = sorted(state.names("pairs", PAIRS_NAMED).values())
            total = len(state.bag("pairs"))
            at_least = "at least " if state.extra.get("pairs_capped") else ""
            shown = ", ".join(f"{a} to {b}" for a, b in pairs) + more(len(pairs), total)
            what = (f"Zeek raised notice {name}" if kind == "notice" else f"Zeek logged weird {_quoted(name)}")
            claim = (f"{what} {n} time(s) ({span}) across {at_least}{total} address pair(s) ({shown})." + said
                     + (" This notice type is not in ROMULUS's table of Zeek notice types, so it is a lead: a "
                        "site's detection or CVE package may raise it, and its meaning is the script's."
                        if kind == "notice" else
                        " This weird is the shape of IDS evasion or a crafted probe, so it is a lead."
                        if name in EVASION_WEIRDS else
                        " A weird is a protocol or parsing anomaly; alone it is context, not a finding."))
        claim = claim.replace(f'{n} time(s)', f'{n} raw reference(s)')
        cited_refs = len({ref.key for event in evs for ref in event.raw})
        claim += (f' {cited_refs} raw reference(s) are cited as bounded examples; '
                  'raw references can describe the same network action.')
        claim += bound_note(missing, state.ends)
        if missing:
            notes.append('Citation coverage is partial: supporting records could not all be retained.')
        e0 = evs[0]
        named = "intel.indicator" if kind == "intel" else "alert.signature"
        predicates = [pf(e0, field) for field in (named, "alert.kind", "source.ip", "destination.ip") if e0.has(field)]
        match = Match(self.id, claim, self.claim_type, evs, predicates, e0.ts, severity, lane, "high",
                      e0.entities(), group_key="|".join(str(part) for part in key), context_ids=context)
        match.notes.extend(notes)
        return match

    def uncited_finding(self, key, state, match):
        match.proposed_lane, match.severity, notes = self.site_decision(key)
        match.notes.extend(notes)
        match.group_key = "|".join(str(part) for part in key)
        return match


ZEEK_ALERT_PLAYBOOKS = [ZeekAlerts]
