"""Recommendations for the partner, built from the reportable findings and the ATT&CK mitigations they map to.

Each finding's techniques are its own validated ATT&CK context when it carries one, else its rule's. Every technique
is resolved in the pinned ATT&CK release (Enterprise or ICS, by the rule's domain first) and mapped through the
release's `mitigates` relationships to its mitigations. One recommendation is made per mitigation, listing the
techniques, findings and entities it addresses; its priority comes from the strongest finding it addresses:

- immediate:   an urgent finding, a high finding of critical or high severity, or a finding an analyst confirmed
               malicious;
- near-term:   any other high finding, or a lead of critical or high severity;
- longer-term: any other lead.

A finding the AI agent proposed is unconfirmed, so it raises a recommendation to near-term at most until an analyst
confirms it malicious; a finding an analyst marked benign or expected raises it no higher than longer-term. A finding with no technique, or whose
techniques have no actionable mitigation in the release, gets a triage recommendation at its own priority: no
reportable finding is left out. A finding whose claim is a mention (text a record contains) drives no
recommendation: it is counted and listed apart. Lists are bounded and every count is exact; distinct entities are
counted on disk (`romulus.report.spill`). Recommendations are suggestions for human decision, never actions taken.
"""
from __future__ import annotations

from collections import Counter

from romulus.catalog.mitigations import ATTRIBUTION, NOT_ACTIONABLE, load_mitigations
from romulus.report.spill import scratch_db

LABEL = "Suggestions for human decision, never automated actions"
PRIORITIES = ("immediate", "near_term", "longer_term")
# ids listed per recommendation (the rest are counted), entities listed, checks listed, techniques listed
FINDING_IDS = 50
ENTITIES = 20
CHECKS = 10
TECHNIQUES = 40
MENTION_IDS = 50
# ATT&CK for ICS mitigations that would mean actively probing OT devices: ROMULUS recommends passive measures only
OT_ACTIVE_PROBING = frozenset({"M0916"})
CLEARED = frozenset({"benign", "expected_activity"})
# every recommendation from ATT&CK for ICS carries this: ATT&CK's wording (audits or scans of systems) is never an
# instruction to touch control devices
OT_CAVEAT = ("Passive measures only on OT devices: do not scan, probe or actively query controllers or field devices; "
             "use configuration reviews, vendor information and logs, under the asset owner's change procedures.")
TRIAGE_TEXT = ("Verify and scope these findings: confirm with the system owners whether the activity was authorized, "
               "identify every affected host and account, and contain what is not authorized. ATT&CK maps no "
               "actionable mitigation to them.")
MENTION_NOTE = ("A mention is text a record contains, not an action: these findings are listed with the others, and "
                "no recommendation rests on them")
TRIAGE_REASONS = {"no_technique": "no ATT&CK technique", "unknown_technique": "technique not in the ATT&CK release",
                  "no_mitigation": "ATT&CK maps no mitigation", "not_actionable": "ATT&CK states no preventive "
                  "control applies", "passive_only": "the only mitigation would probe OT devices",
                  "attack_unavailable": "ATT&CK mitigation data unavailable"}


def finding_priority(finding: dict) -> tuple[str, str]:
    """The priority one finding gives a recommendation, and why."""
    lane, severity = finding.get("lane"), finding.get("severity")
    status = finding.get("analyst_status")
    strong = severity in ("critical", "high")
    if status == "confirmed_malicious":
        # an analyst's confirmation outranks the AI agent's cap: the finding is no longer unconfirmed
        return "immediate", ("an analyst confirmed an AI agent finding malicious" if finding.get("provenance") == "agent"
                             else "an analyst confirmed a finding malicious")
    if status in CLEARED:
        return "longer_term", f"an analyst marked the finding {status.replace('_', ' ')}"
    if lane == "urgent" or (lane == "high" and strong):
        level, reason = "immediate", ("an urgent finding" if lane == "urgent" else f"a high finding of {severity} "
                                      "severity")
    elif lane == "high" or (lane == "lead" and strong):
        level, reason = "near_term", ("a high finding" if lane == "high" else f"a lead of {severity} severity")
    else:
        level, reason = "longer_term", "a lead"
    if finding.get("provenance") == "agent" and level == "immediate":
        return "near_term", reason + " proposed by the AI agent (unconfirmed)"
    return level, reason + (" proposed by the AI agent (unconfirmed)" if finding.get("provenance") == "agent" else "")


def _techniques(finding: dict, rules: dict) -> tuple[tuple[str, ...], str | None]:
    rule = rules.get(finding.get("rule_id"))
    domain = getattr(rule, "attack_domain", None) if rule is not None else None
    own = tuple(str(item) for item in finding.get("attack") or ())
    if own:
        return own, domain
    return tuple(str(item) for item in getattr(rule, "attack", ()) or ()), domain


class _Group:
    """One recommendation being built: exact counts, bounded lists."""

    def __init__(self, key: int):
        self.key = key
        self.findings = 0
        self.ids: list[str] = []
        self.lanes: Counter = Counter()
        self.agent = 0
        self.priority: tuple[int, str, str] | None = None
        self.techniques: Counter = Counter()
        self.checks: Counter = Counter()
        self.reasons: Counter = Counter()

    def add(self, finding: dict, priority: tuple[str, str]) -> None:
        self.findings += 1
        if len(self.ids) < FINDING_IDS:
            self.ids.append(finding["id"])
        self.lanes[finding.get("lane")] += 1
        self.agent += finding.get("provenance") == "agent"
        rank = (PRIORITIES.index(priority[0]), priority[1], finding["id"])
        if self.priority is None or rank[0] < self.priority[0]:
            self.priority = rank
        for check in dict.fromkeys(str(item) for item in finding.get("next_checks") or ()):
            self.checks[check] += 1


def _bounded_ids(group: _Group) -> dict:
    return {"count": group.findings, "ids": list(group.ids), "more": group.findings - len(group.ids),
            "lanes": dict(sorted(group.lanes.items())), "agent": group.agent}


def _checks(group: _Group) -> dict:
    ordered = sorted(group.checks.items(), key=lambda pair: (-pair[1], pair[0]))
    return {"count": len(ordered), "items": [{"check": check, "findings": count} for check, count in ordered[:CHECKS]],
            "more": max(0, len(ordered) - CHECKS)}


def build(findings: list[dict], rules: dict, *, index=None, scratch=None) -> dict:
    """The recommendations view of the manifest for `findings` (reportable findings in report order); `rules` maps
    rule ids to their metadata (techniques and ATT&CK domain)."""
    status, reason = "complete", None
    if index is None:
        try:
            index = load_mitigations()
        except Exception as exc:  # noqa: BLE001 - unreadable ATT&CK data leaves every finding on triage, never lost
            status, reason = "unavailable", f"ATT&CK mitigation data could not be read: {type(exc).__name__}: {exc}"
    groups: dict[tuple, _Group] = {}
    technique_rows: dict[tuple[str, str], dict] = {}
    unknown: Counter = Counter()
    mentions: list[str] = []
    mention_count = 0
    counts = Counter()
    with scratch_db(scratch) as db:
        db.execute("CREATE TABLE entity (rec INTEGER, kind TEXT, value TEXT, seq INTEGER, "
                   "PRIMARY KEY (rec, kind, value)) WITHOUT ROWID")

        def group(key: tuple) -> _Group:
            if key not in groups:
                groups[key] = _Group(len(groups))
            return groups[key]

        for seq, finding in enumerate(findings):
            counts["findings"] += 1
            if finding.get("claim_type") == "mention":
                mention_count += 1
                if len(mentions) < MENTION_IDS:
                    mentions.append(finding["id"])
                continue
            priority = finding_priority(finding)
            techniques, domain = _techniques(finding, rules)
            mapped: dict[str, list[str]] = {}
            reasons: set[str] = set()
            if not techniques:
                reasons.add("no_technique")
            for technique in dict.fromkeys(techniques):
                resolved = index.resolve(technique, domain) if index is not None else None
                if resolved is None:
                    if index is not None:
                        unknown[technique] += 1
                    reasons.add("unknown_technique" if index is not None else "attack_unavailable")
                    continue
                technique_domain, technique_id = resolved
                pairs, basis = index.mitigations_for(technique_domain, technique_id)
                actionable = []
                for mitigation_id, guidance in pairs:
                    if mitigation_id in NOT_ACTIONABLE:
                        reasons.add("not_actionable")
                    elif technique_domain == "ics" and mitigation_id in OT_ACTIVE_PROBING:
                        reasons.add("passive_only")
                    else:
                        actionable.append(mitigation_id)
                        mapped.setdefault(f"{technique_domain}:{mitigation_id}", []).append(technique_id)
                if not pairs:
                    reasons.add("no_mitigation")
                row = technique_rows.setdefault((technique_domain, technique_id), {
                    "id": technique_id, "domain": technique_domain,
                    "name": index.techniques[(technique_domain, technique_id)].name, "findings": 0,
                    "mitigations": actionable, "basis": basis,
                    "guidance": {mitigation_id: guidance for mitigation_id, guidance in pairs
                                 if mitigation_id in actionable}})
                row["findings"] += 1
            targets = ([("mitigation", key) for key in sorted(mapped)] if mapped
                       else [("triage", priority[0])])
            counts["with_mitigation" if mapped else "triage"] += 1
            entities = list(dict.fromkeys((str(item[0]), str(item[1])) for item in finding.get("entities") or ()
                                          if isinstance(item, (list, tuple)) and len(item) >= 2))
            for target in targets:
                built = group(target)
                built.add(finding, priority)
                if target[0] == "mitigation":
                    built.techniques.update(dict.fromkeys(mapped[target[1]], 1))
                else:
                    built.reasons.update(reasons or {"no_technique"})
                db.executemany("INSERT OR IGNORE INTO entity VALUES (?, ?, ?, ?)",
                               [(built.key, kind, value, seq) for kind, value in entities])
        items = []
        for key, built in groups.items():
            entity_count = db.execute("SELECT count(*) FROM entity WHERE rec = ?", (built.key,)).fetchone()[0]
            listed = db.execute("SELECT kind, value FROM entity WHERE rec = ? ORDER BY seq, kind, value LIMIT ?",
                                (built.key, ENTITIES)).fetchall()
            level, why, finding_id = built.priority
            item = {"priority": PRIORITIES[level], "priority_reason": f"{why} ({finding_id})",
                    "findings": _bounded_ids(built),
                    "entities": {"count": entity_count, "items": [list(row) for row in listed],
                                 "more": entity_count - len(listed)},
                    "next_checks": _checks(built)}
            if key[0] == "mitigation":
                domain, mitigation_id = key[1].split(":", 1)
                mitigation = index.mitigations[(domain, mitigation_id)]
                techniques = sorted(built.techniques.items(), key=lambda pair: (-pair[1], pair[0]))
                item.update({
                    "id": f"rec-{domain}-{mitigation_id}", "kind": "attack_mitigation",
                    "mitigation": {"id": mitigation_id, "name": mitigation.name, "domain": domain,
                                   "summary": mitigation.summary, "url": mitigation.url,
                                   "stix_id": mitigation.stix_id},
                    "text": f"{mitigation.name} ({mitigation_id}): {mitigation.summary}"
                            + (f" {OT_CAVEAT}" if domain == "ics" else ""),
                    "techniques": {"count": len(techniques), "items": [
                        {"id": technique_id, "name": technique_rows[(domain, technique_id)]["name"],
                         "findings": count, "basis": technique_rows[(domain, technique_id)]["basis"],
                         "guidance": technique_rows[(domain, technique_id)]["guidance"].get(mitigation_id, "")}
                        for technique_id, count in techniques[:TECHNIQUES]],
                        "more": max(0, len(techniques) - TECHNIQUES)},
                })
                if domain == "ics":
                    item["caveat"] = OT_CAVEAT
            else:
                item.update({"id": f"rec-triage-{key[1]}", "kind": "triage", "text": TRIAGE_TEXT,
                             "reasons": {name: built.reasons[name] for name in TRIAGE_REASONS if built.reasons[name]}})
            items.append(item)
    items.sort(key=lambda item: (PRIORITIES.index(item["priority"]), item["kind"] != "attack_mitigation",
                                 -item["findings"]["count"], item["id"]))
    techniques_view = sorted(technique_rows.values(), key=lambda row: (row["domain"], row["id"]))
    view = {
        "label": LABEL, "status": status,
        "attack": {"versions": dict(index.version) if index is not None else {}, "attribution": ATTRIBUTION},
        "counts": {"findings": counts["findings"], "with_mitigation": counts["with_mitigation"],
                   "triage": counts["triage"], "mentions_not_recommended": mention_count, "items": len(items),
                   "by_priority": {level: sum(item["priority"] == level for item in items) for level in PRIORITIES}},
        "items": items,
        "techniques": [{key: row[key] for key in ("id", "domain", "name", "findings", "mitigations", "basis")}
                       for row in techniques_view],
        "unknown_techniques": dict(sorted(unknown.items())),
        "mentions": {"count": mention_count, "finding_ids": mentions, "more": mention_count - len(mentions),
                     "note": MENTION_NOTE},
        "triage_reasons": TRIAGE_REASONS,
    }
    if reason:
        view["reason"] = reason
    return view
