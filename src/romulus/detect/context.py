"""Anchor-gated context rules. They never run in the full-window sweep."""
from __future__ import annotations

import ipaddress

from romulus.detect.base import ContextAnchor, ContextLink, ContextPlaybook, Match, basename, pf
from romulus.detect.host import is_internal
from romulus.evidence.typed import Outcome

DISCOVERY_COMMANDS = {
    "id": ("T1033", "identity enumeration"),
    "whoami": ("T1033", "identity enumeration"),
    "hostname": ("T1082", "host enumeration"),
    "hostnamectl": ("T1082", "host enumeration"),
    "uname": ("T1082", "host enumeration"),
    "ip": ("T1016", "network enumeration"),
    "ifconfig": ("T1016", "network enumeration"),
    "route": ("T1016", "network enumeration"),
    "netstat": ("T1016", "network enumeration"),
    "ss": ("T1016", "network enumeration"),
    "arp": ("T1016", "network enumeration"),
    "users": ("T1087", "account enumeration"),
    "who": ("T1087", "account enumeration"),
    "w": ("T1087", "account enumeration"),
    "groups": ("T1069", "permission-group enumeration"),
}


def _discovery(argv: list[str]) -> tuple[str, str] | None:
    if not argv:
        return None
    name = basename(str(argv[0]))
    if name == "getent" and len(argv) >= 2:
        return ({"passwd": ("T1087", "account enumeration"),
                 "group": ("T1069", "permission-group enumeration")}.get(str(argv[1])))
    return DISCOVERY_COMMANDS.get(name)


def _context_suffix(anchor: ContextAnchor, link: ContextLink) -> str:
    if link.strength == "inferred":
        return (f"This is a hypothesis linked to {anchor.id} by inferred {link.link_type} link {link.id}; "
                "no observed session or lineage key proves the actor is the same.")
    return f"It was reached from {anchor.id} through observed {link.link_type} link {link.id}."


class PostAccessDiscovery(ContextPlaybook):
    id = "context.post_access_discovery"
    version = "1"
    title = "Discovery command in an anchored session or process lineage"
    anchor_classes = ("initial_access", "remote_login", "web_shell", "execution", "credential_access")
    link_types = ("login_session", "process_lineage")
    families = ("process_exec",)
    required_fields = ("process.argv",)
    assures_negative = False
    claim_type = "correlated_observation"
    severity, lane = "high", "high"
    attack = ("T1033", "T1082", "T1016", "T1087", "T1069")
    benign = ("administrator troubleshooting after an approved login", "inventory and compliance scripts")
    next_checks = ("other commands in the same session or lineage", "network flows after the discovery")

    def match_linked(self, anchor, link, events):
        out = []
        for event in self.applicable(events):
            found = _discovery(event.get("process.argv"))
            if found is None:
                continue
            technique, behavior = found
            command = basename(str(event.get("process.argv")[0]))
            claim = (f"A process execution record on {event.host} contains the argv-identified {behavior} command "
                     f"'{command}'. {_context_suffix(anchor, link)}")
            match = Match(
                self.id, claim, self.claim_type, [event], [pf(event, "process.argv")], event.ts,
                self.severity, self.lane, "medium", event.entities(),
                group_key=event.id,
            )
            match.notes.append(technique)
            out.append(match)
        return out


class EntryPointPromotion(ContextPlaybook):
    id = "context.entry_point_promotion"
    version = "1"
    title = "Remote-login entry point linked to a later anchor-class finding"
    anchor_classes = ("*",)
    link_types = ("login_session",)
    families = ("auth",)
    required_fields = ("auth.service", "source.ip", "user.name")
    claim_type = "correlated_observation"
    severity, lane = "high", "high"
    attack = ("T1078", "T1021.004")
    benign = ("approved remote administration followed by authorized maintenance",)
    next_checks = ("the complete login session", "the source address across hosts")

    def match_linked(self, anchor, link, events):
        out = []
        for event in self.applicable(events):
            if event.get("auth.service") != "sshd" or event.outcome != Outcome.success:
                continue
            try:
                source = ipaddress.ip_address(str(event.get("source.ip")))
            except ValueError:
                self.missing_required += 1
                continue
            if is_internal(source):
                continue
            claim = (f"A successful remote login from {source} on {event.host} began the observed login "
                     f"session that later performed {anchor.id}. {_context_suffix(anchor, link)}")
            out.append(Match(
                self.id, claim, self.claim_type, [event],
                [pf(event, "source.ip"), pf(event, "user.name")], event.ts,
                self.severity, self.lane, "high", event.entities(),
                group_key=event.id,
            ))
        return out


CONTEXT_PLAYBOOKS = [PostAccessDiscovery, EntryPointPromotion]
