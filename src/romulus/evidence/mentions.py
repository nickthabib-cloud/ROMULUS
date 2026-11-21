"""Mentions: text a record contains that a curated pattern names, never an action.

A mention is what the mention sweep (`romulus.hunt.mentions`) finds in the raw text (`message`, else
`event.original`) of a record no normalizer read: a pattern's literal or anchored expression occurs in it. It shows only
that a record with this text exists. The contract every reader keeps:

- it is labelled as a mention everywhere (report manifest, Markdown, DOCX, web, the agent's dossier);
- it lives in its own lane, `mention`, between context and lead, stored outside the findings table, so it never
  reaches a reportable lane (lead, high, urgent) on its own and no ranking, triage, expansion or entity path reads it;
- it carries its first record as a citation through the raw-record path (`evidence.raw_citation`: cleaned, redacted,
  bounded, rendered as inert text);
- it never decides or refutes a hypothesis and never creates an entity or ATT&CK link as fact: a pattern's ATT&CK
  tags are shown as the pattern's own metadata;
- it is never reported as an action. Only typed evidence makes an action-level finding.
"""
from __future__ import annotations

MENTION_KIND = "mention"
MENTION_LANE = "mention"
MENTION_LABEL = ("mention: text a record contains, matched by a curated pattern; it shows that a record with this "
                 "text exists, not that an action happened")
MENTION_LABEL_SHORT = "mention (text a record contains, not an action)"
# where the mention lane sits in every ordering of lanes: below lead, above context
LANE_ORDER = ("urgent", "high", "lead", MENTION_LANE, "context")
# a pattern's ATT&CK tags are the pattern author's, never an observed technique
PATTERN_ATTACK_LABEL = "pattern metadata: the technique the pattern's text is associated with, not an observed technique"

STRENGTHS = ("strong", "medium", "weak")
STRENGTH_RANK = {"strong": 3, "medium": 2, "weak": 1}
TELEMETRY = ("linux_text", "windows_text", "any")
# the telemetry class of a scanned record: a Windows event record's rendered text, any other host text, or text of a
# record that is neither (a network sensor's record), which only `any` patterns read
LINUX_TEXT, WINDOWS_TEXT, OTHER_TEXT = "linux_text", "windows_text", "other"
