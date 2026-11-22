"""Mentions: text a record contains that a curated pattern names, never an action.

A mention is what the mention sweep (`romulus.hunt.mentions`) finds in the free-text fields of a record no rule reads
(`romulus.hunt.mention_fields`: message lines, command lines, URLs and the like, never a serialized record): a
pattern's literal or anchored expression occurs in it. It shows only
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
# a pattern's ATT&CK tags are the pattern author's, never an observed technique
PATTERN_ATTACK_LABEL = "pattern metadata: the technique the pattern's text is associated with, not an observed technique"

STRENGTH_RANK = {"strong": 3, "medium": 2, "weak": 1}
# the telemetry class of a scanned record: a Windows event record's rendered text, any other host text, or text of a
# record that is neither (a network sensor's record), which only `any` patterns read
LINUX_TEXT, WINDOWS_TEXT, OTHER_TEXT = "linux_text", "windows_text", "other"
