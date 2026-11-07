"""Whole-hunt, disk-backed DC logon joins for declared synchronization accounts.

Rows are written directly to the indexed disk store, including old logons. A time
horizon never forgets a logon: long-lived sessions and late targets must still join.
Only the physical disk allowance can refuse state, with named partial coverage.
"""

from __future__ import annotations

import hashlib
import json

from romulus.detect.base import pf
from romulus.detect.site_roles import address_member, host_member
from romulus.detect.windows_linked import _session
from romulus.detect.windows_rows import WindowsRows, row_key
from romulus.evidence.typed import Outcome


def dc_name(event):
    return str(event.get("host.full_name") or event.host or "").casefold().rstrip(".")


def auth_keys(event):
    keys = {str(event.get("auth.target_account") or "").casefold()}
    name, domain = event.get("account.name"), event.get("account.domain")
    if name and domain:
        keys.add(f"name:{domain}\\{name}".casefold())
    return keys - {""}


class ReplicationSourceJoin:
    """Stage only declared-account replication facts and their successful logons."""

    def __init__(self):
        super().__init__()
        self._sync_rows = WindowsRows(self)

    def _sync_sources_declared(self):
        facts = getattr(self, "site_facts", None)
        return bool(
            facts and facts.present and (facts.directory_sync_hosts or facts.directory_sync_addresses)
        )

    def _sync_sensitive(self, event):
        return (
            self._sync_sources_declared() and event.get("event.code") == 4662 and bool(self.sync_actor(event))
        )

    def _sync_session(self, event):
        return _session(
            event.get("directory.actor_session_id") or event.get("windows.event_data.SubjectLogonId")
        )

    def sync_source(self, event):
        if not self._sync_rows.ready or not self._sync_sensitive(event):
            return None
        session = self._sync_session(event)
        if not session or not dc_name(event):
            return None
        key = row_key("logon", dc_name(event), session)
        rows = self._sync_rows.store().execute(
            "SELECT event,raw FROM windows_rows WHERE k=? AND ts<=? ORDER BY ts DESC,id",
            (key, event.ts.timestamp()),
        )
        for row in rows:
            logon, raw = self._sync_rows.hydrate(row)
            if not self.sync_actor(event) & auth_keys(logon):
                continue
            boot, lboot = event.get("host.boot.id"), logon.get("host.boot.id")
            if boot and lboot and boot != lboot:
                continue
            return logon, raw
        return None

    def _publish_sync_event(self, event, *, final):
        marker = row_key("replication-published", event.id)
        previous_text = self._sync_rows.marker(marker)
        previous = json.loads(previous_text) if previous_text is not None else None
        hits = self.judge(event)
        if not hits or previous is None and not final and not any(hit.lane == "high" for hit in hits):
            return
        hit = hits[0]
        material = [hit.behavior, hit.lane, hit.severity, [item.id for item in hit.context], hit.content]
        decision = hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()
        if previous is not None and previous["decision"] == decision:
            return
        out = []
        if previous is None:
            self.evaluated += 1
            if not self._events_pre_scoped:
                self.os_applicable += 1
            if self.one_shot:
                out.append(self.record_match(event, hit))
                fold = (None, "own")
            else:
                fold = self._finalize_fold(event, hit, out)
        else:
            old_shape, old_role = previous["fold"]
            self._exclude(event, ((old_shape, old_role),))
            if old_role == "own":
                correction = self.record_match(event, hit)
                correction.revision_reason = (
                    "Later DC logon records changed the source attribution for this directory access."
                )
                correction.notes.append(
                    "The earlier source decision is retained in this finding's revision history."
                )
                out.append(correction)
                # A corrected standalone observation stays standalone; repeated
                # reconciliations must not withdraw its old group member again.
                fold = (None, "own")
            else:
                fold = self._finalize_fold(event, hit, out)
        self._sync_rows.remember(marker, json.dumps({"decision": decision, "fold": fold}))
        yield from out

    def _publish_sync_pending(self, key, *, final):
        for _, event, _, _ in self._sync_rows.iterate(key):
            yield from self._publish_sync_event(event, final=final)

    def _consume_sync(self, events):
        for event in events:
            if not self.event_in_os_scope(event) or event.family not in self.families:
                continue
            if event.family == "auth":
                if (
                    event.get("event.code") != 4624
                    or event.outcome != Outcome.success
                    or not auth_keys(event)
                    & {value.casefold() for value in self.site_facts.directory_sync_accounts}
                ):
                    continue
                session = _session(event.get("auth.session_id"))
                if not session or not dc_name(event):
                    continue
                if self._sync_rows.put(row_key("logon", dc_name(event), session), event):
                    yield from self._publish_sync_pending(
                        row_key("replication", dc_name(event), session), final=self.one_shot
                    )
            elif self._sync_sensitive(event):
                hits = self.judge(event)
                if not hits:
                    continue
                session = self._sync_session(event)
                key = row_key("replication", dc_name(event), session)
                if self._sync_rows.put(key, event):
                    yield from self._publish_sync_event(event, final=self.one_shot)
                elif not self._sync_rows.store().execute(
                    "SELECT 1 FROM windows_rows WHERE k=? AND id=?", (key, event.id)
                ).fetchone():
                    # A computed positive does not need the refused join row to
                    # publish. Keep a source decision already supported by a
                    # retained logon; refusal cannot lower that evidence's lane.
                    hit = hits[0]
                    status, _, _ = self.source_decision(event)
                    hit.notes += (
                        "source unresolved: join state refused at the disk ceiling"
                        if status == "unresolved"
                        else "join state refused at the disk ceiling; the currently supported source decision is retained.",
                    )
                    self.evaluated += 1
                    if not self._events_pre_scoped:
                        self.os_applicable += 1
                    yield self.record_match(event, hit)
            else:
                yield from super().consume([event])

    def consume(self, events):
        if not self._sync_sources_declared():
            return super().consume(events)
        return self._consume_sync(events)

    def finalize(self):
        if self._sync_rows.ready:
            # Distinct indexed keys stream from disk; no event bodies or set of
            # all sessions is retained just to find pending groups.
            for (key,) in self._sync_rows.store().execute("SELECT DISTINCT k FROM windows_rows ORDER BY k"):
                if json.loads(key)[0] == "replication":
                    yield from self._publish_sync_pending(key, final=True)
        yield from super().finalize()

    def _fleet_match(self, shape, group, *, final):
        result = super()._fleet_match(shape, group, final=final)
        if result is None or not self._sync_rows.ready:
            return result
        subjects = [event for event in result.events if self._sync_sensitive(event)]
        if not subjects:
            return result
        # Joined source facts need their own cited logon witnesses, including
        # rollups. Keep context records out of the stated directory-record count.
        source_fields = {"auth.session_id", "auth.target_account", "source.ip", "source.hostname"}
        result.predicate = [fact for fact in result.predicate if fact.field not in source_fields]
        cited = {event.id for event in result.events}
        for event in subjects:
            pair = self.sync_source(event)
            if pair is None:
                continue
            logon, raw = pair
            if logon.id not in cited:
                result.events.append(logon)
                cited.add(logon.id)
            result.context_ids.add(logon.id)
            result.raw_copies.update(raw)
            result.predicate.extend(pf(logon, name) for name in sorted(source_fields) if logon.has(name))
        if group.excluded:
            result.claim = result.claim.replace(
                "after later records withdrew their parent",
                "after later DC logon records changed their source attribution",
            ).replace(
                "a record of the parent process id inside the child's window",
                "a newer logon before the directory access in the same DC session",
            )
            result.revision_reason = result.revision_reason.replace(
                "after later records withdrew their parent",
                "after later DC logon records changed their source attribution",
            )
            if group.records <= 0:
                result.proposed_lane, result.severity = "context", "info"
                result.notes.append(
                    "This historical aggregate has no remaining supported members; current source decisions are retained separately."
                )
        return result

    def source_decision(self, event):
        pair = self.sync_source(event)
        if pair is None:
            return "unresolved", None, {}
        logon, raw = pair
        facts = self.site_facts
        # WorkstationName in a 4624 is client-reported. When an address can
        # be checked against declared addresses, a claimed name cannot override it.
        if facts.directory_sync_addresses and logon.get("source.ip"):
            listed = address_member(logon.get("source.ip"), facts.directory_sync_addresses)
        elif facts.directory_sync_hosts and logon.get("source.hostname"):
            listed = host_member(logon.get("source.hostname"), facts.directory_sync_hosts)
        else:
            return "unresolved", logon, raw
        return "declared" if listed else "undeclared", logon, raw

    def source_hit(self, event, hit, status, logon, raw):
        notes = list(hit.notes)
        if status == "undeclared":
            hit.lane, hit.severity = "high", "high"
            notes.append("declared directory-sync account used from an undeclared host")
        elif status == "declared":
            notes.append(
                "The matching DC logon records a declared directory-sync source; retain this observation as a lead."
            )
        else:
            notes.append(
                "The declared directory-sync account source host is unresolved: no matching successful 4624 with a checkable source was in the hunt."
            )
        if logon is not None:
            if self.site_facts.directory_sync_hosts and logon.get("source.hostname") and (
                not self.site_facts.directory_sync_addresses or not logon.get("source.ip")
            ):
                hit.text += "; the source name is client-reported by the matching logon"
                hit.common += "; the source name is client-reported by the matching logon"
                notes.append("The source-name comparison uses client-reported WorkstationName, not a verified host identity.")
            hit.context.append(logon)
            hit.raw_copies.update(raw)
            for item, names in (
                (event, ("directory.actor_session_id", "windows.event_data.SubjectLogonId")),
                (logon, ("auth.session_id", "auth.target_account", "source.ip", "source.hostname")),
            ):
                hit.predicate.extend(pf(item, name) for name in names if item.has(name))
            if event.get("host.boot.id") and logon.get("host.boot.id"):
                notes.append("The source is linked by the same DC, canonical logon ID and recorded boot ID.")
            else:
                notes.append(
                    "The source is linked by the same DC and canonical logon ID; missing boot identity leaves reuse across boots unresolved."
                )
            hit.content += "|sync-source:" + str(logon.get("source.ip") or logon.get("source.hostname"))
        hit.notes = tuple(notes)
        return hit
