"""Recorded process identity, lineage and account-transition observations."""
from __future__ import annotations

import hashlib
import ntpath
import re
import sqlite3

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.bounded import StateExhausted
from romulus.detect.windows_cmdline import is_user_writable, split_argv
from romulus.detect.windows_common import (
    SPAWNED_CODE_RUNNERS,
    Undecided,
    WindowsProcessRule,
    parent_predicate,
    resolve_parent,
)
from romulus.detect.windows_compact_rows import FENCE_FIELDS, CompactWindowsRows
from romulus.detect.windows_events import basename, local_path_components, signal
from romulus.detect.windows_path_data import has_short_name, installation_parts, writable_windows_path
from romulus.detect.windows_rows import row_key
from romulus.detect.windows_system_data import ACCESSIBILITY_BINARIES, SYSTEM_BINARIES
from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL

_SYSMON = "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"
_FIELDS = ("process.executable", "process.executable_key", "process.guid", "process.parent.guid",
           "process.user", "user.name", "user.domain", "process.integrity_level",
           "process.original_file_name", "process.description", "process.product", "process.fence", "system.event")


def _path(event):
    return event.get("process.executable_key") or event.get("process.executable")


def _writable(path):
    return is_user_writable(str(path or "")) or writable_windows_path(path)


def _absolute(path):
    text = str(path or "").replace("/", "\\")
    return bool(re.match(r"(?i)^(?:[a-z]:\\|%(?:systemroot|windir|systemdrive|temp|tmp|appdata|localappdata|userprofile|public|programdata|programfiles|programfiles\(x86\))%\\|\\\\|\\device\\|\\systemroot\\)", text))


def _outside_install(path):
    if not _absolute(path):
        return False
    text = str(path).replace("/", "\\").casefold()
    if text.startswith(("\\\\?\\", "\\??\\")):
        text = text[4:]
    # A recorded D:\\Windows path is still an installation path. Do not use
    # the local machine's C: convention as evidence about a remote machine.
    if text.startswith(("%windir%\\", "%systemroot%\\", "\\systemroot\\", "%programfiles%\\", "%programfiles(x86)%\\")):
        return False
    drive, tail = ntpath.splitdrive(text)
    if not re.fullmatch(r"[a-z]:", drive) or not tail.startswith("\\"):
        return False
    return tail.split("\\")[1] not in {"windows", "program files", "program files (x86)"}


def _user(event):
    value = event.get("process.user")
    if isinstance(value, str) and value.strip():
        return value.strip()
    name, domain = event.get("user.name"), event.get("user.domain")
    if isinstance(name, str) and name.strip():
        return f"{domain}\\{name}" if domain else name
    return ""


def _system_user(user):
    return user.casefold() in {"nt authority\\system", "s-1-5-18"}


def _expected_system_location(name, path):
    # This rule compares recorded directory structure; it does not certify the
    # local volume as the system volume or confer trust on the image.
    parts = local_path_components(path) or installation_parts(path)
    if len(parts) < 3 or parts[:2] not in {("windows", "system32"), ("windows", "syswow64"), ("windows", "sysnative")}:
        return False
    middle = tuple(parts[2:-1])
    return not middle or middle in SYSTEM_BINARIES[name].get("expected_subdirs", ())


class ServerOrBootProcessChild(WindowsProcessRule):
    id = "win.server_or_boot_process_child"
    title = "A server or startup process created a code launcher"
    version = '2'
    reads_command_line = False
    uses_parent = True
    parent_images = frozenset({"w3wp.exe", "httpd.exe", "php-cgi.exe", "sqlservr.exe", "smss.exe",
                               "winlogon.exe", "services.exe", *ACCESSIBILITY_BINARIES})
    attack = ("T1505.003", "T1505.001", "T1546.008", "T1569.002", "T1068")
    research = (_SYSMON, "https://attack.mitre.org/techniques/T1505/003/",
                "https://attack.mitre.org/techniques/T1546/008/")

    def candidate_child(self, event):
        # smss's abnormal-child case also includes non-launcher children.
        return True

    def judge(self, event):
        child = basename(_path(event))
        if not child:
            return []
        parent = resolve_parent(event, self.lineage)
        parent_name = parent.name
        selected = parent_name in self.parent_images or bool(re.fullmatch(r"tomcat(?:[0-9]+)?\.exe", parent_name))
        if not selected:
            return []
        if parent_name == "smss.exe":
            if child in {"smss.exe", "autochk.exe", "csrss.exe", "wininit.exe", "winlogon.exe"}:
                return []
        elif child not in SPAWNED_CODE_RUNNERS:
            return []
        argv = split_argv(str(event.get('process.command_line') or ''))
        if (parent_name == 'services.exe' and child == 'msiexec.exe' and len(argv) == 2
                and argv[1].casefold() == '/v' and _expected_system_location(child, _path(event))):
            return []
        predicate, context, how, raw = parent_predicate(event, parent)
        integrity = str(event.get("process.integrity_level") or "").casefold()
        reason = "the child executable has a writable-path indicator" if _writable(_path(event)) else ""
        if not reason and integrity in {'high', 'system'} and event.get('process.parent.guid') and self.lineage:
            try:
                joined = self.lineage.parent(event)
            except Undecided:
                joined = None
            levels = {'low': 0, 'medium': 1, 'high': 2, 'system': 3}
            if joined and joined.event and joined.event.get('process.guid') == event.get('process.parent.guid'):
                prior = str(joined.event.get('process.integrity_level') or '').casefold()
                if prior in levels and levels[prior] < levels[integrity]:
                    reason = f'the GUID-associated parent records {prior} integrity below the child\'s {integrity} integrity'
                    context.append(joined.event)
                    predicate.append(pf(joined.event, 'process.integrity_level'))
                    raw.update(dict(joined.raw_copies))
        text = f"Recorded parent '{parent_name}' created '{child}' (parent resolved from {how})"
        if reason:
            text += "; high priority because " + reason
        hit = signal(event, "server_boot_child", text, self.attack, _FIELDS,
                     lane="high" if reason else "lead", severity="high" if reason else "medium",
                     content=row_key(_path(event), parent.key, integrity, reason),
                     notes=("Parent and executable names alone identify a review lead; they do not prove exploitation.",))
        hit.predicate.extend(predicate)
        hit.context.extend(context)
        hit.raw_copies.update(raw)
        hit.parent_name = parent_name
        return [hit]


class RenamedSystemBinary(WindowsProcessRule):
    id = "win.renamed_or_relocated_system_binary"
    title = "Process image differs from recorded system-binary metadata or expected location"
    version = "1"
    reads_command_line = False
    attack = ("T1036.003", "T1036.005")
    research = (_SYSMON, "https://attack.mitre.org/techniques/T1036/003/")

    def judge(self, event):
        path = _path(event)
        if not isinstance(path, str):
            return []
        image_name = basename(path)
        original = event.get("process.original_file_name")
        identity, evidence = None, ""
        recorded_identity = None
        if isinstance(original, str) and original.casefold() not in {"", "unknown", "unknown_file", "-"}:
            observed = ntpath.basename(original).casefold()
            for name, item in SYSTEM_BINARIES.items():
                if observed in {alias.casefold() for alias in item["original_file_names"]}:
                    recorded_identity = name
                    if image_name != name:
                        identity, evidence = name, f"OriginalFileName '{original}' differs from recorded image basename '{image_name}'"
                    break
        else:
            description, product = event.get("process.description"), event.get("process.product")
            if isinstance(description, str) and isinstance(product, str):
                for name, item in SYSTEM_BINARIES.items():
                    if (description.casefold() in {value.casefold() for value in item["descriptions"]}
                            and product.casefold() in {value.casefold() for value in item["products"]}):
                        recorded_identity = name
                        if image_name != name:
                            identity, evidence = name, f"recorded Description/Product identify '{name}' while image basename is '{image_name}'"
                        break
        if identity is None and image_name in SYSTEM_BINARIES and _absolute(path):
            if has_short_name(path):
                raise Undecided("location_alias", "the recorded short-name directory cannot establish system-binary relocation without an alias map")
            if not _expected_system_location(image_name, path):
                identity, evidence = image_name, f"system-named image '{image_name}' was created outside its expected system directory"
        if not evidence:
            return []
        recorded_launcher = recorded_identity == identity and recorded_identity in SPAWNED_CODE_RUNNERS
        high = recorded_launcher or _writable(path)
        reason = ("the recorded executable has a writable-path indicator" if _writable(path) else
                  "the recorded metadata identifies a curated code launcher" if recorded_launcher else "")
        text = f"Process '{path}': {evidence}" + ("; high priority because " + reason if reason else "")
        return [signal(event, "system_identity", text, self.attack, _FIELDS,
                       lane="high" if high else "lead", severity="high" if high else "medium",
                       content=row_key(path, original, event.get("process.description"), evidence),
                       notes=("Recorded version metadata and names do not establish signature validity or authentic Microsoft provenance.",))]


class _ProcessRows(CompactWindowsRows):
    """Schema allocation has the same physical ceiling as subsequent row writes."""
    def compact_fields(self, key):
        if key.startswith(('termination:', 'boot:')):
            return FENCE_FIELDS
        if key.startswith('pending:'):
            return frozenset((*_FIELDS, 'event.code', 'event.channel', 'event.provider',
                              'user.entity_id', 'user.sid', 'auth.target_account'))
        return None

    def store(self):
        spill = self.owner.spill()
        if not self.ready:
            self.account = self.owner.state_budget().account(f"{self.owner.id}:windows_rows", strong=True)
            spill.cap()
            try:
                spill.db.execute("SAVEPOINT process_schema")
                spill.db.execute("CREATE TABLE IF NOT EXISTS windows_rows(k TEXT,id TEXT,ts REAL,value TEXT,event TEXT,raw TEXT,PRIMARY KEY(k,id))")
                spill.db.execute("CREATE INDEX IF NOT EXISTS windows_rows_time ON windows_rows(k,ts,id)")
                spill.db.execute("CREATE INDEX IF NOT EXISTS windows_rows_value ON windows_rows(k,value,ts)")
                spill.db.execute("CREATE TABLE IF NOT EXISTS windows_marks(k TEXT PRIMARY KEY,value TEXT)")
                spill.db.execute("RELEASE process_schema")
                self.ready = True
            except sqlite3.OperationalError as error:
                spill.db.rollback()
                raise spill.failed(error, account=self.account) from error
            finally:
                spill.grew()
        return spill


class ParentAccountTransition(Playbook):
    id = "win.process_account_transition"
    title = "A SYSTEM child records a different account than its GUID-associated parent"
    version = '2'
    families = ("process_exec", "process_termination", "system_state")
    context_families = ("process_termination", "system_state")
    os_families = ("windows",)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 1),)
    required_fields = ("process.executable_key",)
    assures_negative = False
    positive_only_reason = "A GUID account-context association requires both native creation records; missing history cannot establish a negative."
    kind = "aggregate"
    state_slice = "strong"
    claim_type = "correlated_observation"
    attack = ("T1134.001", "T1134.002")
    research = (_SYSMON, "https://attack.mitre.org/techniques/T1134/001/",
                "https://learn.microsoft.com/en-us/windows/win32/services/service-user-accounts")

    def __init__(self):
        super().__init__()
        self.rows = _ProcessRows(self)
        self.refused_parent_keys = {}
        self.refused_parent_overflow = False
        self.refused_conflict_overflow = False

    def _refused(self, key):
        # Fixed-size binary digests bound the emergency RAM path even when disk
        # cannot accept uncertainty metadata. Never evict an earlier known key.
        if key is None:
            return
        digest = hashlib.sha256(key.encode()).digest()[:16]
        if len(self.refused_parent_keys) < 4096 or digest in self.refused_parent_keys:
            self.refused_parent_keys.setdefault(digest, False)
        else:
            self.refused_parent_overflow = True
            self.note_limit('process_account_refusal_keys', 'The 4096-key refusal uncertainty limit was reached; further affected associations cannot be individually named.')

    def _identity(self, event, parent=False):
        guid = event.get("process.parent.guid" if parent else "process.guid")
        return row_key(event.host, guid) if isinstance(guid, str) and guid else None

    def _match(self, child, live_parent=None, *, child_raw=None, fence_only=False):
        key = self._identity(child, parent=True)
        if not key or not self.rows.ready:
            return None
        key_digest = hashlib.sha256(key.encode()).digest()[:16]
        # value is a semantic fingerprint: shipper copies with identical facts do
        # not become false conflicts, and only two distinct versions need loading.
        cursor = self.rows.store().execute("SELECT event,raw,value FROM windows_rows WHERE k=? GROUP BY value ORDER BY value LIMIT 2", ("parent:" + key,))
        versions = list(cursor)
        parents = [self.rows.hydrate(row[:2]) for row in versions if row[0]]
        unretained_parent = live_parent is not None and self._fingerprint(live_parent) not in {row[2] for row in versions}
        if unretained_parent:
            parents.append((live_parent, self.raw_of(live_parent)))
            versions.append((None, None, self._fingerprint(live_parent)))
        if not parents and len(versions) < 2:
            if fence_only:
                self.note_limit("process_account_parent_absent", "A SYSTEM child has no retained same-host GUID parent creation; its account transition is unresolved.")
            return None
        if len(versions) > 1 or len(parents) > 1 or self.refused_parent_keys.get(key_digest, False):
            if unretained_parent and len(versions) == 2:
                # The second fact may be live only after its write was refused.
                # Reuse the same bounded digest entry to forbid restoring this lead.
                if key_digest in self.refused_parent_keys:
                    self.refused_parent_keys[key_digest] = True
                else:
                    self.refused_conflict_overflow = True
                    self.note_limit('process_account_refusal_conflicts', 'The bounded refusal state could not retain a live GUID conflict; final high-preserving caveat revisions are unavailable.')
            if fence_only:
                return None
            self.note_limit("parent_guid_ambiguity", "Conflicting creation facts share a host/process GUID; account transition is unresolved.")
            match = Match(self.id, "The SYSTEM child records a parent GUID that has conflicting same-host creation/account facts; its account transition is unresolved.",
                          self.claim_type, [child, *(parent for parent, _raw in parents)],
                          [pf(event, name) for event in (child, *(parent for parent, _raw in parents)) for name in _FIELDS if event.has(name)], child.ts,
                          "medium", "lead", "medium", child.entities(),
                          group_key="account-transition:" + child.id, bounded_revision=True,
                          revision_reason="Conflicting native creation facts invalidate the earlier unique parent/account association.")
            for _parent, raw in parents:
                match.raw_copies.update(raw)
            match.raw_copies.update(child_raw or self.raw_of(child))
            return match
        parent, raw = parents[0]
        parent_user, child_user = _user(parent), _user(child)
        if fence_only and (not parent_user or parent.ts > child.ts):
            self.note_limit("process_account_parent_context", "A GUID-associated parent lacks a recorded account or has creation after the child; account transition is unresolved.")
        if (parent.ts > child.ts or not parent_user or _system_user(parent_user)
                or not _system_user(child_user) or not _outside_install(_path(parent))):
            return None
        fence = None
        for fence_key in ("termination:" + key, "boot:" + row_key(child.host)):
            row = self.rows.store().execute("SELECT event,raw FROM windows_rows WHERE k=? AND ts>=? AND ts<? ORDER BY ts,id LIMIT 1",
                                            (fence_key, parent.ts.timestamp(), child.ts.timestamp())).fetchone()
            if row:
                fence = self.rows.hydrate(row)
                break
        if fence:
            fence_event, fence_raw = fence
            match = Match(self.id, "The SYSTEM child records a parent GUID whose associated creation precedes a recorded termination or boot fence; the parent account transition is unresolved.",
                          self.claim_type, [child, parent, fence_event],
                          [pf(event, name) for event in (child, parent, fence_event) for name in _FIELDS if event.has(name)],
                          child.ts, "medium", "lead", "medium", child.entities(),
                          group_key="account-transition:" + child.id, bounded_revision=True,
                          revision_reason="A native termination or boot fence invalidates the live-parent account association.")
            match.raw_copies.update(raw)
            match.raw_copies.update(fence_raw)
            match.raw_copies.update(child_raw or self.raw_of(child))
            return match
        uncertain = (key_digest in self.refused_parent_keys
                     or hashlib.sha256(('boot:' + row_key(child.host)).encode()).digest()[:16] in self.refused_parent_keys)
        if fence_only and (not uncertain or self.refused_conflict_overflow):
            return None
        match = Match(self.id,
                      f"Creation of '{_path(child)}' records account '{child_user}'; its same-host GUID-associated parent "
                      f"creation records account '{parent_user}' and executable '{_path(parent)}' outside standard installation roots. "
                      "This is an account-context difference, not proof of token theft or successful exploitation.",
                      self.claim_type, [child, parent],
                      [pf(event, name) for event in (child, parent) for name in _FIELDS if event.has(name)],
                      child.ts, "high", "high", "medium", child.entities(),
                      ["Parent GUID and recorded account fields support the association; executable names do not supply an account or integrity level."],
                      group_key="account-transition:" + child.id, bounded_revision=True,
                      revision_reason="Native parent/child account context was associated by the recorded GUID.")
        match.raw_copies.update(raw)
        match.raw_copies.update(child_raw or self.raw_of(child))
        if uncertain:
            match.claim += " Additional history for this host/GUID was refused by the physical disk limit; retained parent/child facts still support this high, with incomplete conflict or lifetime coverage."
        if self.refused_parent_overflow:
            match.notes.append('Refusal-key tracking overflowed its 4096-key limit; additional history uncertainty cannot be scoped beyond that limit.')
        return match

    @staticmethod
    def _fingerprint(event):
        return hashlib.sha256(row_key(_user(event).casefold(), _path(event), event.ts.replace(microsecond=0).isoformat()).encode()).hexdigest()

    def consume(self, events):
        selected = self.applicable([item for item in events if item.family == "process_exec" and item.get("event.code") == 1])
        selected += [event for event in events if self.event_in_os_scope(event)
                     and (event.family == "process_termination" and event.get("process.guid")
                          or event.family == "system_state" and event.get("process.fence") == "boot"
                          and event.get("system.event") == "boot_start")]
        if not selected:
            return
        for event in sorted(selected, key=lambda item: (item.ts, item.id)):
            key = self._identity(event)
            refusal_key = 'boot:' + row_key(event.host) if event.family == 'system_state' else key
            # Compute a live child's positive before optional retention writes.
            # Refusing its citation body must not discard already known facts.
            live_match = self._match(event) if _system_user(_user(event)) else None
            try:
                if event.family in self.context_families:
                    fence_key = "termination:" + key if event.family == "process_termination" else "boot:" + row_key(event.host)
                    existed = self.rows.store().execute("SELECT 1 FROM windows_rows WHERE k=? AND id=?", (fence_key, event.id)).fetchone()
                    if not existed and not self.rows.put(fence_key, event):
                        self._refused(key if event.family == 'process_termination' else fence_key)
                        self.note_limit("process_account_fences", "A GUID termination/boot fence could not be retained; live parent/account association may be unresolved.")
                    continue
                if key:
                    fingerprint = self._fingerprint(event)
                    versions = self.rows.store().execute("SELECT value FROM windows_rows WHERE k=? GROUP BY value LIMIT 2", ("parent:" + key,)).fetchall()
                    existed = any(row[0] == fingerprint for row in versions)
                    # Two conflicting facts are terminal for this GUID. Extra
                    # copies/versions cannot replay the pending children again.
                    accepted = False
                    if not existed and len(versions) < 2:
                        qualifies = bool(_user(event)) and not _system_user(_user(event)) and _outside_install(_path(event))
                        writer = self.rows.put if qualifies else self.rows.fingerprint
                        accepted = writer("parent:" + key, event, fingerprint)
                        if not accepted:
                            self._refused(key)
                            self.note_limit("process_account_parent_history", "FULL physical disk limit refused parent creation history; later account uniqueness cannot be established.")
                    # Only a new fact version can change pending children; all
                    # lookups are indexed by the relevant host/GUID key.
                    if not existed and len(versions) < 2:
                        for _key, child, child_raw, _value in self.rows.iterate("pending:" + key):
                            match = self._match(child, live_parent=event, child_raw=child_raw)
                            if match is not None:
                                yield match
                if _system_user(_user(event)):
                    parent_key = self._identity(event, parent=True)
                    if parent_key:
                        self.rows.put("pending:" + parent_key, event)
                    else:
                        self.note_limit("parent_guid_absent", "SYSTEM child has no parent GUID; account transition cannot be associated.")
                    match = live_match or self._match(event)
                    if match is not None:
                        yield match
            except StateExhausted as error:
                self._refused(refusal_key)
                self.note_limit("process_account_history", f"GUID account association is incomplete after a physical disk refusal: {error}")
                # An already retained parent can still establish the live child's
                # positive even if storing that child's body was refused.
                match = live_match or self._match(event)
                if match is not None:
                    yield match

    def finalize(self):
        # One streamed prefix pass checks late fences and scoped refusals.
        # Retained or live-only conflicts cannot be restored to high.
        if self.rows.ready:
            for _key, child, child_raw, _value in self.rows.iterate(prefix='pending:'):
                match = self._match(child, child_raw=child_raw, fence_only=True)
                if match is not None:
                    yield match

    def release_state(self):
        self.rows.close()
        super().release_state()


RULES = (ParentAccountTransition, ServerOrBootProcessChild, RenamedSystemBinary)
