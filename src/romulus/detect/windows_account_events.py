"""Positive account-management signals from typed Windows Security events."""
from __future__ import annotations

import re

from romulus.detect.windows_events import WindowsEventRule, integer, signal
from romulus.evidence.typed import Outcome, TypedEvent
from romulus.evidence.windows_catalog import SECURITY

_DOMAIN_SID = re.compile(r"s-1-5-21-(\d{1,10})-(\d{1,10})-(\d{1,10})-(\d{1,10})", re.ASCII)
_GROUPS = {
    512: "Domain Admins", 516: "Domain Controllers", 517: "Cert Publishers", 518: "Schema Admins",
    519: "Enterprise Admins", 520: "Group Policy Creator Owners", 521: "Read-only Domain Controllers",
    526: "Key Admins", 527: "Enterprise Key Admins",
}
_BUILTIN = {544: "Administrators", 548: "Account Operators", 549: "Server Operators", 550: "Print Operators",
            551: "Backup Operators", 552: "Replicator", 555: "Remote Desktop Users", 580: "Remote Management Users"}
_IDENTITY = ("account.group_id", "auth.target_account", "account.name", "account.domain", "account.sam_name",
             "user.entity_id", "user.name", "user.domain")
_MEMBERSHIP = (*_IDENTITY, "account.member_id", "account.member_name", "account.group_name", "account.action")
_ACCOUNT_DOC = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-"


def _domain_sid(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    match = _DOMAIN_SID.fullmatch(value.strip().casefold())
    if match is None:
        return None
    numbers = tuple(int(part) for part in match.groups())
    if any(part > 0xffffffff for part in numbers) or numbers[-1] == 0:
        return None
    return "s-1-5-21-" + "-".join(str(part) for part in numbers)


def _sid(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip().casefold()
    if re.fullmatch(r"s-1-\d{1,15}(?:-\d{1,10}){1,15}", text, re.ASCII) is None:
        return None
    parts = [int(part) for part in text.split("-")[2:]]
    if parts[0] > 0xffffffffffff or any(part > 0xffffffff for part in parts[1:]) or text == "s-1-0-0":
        return None
    return "s-1-" + "-".join(str(part) for part in parts)


def privileged_group_sid(value: object) -> str | None:
    """Return a validated canonical sensitive group SID; names and RID suffixes alone never qualify."""
    sid = _domain_sid(value)
    if sid and int(sid.rsplit("-", 1)[1]) in _GROUPS:
        return sid
    sid = _sid(value)
    if sid and sid in {f"s-1-5-32-{rid}" for rid in _BUILTIN}:
        return sid
    return None


def creation_target_sid(event: TypedEvent) -> str | None:
    """The target account's SID, not its creator or target account name.

    The normalizer currently exposes native TargetSid as account.group_id for creations.
    A conflicting or malformed recorded SID refuses a correlation identity.
    """
    if event.get("event.code") not in {4720, 4741}:
        return None
    raw = event.get("account.group_id")
    target = _domain_sid(raw)
    if raw not in (None, "") and target is None:
        return None
    fallback = event.get("auth.target_account")
    alternate = _domain_sid(fallback[4:]) if isinstance(fallback, str) and fallback.casefold().startswith("sid:") else None
    if isinstance(fallback, str) and fallback.casefold().startswith("sid:") and alternate is None:
        return None
    if target and alternate and target != alternate:
        return None
    return target or alternate


def _target_text(event: TypedEvent) -> str:
    target = _domain_sid(event.get("account.group_id"))
    return target or str(event.get("auth.target_account") or event.get("account.name") or "an unresolved account")


class _AccountRule(WindowsEventRule):
    families = ("account_change",)
    positive_only_reason = "These are positive account-management records; collection and history cannot prove absence."
    required_fields = ("event.code",)


class PrivilegedGroupAddition(_AccountRule):
    id = "win.privileged_group_addition"
    title = "An account was added to a sensitive local or domain group"
    windows_event_classes = tuple(("Security", SECURITY, code) for code in (4728, 4732, 4756))
    attack = ("T1098.007",)
    benign = ("approved administrator provisioning and remote-access group changes",)
    next_checks = ("validate the member SID and change approval", "inspect the actor and subsequent member logons")
    research = ("https://attack.mitre.org/techniques/T1098/007/", _ACCOUNT_DOC + "4728",
                "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers")

    def judge(self, event):
        if event.get("event.code") not in {4728, 4732, 4756}:
            return []
        raw_group = event.get("account.group_id")
        group = privileged_group_sid(raw_group)
        if group is None:
            if _sid(raw_group):
                return []
            return [signal(event, "group_identity_unknown", "Windows recorded a group-member addition; the group SID "
                           "is missing or malformed, so its privilege is unknown", self.attack, _MEMBERSHIP)]
        member = _sid(event.get("account.member_id"))
        rid = int(group.rsplit("-", 1)[1])
        label = _BUILTIN[rid] if group.startswith("s-1-5-32-") else _GROUPS[rid]
        notes = (("Builtin group membership is scoped to the recorded computer; a SID identifies the group role, "
                  "not the actor's intent. Remote-access groups do not establish administrator privileges."),)
        if event.outcome != Outcome.success:
            outcome = "failed" if event.outcome == Outcome.failure else "has an unresolved outcome"
            return [signal(event, "sensitive_group_attempt", f"Windows recorded an attempt to add a member to "
                           f"{label} ({group}); the operation {outcome}", self.attack, _MEMBERSHIP, notes=notes)]
        if member is None:
            return [signal(event, "sensitive_group_member_unknown", f"Windows recorded a member addition to "
                           f"{label} ({group}); the member SID is missing or malformed", self.attack, _MEMBERSHIP,
                           notes=notes)]
        return [signal(event, "sensitive_group_added", f"Windows recorded member {member} added to {label} ({group})",
                       self.attack, _MEMBERSHIP, lane="high", severity="high", notes=notes)]


class SidHistoryChange(_AccountRule):
    id = "win.sid_history_change"
    title = "SID history addition or failed addition was recorded"
    windows_event_classes = tuple(("Security", SECURITY, code) for code in (4765, 4766))
    attack = ("T1134.005",)
    benign = ("authorized account migration between domains",)
    next_checks = ("validate the migration and source domain", "inspect the exact SID-history values and resulting access")
    research = ("https://attack.mitre.org/techniques/T1134/005/", _ACCOUNT_DOC + "4765", _ACCOUNT_DOC + "4766")

    def judge(self, event):
        code = event.get("event.code")
        if code not in {4765, 4766}:
            return []
        fields = (*_IDENTITY, "account.sid_history", "account.privileges", "account.action")
        if code == 4766:
            return [signal(event, "sid_history_failed", "Windows recorded a failed attempt to add SID history to "
                           + self.describe(_target_text(event)), self.attack, fields)]
        if event.outcome != Outcome.success:
            return [signal(event, "sid_history_outcome_unknown", "Windows recorded a SID-history addition event "
                           "with a non-success normalized outcome; successful addition is not established",
                           self.attack, fields)]
        return [signal(event, "sid_history_added", "Windows recorded SID history added to "
                       + self.describe(_target_text(event)), self.attack, fields, lane="high", severity="high",
                       notes=(("SID-history addition also occurs during authorized migration; this event does not "
                               "establish malicious injection or the exact source SID when it is not typed."),))]


class DsrmPasswordAttempt(_AccountRule):
    id = "win.dsrm_password_attempt"
    title = "DSRM administrator password-setting attempt was recorded"
    windows_event_classes = (("Security", SECURITY, 4794),)
    attack = ("T1098",)
    benign = ("authorized recovery-password rotation and domain-controller maintenance",)
    next_checks = ("verify the original status and audit outcome", "validate the operator, maintenance window and DSRM use")
    research = (_ACCOUNT_DOC + "4794", "https://attack.mitre.org/techniques/T1098/")

    def judge(self, event):
        if event.get("event.code") != 4794:
            return []
        return [signal(event, "dsrm_password_attempt", "Windows recorded a Directory Services Restore Mode "
                       "administrator password-setting attempt", self.attack, _IDENTITY,
                       notes=(("This signal claims an attempt. The account-change normalizer does not retain the "
                               "native status field or honor every audit outcome marker, so success is not inferred."),))]


class AccountCreation(_AccountRule):
    id = "win.account_creation"
    title = "A user or domain computer account was created"
    windows_event_classes = tuple(("Security", SECURITY, code) for code in (4720, 4741))
    attack = ("T1136", "T1136.002")
    benign = ("approved user provisioning and domain joins",)
    next_checks = ("validate the creator and provisioning request", "follow the target SID into group additions and logons")
    research = (_ACCOUNT_DOC + "4720", _ACCOUNT_DOC + "4741", "https://attack.mitre.org/techniques/T1136/002/")

    def judge(self, event):
        code = event.get("event.code")
        if code not in {4720, 4741}:
            return []
        noun = "domain computer" if code == 4741 else "user"
        actor = event.get("user.entity_id") or event.get("user.name") or "an unresolved actor account"
        target = creation_target_sid(event)
        text = f"Windows recorded creation of a {noun} account {self.describe(target or _target_text(event))} "
        text += f"by the recorded actor account {self.describe(actor)}"
        if event.outcome != Outcome.success:
            text = f"Windows recorded a {noun}-account creation event with a non-success outcome; creation is not established"
        if target is None:
            text += "; the target SID is unresolved"
        return [signal(event, "account_created" if event.outcome == Outcome.success else "account_creation_outcome",
                       text, ("T1136.002",) if code == 4741 else ("T1136",), _IDENTITY,
                       notes=(("The recorded actor account does not independently establish whether its operator is "
                               "an ordinary user or an administrator. A computer-account name suffix is not proof "
                               "of the actor's privileges or object type."),))]


# OldUacValue/NewUacValue use MS-SAMR USER_ACCOUNT codes, not AD userAccountControl bits.
_FLAGS = (
    (0x4, "password_not_required", "password-not-required"),
    (0x200, "dont_expire_password", "password-never-expires"),
    (0x800, "encrypted_text_password_allowed", "reversible password storage"),
    (0x2000, "trusted_for_delegation", "trusted-for-delegation"),
    (0x8000, "use_des_key_only", "DES-only Kerberos keys"),
    (0x10000, "dont_require_preauth", "Kerberos preauthentication exemption"),
    (0x40000, "trusted_to_auth_for_delegation", "protocol-transition delegation"),
    (0x80000, "exclude_authorization_information", "Kerberos authorization-data exclusion"),
)
_SPN = re.compile(r"[^\s/<>]+/[^\s/<>]+(?:/[^\s/<>]+)?", re.ASCII)


class ComputerAccountConfiguration(_AccountRule):
    id = "win.computer_account_configuration"
    title = "Computer-account delegation or sensitive SAMR flags changed"
    windows_event_classes = (("Security", SECURITY, 4742),)
    attack = ("T1098",)
    benign = ("approved service delegation, compatibility work and account-policy changes",)
    next_checks = ("validate the full delegation list and SAMR flag changes", "inspect the operator and related directory changes")
    research = (_ACCOUNT_DOC + "4742", "https://attack.mitre.org/techniques/T1098/",
                "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/b10cfda1-f24f-441b-8f43-80cb93e786ec")

    def judge(self, event):
        if event.get("event.code") != 4742:
            return []
        fields = (*_IDENTITY, "account.allowed_to_delegate_to", "account.old_uac", "account.new_uac", "account.uac_changes")
        hits = []
        if "account.allowed_to_delegate_to" in event.fields:
            targets = event.get("account.allowed_to_delegate_to")
            clear = targets in ([], (), ["<value not set>"], ["-"])
            valid = (isinstance(targets, (list, tuple)) and bool(targets)
                     and all(isinstance(item, str) and "%%" not in item and _SPN.fullmatch(item) for item in targets))
            if clear:
                detail, high = "delegation target list was recorded cleared", False
            elif valid:
                detail, high = f"new full delegation target list was recorded as {self.describe(targets)}", True
            else:
                detail, high = "delegation list changed with missing, sentinel or malformed targets; its effect is unknown", False
            if event.outcome != Outcome.success:
                detail, high = "delegation configuration event has a non-success outcome; its effect is unknown", False
            hits.append(signal(event, "computer_delegation", "Computer-account " + detail, self.attack, fields,
                               lane="high" if high else "lead", severity="high" if high else "medium",
                               notes=(("AllowedToDelegateTo is the new full list, not an additions delta. This record "
                                       "does not establish resource-based constrained delegation or ticket use."),)))
        old, new = integer(event.get("account.old_uac")), integer(event.get("account.new_uac"))
        tokens = event.get("account.uac_changes", [])
        malformed = (not isinstance(tokens, (list, tuple)) or any(not isinstance(token, str) for token in tokens))
        token_set = {token.casefold() for token in tokens} if not malformed else set()
        malformed |= any(name in event.fields and integer(event.get(name)) is None
                         for name in ("account.old_uac", "account.new_uac"))
        known = {name + suffix for _, name, _ in _FLAGS for suffix in ("_enabled", "_disabled")}
        if malformed or token_set - known:
            hits.append(signal(event, "computer_uac_unknown", "Computer-account SAMR changes contain missing, "
                               "malformed or unrecognized flag data; their security effect is unknown", self.attack, fields))
        for mask, name, label in _FLAGS:
            enabled, disabled = name + "_enabled" in token_set, name + "_disabled" in token_set
            both = old is not None and new is not None
            transition_on = both and not old & mask and bool(new & mask)
            transition_off = both and bool(old & mask) and not new & mask
            conflict = enabled and disabled or (both and ((enabled and not transition_on) or (disabled and not transition_off)))
            if conflict or (malformed and (enabled or disabled or transition_on or transition_off)):
                text, high = f"{label} has inconsistent or malformed change evidence; its resulting state is unknown", False
            elif enabled or transition_on:
                text, high = f"{label} was recorded enabled", True
            elif disabled or transition_off:
                text, high = f"{label} was recorded disabled", False
            elif old is None and new is not None and new & mask:
                text, high = f"{label} is present in the new flags, but its previous state and transition are unknown", False
            else:
                continue
            if event.outcome != Outcome.success:
                text, high = f"{label} change has a non-success outcome; its effect is unknown", False
            hits.append(signal(event, "computer_flag_" + name, "Computer-account " + text, self.attack, fields,
                               lane="high" if high else "lead", severity="high" if high else "medium"))
        if len(hits) <= 1:
            return hits
        # The publisher identifies direct candidates by rule and cited record. Keep every
        # supported qualifier together so an earlier lead cannot displace a later high.
        high = any(hit.lane == "high" for hit in hits)
        notes = tuple(dict.fromkeys(note for hit in hits for note in hit.notes))
        return [signal(event, "computer_account_configuration", "; ".join(hit.text for hit in hits),
                       self.attack, fields, lane="high" if high else "lead",
                       severity="high" if high else "medium", notes=notes)]


WINDOWS_ACCOUNT_PLAYBOOKS = (PrivilegedGroupAddition, SidHistoryChange, DsrmPasswordAttempt, AccountCreation,
                             ComputerAccountConfiguration)
