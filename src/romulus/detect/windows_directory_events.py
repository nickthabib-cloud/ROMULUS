"""Direct positive Windows directory and Kerberos observations, with frozen site facts.

Replication rights and weak ticket encryption are investigation signals. They do not
prove credential extraction, offline password cracking or ticket forgery.
"""
from __future__ import annotations

import json
import re

from romulus.detect.base import PredicateField
from romulus.detect.windows_events import WindowsEventRule, integer
from romulus.detect.windows_events import signal as _signal
from romulus.evidence.typed import Outcome
from romulus.evidence.windows_catalog import SECURITY
from romulus.site import SiteFacts, absent_site_facts

_AUDIT = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/"
_GUID_TEXT = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
_GUID = re.compile(rf"(?:\{{({_GUID_TEXT})\}}|({_GUID_TEXT}))", re.IGNORECASE)
_GUID_TOKEN = re.compile(rf"(?<![a-z0-9{{}}-])(?:\{{({_GUID_TEXT})\}}|({_GUID_TEXT}))(?![a-z0-9{{}}-])",
                         re.IGNORECASE)
_REPLICATION = frozenset({"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
                          "89e95b76-444d-4c62-991a-0facbeda640c"})
_ACTOR = ("user.entity_id", "user.name", "user.domain")
_KERBEROS = ("auth.action", "auth.target_account", "account.name", "account.domain", "source.ip",
             "auth.service_name", "auth.service_sid", "auth.encryption_type", "auth.preauth_type",
             "auth.status", "auth.failure_code", "auth.logon_guid")
_DIRECTORY = (*_ACTOR, "directory.change.action", "directory.object.dn", "directory.object.guid",
              "directory.object.class", "directory.attribute.ldap_name", "directory.attribute.value",
              "directory.change.operation_type")
_MOVE_DNS = ("windows.event_data.OldObjectDN", "windows.event_data.NewObjectDN")
_CHANGES = {5136: "modification", 5137: "creation", 5138: "restoration", 5139: "move", 5141: "deletion"}


def signal(event, behavior, text, attack, fields, **kwargs):
    semantic = {name: event.get(name) for name in fields if name != "auth.logon_guid"}
    kwargs.setdefault("content", json.dumps({"outcome": event.outcome.value, "event.code": event.get("event.code"),
                                            **semantic}, sort_keys=True))
    return _signal(event, behavior, text, attack, fields, **kwargs)


def _security(*codes):
    return tuple(("Security", SECURITY, code) for code in codes)


def _text(value):
    return str(value or "").strip().casefold()


def _guid(value):
    match = _GUID.fullmatch(_text(value))
    return (match.group(1) or match.group(2)) if match else None


def _replication_rights(event):
    values = event.get("directory.rights.guids")
    if not isinstance(values, list):
        return set()
    rights = {_guid(value) for value in values} & _REPLICATION
    # The normalizer's GUID extractor has no token boundary. Cross-check the
    # structured native property field when present rather than interpreting text
    # in unrelated fields or accepting a GUID substring as an extended right.
    native_properties = event.get("windows.event_data.Properties")
    if native_properties is not None:
        tokens = {(match.group(1) or match.group(2)).casefold()
                  for match in _GUID_TOKEN.finditer(str(native_properties))}
        rights &= tokens
    return rights


def _actor_keys(event):
    keys = set()
    identity = _text(event.get("user.entity_id"))
    if identity.startswith(("sid:", "name:")):
        keys.add(identity)
    domain, name = _text(event.get("user.domain")), _text(event.get("user.name"))
    if domain and name:
        keys.add(f"name:{domain}\\{name}")
    return keys


def _listed_actor(event, facts):
    if _actor_keys(event) & {value.casefold() for value in facts.directory_sync_accounts}:
        return True
    # A matching DC account name is a reason to retain a lead, not proof of that
    # machine's account SID or authorization. No suffix alone excludes an actor.
    name = _text(event.get("user.name"))
    if not name.endswith("$"):
        return False
    machine = name[:-1].rstrip(".")
    domain = _text(event.get("user.domain"))
    for dc in facts.domain_controllers:
        full = dc.casefold().rstrip(".")
        host, separator, suffix = full.partition(".")
        if machine not in {full, host}:
            continue
        # DNS realms can be compared directly. A short/NetBIOS name has no
        # authoritative conversion to a DNS suffix, so a mismatch is unresolved.
        if domain and separator and "." in domain and domain.rstrip(".") != suffix:
            continue
        return True
    return False


class DirectoryReplicationAccess(WindowsEventRule):
    id = "win.directory_replication_access"
    version = "6"
    title = "A directory access record named replication extended rights"
    families = ("directory_access",)
    windows_event_classes = _security(4662)
    attack = ("T1003.006",)
    benign = ("domain controller replication, directory synchronization and authorized directory diagnostics",)
    next_checks = ("verify the actor SID and replication authorization independently",
                   "inspect the source host, logon and other replication-right records")
    research = (_AUDIT + "event-4662", "https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-all",
                "https://attack.mitre.org/techniques/T1003/006/")
    site_facts: SiteFacts | None = absent_site_facts()

    def judge(self, event):
        if event.get("event.code") != 4662 or not _replication_rights(event):
            return []
        facts = self.site_facts or absent_site_facts()
        declared_sync = bool(facts.directory_sync_accounts or facts.content.get("directory_sync_accounts_declared"))
        configured = bool(facts.present and facts.domain_controllers and declared_sync)
        listed = _listed_actor(event, facts)
        mask = integer(event.get("directory.access.access_mask"))
        actor_complete = bool(_actor_keys(event) and event.get("user.name") and event.get("user.domain"))
        positive = (event.outcome == Outcome.success and _text(event.get("directory.object.server")) == "ds"
                    and mask is not None and bool(mask & 0x100) and actor_complete)
        high = configured and positive and not listed
        notes = ["Replication extended-right access is not proof that credentials were extracted."]
        if not configured:
            notes.append("Domain controller or directory-sync account lists are not configured; actor authorization is unresolved.")
            self.note_coverage("site_facts", "Domain controller or directory-sync account lists are not configured.")
        if listed:
            notes.append("The recorded actor is listed by site identity or DC account name; retain the observation as a lead.")
        if not positive:
            notes.append("The full successful DS/control-access/actor conjunction is not recorded; this is a lead.")
        prefix = "A failed directory access record" if event.outcome == Outcome.failure else "A directory access record"
        actor = self.describe(event.get("user.entity_id") or event.get("user.name"))
        target = self.describe(event.get("directory.object.dn"))
        return [signal(event, "directory_replication_rights",
                       f"{prefix} named replication extended rights on {target} by actor {actor}",
                       self.attack, (*_ACTOR, "directory.object.server", "directory.object.dn", "directory.object.type",
                                     "directory.access.action", "directory.access.access_mask", "directory.access.accesses",
                                     "directory.rights.guids", "directory.rights.names", "windows.event_data.Properties"),
                       lane="high" if high else "lead", severity="high" if high else "medium", notes=tuple(notes))]


class WeakKerberosTicketEncryption(WindowsEventRule):
    id = "win.weak_kerberos_ticket_encryption"
    version = "4"
    title = "A Kerberos ticket record reported DES or RC4 encryption"
    families = ("auth",)
    windows_event_classes = _security(4768, 4769, 4770)
    attack = ("T1558.003", "T1558")
    benign = ("legacy applications, interoperability and service-account key configuration can require weak encryption",)
    next_checks = ("check the service account object type, key material and allowed encryption types",
                   "review the requester, client and service-ticket request diversity")
    research = (_AUDIT + "event-4769", "https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos",
                "https://attack.mitre.org/techniques/T1558/003/")

    def judge(self, event):
        code, etype = event.get("event.code"), integer(event.get("auth.encryption_type"))
        if code not in {4768, 4769, 4770} or etype not in {1, 3, 23, 24}:
            return []
        service = _text(event.get("auth.service_name"))
        user_service = (code == 4769 and etype in {23, 24} and service not in {"", "-", "krbtgt"}
                        and not service.endswith("$") and service.split("/", 1)[0] != "krbtgt")
        prefix = "A failed Kerberos ticket request" if event.outcome == Outcome.failure else "A Kerberos ticket record"
        suffix = "RC4 encryption and a user-service-like service name" if user_service else "weak DES or RC4 encryption"
        return [signal(event, "rc4_user_service" if user_service else "weak_ticket_encryption", prefix + " reported " + suffix,
                       self.attack, _KERBEROS,
                       notes=(("Encryption and service-name shape are not proof of roasting or ticket forgery. "
                               "A name ending in '$' is not proof of the account object type."),))]


class KerberosNoPreauthentication(WindowsEventRule):
    id = "win.kerberos_no_preauthentication"
    version = "4"
    title = "A TGT request recorded pre-authentication type zero"
    families = ("auth",)
    windows_event_classes = _security(4768)
    attack = ("T1558.004",)
    benign = ("accounts intentionally configured without pre-authentication and legacy interoperability",)
    next_checks = ("verify the account's pre-authentication policy and request result",
                   "review the requesting client and subsequent authentication activity")
    research = (_AUDIT + "event-4768", "https://attack.mitre.org/techniques/T1558/004/")

    def judge(self, event):
        if (event.get("event.code") != 4768 or integer(event.get("auth.preauth_type")) != 0
                or event.outcome == Outcome.failure):
            return []
        results = [integer(event.get(field)) for field in ("auth.status", "auth.failure_code") if event.has(field)]
        if any(value is not None and value != 0 for value in results):
            return []
        confirmed = event.outcome == Outcome.success and bool(results) and all(value == 0 for value in results)
        text = ("A successful TGT request recorded that Kerberos pre-authentication was not used" if confirmed else
                "A TGT request recorded pre-authentication type zero; successful issuance is unconfirmed")
        return [signal(event, "kerberos_no_preauthentication", text, self.attack, _KERBEROS,
                       notes=("This records the request and its reported result, not offline password cracking.",))]


def _split_unescaped(text, separator):
    parts, start, index = [], 0, 0
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == separator:
            parts.append(text[start:index])
            start = index + 1
        index += 1
    parts.append(text[start:])
    return parts


def _unescape_rdn(text):
    buffer, index = bytearray(), 0
    while index < len(text):
        char = text[index]
        if char != "\\":
            if char in {'"', '<', '>', ';', '\x00'}:
                return None
            try:
                buffer.extend(char.encode("utf-8"))
            except UnicodeEncodeError:
                return None
            index += 1
            continue
        if index + 1 >= len(text):
            return None
        pair = text[index + 1:index + 3]
        if len(pair) == 2 and re.fullmatch(r"[0-9a-fA-F]{2}", pair):
            buffer.append(int(pair, 16))
            index += 3
        elif text[index + 1] in ' #+,;<>="\\':
            buffer.extend(text[index + 1].encode("utf-8"))
            index += 2
        else:
            return None
    try:
        return buffer.decode("utf-8").casefold()
    except UnicodeDecodeError:
        return None


def parse_dn(value):
    """Parse escaped commas, UTF-8 hex escapes and multi-valued RDNs without substring matching."""
    if not isinstance(value, str) or not value.strip():
        return None
    rdns = []
    for raw_rdn in _split_unescaped(value, ","):
        attributes = []
        for raw_attribute in _split_unescaped(raw_rdn, "+"):
            name, separator, raw_value = raw_attribute.partition("=")
            name = name.strip().casefold()
            if not separator or not re.fullmatch(r"[a-z][a-z0-9-]*|[0-9]+(?:\.[0-9]+)+", name):
                return None
            decoded = _unescape_rdn(raw_value.strip())
            if decoded in (None, ""):
                return None
            attributes.append((name, decoded))
        rdns.append(tuple(sorted(attributes)))
    return tuple(rdns)


def _domain_suffix(rdns):
    return bool(rdns) and all(len(rdn) == 1 and rdn[0][0] == "dc" and rdn[0][1] for rdn in rdns)


def _adminsdholder(rdns):
    return (bool(rdns) and rdns[:2] == ((("cn", "adminsdholder"),), (("cn", "system"),))
            and _domain_suffix(rdns[2:]))


def _policy_path(rdns):
    if not rdns:
        return False
    container = ((("cn", "policies"),), (("cn", "system"),))
    if rdns[:2] == container and _domain_suffix(rdns[2:]):
        return True
    return (len(rdns) >= 4 and len(rdns[0]) == 1 and rdns[0][0][0] == "cn" and _guid(rdns[0][0][1])
            and rdns[1:3] == container and _domain_suffix(rdns[3:]))


class _DirectoryChangeRule(WindowsEventRule):
    families = ("directory_change",)
    windows_event_classes = _security(*_CHANGES)

    def selected(self, event, rdns):
        raise NotImplementedError

    def judge(self, event):
        code = event.get("event.code")
        action = _CHANGES.get(code)
        if not action:
            return []
        endpoint_event = code in {5138, 5139}
        names = ("directory.object.dn", *_MOVE_DNS) if endpoint_event else ("directory.object.dn",)
        parsed = {name: parse_dn(event.get(name)) for name in names if event.has(name)}
        # Native move/restoration schemas record old/new DNs instead of ObjectDN.
        # Prefer those schema fields when present; a stray ObjectDN cannot override
        # their recorded endpoints. Exact class/attribute selection remains useful
        # when an endpoint is missing or malformed.
        candidates = (_MOVE_DNS if endpoint_event and any(event.has(name) for name in _MOVE_DNS)
                      else ("directory.object.dn",))
        if not any(self.selected(event, parsed.get(name)) for name in candidates):
            return []
        prefix = "A failed directory-change audit" if event.outcome == Outcome.failure else "A directory-change record"
        text = prefix + f" reported {action} of {self.subject}"
        text += (f"; actor {self.describe(event.get('user.entity_id') or event.get('user.name'))}"
                 f"; object {self.describe(event.get('directory.object.dn'))}"
                 f"; attribute {self.describe(event.get('directory.attribute.ldap_name'))}")
        notes = ["The claim names the event's recorded action; it does not establish a malicious policy effect."]
        if endpoint_event:
            if all(parsed.get(name) is not None for name in _MOVE_DNS):
                old, new = (self.describe(event.get(name)) for name in _MOVE_DNS)
                text += f" from {old!r} to {new!r}"
            else:
                notes.append("An old or new distinguished name is unrecorded or malformed; endpoint direction is unresolved.")
        hit = signal(event, self.behavior, text, self.attack, (*_DIRECTORY, *_MOVE_DNS) if endpoint_event else _DIRECTORY,
                     notes=tuple(notes))
        for name, rdns in parsed.items():
            if rdns is not None:
                hit.predicate.append(PredicateField(name, rdns, event.fields[name].origin + "#parsed:directory-rdns"))
        return [hit]


class AdminSdHolderChange(_DirectoryChangeRule):
    id = "win.adminsdholder_change"
    version = "5"
    title = "A directory change named the exact AdminSDHolder object"
    behavior, subject = "adminsdholder_change", "the domain AdminSDHolder object"
    attack = ("T1098",)
    benign = ("authorized changes to protected-account permissions and directory recovery",)
    next_checks = ("inspect the exact changed attribute and security descriptor",
                   "verify the actor's authorization and resulting protected-account permissions")
    research = (_AUDIT + "event-5136", _AUDIT + "event-5139", "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory",
                "https://attack.mitre.org/techniques/T1098/")

    def selected(self, event, rdns):
        return _adminsdholder(rdns)


class GroupPolicyDirectoryChange(_DirectoryChangeRule):
    id = "win.group_policy_directory_change"
    version = "5"
    title = "A directory change named a GPO object, policy container or policy link attribute"
    behavior, subject = "group_policy_directory_change", "a group-policy object, policy container or link attribute"
    attack = ("T1484.001",)
    benign = ("routine policy administration, software deployment and policy-link maintenance",)
    next_checks = ("review the complete GPO and SYSVOL contents", "verify the actor, change request and linked scope")
    research = (_AUDIT + "event-5136", _AUDIT + "event-5139", "https://attack.mitre.org/techniques/T1484/001/")

    def selected(self, event, rdns):
        return (_text(event.get("directory.object.class")) == "grouppolicycontainer" or _policy_path(rdns)
                or _text(event.get("directory.attribute.ldap_name")) in {"gplink", "gpoptions"})


class TrustDirectoryChange(_DirectoryChangeRule):
    id = "win.trust_directory_change"
    version = "5"
    windows_event_classes = _security(*_CHANGES, 4706, 4716)
    title = "A directory change named a trust object or exact trust attribute"
    behavior, subject = "trust_directory_change", "a trust object or trust attribute"
    attack = ("T1484.002",)
    benign = ("authorized forest/domain trust maintenance, rotation and recovery",)
    next_checks = ("review trust direction, attributes and authentication material", "verify partner domain and actor authorization")
    research = (_AUDIT + "event-4706", _AUDIT + "event-4716", _AUDIT + "event-5136", _AUDIT + "event-5139",
                "https://attack.mitre.org/techniques/T1484/002/")

    def judge(self, event):
        code = event.get("event.code")
        if code not in {4706, 4716}:
            return super().judge(event)
        fields = (*_ACTOR, "directory.trust.domain_name", "directory.trust.domain_sid", "directory.trust.type",
                  "directory.trust.direction", "directory.trust.attributes", "directory.trust.sid_filtering_enabled")
        action = "creation" if code == 4706 else "modification"
        return [signal(event, "trust_directory_change", f"Windows recorded a domain trust {action} event; "
                       "the recorded values do not establish a malicious trust effect", self.attack, fields)]

    def selected(self, event, rdns):
        return (_text(event.get("directory.object.class")) == "trusteddomain"
                or _text(event.get("directory.attribute.ldap_name")) in {
                    "trustattributes", "trustdirection", "trusttype", "trustpartner", "trustauthincoming",
                    "trustauthoutgoing", "msds-trustforesttrustinfo",
                })


class SensitiveDirectoryAttributeChange(_DirectoryChangeRule):
    id = "win.sensitive_directory_attribute_change"
    version = "4"
    title = "A directory change names a credential, delegation or domain-root permissions attribute"
    windows_event_classes = _security(5136)
    behavior, subject = "sensitive_directory_attribute_change", "a credential, delegation or domain-root permissions attribute"
    attack = ("T1098",)
    benign = ("authorized delegation, key provisioning, SPN registration and directory permission changes",)
    next_checks = ("inspect added and deleted values and the target object's effective permissions",)
    research = (_AUDIT + "event-5136", "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/45916e5b-d66f-444e-b1e5-5b0666ed4d66",
                "https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtoactonbehalfofotheridentity")

    def selected(self, event, rdns):
        attribute = _text(event.get("directory.attribute.ldap_name"))
        return (event.get("event.code") == 5136 and (attribute in {
            "msds-allowedtoactonbehalfofotheridentity", "msds-keycredentiallink", "serviceprincipalname",
        } or attribute == "ntsecuritydescriptor" and _domain_suffix(rdns)))


WINDOWS_DIRECTORY_PLAYBOOKS = (
    DirectoryReplicationAccess, WeakKerberosTicketEncryption, KerberosNoPreauthentication,
    AdminSdHolderChange, GroupPolicyDirectoryChange, TrustDirectoryChange, SensitiveDirectoryAttributeChange,
)
