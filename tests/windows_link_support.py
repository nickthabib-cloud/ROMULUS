"""Native envelopes for Windows pair facts and their frozen-site integration tests."""
import hashlib
from datetime import timedelta

from romulus.evidence.typed import fv
from romulus.evidence.windows import normalize_windows
from romulus.evidence.windows_catalog import SECURITY
from tests.windows_event_support import START
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit


def event(family, code, *, host="ws01", offset=0, native=None, outcome="success", **fields):
    names = {"auth.logon_guid": "LogonGuid", "auth.session_id": "TargetLogonId",
             "process.subject_session_id": "SubjectLogonId", "process.target_session_id": "TargetLogonId",
             "process.session_id": "SubjectLogonId", "user.name": "SubjectUserName",
             "user.domain": "SubjectDomainName", "user.entity_id": "SubjectUserSid",
             "directory.rights.guids": "Properties", "directory.object.server": "ObjectServer",
             "directory.access.access_mask": "AccessMask"}
    data = {}
    for name, value in fields.items():
        if name in {"host.boot.id", "host.os.family"}:
            continue  # Boot identity is supplied by the hunt's separate observed-boot context.
        assert name in names, f"Native test mapping missing: {name}"
        if isinstance(value, (list, tuple)):
            value = " ".join(value)
        if name == "user.entity_id":
            value = str(value).removeprefix("sid:")
        data[names[name]] = value
    record = int(hashlib.sha256(str((family, code, host, offset, native, fields)).encode()).hexdigest()[:12], 16)
    logical = LogicalWindowsEvent("Security", SECURITY, code, host, record,
                                  (START + timedelta(seconds=offset)).isoformat(), data)
    hit = windows_hit(logical, "winlogbeat_8")
    hit["_source"].setdefault("event", {})["outcome"] = outcome
    observed = normalize_windows(hit)
    assert observed.family == family
    if "host.boot.id" in fields:
        observed.fields["host.boot.id"] = fv(fields["host.boot.id"], "test:observed-boot-context")
    if "host.os.family" in fields:
        observed.fields["host.os.family"] = fv(fields["host.os.family"], "test:os-scope-fence")
    return observed
