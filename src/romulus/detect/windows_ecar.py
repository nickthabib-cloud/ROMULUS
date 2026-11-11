"""Semantic class alternatives for eCAR records without Windows event-log IDs."""
from __future__ import annotations

from romulus.evidence.typed import TypedEvent


def ecar_record(event: TypedEvent) -> bool:
    return event.normalizer.partition("@")[0] == "ecar" and event.get("host.os.family") == "windows"


def class_discriminator(event: TypedEvent, code: int, family: str) -> bool:
    """Preserve the event-code gate for event logs; use typed semantics for eCAR.

    These alternatives describe only classes whose meaning is completely carried
    by the normalized family and action. Audit results, grants, access masks and
    event-log-specific semantics have no alternative here.
    """
    if not ecar_record(event):
        return event.get("event.code") == code
    if event.family != family:
        return False
    object_name, action = event.get("ecar.object"), event.get("ecar.action")
    if code in {1, 4688}:
        return family == "process_exec" and (object_name, action) == ("PROCESS", "CREATE")
    if code == 3:
        return family == "net_socket" and object_name == "FLOW" and action in {"START", "OPEN", "MESSAGE"}
    if code == 7:
        return (family == "image_load" and (object_name, action) == ("MODULE", "LOAD")
                and event.get("image.kind") == "image")
    if code == 11:
        return (family == "file_change" and (object_name, action) == ("FILE", "CREATE")
                and event.get("file.action") == "created")
    if code in {23, 26}:
        return (family == "file_change" and (object_name, action) == ("FILE", "DELETE")
                and event.get("file.action") == "deleted")
    if code == 12:
        return (family == "registry_change" and object_name == "REGISTRY"
                and event.get("registry.action") in {"object_created", "object_deleted"})
    if code in {13, 4657}:
        return (family == "registry_change" and object_name == "REGISTRY" and action in {"ADD", "EDIT"}
                and event.get("registry.action") in {"value_set", "value_modified"})
    return False


def source_label(event: TypedEvent) -> str:
    return "eCAR" if ecar_record(event) else "Sysmon"
