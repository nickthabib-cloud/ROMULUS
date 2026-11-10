"""eCAR object/action contracts and explicitly supported property names.

The public eCAR schema documents PROCESS/CREATE; the remaining rows are expected
export vocabulary based on the CAR model, not assertions about a particular sensor.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

ECAR_SCHEMA = "https://github.com/FiveDirections/OpTC-data/blob/master/ecar.md"
CAR_MODEL = "https://car.mitre.org/data_model/"


@dataclass(frozen=True)
class EcarRow:
    family: str | None
    properties: dict[str, str]
    support: Literal["documented", "expected"] = "expected"
    reason: str = ""


_PROCESS = {"image_path": "process.executable", "parent_image_path": "process.parent.executable",
            "command_line": "process.command_line", "user": "process.user", "sid": "user.sid"}
_ACTOR = {"image_path": "process.executable", "user": "process.user", "sid": "user.sid"}
_FLOW = {**_ACTOR, "src_ip": "source.ip", "src_port": "source.port", "dest_ip": "destination.ip",
         "dest_port": "destination.port", "direction": "network.direction", "l4protocol": "network.transport",
         "network_direction": "network.direction", "transport_protocol": "network.transport",
         "bro_id": "zeek.uid", "bro-id": "zeek.uid", "zeek_uid": "zeek.uid",
         "acuity_level": "ecar.acuity_level"}
_FILE = {**_ACTOR, "file_path": "file.path", "new_path": "file.new_path"}
_MODULE = {**_ACTOR, "module_path": "image.path"}
_REGISTRY = {**_ACTOR, "key": "registry.path", "value": "registry.value_name",
             "data": "registry.value", "type": "registry.value_type"}
_THREAD = {**_ACTOR, "src_pid": "source.pid", "tgt_pid": "target.pid", "src_tid": "source.thread.id",
           "tgt_tid": "thread.id", "start_address": "thread.start_address",
           "start_function": "thread.start_function", "start_module": "thread.start_module"}
_SESSION = {**_ACTOR, "user": "auth.target_user", "logon_id": "auth.session_id",
            "login_id": "auth.session_id", "requesting_domain": "user.domain",
            "requesting_user": "user.name", "src_ip": "source.ip", "src_port": "source.port",
            "login_successful": "auth.login_successful", "login_type": "auth.logon_type"}
_SERVICE = {"name": "service.name", "image_path": "service.image_path", "start_type": "service.start_type",
            "service_type": "service.type", "user": "service.account"}
_TASK = {**_ACTOR, "task_name": "task.name", "path": "task.path", "user_name": "task.user_context"}
_SHELL = {**_ACTOR, "payload": "script.text", "context_info": "script.context"}


def _row(family, properties, support="expected", reason=""):
    return EcarRow(family, MappingProxyType(properties), support, reason)


ECAR_ROWS = {
    ("PROCESS", "CREATE"): _row("process_exec", _PROCESS, "documented"),
    ("PROCESS", "TERMINATE"): _row("process_termination", _PROCESS),
    ("PROCESS", "OPEN"): _row("process_access", {
        **_PROCESS, "target_pid": "target.pid", "target_name": "target.executable",
        "access_level": "process.access.mask", "call_trace": "process.access.call_trace"}),
    **{("FLOW", action): _row("net_socket", _FLOW) for action in ("START", "OPEN", "MESSAGE")},
    **{("FILE", action): _row("file_change", _FILE) for action in ("CREATE", "DELETE", "RENAME")},
    **{("FILE", action): _row(None, _FILE, reason="Windows file-access semantics are not typed")
       for action in ("MODIFY", "WRITE", "READ")},
    ("MODULE", "LOAD"): _row("image_load", _MODULE),
    **{("REGISTRY", action): _row("registry_change", _REGISTRY) for action in ("ADD", "EDIT", "REMOVE")},
    ("THREAD", "REMOTE_CREATE"): _row("remote_thread", _THREAD),
    **{("THREAD", action): _row(None, _THREAD, reason="local thread lifecycle is not typed")
       for action in ("CREATE", "TERMINATE")},
    **{("USER_SESSION", action): _row("auth", _SESSION)
       for action in ("LOGIN", "LOGOUT", "INTERACTIVE", "REMOTE", "RDP", "UNLOCK", "GRANT")},
    ("SERVICE", "CREATE"): _row("service_change", _SERVICE),
    **{("TASK", action): _row("scheduled_task", _TASK) for action in ("CREATE", "MODIFY", "DELETE", "START")},
    ("SHELL", "COMMAND"): _row("script_block", _SHELL),
    ("HOST", "START"): _row("system_state", {}),
}
ECAR_FAMILIES = frozenset(row.family for row in ECAR_ROWS.values() if row.family)


def lookup_ecar(source: dict) -> EcarRow | None:
    object_name, action = source.get("object"), source.get("action")
    if not isinstance(object_name, str) or not isinstance(action, str):
        return None
    return ECAR_ROWS.get((object_name, action))
