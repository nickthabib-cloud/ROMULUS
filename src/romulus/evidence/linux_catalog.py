"""Linux host datasets, the shipper shapes they arrive in, and the audit action families with their typed fields.

The syscall numbers follow Linux's architecture UAPI tables. Only an explicit audit
watch key admits read-only opens; a missing path or operation remains missing.

Logical datasets. Coverage, baselines, pivots, Sigma and the catalog key Linux host telemetry by a logical dataset
id (`linux.audit`, `systemd.journal`, `linux.syslog`, `apache.access`, `apache.error`). Each id is delivered by one
or more shipper shapes: the dataset name a shipper writes, plus what else must hold for a document to be that shape
(Auditbeat's bare `auditd` dataset name is only Auditbeat's with `event.module: auditd`; Filebeat's journald input
writes no dataset at all). `LINUX_SHIPPER_DATASETS` is the one table every module reads.
"""
from __future__ import annotations

from dataclasses import dataclass

MODULE_SYSCALLS = {
    "c000003e": {175: "init_module", 313: "finit_module", 176: "delete_module"},
    "c00000b7": {105: "init_module", 273: "finit_module", 106: "delete_module"},
}
FAMILY_FIELDS = {
    "kernel_module": ("module.name", "module.op", "module.path", "process.executable",
                      "process.pid", "process.ppid", "process.uid", "process.euid", "process.auid", "audit.serial"),
    "file_access": ("file.path", "file.access", "file.owner.id", "file.owner.name", "file.open_flags",
                    "process.executable", "process.pid", "process.uid", "audit.serial", "audit.key"),
}
WATCH_PLACEHOLDERS = frozenset({"", "(null)", "(none)", "-", "null", "none"})
SOURCES = (
    "https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/entry/syscalls/syscall_64.tbl",
    "https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/asm-generic/unistd.h",
    "https://man7.org/linux/man-pages/man2/init_module.2.html",
)

# Shapes: how a document of a shipper dataset carries its record.
AUDIT_RECORD = "audit_record"        # one audit record: a raw line, or fields the shipper parsed from one
AUDIT_EVENT = "audit_event"          # one audit event, its records merged by the shipper (Auditbeat, Auditd Manager)
JOURNAL_JSON = "journal_json"        # the journal record as JSON in event.original (the dev importer)
JOURNAL_FIELDS = "journal_fields"    # journal fields mapped to ECS by the shipper (Filebeat/Agent journald input)
SYSLOG_LINE = "syslog_line"          # a syslog line from a file or the journal (System integration, system module)
APACHE_ACCESS = "apache_access"
APACHE_ERROR = "apache_error"


@dataclass(frozen=True)
class ShipperShape:
    """One way a logical dataset arrives. `dataset` is the shipper's dataset name (None: the shipper writes none);
    `module` and `input_type` are the event.module and input.type the document must also carry."""
    dataset: str | None
    shape: str
    shipper: str
    module: str | None = None
    input_type: str | None = None

    @property
    def key(self) -> str:
        """The shape's name in counts and reasons: its dataset, qualified when the dataset alone does not decide."""
        if self.dataset is None:
            return f"input.type:{self.input_type}" if self.input_type else f"event.module:{self.module}"
        return f"{self.dataset}+event.module:{self.module}" if self.module else self.dataset

    @property
    def undated(self) -> tuple[str, str] | None:
        """(field, value) that selects this shape's documents, which name no dataset; None for a named dataset."""
        if self.dataset is not None:
            return None
        return ("input.type", self.input_type) if self.input_type else ("event.module", str(self.module))


LINUX_SHIPPER_DATASETS: dict[str, tuple[ShipperShape, ...]] = {
    "linux.audit": (
        ShipperShape("linux.audit", AUDIT_RECORD, "dev importer (raw audit line)"),
        ShipperShape("auditd.log", AUDIT_RECORD, "Filebeat auditd module or Elastic Agent Auditd Logs"),
        ShipperShape("auditd", AUDIT_EVENT, "Auditbeat auditd module", module="auditd"),
        ShipperShape("auditd_manager.auditd", AUDIT_EVENT, "Elastic Agent Auditd Manager"),
        # Auditbeat's own documents carry event.module and no event.dataset
        ShipperShape(None, AUDIT_EVENT, "Auditbeat auditd module (no dataset)", module="auditd"),
    ),
    "systemd.journal": (
        ShipperShape("systemd.journal", JOURNAL_JSON, "dev importer (journal JSON)"),
        ShipperShape("journald.logs", JOURNAL_FIELDS, "Elastic Agent Custom Journald"),
        ShipperShape(None, JOURNAL_FIELDS, "Filebeat journald input", input_type="journald"),
    ),
    "linux.syslog": (
        ShipperShape("system.auth", SYSLOG_LINE, "System integration or Filebeat system module"),
        ShipperShape("system.syslog", SYSLOG_LINE, "System integration or Filebeat system module"),
    ),
    "apache.access": (ShipperShape("apache.access", APACHE_ACCESS, "Apache integration or Filebeat module"),),
    "apache.error": (ShipperShape("apache.error", APACHE_ERROR, "Apache integration or Filebeat module"),),
}
LINUX_LOGICAL_DATASETS: tuple[str, ...] = tuple(LINUX_SHIPPER_DATASETS)

# The event families each logical dataset can feed. An audit group's records can be any of its families; journal
# and syslog lines feed sshd/sudo/useradd/systemd records.
_AUDIT_ADMIN = frozenset({"account_change", "service_change", "audit_config", "system_state"})
LOGICAL_FAMILIES: dict[str, frozenset[str]] = {
    "linux.audit": frozenset({"process_exec", "net_socket", "auth", "file_change", "file_access", "kernel_module",
                              "process_observed"}) | _AUDIT_ADMIN,
    "systemd.journal": frozenset({"auth", "privilege_use", "service_change"}),
    "linux.syslog": frozenset({"auth", "privilege_use", "account_change", "service_change"}),
    "apache.access": frozenset({"http_access"}),
    "apache.error": frozenset({"web_error"}),
}
FAMILY_DATASETS = {name: ("linux.audit",) for name in FAMILY_FIELDS}
# event.module values (and the journald input type) whose documents are Linux host telemetry of one logical dataset:
# a document of one that matches no shape above is a blind spot of that dataset's families, never silently unread.
_MODULE_LOGICAL = {"auditd": ("linux.audit",), "system": ("linux.syslog",),
                   "apache": ("apache.access", "apache.error")}


def _value(source: dict, path: str):
    cur = source
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def document_dataset(source: dict) -> str:
    """The dataset a document names: event.dataset, else data_stream.dataset (empty when it names none)."""
    for path in ("event.dataset", "data_stream.dataset"):
        value = _value(source, path)
        if isinstance(value, str) and value:
            return value
    return ""


def match_shape(source: dict) -> tuple[str, ShipperShape] | None:
    """(logical dataset, shape) of a Linux host document, or None when it is no shape the table lists."""
    dataset = document_dataset(source)
    module = _value(source, "event.module")
    input_type = _value(source, "input.type")
    for logical, shapes in LINUX_SHIPPER_DATASETS.items():
        for shape in shapes:
            if shape.dataset is None:
                field, value = shape.undated
                if not dataset and (input_type if field == "input.type" else module) == value:
                    return logical, shape
            elif dataset == shape.dataset and (shape.module is None or module == shape.module):
                return logical, shape
    return None


def unmatched_families(source: dict) -> frozenset[str] | None:
    """For a document that matches no shape: the families it could have fed when it is plainly Linux host telemetry
    of a module we read (event.module auditd, system or apache, or the journald input), else None."""
    module = _value(source, "event.module")
    logicals = _MODULE_LOGICAL.get(module) if isinstance(module, str) else None
    if logicals is None and _value(source, "input.type") == "journald":
        logicals = ("systemd.journal",)
    if logicals is None:
        return None
    return frozenset().union(*(LOGICAL_FAMILIES[name] for name in logicals))


def shipper_names(logicals=None) -> tuple[str, ...]:
    """Every shipper dataset name of the logical datasets (all of them by default), in table order."""
    names: list[str] = []
    for logical in LINUX_LOGICAL_DATASETS if logicals is None else logicals:
        for shape in LINUX_SHIPPER_DATASETS.get(logical, ()):
            if shape.dataset is not None and shape.dataset not in names:
                names.append(shape.dataset)
    return tuple(names)


def logical_of(name: str) -> str | None:
    """The logical dataset a shipper dataset name (as an inventory lists it) belongs to; None for other names."""
    for logical, shapes in LINUX_SHIPPER_DATASETS.items():
        if any(shape.dataset == name for shape in shapes):
            return logical
    return None


def with_logical(names) -> set[str]:
    """The dataset names, plus the logical dataset of each Linux shipper name among them."""
    out = {str(name) for name in names}
    return out | {logical for name in out if (logical := logical_of(name)) is not None}


def exec_capable_dataset(name) -> bool:
    """Whether records of a dataset (a shipper name, a logical id or an error tag) can hold process executions."""
    text = str(name)
    return text.startswith("linux.audit") or logical_of(text) == "linux.audit"


def dataset_selection(values, *, module_searchable: bool, input_type_searchable: bool
                      ) -> tuple[list[str], list[tuple[str, str]], list[tuple[str, str]], list[str]]:
    """How a dataset predicate over `values` is searched: (plain dataset names, (dataset name, event.module) pairs,
    (field, value) pairs selecting documents that name no dataset, shape keys that cannot be searched on this
    target). A logical Linux id expands to all its shapes; any other value is kept as it is."""
    plain: list[str] = []
    with_module: list[tuple[str, str]] = []
    input_types: list[tuple[str, str]] = []
    unsearchable: list[str] = []
    for value in values:
        shapes = LINUX_SHIPPER_DATASETS.get(value)
        if shapes is None:
            if value not in plain:
                plain.append(value)
            continue
        for shape in shapes:
            if shape.dataset is None:
                item = shape.undated
                searchable = input_type_searchable if item[0] == "input.type" else module_searchable
                target = input_types
            elif shape.module is not None:
                target, searchable, item = with_module, module_searchable, (shape.dataset, shape.module)
            else:
                target, searchable, item = plain, True, shape.dataset
            if not searchable:
                if shape.key not in unsearchable:
                    unsearchable.append(shape.key)
            elif item not in target:
                target.append(item)
    return plain, with_module, input_types, unsearchable


def module_syscall(record):
    if record is None:
        return None
    table = MODULE_SYSCALLS.get(record.fields.get("arch"), {})
    number = record.fields.get("syscall", "")
    return table.get(int(number)) if number.isdigit() else None
