"""Linux audit action families and their typed fields.

The syscall numbers follow Linux's architecture UAPI tables. Only an explicit audit
watch key admits read-only opens; a missing path or operation remains missing.
"""
from __future__ import annotations

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
FAMILY_DATASETS = {name: ("linux.audit",) for name in FAMILY_FIELDS}
WATCH_PLACEHOLDERS = frozenset({"", "(null)", "(none)", "-", "null", "none"})
SOURCES = (
    "https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/entry/syscalls/syscall_64.tbl",
    "https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/asm-generic/unistd.h",
    "https://man7.org/linux/man-pages/man2/init_module.2.html",
)


def module_syscall(record):
    if record is None:
        return None
    table = MODULE_SYSCALLS.get(record.fields.get("arch"), {})
    number = record.fields.get("syscall", "")
    return table.get(int(number)) if number.isdigit() else None
