"""Linux host records in each shipper's indexed shape, built from one activity's raw records.

Written for ROMULUS from the shippers' documentation and the behaviour of their parsers: the Elastic Agent Auditd Logs
ingest pipeline (key=value parse, hex and boolean handling, the go-libaudit identity copies, the ECS renames, Fleet's
removal of event.original), Auditbeat's merged event documents (go-libaudit field names), the journald input's field
layout in both of its spellings, and the System integration / Filebeat system module auth fields. No shipper test file
is copied; every document is generated here from the raw lines below.

Shapes:
- dev: the dev importer (`linux.audit` raw line, `systemd.journal` JSON);
- filebeat_audit: Filebeat's auditd module (`auditd.log`, raw line kept);
- agent_audit: Elastic Agent Auditd Logs (`auditd.log`, fields only; with `preserve=True` the raw line is kept);
- auditbeat_raw / auditd_manager_raw: one event per document with its raw lines (array / newline-joined string);
- auditbeat_event: one event per document, fields only (built per activity);
- journald: Agent Custom Journald (`journald.logs`) or Filebeat's journald input (no dataset), old or new spelling;
- syslog: System integration lines from a file or the journal, and the Filebeat system module with its message
  dropped after its own pattern matched.
"""
from __future__ import annotations

import json
import re
from datetime import UTC, datetime

HOST = "web1"
T0 = 1731938400.0          # 2024-11-18T14:00:00Z


def iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def hexs(text: str) -> str:
    return text.encode().hex().upper()


def hit(source: dict, native_id: str, index: str = "linux-x") -> dict:
    return {"_index": index, "_id": native_id, "_source": source}


# ---------------------------------------------------------------------------------------------------------------
# One event's raw audit records per activity (x86_64)
# ---------------------------------------------------------------------------------------------------------------

def _hdr(kind: str, ts: float, serial: int) -> str:
    return f"type={kind} msg=audit({ts:.3f}:{serial}):"


def _syscall(ts, serial, *, number, a, success="yes", exit_code="0", items=0, ppid=4000, pid=4001, comm, exe,
             uid="1000", euid="1000", auid="1000", ses="7", tty="pts0", key="(null)", enrich=True) -> str:
    key_text = key if key == "(null)" else f'"{key}"'
    line = (f"{_hdr('SYSCALL', ts, serial)} arch=c000003e syscall={number} success={success} exit={exit_code} "
            f"a0={a[0]} a1={a[1]} a2={a[2]} a3={a[3]} items={items} ppid={ppid} pid={pid} auid={auid} uid={uid} "
            f"gid=1000 euid={euid} suid={euid} fsuid={euid} egid=1000 sgid=1000 fsgid=1000 tty={tty} ses={ses} "
            f'comm="{comm}" exe="{exe}" key={key_text}')
    if enrich:
        names = {"0": "root", "1000": "alice"}
        line += (f'\x1dARCH=x86_64 AUID="{names.get(auid, auid)}" UID="{names.get(uid, uid)}" GID="alice" '
                 f'EUID="{names.get(euid, euid)}"')
    return line


def _path(ts, serial, item, name, *, inode, mode="0100755", ouid="0", ogid="0", nametype="NORMAL") -> str:
    return (f'{_hdr("PATH", ts, serial)} item={item} name="{name}" inode={inode} dev=08:01 mode={mode} ouid={ouid} '
            f"ogid={ogid} rdev=00:00 nametype={nametype}")


def _execve(ts, serial, argv: list[str]) -> str:
    parts = []
    for index, arg in enumerate(argv):
        needs = any(ord(c) < 0x21 or c == '"' or ord(c) > 0x7e for c in arg)
        parts.append(f"a{index}={hexs(arg)}" if needs else f'a{index}="{arg}"')
    return f"{_hdr('EXECVE', ts, serial)} argc={len(argv)} " + " ".join(parts)


def _cwd(ts, serial, cwd) -> str:
    return f'{_hdr("CWD", ts, serial)} cwd="{cwd}"'


def _proctitle(ts, serial, argv) -> str:
    return f"{_hdr('PROCTITLE', ts, serial)} proctitle={'00'.join(hexs(a) for a in argv)}"


def exec_lines(ts=T0 + 0.123, serial=100, argv=None, exe="/usr/bin/curl", cwd="/home/alice", pid=4001,
               ppid=4000, uid="1000") -> list[str]:
    argv = argv or ["curl", "-o", "/tmp/x", "http://203.0.113.5/a b"]
    comm = exe.rsplit("/", 1)[-1][:15]
    return [_syscall(ts, serial, number=59, a=("55d0", "55d1", "55d2", "0"), items=2, comm=comm, exe=exe,
                     key="exec", pid=pid, ppid=ppid, uid=uid, euid=uid),
            _execve(ts, serial, argv), _cwd(ts, serial, cwd),
            _path(ts, serial, 0, exe, inode=1234),
            _path(ts, serial, 1, "/lib64/ld-linux-x86-64.so.2", inode=99),
            _proctitle(ts, serial, argv)]


def chmod_lines(ts=T0 + 5.5, serial=150, path="/tmp/x") -> list[str]:
    return [_syscall(ts, serial, number=90, a=("55e0", "1ed", "0", "0"), items=1, comm="chmod",
                     exe="/usr/bin/chmod", pid=4010, key="perm"),
            _cwd(ts, serial, "/home/alice"),
            _path(ts, serial, 0, path, inode=777, mode="0100644", ouid="1000", ogid="1000"),
            _proctitle(ts, serial, ["chmod", "+x", path])]


def connect_lines(ts=T0 + 1.25, serial=200) -> list[str]:
    saddr = "020001BBCB0071050000000000000000"             # AF_INET 203.0.113.5:443
    return [_syscall(ts, serial, number=42, a=("3", "7ffd0", "10", "0"), comm="curl", exe="/usr/bin/curl",
                     key="net"),
            f"{_hdr('SOCKADDR', ts, serial)} saddr={saddr}",
            _proctitle(ts, serial, ["curl", "http://203.0.113.5/"])]


def shadow_lines(ts=T0 + 2.5, serial=300) -> list[str]:
    return [_syscall(ts, serial, number=257, a=("ffffff9c", "7ffd1", "0", "0"), items=1, exit_code="3",
                     comm="cat", exe="/usr/bin/cat", pid=4020, key="shadow"),
            _cwd(ts, serial, "/home/alice"),
            _path(ts, serial, 0, "/etc/shadow", inode=555, mode="0100640", ogid="42"),
            _proctitle(ts, serial, ["cat", "/etc/shadow"])]


def insmod_lines(ts=T0 + 3.75, serial=400) -> list[str]:
    return [_syscall(ts, serial, number=313, a=("3", "55f0", "0", "0"), items=1, comm="insmod",
                     exe="/usr/bin/kmod", pid=4030, uid="0", euid="0", key="modules"),
            f'{_hdr("KERN_MODULE", ts, serial)} name="evil"',
            _cwd(ts, serial, "/tmp"),
            _path(ts, serial, 0, "/tmp/evil.ko", inode=888, mode="0100644"),
            _proctitle(ts, serial, ["insmod", "/tmp/evil.ko"])]


def login_lines(ts=T0 + 4.5, serial=500, result="success", address="203.0.113.9") -> list[str]:
    return [(f"{_hdr('USER_LOGIN', ts, serial)} pid=2200 uid=0 auid=1000 ses=9 msg='op=login acct=\"alice\" "
            f"exe=\"/usr/sbin/sshd\" hostname={address} addr={address} terminal=/dev/pts/1 res={result}'"
            '\x1dUID="root" AUID="alice"')]


def useradd_lines(ts=T0 + 6.0, serial=600) -> list[str]:
    return [(f"{_hdr('ADD_USER', ts, serial)} pid=1264 uid=0 auid=1000 ses=7 msg='op=add-user acct=\"eve\" "
            "exe=\"/usr/sbin/useradd\" hostname=web1 addr=? terminal=pts/0 res=success'"
            '\x1dUID="root" AUID="alice"')]


# ---------------------------------------------------------------------------------------------------------------
# Audit shapes from raw lines
# ---------------------------------------------------------------------------------------------------------------

def dev_audit(lines, prefix="dev", host=HOST) -> list[dict]:
    """The dev importer: dataset linux.audit, the raw line in event.original and message."""
    return [hit({"@timestamp": iso(_epoch(line)), "event": {"dataset": "linux.audit", "original": line},
                 "message": line, "host": {"name": host}}, f"{prefix}-{index}")
            for index, line in enumerate(lines)]


def filebeat_audit(lines, prefix="fb", host=HOST) -> list[dict]:
    """Filebeat's auditd module: the raw line always kept in event.original, beside the fields it parsed."""
    out = []
    for index, line in enumerate(lines):
        doc = agent_source(line, host=host, preserve=True)
        doc["tags"] = []
        doc["event"]["original"] = line
        out.append(hit(doc, f"{prefix}-{index}"))
    return out


def agent_audit(lines, prefix="agent", host=HOST, preserve=False) -> list[dict]:
    """Elastic Agent Auditd Logs: one document per record, fields only unless preserve_original_event."""
    return [hit(agent_source(line, host=host, preserve=preserve), f"{prefix}-{index}")
            for index, line in enumerate(lines)]


def auditbeat_raw(lines, native_id="ab-raw", host=HOST, joined=False) -> dict:
    """One Auditbeat event document carrying its raw records (include_raw_message): an array, or (Auditd Manager)
    one newline-joined string."""
    source = {"@timestamp": iso(_epoch(lines[0])), "host": {"name": host},
              "event": {"module": "auditd", "dataset": "auditd_manager.auditd" if joined else "auditd",
                        "original": "\n".join(lines) if joined else list(lines)},
              "auditd": {"sequence": int(_header(lines[0])[3])}}
    return hit(source, native_id)


def _header(line: str):
    m = re.match(r"^(?:node=(\S+) )?type=(\S+) msg=audit\(([\d.]+):(\d+)\):\s*(.*)$", line.partition("\x1d")[0],
                 re.DOTALL)
    assert m, line
    return m.groups()


def _epoch(line: str) -> float:
    return float(_header(line)[2])


# The Auditd Logs pipeline, forward: what it writes for one raw line.
_PIPELINE_HEX_KEYS = {"exe", "cmd", "data", "path", "comm", "file", "name", "watch", "cwd", "acct", "dir", "vm",
                      "old-chardev", "new-chardev", "old-disk", "new-disk", "old-fs", "new-fs", "old-net", "new-net",
                      "device", "cgroup", "apparmor", "operation", "denied_mask", "info", "profile",
                      "requested_mask", "old-rng", "new-rng", "ocomm", "grp", "new_group", "invalid_context", "sw",
                      "root_dir", "proctitle"}
_PIPELINE_RENAMES = [("acct", "user.name"), ("user", "user.name"), ("uid", "user.id"), ("gid", "user.group.id"),
                     ("agid", "user.audit.group.id"), ("auid", "user.audit.id"),
                     ("fsgid", "user.filesystem.group.id"), ("fsuid", "user.filesystem.id"),
                     ("egid", "user.effective.group.id"), ("euid", "user.effective.id"),
                     ("sgid", "user.saved.group.id"), ("suid", "user.saved.id"),
                     ("ogid", "user.owner.group.id"), ("ouid", "user.owner.id")]
_PIPELINE_ENRICHED = [("UID", "user.name"), ("GID", "user.group.name"), ("AUID", "user.audit.name"),
                      ("EUID", "user.effective.name"), ("OUID", "user.owner.name"), ("OGID", "user.owner.group.name")]
_PIPELINE_PROCESS = [("comm", "process.name"), ("exe", "process.executable"), ("pid", "process.pid"),
                     ("ppid", "process.parent.pid")]
_PIPELINE_LATE = [("exit", "process.exit_code"), ("cwd", "process.working_directory"),
                  ("terminal", "user.terminal")]
_ACCT_KEPT = {"ACCT_LOCK", "ACCT_UNLOCK", "ADD_USER", "DEL_USER", "USER_CHAUTHTOK", "USER_MGMT"}
# go-libaudit's copies for the user-space types these fixtures write: (sources in preference order, target)
_COPIES = {
    "USER_LOGIN": [(("auid",), "user"), (("acct", "id", "uid"), "user.effective")],
    "USER_START": [(("auid",), "user"), (("AUID",), "user"), (("acct", "id", "uid"), "user.effective"),
                   (("UID",), "user.effective")],
    "ADD_USER": [(("auid",), "user"), (("AUID",), "user"), (("uid",), "user.effective"), (("UID",), "user.effective"),
                 (("id", "acct"), "user.target"), (("ID",), "user.target")],
    "ADD_GROUP": [(("auid",), "user"), (("AUID",), "user"), (("uid",), "user.effective"),
                  (("UID",), "user.effective"), (("id", "acct"), "group"), (("ID",), "group")],
}
_ACTIONS = {"USER_LOGIN": ["logged-in"], "USER_START": ["started-session"], "ADD_USER": ["added-user-account"],
            "ADD_GROUP": ["added-group-account-to"], "SERVICE_START": ["started-service"],
            "KERN_MODULE": ["loaded-kernel-module"]}


def _set(doc: dict, path: str, value, override=True) -> bool:
    parts = path.split(".")
    cur = doc
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    if not override and parts[-1] in cur:
        return False
    cur[parts[-1]] = value
    return True


def _has(doc: dict, path: str) -> bool:
    cur = doc
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return False
        cur = cur[part]
    return True


def _pipeline_value(key: str, value: str):
    if value in ("?", "(null)", ""):
        return None
    if key in _PIPELINE_HEX_KEYS and re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", value):
        out, needed = [], False
        for i in range(0, len(value), 2):
            cp = int(value[i:i + 2], 16)
            needed = needed or cp < 33 or cp == 34 or cp == 127
            out.append("^" + chr(cp ^ 64) if cp < 32 or cp == 127 else chr(cp))
        if needed:
            value = "".join(out)
    if key in ("success", "key_enforce"):
        return value.lower() in ("yes", "true", "1")
    if value[:1] in "'\"":
        value = value[1:]
    if value[-1:] in "'\"":
        value = value[:-1]
    if key == "arch" and value == "c000003e":
        value = "x86_64"
    return value


def _pairs(text: str) -> list[tuple[str, str]]:
    return re.findall(r'([A-Za-z0-9_\-\[\]]+)=("[^"]*"|\S*)', text)


def agent_source(line: str, *, host=HOST, preserve=False) -> dict:
    """The document the Auditd Logs pipeline (then Fleet) writes for one raw audit line."""
    main, _, enrich = line.partition("\x1d")
    node, rtype, epoch, sequence, body = _header(main)
    um = re.search(r"(?:^|\s)msg='(.*)'$", body)
    outer, inner = (body[:um.start()], um.group(1)) if um else (body, "")
    log: dict = {}
    for key, value in [*_pairs(outer), *_pairs(inner), *_pairs(enrich)]:
        processed = _pipeline_value(key, value)
        if processed is not None:
            log[key] = processed
    doc: dict = {"@timestamp": iso(float(epoch)), "host": {"name": host}, "ecs": {"version": "8.17.0"},
                 "event": {"dataset": "auditd.log", "module": "auditd", "kind": "event"},
                 "data_stream": {"dataset": "auditd.log", "namespace": "default", "type": "logs"}}
    log["record_type"], log["sequence"] = rtype, int(sequence)
    if node:
        log["node"] = node
    if rtype == "EXECVE":
        args = sorted(((int(re.match(r"a(\d+)", k).group(1)), v) for k, v in log.items()
                       if re.fullmatch(r"a\d+(?:\[\d+\])?", k)), key=lambda item: item[0])
        for key in [k for k in log if re.fullmatch(r"a\d+(?:\[\d+\]|_len)?", k)]:
            del log[key]
        values = [value for _index, value in args]
        if args and args[0][0] == 0:
            _set(doc, "process.executable", values[0])
        elif args:
            values.insert(0, f"[... {args[0][0]} truncated arguments ...]")
        _set(doc, "process.args", values)
    for sources, target in _COPIES.get(rtype, ()):
        value = next((log[s] for s in sources if isinstance(log.get(s), str) and log[s] not in ("unset", "?")), None)
        if value is not None:
            _set(doc, target + (".id" if value.isdigit() else ".name"), value)
    if "arch" in log:
        _set(doc, "host.architecture", log["arch"])
    for key, path in _PIPELINE_RENAMES:
        if key in log and not (key == "acct" and rtype in _ACCT_KEPT) and _set(doc, path, log[key], override=False):
            del log[key]
    for key, path in _PIPELINE_ENRICHED:
        if key in log and log[key] not in ("?", "unset"):
            _set(doc, path, log[key], override=False)
    for key, path in _PIPELINE_PROCESS:
        if key in log and _set(doc, path, int(log[key]) if key in ("pid", "ppid") else log[key], override=False):
            del log[key]
    if "argc" in log:
        _set(doc, "process.args_count", int(log.pop("argc")))
    for key, path in _PIPELINE_LATE:
        if key in log and _set(doc, path, int(log[key]) if key == "exit" else log[key], override=False):
            del log[key]
    for key in ("res", "result"):
        if key in log and "outcome" not in doc["event"]:
            res = log[key]
            doc["event"]["outcome"] = ("success" if res in ("1", "success") else "failure" if res in ("0", "failed")
                                       else "unknown")
    action = _ACTIONS.get(rtype)
    doc["event"]["action"] = action if action else rtype.lower()
    if "addr" in log and _set(doc, "source.address", log["addr"], override=False):
        del log["addr"]
        if re.fullmatch(r"[0-9.]+|[0-9a-fA-F:]+", doc["source"]["address"]):
            doc["source"]["ip"] = doc["source"]["address"]
    for key in ("arch", "res", "result", "acct"):
        log.pop(key, None)
    doc["auditd"] = {"log": log}
    if preserve:
        doc["event"]["original"] = line
        doc["tags"] = ["preserve_original_event"]
    return doc


# ---------------------------------------------------------------------------------------------------------------
# Auditbeat event documents (fields only), per activity
# ---------------------------------------------------------------------------------------------------------------

def _ab_base(native_id, ts, serial, message_type, action, *, result="success", pid=4001, ppid=4000,
             exe="/usr/bin/curl", comm="curl", uid="1000", auid="1000", session="7", tags=(), host=HOST) -> dict:
    names = {"0": "root", "1000": "alice"}
    source = {
        "@timestamp": iso(ts), "host": {"name": host}, "tags": list(tags),
        "event": {"module": "auditd", "dataset": "auditd", "action": action, "category": "audit-rule"},
        "auditd": {"message_type": message_type, "sequence": serial, "result": result, "session": session,
                   "data": {}},
        "process": {"pid": pid, "executable": exe, "name": comm},
        "user": {"id": uid, "name": names.get(uid, uid), "audit": {"id": auid, "name": names.get(auid, auid)},
                 "effective": {"id": uid, "name": names.get(uid, uid)}},
    }
    if ppid is not None:
        source["process"]["parent"] = {"pid": ppid}
    return hit(source, native_id)


def _ab_paths(lines) -> list[dict]:
    paths = []
    for line in lines:
        _node, rtype, _epoch, _serial, body = _header(line)
        if rtype == "PATH":
            paths.append({k: v.strip('"') for k, v in _pairs(body)})
    return paths


def _ab_data(line: str, *, syscall: str) -> dict:
    fields = dict(_pairs(line.partition("\x1d")[0]))
    data = {k: fields[k] for k in ("a0", "a1", "a2", "a3", "exit") if k in fields}
    data.update({"arch": "x86_64", "syscall": syscall, "tty": fields.get("tty", "(none)")})
    return data


def auditbeat_exec(lines=None, native_id="ab-exec") -> dict:
    lines = lines or exec_lines()
    _n, _t, epoch, serial, _b = _header(lines[0])
    argv_line = next(line for line in lines if " type=EXECVE" in " " + line or line.startswith("type=EXECVE"))
    fields = dict(_pairs(argv_line))
    argv = []
    for index in range(int(fields["argc"])):
        value = fields[f"a{index}"]
        argv.append(value.strip('"') if value.startswith('"') else bytes.fromhex(value).decode())
    sys_fields = dict(_pairs(lines[0].partition("\x1d")[0]))
    exe = sys_fields["exe"].strip('"')
    h = _ab_base(native_id, float(epoch), int(serial), "syscall", "executed", exe=exe,
                 comm=sys_fields["comm"].strip('"'), pid=int(sys_fields["pid"]), ppid=int(sys_fields["ppid"]),
                 uid=sys_fields["uid"], tags=[sys_fields["key"].strip('"')])
    src = h["_source"]
    src["auditd"]["data"] = {**_ab_data(lines[0], syscall="execve"), "argc": str(len(argv))}
    src["auditd"]["paths"] = _ab_paths(lines)
    cwd = next(dict(_pairs(line))["cwd"].strip('"') for line in lines if "type=CWD" in line)
    src["process"].update({"args": argv, "title": " ".join(argv), "working_directory": cwd})
    return h


def auditbeat_connect(native_id="ab-connect") -> dict:
    lines = connect_lines()
    _n, _t, epoch, serial, _b = _header(lines[0])
    h = _ab_base(native_id, float(epoch), int(serial), "syscall", "connected-to", tags=["net"])
    src = h["_source"]
    src["auditd"]["data"] = {**_ab_data(lines[0], syscall="connect"),
                             "socket": {"family": "ipv4", "addr": "203.0.113.5", "port": "443"}}
    src["destination"] = {"ip": "203.0.113.5", "port": "443"}
    return h


def auditbeat_shadow(native_id="ab-shadow") -> dict:
    lines = shadow_lines()
    _n, _t, epoch, serial, _b = _header(lines[0])
    h = _ab_base(native_id, float(epoch), int(serial), "syscall", "opened-file", pid=4020, exe="/usr/bin/cat",
                 comm="cat", tags=["shadow"])
    src = h["_source"]
    src["auditd"]["data"] = _ab_data(lines[0], syscall="openat")
    src["auditd"]["paths"] = _ab_paths(lines)
    src["process"]["working_directory"] = "/home/alice"
    src["file"] = {"path": "/etc/shadow", "inode": "555", "mode": "0640", "uid": "0", "gid": "42"}
    return h


def auditbeat_insmod(native_id="ab-insmod") -> dict:
    lines = insmod_lines()
    _n, _t, epoch, serial, _b = _header(lines[0])
    h = _ab_base(native_id, float(epoch), int(serial), "syscall", "loaded-kernel-module", pid=4030,
                 exe="/usr/bin/kmod", comm="insmod", uid="0", tags=["modules"])
    src = h["_source"]
    src["auditd"]["data"] = {**_ab_data(lines[0], syscall="finit_module"), "name": "evil"}
    src["auditd"]["paths"] = _ab_paths(lines)
    src["process"]["working_directory"] = "/tmp"
    return h


def auditbeat_login(native_id="ab-login", result="success") -> dict:
    lines = login_lines(result=result)
    _n, _t, epoch, serial, _b = _header(lines[0])
    h = _ab_base(native_id, float(epoch), int(serial), "user_login", "logged-in", pid=2200, ppid=None,
                 exe="/usr/sbin/sshd", comm=None, uid="0", session="9", result="success" if result == "success"
                 else "fail")
    src = h["_source"]
    del src["process"]["name"]
    src["auditd"]["data"] = {"acct": "alice", "op": "login", "terminal": "/dev/pts/1", "hostname": "203.0.113.9"}
    src["source"] = {"ip": "203.0.113.9"}
    return h


def auditbeat_useradd(native_id="ab-useradd") -> dict:
    lines = useradd_lines()
    _n, _t, epoch, serial, _b = _header(lines[0])
    h = _ab_base(native_id, float(epoch), int(serial), "add_user", "added-user-account", pid=1264, ppid=None,
                 exe="/usr/sbin/useradd", comm=None, uid="0")
    src = h["_source"]
    del src["process"]["name"]
    src["auditd"]["data"] = {"acct": "eve", "op": "add-user", "terminal": "pts/0", "hostname": "web1"}
    return h


# ---------------------------------------------------------------------------------------------------------------
# Journal and syslog shapes
# ---------------------------------------------------------------------------------------------------------------

BOOT = "0123456789abcdef0123456789abcdef"


def sshd_journal(ts=T0 + 10.0) -> dict:
    return {"MESSAGE": "Accepted password for alice from 203.0.113.9 port 51515 ssh2", "SYSLOG_IDENTIFIER": "sshd",
            "_COMM": "sshd", "_EXE": "/usr/sbin/sshd", "_SYSTEMD_UNIT": "ssh.service", "_PID": "2200",
            "SYSLOG_PID": "2200", "_HOSTNAME": HOST, "_BOOT_ID": BOOT, "_TRANSPORT": "syslog",
            "SYSLOG_FACILITY": "4", "__REALTIME_TIMESTAMP": str(int(ts * 1_000_000))}


def sudo_journal(ts=T0 + 11.0) -> dict:
    return {"MESSAGE": "bob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; "
                       "COMMAND=/bin/bash",
            "SYSLOG_IDENTIFIER": "sudo", "_COMM": "sudo", "_EXE": "/usr/bin/sudo", "_PID": "3100",
            "_HOSTNAME": HOST, "_BOOT_ID": BOOT, "_TRANSPORT": "syslog", "SYSLOG_FACILITY": "10",
            "__REALTIME_TIMESTAMP": str(int(ts * 1_000_000))}


def unit_journal(ts=T0 + 12.0) -> dict:
    return {"MESSAGE": "Started evil.service.", "SYSLOG_IDENTIFIER": "systemd", "_COMM": "systemd",
            "_EXE": "/usr/lib/systemd/systemd", "_PID": "1", "_SYSTEMD_UNIT": "init.scope", "UNIT": "evil.service",
            "JOB_TYPE": "start", "JOB_RESULT": "done", "MESSAGE_ID": "39f53479d3a045ac8e11786248231fbf",
            "_HOSTNAME": HOST, "_BOOT_ID": BOOT, "_TRANSPORT": "journal", "SYSLOG_FACILITY": "3",
            "__REALTIME_TIMESTAMP": str(int(ts * 1_000_000))}


def audit_copy_journal(ts=T0 + 13.0) -> dict:
    return {"MESSAGE": "SYSCALL arch=c000003e syscall=59", "SYSLOG_IDENTIFIER": "audit", "_TRANSPORT": "audit",
            "_AUDIT_ID": "100", "_AUDIT_TYPE": "1300", "_AUDIT_TYPE_NAME": "SYSCALL", "_HOSTNAME": HOST,
            "_BOOT_ID": BOOT, "_SOURCE_REALTIME_TIMESTAMP": str(int(T0 * 1_000_000) + 123_000),
            "__REALTIME_TIMESTAMP": str(int(ts * 1_000_000))}


def _journal_ts(j: dict) -> str:
    return iso(int(j["__REALTIME_TIMESTAMP"]) / 1_000_000)


def dev_journal(j: dict, native_id="dev-j", host=HOST) -> dict:
    return hit({"@timestamp": _journal_ts(j), "host": {"name": host},
                "event": {"dataset": "systemd.journal", "original": json.dumps(j)}, "message": j["MESSAGE"]},
               native_id)


_JOURNALD_PATHS = {"_BOOT_ID": "journald.host.boot_id", "_HOSTNAME": "host.hostname",
                   "_COMM": "journald.process.name", "_EXE": "journald.process.executable",
                   "_CMDLINE": "journald.process.command_line", "_PID": "journald.pid",
                   "_SYSTEMD_UNIT": "systemd.unit", "_TRANSPORT": "systemd.transport", "UNIT": "journald.unit"}
_SPELLINGS = {"old": {"SYSLOG_IDENTIFIER": "syslog.identifier", "SYSLOG_PID": "syslog.pid",
                      "SYSLOG_FACILITY": "syslog.facility"},
              "new": {"SYSLOG_IDENTIFIER": "log.syslog.appname", "SYSLOG_PID": "log.syslog.procid",
                      "SYSLOG_FACILITY": "log.syslog.facility.code"}}
# journald fields the input reads with their own meaning and does not keep (the source time among them)
_JOURNALD_DROPPED = {"__REALTIME_TIMESTAMP", "_SOURCE_REALTIME_TIMESTAMP", "MESSAGE"}


def journald(j: dict, native_id="jd", *, dataset: str | None = "journald.logs", spelling="new",
             host=HOST) -> dict:
    """Agent Custom Journald (`journald.logs`) or Filebeat's journald input (`dataset=None`)."""
    source: dict = {"@timestamp": _journal_ts(j), "host": {"name": host}, "message": j["MESSAGE"],
                    "input": {"type": "journald"}, "event": {"kind": "event"}}
    if dataset:
        source["event"]["dataset"] = dataset
        source["data_stream"] = {"dataset": dataset, "type": "logs", "namespace": "default"}
    paths = {**_JOURNALD_PATHS, **_SPELLINGS[spelling]}
    for key, value in j.items():
        if key in _JOURNALD_DROPPED:
            continue
        path = paths.get(key) or f"journald.custom.{key.lstrip('_').lower()}"
        number = key in ("_PID", "SYSLOG_FACILITY") or (key == "SYSLOG_PID" and spelling == "old")
        _set(source, path, int(value) if number and value.isdigit() else value)
        if key == "_PID":
            _set(source, "process.pid", int(value))
    return hit(source, native_id)


def syslog(ident: str, pid: int | None, message: str, native_id="sl", *, dataset="system.auth", from_journal=False,
           ts=T0 + 10.0, host=HOST) -> dict:
    """A System integration line (from a log file, or from the journal) with its message kept."""
    source = {"@timestamp": iso(ts), "host": {"name": "collector" if not from_journal else host, "hostname": host},
              "message": message, "process": {"name": ident},
              "input": {"type": "journald" if from_journal else "filestream"},
              "event": {"dataset": dataset, "module": "system", "kind": "event"},
              "data_stream": {"dataset": dataset, "type": "logs", "namespace": "default"}}
    if not from_journal:
        source["event"]["timezone"] = "+00:00"
    if pid is not None:
        source["process"]["pid"] = pid
    return hit(source, native_id)


def parsed_syslog(ident: str, pid: int | None, fields: dict, native_id="ps", *, ts=T0 + 10.0, host=HOST) -> dict:
    """The Filebeat system module after its pattern matched: the message is dropped, the parsed fields stay."""
    source = {"@timestamp": iso(ts), "host": {"name": "collector", "hostname": host},
              "process": {"name": ident}, "input": {"type": "log"}, "event": {"dataset": "system.auth",
                                                                             "module": "system", "timezone": "+00:00"}}
    if pid is not None:
        source["process"]["pid"] = pid
    for path, value in fields.items():
        _set(source, path, value)
    return hit(source, native_id)
