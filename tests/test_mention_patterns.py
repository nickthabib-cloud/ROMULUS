"""Schema and example checks for the mention pattern corpus (content/mentions/*.yaml).

The corpus is matched against raw text lines that no typed parser normalized. These tests hold every entry to the
strict schema, keep anchored patterns inside a linear-time regex subset, prove that every positive example matches and
every benign negative does not, and check that no strong or medium pattern fires on a shared set of everyday admin,
package-manager and monitoring lines.
"""

from __future__ import annotations

import re
import re._constants as sre_c
import re._parser as sre_parse
import time
from functools import lru_cache
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
MENTIONS = ROOT / "content" / "mentions"
THEME_FILES = {
    "cradles.yaml",
    "encoded.yaml",
    "persistence.yaml",
    "reverse_shell.yaml",
    "sigma_keywords.yaml",
    "tools.yaml",
    "webshells.yaml",
}

KEYS_REQUIRED = {
    "id",
    "title",
    "match",
    "case_sensitive",
    "strength",
    "telemetry",
    "source",
    "rationale",
    "examples",
}
KEYS_OPTIONAL = {"attack"}
STRENGTHS = {"strong", "medium", "weak"}
TELEMETRY = {"linux_text", "windows_text", "any"}
SOURCE_KEYS = {"name", "url", "license", "upstream_id"}
ID_RE = re.compile(r"^mention\.[a-z0-9]+(?:[._][a-z0-9]+)*$")
ATTACK_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SIGMA_COMMIT = "698f0912f571d5fac3bf8c51f5421139834a011c"

MAX_ANCHORED_CHARS = 512
MIN_LITERAL_PREFIX = 4
MIN_LITERAL_CHARS = 4
MAX_REPEAT_BOUND = 1024

_FORBIDDEN_OPS = {
    sre_c.GROUPREF: "backreference",
    sre_c.GROUPREF_EXISTS: "conditional backreference",
    sre_c.ASSERT: "lookahead/lookbehind",
    sre_c.ASSERT_NOT: "negative lookahead/lookbehind",
    sre_c.ATOMIC_GROUP: "atomic group",
    sre_c.POSSESSIVE_REPEAT: "possessive quantifier",
}
_REPEAT_OPS = {sre_c.MAX_REPEAT, sre_c.MIN_REPEAT, sre_c.POSSESSIVE_REPEAT}

# Everyday lines from package managers, admins, monitoring and services. No strong or medium pattern may match any.
BENIGN_CORPUS = [
    "Nov 20 03:14:07 web01 sshd[2211]: Accepted publickey for deploy from 10.0.4.12 port 50122 ssh2: ED25519 SHA256:3q2+7w",
    "Nov 20 03:15:01 web01 CRON[3301]: (root) CMD (/usr/lib/php/sessionclean)",
    "Nov 20 03:17:01 web01 CRON[3305]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)",
    "Nov 20 06:25:01 db02 CRON[811]: (root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))",
    "Start-Date: 2026-11-20  06:41:12  Commandline: apt-get -y install curl wget netcat-openbsd socat nmap python3-pip",
    "Unpacking netcat-openbsd (1.226-1ubuntu2) over (1.218-4ubuntu1) ...",
    "Installed: nmap-7.92-1.el9.x86_64 tcpdump-4.99.0-7.el9.x86_64 socat-1.7.4.1-5.el9.x86_64",
    "Nov 20 07:00:00 app01 systemd[1]: Started Daily apt download activities.",
    "Nov 20 07:00:02 app01 systemd[1]: Stopping firewalld - dynamic firewall daemon...",
    "Nov 20 07:00:03 app01 kernel: [ 1122.334455] device eth0 left promiscuous mode",
    "Nov 20 07:01:13 app01 sudo[9912]:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx",
    "Nov 20 07:02:44 app01 sudo[9930]:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt-get update",
    "Nov 20 07:03:10 app01 dockerd[701]: time=\"2026-11-20T07:03:10Z\" level=info msg=\"Pulling image nginx:1.27-alpine\"",
    "10.0.3.7 - - [20/Nov/2026:07:04:01 +0000] \"GET /api/v1/health HTTP/1.1\" 200 17 \"-\" \"kube-probe/1.29\"",
    "10.0.3.8 - - [20/Nov/2026:07:04:02 +0000] \"GET /static/js/app.min.js HTTP/1.1\" 200 81234 \"https://portal.example.org/\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36\"",
    "10.0.3.9 - - [20/Nov/2026:07:04:05 +0000] \"POST /login HTTP/1.1\" 302 0 \"https://portal.example.org/login\" \"Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0\"",
    "2026-11-20 07:05:00,113 INFO  [main] org.springframework.boot.StartupInfoLogger: Started Application in 4.2 seconds",
    "2026-11-20 07:05:09 WARN  HikariPool-1 - Connection is not available, request timed out after 30000ms.",
    "level=info ts=2026-11-20T07:06:00Z caller=node_exporter.go:117 msg=\"Listening on\" address=[::]:9100",
    "Nov 20 07:06:30 mon01 zabbix_agentd[1210]: active check configuration update from [zbx.example.org:10051] started",
    "Nov 20 07:07:00 app01 ansible-ansible.legacy.command: Invoked with _raw_params=systemctl is-active nginx",
    "Nov 20 07:08:00 app01 puppet-agent[4410]: Applied catalog in 3.12 seconds",
    "Nov 20 07:09:00 app01 healthcheck: wait-for-it.sh db:5432 -t 30 -- echo database is up",
    "Nov 20 07:10:00 app01 cloud-init[612]: Cloud-init v. 24.1 running 'modules:final' at Wed, 20 Nov 2026 07:10:00 +0000",
    "Nov 20 07:11:00 app01 useradd[5120]: new user: name=svc_backup, UID=1002, GID=1002, home=/home/svc_backup, shell=/bin/bash",
    "Nov 20 07:12:00 app01 passwd[5130]: pam_unix(passwd:chauthtok): password changed for svc_backup",
    "Nov 20 07:13:00 app01 logrotate[5200]: rotating log /var/log/syslog, log->rotateCount is 7",
    "Nov 20 07:14:00 app01 rsyslogd: [origin software=\"rsyslogd\" swVersion=\"8.2312.0\"] rsyslogd was HUPed",
    "Nov 20 07:15:00 app01 kernel: [ 1500.000001] audit: type=1400 audit(1700000000.123:42): apparmor=\"STATUS\" operation=\"profile_load\"",
    "Nov 20 07:16:00 app01 systemd[1]: Started Session 42 of User alice.",
    "2026-11-20T07:17:00.000Z INFO  backup-agent: uploaded /var/backups/db-2026-11-20.sql.gz (1.2 GiB) to s3://corp-backups/db/",
    "2026-11-20 07:18:00 [INFO] Windows Update: Installation Successful: Windows successfully installed the following update: KB5032189",
    "2026-11-20 07:19:00 [INFO] MsiInstaller: Product: Microsoft Edge -- Installation completed successfully.",
    "2026-11-20 07:20:00 Service Control Manager: The Windows Modules Installer service entered the running state.",
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\ProgramData\\Corp\\inventory.ps1",
    "C:\\Windows\\system32\\cmd.exe /c \"C:\\Program Files\\Corp\\agent\\collect.cmd\" > C:\\ProgramData\\Corp\\agent\\last.log 2>&1",
    "Nov 20 07:21:00 app01 kernel: [ 1700.1] nf_conntrack: default automatic helper assignment has been turned off for security reasons",
    "Nov 20 07:22:00 app01 named[880]: client @0x7f 10.0.0.5#53122 (www.example.org): query: www.example.org IN A +E(0)K (10.0.0.2)",
    "Nov 20 07:23:00 app01 postfix/smtpd[1990]: connect from mail.example.org[198.51.100.25]",
    "Nov 20 07:24:00 app01 auditd[455]: Audit daemon rotating log files",
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq0mJ7v3jXQ6s2mEo5mLw0yXk2b3x8m2C9n4qWvXy7Z deploy@build01",
    "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMyJ9.eyJzdWIiOiJzdmMiLCJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLm9yZyJ9.c2lnbmF0dXJl",
    "Nov 20 07:25:00 app01 grafana[1400]: logger=context userId=3 orgId=1 uname=admin method=GET path=/api/dashboards/home status=200",
    "Nov 20 07:26:00 app01 kubelet[990]: I1120 07:26:00.000000 990 kubelet.go:2412] \"SyncLoop (PLEG): event for pod\" pod=\"kube-system/coredns-5d78c9869d-abcde\"",
    "Nov 20 07:27:00 app01 containerd[700]: time=\"2026-11-20T07:27:00Z\" level=info msg=\"StartContainer for \\\"a1b2c3\\\" returns successfully\"",
    "curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc",
    "pip install --upgrade requests==2.32.3 urllib3==2.2.3",
    "git clone https://git.example.org/platform/deploy-scripts.git /opt/deploy-scripts",
]


def _mention_files() -> list[Path]:
    return sorted(MENTIONS.glob("*.yaml"))


@lru_cache(maxsize=1)
def _corpus() -> tuple[tuple[str, dict], ...]:
    entries: list[tuple[str, dict]] = []
    for path in _mention_files():
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(data, list) and data, f"{path.name}: top level must be a non-empty list of patterns"
        for entry in data:
            entries.append((path.name, entry))
    return tuple(entries)


@lru_cache(maxsize=1)
def _attack():
    from romulus.catalog.attack import load_attack_bundle

    return load_attack_bundle()


def _walk(items, inside_repeat: bool, where: str) -> None:
    """Reject regex features outside the linear-time subset; `items` is a parsed (sub)pattern."""
    for op, av in items:
        if op in _FORBIDDEN_OPS:
            raise AssertionError(f"{where}: {_FORBIDDEN_OPS[op]} is not allowed")
        if op in _REPEAT_OPS:
            low, high, sub = av
            if inside_repeat:
                raise AssertionError(f"{where}: nested quantifier")
            if high == sre_c.MAXREPEAT or high > MAX_REPEAT_BOUND:
                raise AssertionError(f"{where}: every quantifier needs an upper bound <= {MAX_REPEAT_BOUND}")
            _walk(sub, True, where)
        elif op is sre_c.SUBPATTERN:
            _group, add_flags, del_flags, sub = av
            if add_flags or del_flags:
                raise AssertionError(f"{where}: inline flags are not allowed")
            _walk(sub, inside_repeat, where)
        elif op is sre_c.BRANCH:
            for alternative in av[1]:
                _walk(alternative, inside_repeat, where)


def _literal_prefix_length(parsed) -> int:
    count = 0
    for op, _av in parsed:
        if op is not sre_c.LITERAL:
            break
        count += 1
    return count


_METACHARS = set(".^$*+?{}[]|()")


def _textual_literal_prefix_length(pattern: str) -> int:
    """Leading characters written as plain literals (or escaped punctuation); a scanner can read these without a
    regex parser. A literal followed by a quantifier is optional and does not count."""
    count = 0
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            if index + 1 >= len(pattern) or pattern[index + 1].isalnum():
                break
            step = 2
        elif char in _METACHARS:
            break
        else:
            step = 1
        following = pattern[index + step : index + step + 1]
        if following and following in "?*{+":
            break
        count += 1
        index += step
    return count


def check_anchored(pattern: str, case_sensitive: bool, where: str) -> re.Pattern:
    assert isinstance(pattern, str) and pattern, f"{where}: anchored must be a non-empty string"
    assert len(pattern) <= MAX_ANCHORED_CHARS, f"{where}: anchored is longer than {MAX_ANCHORED_CHARS} chars"
    assert "\n" not in pattern and "\r" not in pattern, f"{where}: anchored must be one line"
    flags = 0 if case_sensitive else re.IGNORECASE
    compiled = re.compile(pattern, flags)
    parsed = sre_parse.parse(pattern, flags)
    assert not parsed.state.groupdict, f"{where}: named groups are not allowed"
    baseline_flags = sre_parse.parse("x", flags).state.flags
    assert parsed.state.flags == baseline_flags, f"{where}: inline flags are not allowed"
    _walk(parsed, False, where)
    first = parsed[0] if len(parsed) else None
    starts_caret = first is not None and first[0] is sre_c.AT and first[1] is sre_c.AT_BEGINNING
    prefix = min(_literal_prefix_length(parsed), _textual_literal_prefix_length(pattern))
    assert starts_caret or prefix >= MIN_LITERAL_PREFIX, (
        f"{where}: anchored must start with ^ or a literal prefix of at least {MIN_LITERAL_PREFIX} characters"
    )
    return compiled


def matcher(entry: dict):
    match = entry["match"]
    case_sensitive = entry["case_sensitive"]
    if "literal" in match:
        literals = list(match["literal"])
        if case_sensitive:
            return lambda line: any(literal in line for literal in literals)
        folded = [literal.lower() for literal in literals]
        return lambda line: any(literal in line.lower() for literal in folded)
    compiled = re.compile(match["anchored"], 0 if case_sensitive else re.IGNORECASE)
    return lambda line: compiled.search(line) is not None


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def test_no_control_characters_in_any_field() -> None:
    """A stray escape (a backslash sequence decoded by a tool) must not silently change a pattern or example."""
    for filename, entry in _corpus():
        for text in _strings(entry):
            bad = [hex(ord(char)) for char in text if ord(char) < 0x20 and char not in "\n"]
            assert not bad, f"{filename}:{entry.get('id')}: control characters {bad} in {text[:60]!r}"
        for line in entry["examples"]["positive"] + entry["examples"]["negative"]:
            assert "\n" not in line, f"{filename}:{entry.get('id')}: an example is one log line"


def test_theme_files_present_and_only_yaml() -> None:
    names = {path.name for path in _mention_files()}
    assert THEME_FILES <= names, f"missing theme files: {sorted(THEME_FILES - names)}"
    strays = [p.name for p in MENTIONS.iterdir() if p.is_file() and p.suffix != ".yaml"]
    assert not strays, f"only .yaml pattern files belong in content/mentions: {strays}"


def test_every_entry_matches_the_schema() -> None:
    seen_ids: set[str] = set()
    for filename, entry in _corpus():
        assert isinstance(entry, dict), f"{filename}: each pattern must be a mapping"
        where = f"{filename}:{entry.get('id', '?')}"
        keys = set(entry)
        assert KEYS_REQUIRED <= keys, f"{where}: missing keys {sorted(KEYS_REQUIRED - keys)}"
        assert keys <= KEYS_REQUIRED | KEYS_OPTIONAL, f"{where}: unknown keys {sorted(keys - KEYS_REQUIRED - KEYS_OPTIONAL)}"

        assert isinstance(entry["id"], str) and ID_RE.match(entry["id"]), f"{where}: bad id"
        assert entry["id"] not in seen_ids, f"{where}: duplicate id"
        seen_ids.add(entry["id"])
        assert isinstance(entry["title"], str) and 0 < len(entry["title"]) <= 120, f"{where}: bad title"
        assert isinstance(entry["case_sensitive"], bool), f"{where}: case_sensitive must be a bool"
        assert entry["strength"] in STRENGTHS, f"{where}: bad strength"
        rationale = entry["rationale"]
        assert isinstance(rationale, str) and len(rationale.strip()) >= 40, f"{where}: rationale too short"
        if entry["strength"] == "strong":
            assert len(rationale.strip()) >= 80, f"{where}: a strong pattern needs a fuller rationale"

        telemetry = entry["telemetry"]
        assert isinstance(telemetry, list) and telemetry, f"{where}: telemetry must be a non-empty list"
        assert set(telemetry) <= TELEMETRY and len(set(telemetry)) == len(telemetry), f"{where}: bad telemetry"
        assert "any" not in telemetry or telemetry == ["any"], f"{where}: 'any' stands alone"

        match = entry["match"]
        assert isinstance(match, dict) and len(match) == 1, f"{where}: match has exactly one of literal/anchored"
        if "literal" in match:
            literals = match["literal"]
            assert isinstance(literals, list) and literals, f"{where}: literal must be a non-empty list"
            for literal in literals:
                assert isinstance(literal, str), f"{where}: literals are strings"
                assert len(literal.strip()) >= MIN_LITERAL_CHARS, f"{where}: literal {literal!r} is too short"
                assert "\n" not in literal and "\r" not in literal, f"{where}: literal must be one line"
            keyed = [lit if entry["case_sensitive"] else lit.lower() for lit in literals]
            assert len(set(keyed)) == len(keyed), f"{where}: duplicate literal"
        else:
            assert set(match) == {"anchored"}, f"{where}: match key must be literal or anchored"
            check_anchored(match["anchored"], entry["case_sensitive"], where)

        if "attack" in entry:
            attack = entry["attack"]
            assert isinstance(attack, list) and attack, f"{where}: attack, when present, is a non-empty list"
            assert len(set(attack)) == len(attack), f"{where}: duplicate ATT&CK id"
            for attack_id in attack:
                assert isinstance(attack_id, str) and ATTACK_RE.match(attack_id), f"{where}: bad ATT&CK id"

        source = entry["source"]
        assert isinstance(source, dict) and set(source) == SOURCE_KEYS, f"{where}: source keys are {SOURCE_KEYS}"
        for key in ("name", "url", "license"):
            assert isinstance(source[key], str) and source[key].strip(), f"{where}: source.{key} required"
        assert source["url"].startswith("https://"), f"{where}: source.url must be https"
        upstream = source["upstream_id"]
        assert upstream is None or (isinstance(upstream, str) and upstream.strip()), f"{where}: bad upstream_id"
        if source["name"].startswith("SigmaHQ"):
            assert isinstance(upstream, str) and UUID_RE.match(upstream), f"{where}: Sigma entries cite the rule id"
            assert source["license"] == "DRL-1.1", f"{where}: Sigma rules are DRL-1.1"
            assert SIGMA_COMMIT in source["url"], f"{where}: Sigma url pins the reviewed commit"

        examples = entry["examples"]
        assert isinstance(examples, dict) and set(examples) == {"positive", "negative"}, f"{where}: bad examples"
        assert isinstance(examples["positive"], list) and len(examples["positive"]) >= 1, f"{where}: >=1 positive"
        assert isinstance(examples["negative"], list) and len(examples["negative"]) >= 2, f"{where}: >=2 negatives"
        for line in examples["positive"] + examples["negative"]:
            assert isinstance(line, str) and line.strip(), f"{where}: examples are non-empty strings"


def test_no_literal_is_shared_between_patterns() -> None:
    owners: dict[str, str] = {}
    for filename, entry in _corpus():
        if "literal" not in entry["match"]:
            continue
        for literal in entry["match"]["literal"]:
            key = literal.lower()
            assert key not in owners, f"{filename}:{entry['id']}: literal {literal!r} also in {owners[key]}"
            owners[key] = entry["id"]


def test_attack_ids_are_current_enterprise_20() -> None:
    knowledge = _attack()
    for filename, entry in _corpus():
        for attack_id in entry.get("attack", ()):
            try:
                technique = knowledge.technique(attack_id)
            except KeyError:
                pytest.fail(f"{filename}:{entry['id']}: {attack_id} is not in the vendored ATT&CK bundle")
            assert not technique.revoked and not technique.deprecated, (
                f"{filename}:{entry['id']}: {attack_id} is revoked or deprecated "
                f"(use {knowledge.replacement(attack_id)})"
            )


def test_positives_match_and_negatives_do_not() -> None:
    for filename, entry in _corpus():
        matches = matcher(entry)
        where = f"{filename}:{entry['id']}"
        for line in entry["examples"]["positive"]:
            assert matches(line), f"{where}: positive example does not match: {line!r}"
        for line in entry["examples"]["negative"]:
            assert not matches(line), f"{where}: benign negative matches: {line!r}"


def test_strong_patterns_do_not_fire_on_other_patterns_negatives() -> None:
    corpus = _corpus()
    negatives = [(entry["id"], line) for _f, entry in corpus for line in entry["examples"]["negative"]]
    for filename, entry in corpus:
        if entry["strength"] != "strong":
            continue
        matches = matcher(entry)
        for owner, line in negatives:
            assert not matches(line), f"{filename}:{entry['id']}: matches benign negative of {owner}: {line!r}"


def test_strong_and_medium_patterns_stay_quiet_on_everyday_lines() -> None:
    for filename, entry in _corpus():
        if entry["strength"] == "weak":
            continue
        matches = matcher(entry)
        for line in BENIGN_CORPUS:
            assert not matches(line), f"{filename}:{entry['id']}: fires on everyday line {line!r}"


def test_anchored_patterns_stay_fast_on_large_adversarial_lines() -> None:
    """Python's backtracking engine is the worst case: a long line full of near-misses must still scan quickly."""
    budget_seconds = 1.0
    for filename, entry in _corpus():
        pattern = entry["match"].get("anchored")
        if pattern is None:
            continue
        flags = 0 if entry["case_sensitive"] else re.IGNORECASE
        compiled = re.compile(pattern, flags)
        parsed = sre_parse.parse(pattern, flags)
        prefix = "".join(chr(av) for op, av in parsed[: _literal_prefix_length(parsed)] if op is sre_c.LITERAL)
        filler = "A1/+ x" * 40
        line = (prefix + filler) * 400 + "Z" * 65536
        started = time.perf_counter()
        compiled.search(line)
        elapsed = time.perf_counter() - started
        assert elapsed < budget_seconds, f"{filename}:{entry['id']}: {elapsed:.2f}s on a {len(line)}-char line"


def test_validator_rejects_unsafe_regex_features() -> None:
    unsafe = [
        r"(abcd)\1",  # backreference
        r"abcd(?=x)",  # lookahead
        r"abcd(?<!x)y",  # lookbehind
        r"abcd(?:x{1,3}){1,5}",  # nested quantifier
        r"abcd(?:[a-z]{0,9}x)?",  # optional group holding a quantifier
        r"abcd.*x",  # unbounded quantifier
        r"abcd[a-z]+",  # unbounded quantifier
        r"(?i)abcd",  # inline flag
        r"(?P<n>abcd)",  # named group
        r"abc[d]x",  # three-character literal prefix
        r"ab|cdef",  # top-level alternation has no literal prefix
        r"[a-z]{4}abcd",  # starts with a class
        "abcd" + "x" * 600,  # over the length cap
    ]
    for pattern in unsafe:
        with pytest.raises(AssertionError):
            check_anchored(pattern, True, f"probe {pattern!r}")
    for pattern in (r"^\S{1,20} abc", r"abcd[^\n]{0,80}efg", r"/dev/(?:tcp|udp)/[0-9]{1,3}"):
        check_anchored(pattern, True, f"probe {pattern!r}")
