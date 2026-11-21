"""Corpus checks for the mention patterns (content/mentions/*.yaml).

The corpus is matched against raw text lines that no typed parser normalized. Every file must load through the
engine the sweep runs (`load_mention_patterns`), which holds each entry to the strict schema, keeps anchored patterns
inside its linear-time regex subset and proves each file's examples. Matching here goes through `PatternSet.match`, so
a line counts as matched exactly when the sweep would match it. On top of that, these tests hold the corpus to its own
editorial policy (fuller rationales, two benign negatives, cited sources, titles that describe text), keep the public
true-positive catalogs from regressing, and check that no strong or medium pattern fires on a shared set of everyday
admin, package-manager and monitoring lines.
"""

from __future__ import annotations

import json
import re
import time
from functools import cache, lru_cache
from pathlib import Path

import pytest
import yaml

from romulus.content.mention_patterns import PatternSet, compile_anchored, load_mention_patterns

ROOT = Path(__file__).resolve().parents[1]
MENTIONS = ROOT / "content" / "mentions"
THEME_FILES = {
    "cradles.yaml",
    "credential_access.yaml",
    "encoded.yaml",
    "evasion_impact.yaml",
    "lolbins.yaml",
    "persistence.yaml",
    "reverse_shell.yaml",
    "sigma_keywords.yaml",
    "tools.yaml",
    "webshells.yaml",
}

SOURCE_KEYS = {"name", "url", "license", "upstream_id"}
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SIGMA_COMMIT = "698f0912f571d5fac3bf8c51f5421139834a011c"
# corpus policy, stricter than the engine's floor of three characters
MIN_LITERAL_CHARS = 4
REGRESSION_DIR = ROOT / "tests" / "data" / "mention_regression"
STRENGTH_RANK = {"none": 0, "weak": 1, "medium": 2, "strong": 3}
# Titles describe text, never an executed action: no past-tense or participle verbs outside quoted text.
TITLE_VERB_RE = re.compile(
    r"\b(?:[a-z]+ed|[a-z]+ing|set|made|written|sent|run|ran|shut|put|built|done|taken|shown|runs|writes|creates|"
    r"deletes|adds|removes|opens|executes|loads|starts|stops|sets|makes|copies|saves|exports|dumps|downloads|"
    r"fetches|clears|disables|enables|installs|requests|sends|uses|calls|spawns|pipes|feeds|launches|drops|"
    r"modifies|changes|replaces|reads|connects|binds|listens|hands|wires|points|turns|hides|steals|injects)\b",
    re.IGNORECASE,
)
TITLE_ALLOWED_ED = {"encoded", "embedded", "based", "privileged", "numbered", "compressed", "obfuscated", "need",
                    "speed", "feed", "seed", "red", "shared", "unparsed", "related", "shred", "string", "during", "thing",
                    "spring", "ring", "king", "padding"}

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
    # Vendor bootstrap scripts are fetched, made executable and run from the current directory.
    "curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 && chmod 700 get_helm.sh && ./get_helm.sh",
    "wget -q https://get.example.org/install.sh && chmod +x install.sh && ./install.sh --prefix /opt/tool",
    "ExecStart=/usr/bin/docker run --rm -v /tmp/cache:/cache registry.example.org/img:1.2",
    "ExecStart=/usr/bin/tmpreaper 7d /tmp",
    "IyEvYmluL2Jhc2ggLWV4Cg==",
    "Nov 20 07:30:00 app01 kernel: [ 3001.1] br-3f2a: port 2(veth9a1b2c3) entered promiscuous mode",
    "Nov 20 07:31:00 app01 systemd[1]: Stopping firewalld.service - firewalld - dynamic firewall daemon...",
    "Nov 20 07:32:00 app01 bash[4000]: HISTORY: kubectl get secret db -o jsonpath='{.data.password}' | base64 -d",
    "Nov 20 07:33:00 app01 bash[4001]: HISTORY: python3 -m http.server 8000 --directory ./site",
    # Review probes: admin idioms that strong patterns must not match.
    "Nov 20 07:34:00 app01 bash[4002]: HISTORY: curl -s http://10.0.0.5:9200/_cluster/health | python3 -m json.tool",
    "Nov 20 07:35:00 app01 bash[4003]: HISTORY: curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/app | python -c 'import sys,json; print(json.load(sys.stdin)[\"Expiration\"])'",
    "Nov 20 07:36:00 app01 bash[4004]: HISTORY: echo 'deploy ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/deploy",
    "Nov 20 07:37:00 app01 bash[4005]: HISTORY: echo 'ops ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers.d/ops",
    "*/5 * * * * curl -fsS -m 10 --retry 5 -o /dev/null https://hc-ping.example.org/eb095278-f28d-448d-87fb-7b75c171a6aa",
    "Nov 20 07:38:00 app01 bash[4006]: HISTORY: echo '*/5 * * * * curl -fsS https://hc-ping.example.org/eb095278' | crontab -",
    "Nov 20 07:39:00 app01 bash[4007]: HISTORY: echo 'export http_proxy=http://proxy:3128' >> ~/.bashrc; curl -s https://status.example.org/",
    "Nov 20 07:41:00 app01 bash[4009]: HISTORY: chmod 4755 /usr/local/bin/tool && cp build.log /tmp/",
    "Nov 20 07:42:00 app01 bash[4010]: HISTORY: echo \"wget -q https://mirror.example.org/motd -O /etc/motd\" >> /etc/rc.local",
]

# Everyday lines that a medium pattern is known to match, with the pattern ids allowed to match them. These are the
# documented benign look-alikes of medium entries (strength medium exists for exactly this); any other strong or
# medium match on these lines fails the test.
KNOWN_BENIGN_MEDIUM_MATCHES = {
    # Configuration-management agents launch PowerShell with an encoded command ($ProgressPreference='SilentlyContinue').
    "powershell.exe -NoProfile -NonInteractive -EncodedCommand JABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZgBlAHIAZQBuAGMAZQA9ACcAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAnAA==": {
        "mention.encoded_powershell_encodedcommand"
    },
    # Benign look-alikes kept as negatives of stronger entries; the medium entry matching them is expected.
    '$s=[Convert]::FromBase64String("SGVsbG8gV29ybGQ=")': {"mention.encoded_frombase64string"},
    'powershell -c "[Convert]::FromBase64String($cert)"': {"mention.encoded_frombase64string"},
    "Nov 20 13:09:01 web01 bash[823]: HISTORY: cat /etc/ld.so.preload": {"mention.sigma_ld_so_preload"},
    '2026-11-20 10:30:01 INFO  [exec-9] Runtime.getRuntime().exec("/usr/bin/convert in.png out.jpg") finished': {
        "mention.sigma_java_payload_short"
    },
    # Configuration-management bootstrap from an internal server by IP over HTTPS (Puppet's documented installer).
    "Nov 20 07:43:00 app01 bash[4011]: HISTORY: curl -k https://10.0.0.20:8140/packages/current/install.bash | sudo bash": {
        "mention.cradle_raw_ip_https_to_interpreter"
    },
    # SCCM, Intune and Group Policy tasks run PowerShell with an execution-policy bypass.
    'schtasks /create /tn "Corp\\Inventory" /tr "powershell.exe -ExecutionPolicy Bypass -File C:\\ProgramData\\Corp\\inv.ps1" /sc daily /ru system': {
        "mention.persist_schtasks_bypass_hidden_action"
    },
    # Vagrant and Packer base images append a passwordless grant for the build user.
    'Nov 20 07:44:00 app01 bash[4012]: HISTORY: echo "vagrant ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers': {
        "mention.persist_sudoers_nopasswd_append"
    },
    # Health pings at boot fetch without running anything; the medium @reboot downloader entry still names them.
    "@reboot curl -fsS https://hc-ping.example.org/eb095278 > /dev/null": {"mention.persist_cron_reboot_downloader"},
    "@reboot curl -fsS -m 10 --retry 5 -o /dev/null https://hc-ping.example.org/eb095278": {
        "mention.persist_cron_reboot_downloader"
    },
    # Shared temp directories are made setgid so new files keep the group.
    "Nov 20 07:40:00 app01 bash[4008]: HISTORY: chmod 2775 /tmp/shared": {"mention.persist_setgid_in_temp"},
    "Nov 20 13:10:04 web01 bash[828]: HISTORY: chmod 2775 /tmp/shared": {"mention.persist_setgid_in_temp"},
    # Cloud bootstrap runs user-data from the metadata address; only the medium metadata entry names it.
    "Nov 20 11:00:04 cloud01 cloud-init[612]: curl -s http://169.254.169.254/latest/user-data | sh": {
        "mention.cradle_metadata_ip_to_shell"
    },
    # Administrators download installers and archives to temp paths; driver INF installs; directory lookups.
    "powershell -c \"$wc.DownloadFile('http://10.0.0.5/tools/agent.msi', 'C:\\Temp\\agent.msi')\"": {
        "mention.lolbin_webclient_downloadfile"
    },
    'powershell -c "Invoke-WebRequest https://intranet.example.org/a.zip -OutFile C:\\Temp\\a.zip"': {
        "mention.lolbin_invoke_webrequest_outfile_user_path"
    },
    "rundll32 syssetup.dll,SetupInfObjectInstallAction DefaultInstall 128 C:\\Drivers\\a.inf": {
        "mention.lolbin_rundll32_syssetup_inf"
    },
    "finger alice@mail.corp.example.org": {"mention.lolbin_finger_user_at_host"},
    # Notepad++ Plugins Admin installs a plugin with the GUP updater.
    '"C:\\Program Files\\Notepad++\\updater\\GUP.exe" -unzipTo -clean "C:\\Program Files\\Notepad++" "C:\\Program Files\\Notepad++\\plugins" "ComparePlugin https://www.example.com/pnedev/comparePlugin/releases/download/v2.0.2/ComparePlugin_v2.0.2_X64.zip 5a1e2b"': {
        "mention.lolbin_gup_unzipto_url"
    },
    # The legacy zip-file association opens a .zip through zipfldr RouteTheCall.
    "rundll32.exe zipfldr.dll,RouteTheCall C:\\Users\\alice\\Downloads\\report.zip": {
        "mention.lolbin_rundll32_zipfldr_routethecall"
    },
    # Build trees under /tmp carry setuid helpers before install.
    "Nov 20 13:10:09 build01 bash[832]: HISTORY: chmod 4755 /tmp/build/helper": {"mention.persist_setuid_in_temp_subdir"},
    # A vendor agent bootstrapped from its HTTPS host at boot.
    'Nov 20 13:18:06 web01 sh[854]: echo "curl -fsSL https://get.vendor.example.com/agent.sh | bash" >> /etc/rc.local': {
        "mention.persist_rc_local_https_installer"
    },
    # The Chocolatey installer is a classic download cradle.
    "powershell -c \"iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))\"": {
        "mention.cradle_ps_webclient_download",
        "mention.cradle_ps_iex_download_prefix",
    },
}


def _mention_files() -> list[Path]:
    return sorted(MENTIONS.glob("*.yaml"))


@lru_cache(maxsize=1)
def _corpus() -> tuple[tuple[str, dict], ...]:
    """The raw entries, for the editorial policy the engine does not hold."""
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


@lru_cache(maxsize=1)
def _loaded() -> PatternSet:
    return load_mention_patterns(MENTIONS)


@pytest.fixture(scope="module")
def patterns() -> PatternSet:
    """The shipped corpus as the sweep loads it. Every test that matches text depends on it, so a refused file fails
    them all with one stated cause instead of passing on a partial corpus."""
    loaded = _loaded()
    errors = "\n".join(item["error"] for item in loaded.refused)
    assert not loaded.refused, f"the engine refuses {len(loaded.refused)} shipped file(s):\n{errors}"
    return loaded


@cache
def _ids(line: str) -> frozenset[str]:
    return frozenset(_loaded().match(line))


def _strength(patterns: PatternSet) -> dict[str, str]:
    return {pattern.id: pattern.strength for pattern in patterns.patterns}


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


def test_the_engine_loads_every_file_and_every_entry(patterns) -> None:
    assert [item["name"] for item in patterns.files] == [path.name for path in _mention_files()]
    assert [pattern.id for pattern in patterns.patterns] == [entry["id"] for _f, entry in _corpus()]


def test_every_entry_meets_the_corpus_policy() -> None:
    """Editorial rules on top of the engine's schema: fuller rationales, two benign negatives per entry, every source
    key written out, https sources, Sigma entries pinned to the reviewed commit."""
    for filename, entry in _corpus():
        where = f"{filename}:{entry.get('id', '?')}"
        rationale = entry["rationale"]
        assert isinstance(rationale, str) and len(rationale.strip()) >= 40, f"{where}: rationale too short"
        if entry["strength"] == "strong":
            assert len(rationale.strip()) >= 80, f"{where}: a strong pattern needs a fuller rationale"
        assert len(entry["title"]) <= 120, f"{where}: title too long"
        for literal in entry["match"].get("literal", ()):
            assert len(literal.strip()) >= MIN_LITERAL_CHARS, f"{where}: literal {literal!r} is too short"
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
        negatives = entry["examples"]["negative"]
        assert isinstance(negatives, list) and len(negatives) >= 2, f"{where}: >=2 negatives"
        for line in entry["examples"]["positive"] + negatives:
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


def test_positives_match_and_negatives_do_not(patterns) -> None:
    """The loader proves each file's examples alone; here every example is matched against the whole corpus."""
    for pattern in patterns.patterns:
        for line in pattern.examples.positive:
            assert pattern.id in _ids(line), f"{pattern.id}: positive example does not match: {line!r}"
        for line in pattern.examples.negative:
            assert pattern.id not in _ids(line), f"{pattern.id}: benign negative matches: {line!r}"


def _line_strength(patterns: PatternSet, line: str) -> tuple[str, list[str]]:
    strength = _strength(patterns)
    ids = sorted(_ids(line))
    best = max((strength[pattern_id] for pattern_id in ids), key=STRENGTH_RANK.__getitem__, default="none")
    return best, ids


def test_public_true_positive_corpus_does_not_regress(patterns) -> None:
    """Every command of the cited public catalogs keeps at least the strength it had when the corpus was first
    reviewed (recorded per line in the data file). Narrowing a pattern or shortening a gap must not lose them."""
    files = sorted(REGRESSION_DIR.glob("*.json"))
    assert files, "no regression corpus"
    for path in files:
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data.get("license") and data.get("url") and data.get("commit"), f"{path.name}: attribution missing"
        for item in data["entries"]:
            assert len(item["lines"]) == len(item["expected_min_strength"]), f"{path.name}:{item['name']}"
            for line, expected in zip(item["lines"], item["expected_min_strength"], strict=True):
                got, ids = _line_strength(patterns, line)
                assert STRENGTH_RANK[got] >= STRENGTH_RANK[expected], (
                    f"{path.name}:{item['name']}: expected at least {expected}, got {got} ({ids}) for {line[:160]!r}"
                )


def test_titles_describe_text_not_actions() -> None:
    for filename, entry in _corpus():
        unquoted = re.sub(r"'[^']*'|\"[^\"]*\"", " ", entry["title"])
        verbs = [w for w in TITLE_VERB_RE.findall(unquoted) if w.lower() not in TITLE_ALLOWED_ED]
        assert not verbs, f"{filename}:{entry['id']}: title reads as an action ({verbs}): {entry['title']!r}"


def test_strong_literals_each_have_a_positive_example() -> None:
    for filename, entry in _corpus():
        if entry["strength"] != "strong" or "literal" not in entry["match"]:
            continue
        positives = entry["examples"]["positive"]
        for literal in entry["match"]["literal"]:
            if entry["case_sensitive"]:
                hit = any(literal in line for line in positives)
            else:
                hit = any(literal.lower() in line.lower() for line in positives)
            assert hit, f"{filename}:{entry['id']}: literal {literal!r} has no positive example"


def _loud(patterns: PatternSet, line: str) -> set[str]:
    strength = _strength(patterns)
    return {pattern_id for pattern_id in _ids(line) if strength[pattern_id] != "weak"}


def test_strong_and_medium_patterns_do_not_fire_on_other_patterns_negatives(patterns) -> None:
    for owner in patterns.patterns:
        for line in owner.examples.negative:
            loud = _loud(patterns, line) - set(KNOWN_BENIGN_MEDIUM_MATCHES.get(line, ()))
            assert not loud, f"{sorted(loud)} match benign negative of {owner.id}: {line!r}"


def test_strong_and_medium_patterns_stay_quiet_on_everyday_lines(patterns) -> None:
    strength = _strength(patterns)
    for line in BENIGN_CORPUS:
        assert not _loud(patterns, line), f"{sorted(_loud(patterns, line))} fire on everyday line {line!r}"
    for line, allowed in KNOWN_BENIGN_MEDIUM_MATCHES.items():
        for pattern_id in allowed:
            assert strength.get(pattern_id) == "medium", f"{pattern_id}: a known benign match is allowed only at medium"
        loud = _loud(patterns, line) - set(allowed)
        assert not loud, f"{sorted(loud)} fire on everyday line {line!r}"


def test_known_benign_medium_matches_are_real(patterns) -> None:
    """The allow-list documents real matches; an entry that no longer matches its listed line must be removed."""
    known = {pattern.id for pattern in patterns.patterns}
    for line, allowed in KNOWN_BENIGN_MEDIUM_MATCHES.items():
        for pattern_id in allowed:
            assert pattern_id in known, f"unknown pattern id {pattern_id}"
            assert pattern_id in _ids(line), f"{pattern_id} no longer matches {line!r}"


def _adversarial_lines(prefix: str, positives: list[str]) -> list[str]:
    """Long single lines built to make the matcher work hard: the pattern's literal prefix followed by filler, the
    prefix repeated back to back, and each positive example cut short and repeated."""
    lines = [(prefix + "A1/+ x" * 40) * 400 + "Z" * 65536]
    if prefix:
        lines.append((prefix + " ") * max(1, 200_000 // (len(prefix) + 1)))
    for positive in positives:
        for keep in (0.5, 0.75, 0.9):
            near = positive[: max(1, int(len(positive) * keep))]
            lines.append((near + " ") * max(1, 200_000 // (len(near) + 1)))
    return lines


def test_anchored_patterns_stay_fast_on_large_adversarial_lines(patterns) -> None:
    """A long line full of near-misses must still scan quickly through the whole matcher the sweep runs. Lines are
    about 200 KB; the budget is per line and generous for slow CI hosts."""
    budget_seconds = 2.0
    slowest = (0.0, "")
    for pattern, built in zip(patterns.patterns, patterns.compiled, strict=True):
        if built.regex is None:
            continue
        for line in _adversarial_lines(built.prefix or built.lead, pattern.examples.positive):
            started = time.perf_counter()
            patterns.match(line)
            elapsed = time.perf_counter() - started
            slowest = max(slowest, (elapsed, pattern.id))
            assert elapsed < budget_seconds, f"{pattern.id}: {elapsed:.2f}s on a {len(line)}-char line"
    print(f"slowest corpus match on adversarial lines: {slowest[0]:.3f}s ({slowest[1]})")


@pytest.mark.parametrize("expression", [
    r"(abcd)\1",  # backreference
    r"abcd(?=x)",  # lookahead
    r"abcd(?<!x)y",  # lookbehind
    r"abcd(?:x{1,3}){1,5}",  # nested quantifier
    r"abcd(?:[a-z]{0,9}x)?",  # optional group holding a quantifier
    r"abcd.*x",  # an unbounded open gap
    r"(?i)abcd",  # inline flag
    r"(?P<n>abcd)",  # a group before the literal prefix
    r"abc[x-y]d",  # three-character literal prefix
    r"ab|cdef",  # top-level alternation has no literal prefix
    r"[a-z]{4}abcd",  # starts with a class
    "abcd" + "x" * 600,  # over the length cap
    r"abcd.{0,80}=.{0,80}=.{0,80}=.{0,80}X",  # more than two open gaps along one path
])
def test_the_engine_refuses_unsafe_expressions(expression) -> None:
    with pytest.raises(ValueError):
        compile_anchored(expression, True)


@pytest.mark.parametrize("expression", [
    r"^\S{1,20} abc",
    r"abcd[^\n]{0,80}efg",
    r"/dev/(?:tcp|udp)/[0-9]{1,3}",
    r"abcd[a-z]+",  # an unbounded positive class: the matcher's window bounds it
    r"abc[d]x",  # a one-character class is a literal, so the prefix is abcd
])
def test_the_engine_accepts_bounded_expressions(expression) -> None:
    compile_anchored(expression, True)
