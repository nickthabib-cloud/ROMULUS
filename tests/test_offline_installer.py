"""The installer an offline bundle carries (scripts/install-offline.sh), driven end to end on any machine with a
POSIX shell.

The bundle is a synthetic one (tests/offline_bundle_support.py). The host is stood in for by three small scripts: a
`uname` that says Linux, an interpreter that answers the installer's probes, "creates" a venv and records every pip
and script invocation with the `PIP_*` environment it was given, and the `romulus` command that interpreter leaves in
the venv. Each test runs under every POSIX shell found (sh, bash, dash), because the installer is run with whichever
one the host has. Nothing here reaches a package index or needs Linux.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from tests.offline_bundle_support import SCRIPTS, build, bundle, make_wheel, unpack

FAKE_PYTHON = r"""#!/bin/sh
# A stand-in interpreter: answers the installer's probes, makes a "venv", records what pip and scripts are given.
log() { printf '%s' "$1" >> "$STUB_LOG"; shift; for a in "$@"; do printf '\t%s' "$a" >> "$STUB_LOG"; done; echo >> "$STUB_LOG"; }
case "${1:-}" in
  -c)
    case "$2" in
      *libc_ver*) echo "${STUB_HOST:-3.12 cpython x86_64 glibc 2.39}" ;;
      *) echo "${STUB_VENV_PYTHON:-3.12}" ;;
    esac ;;
  -m)
    case "$2" in
      venv)
        log VENV "$3"
        mkdir -p "$3/bin"; cp "$0" "$3/bin/python"; chmod +x "$3/bin/python" ;;
      pip)
        shift 2
        log PIP "$@"
        env | grep '^PIP_' | while IFS= read -r setting; do log PIPENV "$setting"; done
        case " $* " in *" --version "*) exit 0 ;; esac
        case " $* " in
          *" -e "*)
            case " $* " in
              *" --no-deps "*) ;;
              *) if [ "${STUB_FAIL:-}" = editable ]; then exit 1; fi ;;
            esac
            cp "$STUB_ROMULUS" "$(dirname "$0")/romulus"; chmod +x "$(dirname "$0")/romulus" ;;
          *" -r "*) if [ "${STUB_FAIL:-}" = deps ]; then exit 1; fi ;;
        esac ;;
    esac ;;
  *)
    log SCRIPT "$@"
    if [ "${STUB_FAIL:-}" = check ]; then exit 1; fi ;;
esac
exit 0
"""
FAKE_ROMULUS = r"""#!/bin/sh
printf 'ROMULUS\t%s\tROMULUS_HOME=%s\n' "$*" "${ROMULUS_HOME:-}" >> "$STUB_LOG"
case " $* " in
  *" --help "*) if [ "${STUB_FAIL:-}" = help ]; then exit 1; fi ;;
  *" doctor "*) exit "${STUB_DOCTOR:-0}" ;;
esac
exit 0
"""


def _environment() -> dict[str, str]:
    """The environment the shells run in: no pip settings of this machine's, and, with Git for Windows, its POSIX
    tools on PATH and its rewriting of path-like arguments turned off."""
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("PIP_", "STUB_"))}
    if os.name == "nt":
        environment["PATH"] = os.pathsep.join([*(str(root / "usr" / "bin") for root in _git_roots()),
                                               environment.get("PATH", "")])
        environment.update({"MSYS_NO_PATHCONV": "1", "MSYS2_ARG_CONV_EXCL": "*"})
    return environment


def _git_roots() -> list[Path]:
    bases = [os.environ.get("ProgramFiles"), os.environ.get("ProgramW6432"), os.environ.get("LocalAppData")]
    roots = [Path(base) / "Git" for base in bases if base] + [Path(base) / "Programs" / "Git" for base in bases if base]
    git = shutil.which("git")
    if git:
        roots.append(Path(git).resolve().parents[1])
    return [root for root in dict.fromkeys(roots) if (root / "usr" / "bin").is_dir()]


def _shells() -> list[str]:
    names = ["sh", "bash", "dash"]
    if os.name == "nt":
        candidates = [str(root / "usr" / "bin" / f"{name}.exe") for root in _git_roots() for name in names]
    else:
        candidates = [shutil.which(name) or "" for name in names]
    found: dict[str, str] = {}
    for candidate in candidates:
        if not candidate or not Path(candidate).is_file():
            continue
        try:
            probe = subprocess.run([candidate, "-c", "command -v sha256sum >/dev/null && echo ok"],
                                   capture_output=True, text=True, timeout=30, check=False, env=_environment())
        except (OSError, subprocess.SubprocessError):
            continue
        if probe.stdout.strip() == "ok":
            # sh is often a link to bash or dash: each distinct program is run once, under its own name
            found.setdefault(os.path.normcase(str(Path(candidate).resolve())), candidate)
    return list(found.values())


SHELLS = _shells()
pytestmark = pytest.mark.skipif(not SHELLS, reason="needs a POSIX shell with sha256sum")


@pytest.fixture(params=SHELLS or [None], ids=lambda shell: Path(shell).stem if shell else "no-shell")
def shell(request) -> str:
    return request.param


def posix(path: Path) -> str:
    text = Path(path).resolve().as_posix()
    return f"/{text[0].lower()}{text[2:]}" if os.name == "nt" and text[1:3] == ":/" else text


def write_script(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode())
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


class Host:
    """A stand-in host: where the bundle is unpacked, the stub commands, and one ROMULUS home."""

    def __init__(self, tmp_path: Path, shell: str, **target):
        self.shell = shell
        self.tmp = tmp_path
        self.bundle = unpack(build(tmp_path, target=bundle.Target(**target)), tmp_path / "unpacked")
        self.stubs = tmp_path / "stubs"
        write_script(self.stubs / "bin" / "uname", "#!/bin/sh\necho Linux\n")
        self.python = write_script(self.stubs / "fakepy", FAKE_PYTHON)
        self.root_bin = self.stubs / "rootbin"
        write_script(self.root_bin / "id", '#!/bin/sh\ncase "${1:-}" in -u) echo 0 ;; -un) echo root ;; '
                                             '*) echo "uid=0(root)" ;; esac\n')
        self.romulus = write_script(self.stubs / "romulus-stub", FAKE_ROMULUS)
        self.homes = tmp_path / "homes"
        self.homes.mkdir()
        self.home = self.homes / "home"
        self.log = tmp_path / "stub.log"

    def install(self, *arguments: str, home: Path | str | None = None, env: dict | None = None, as_root: bool = False,
                python: bool = True, before: str = "", after: str = "", directory: Path | None = None):
        """Run the installer. `before`/`after` are shell text run around it in the same shell (to hold a process
        alive across the run, say); the installer's exit status is the one returned."""
        directory = directory or self.bundle
        environment = _environment()
        path = [posix(self.stubs / "bin"), *([posix(self.root_bin)] if as_root else [])]
        environment.update({"STUB_LOG": posix(self.log), "STUB_ROMULUS": posix(self.romulus), **(env or {})})
        target = home if isinstance(home, str) else posix(home or self.home)
        command = [f'"$0" "{posix(directory / "install-offline.sh")}"']
        if python:
            command += ["--python", f'"{posix(self.python)}"']
        command += [f'"{argument}"' for argument in (*arguments, target)]
        script = (f'PATH="{":".join(reversed(path))}:$PATH"; export PATH\n{before}\n{" ".join(command)}\nrc=$?\n'
                  f'{after}\nexit $rc\n')
        return subprocess.run([self.shell, "-c", script, posix(Path(self.shell))], capture_output=True, text=True, timeout=300,
                              check=False, env=environment, cwd=str(self.tmp))

    def calls(self, kind: str) -> list[list[str]]:
        if not self.log.exists():
            return []
        return [line.split("\t")[1:] for line in self.log.read_text(encoding="utf-8").splitlines()
                if line.split("\t")[0] == kind]

    def seed(self, home: Path | None = None) -> Path:
        """An existing install with everything an operator accumulates, and a previous tree in app.old."""
        home = home or self.home
        for directory in ("app/content/indicators", "app.old", "db", "reports/h1", "logs", "stage/h1", "site", "tls",
                          "cache", "venv/bin"):
            (home / directory).mkdir(parents=True, exist_ok=True)
        write_script(home / "venv" / "bin" / "python", FAKE_PYTHON)
        write_script(home / "venv" / "bin" / "romulus", FAKE_ROMULUS)
        (home / "app" / "MARKER").write_text("previous tree\n")
        (home / "app" / "DEPLOYED_COMMIT").write_text("0ldc0mm1\n")
        (home / "app.old" / "MARKER").write_text("the tree before the previous one\n")
        for path, text in KEPT.items():
            (home / path).write_text(text)
        return home


# what an upgrade, a failed upgrade and a refused upgrade must all leave exactly as it was
KEPT = {".env": "ROMULUS_HOME=/somewhere\nES_PASSWORD=kept-secret\n", ".env.bak": "older\n",
        "db/romulus.db": "database\n", "reports/h1/r1.md": "report\n", "logs/web.log": "log\n",
        "stage/h1/events": "staged\n", "site/collection.yaml": "site: facts\n", "tls/key.pem": "key\n",
        "operator-notes.txt": "notes\n"}


def assert_kept(home: Path):
    for path, text in KEPT.items():
        assert (home / path).read_text() == text, path


def assert_no_leftovers(home: Path):
    assert not (home / "app.new").exists() and not (home / "app.prev").exists()
    assert not (home / ".install.lock").exists()


@pytest.fixture
def host(tmp_path, shell):
    return Host(tmp_path, shell)


# ---------------------------------------------------------------------------------------------------------------
# a fresh install


def test_installer_parses_under_this_shell(shell):
    result = subprocess.run([shell, "-n", posix(SCRIPTS / "install-offline.sh")], capture_output=True, text=True,
                            check=False, env=_environment())
    assert result.returncode == 0, result.stderr
    assert b"\r" not in (SCRIPTS / "install-offline.sh").read_bytes()


def test_fresh_install_lays_out_the_home_and_installs_offline(host):
    hostile = {"PIP_INDEX_URL": "http://10.255.255.1/simple", "PIP_EXTRA_INDEX_URL": "http://10.255.255.2/simple",
               "PIP_FIND_LINKS": "/somewhere/else", "PIP_CONFIG_FILE": "/etc/pip-site.conf", "PIP_NO_INDEX": "0",
               "PIP_TRUSTED_HOST": "mirror.invalid"}
    result = host.install(env=hostile)
    assert result.returncode == 0, result.stdout + result.stderr
    home, wheels = host.home, posix(host.bundle / "wheels")
    for directory in ("app", "venv", "db", "logs", "reports", "cache"):
        assert (home / directory).is_dir(), directory
    if os.name != "nt":
        assert stat.S_IMODE(home.stat().st_mode) == 0o700
    assert (home / "app" / "DEPLOYED_COMMIT").read_text() == "abc1234\n"
    assert (home / "app" / "src" / "romulus" / "__init__.py").is_file()
    assert (home / "app" / "scripts" / "web-restart.sh").is_file() and (home / "app" / ".env.example").is_file()
    assert not (home / ".env").exists() and not (home / "app.old").exists() and not (home / "stage").exists()
    assert_no_leftovers(home)
    assert "bundle verified: " in result.stdout and "Next steps:" in result.stdout
    assert f"cp {posix(home)}/app/.env.example {posix(home)}/.env" in result.stdout

    # every pip run that installs: no index, the bundle's wheels only, and nothing from the host's configuration
    pips = host.calls("PIP")
    installs = [call for call in pips if call != ["--version"]]
    assert len(installs) == 2 and len(pips) == 3
    for call in installs:
        assert call[0] == "install" and "--no-index" in call and "--isolated" in call, call
        assert call[call.index("--find-links") + 1] == wheels and "--no-cache-dir" in call, call
    assert installs[0][-4:] == ["-r", "requirements/runtime.txt", "-r", "requirements/extras.txt"]
    assert installs[1][-2:] == ["-e", f"{posix(home)}/app[anthropic]"]
    # ... and pip (with every subprocess it starts) is given no PIP_* setting but the one that blanks its config
    assert host.calls("PIPENV") == [["PIP_CONFIG_FILE=/dev/null"]] * len(pips)
    assert host.calls("VENV") == [[f"{posix(home)}/venv"]]
    # then the command and the install check, from the new tree, with the bundle's optional group
    assert host.calls("ROMULUS") == [["--help", "ROMULUS_HOME="]]
    assert host.calls("SCRIPT") == [[f"{posix(home)}/app/scripts/install_check.py", "--app", f"{posix(home)}/app",
                                     "--extra", "anthropic"]]


def test_no_extras_installs_the_runtime_requirements_only(host):
    result = host.install("--no-extras")
    assert result.returncode == 0, result.stdout + result.stderr
    installs = [call for call in host.calls("PIP") if call != ["--version"]]
    assert installs[0][-2:] == ["-r", "requirements/runtime.txt"] and "requirements/extras.txt" not in installs[0]
    assert installs[1][-2:] == ["-e", f"{posix(host.home)}/app"]
    assert host.calls("SCRIPT") == [[f"{posix(host.home)}/app/scripts/install_check.py", "--app",
                                     f"{posix(host.home)}/app"]]


def test_a_fresh_install_that_fails_leaves_no_application_tree(host):
    result = host.install(env={"STUB_FAIL": "editable"})
    assert result.returncode == 1 and "No application tree was left" in result.stderr
    assert not (host.home / "app").exists()
    assert_no_leftovers(host.home)


def test_the_home_is_taken_as_the_filesystem_names_it(host):
    (host.homes / "sub").mkdir()
    result = host.install(home=f"{posix(host.homes)}/sub/..//home/")
    assert result.returncode == 0, result.stdout + result.stderr
    assert (host.home / "app" / "DEPLOYED_COMMIT").is_file() and not (host.homes / "sub" / "app").exists()
    assert host.calls("VENV") == [[f"{posix(host.home)}/venv"]]


@pytest.mark.parametrize(("home", "message"), [
    ("//", "cannot be /"), ("/.", "cannot be /"), ("/..", "cannot be /"), ("/./", "cannot be /"),
    ("/no-such-directory-here/..", "name the ROMULUS home itself"),
    ("/no-such-directory-here/deeper/home", "does not exist: /no-such-directory-here/deeper"),
    ("relative/home", "absolute path"), ("/has space/home", "may hold only"), ("/", "cannot be /"),
])
def test_a_home_that_is_the_root_or_cannot_be_named_is_refused(host, home, message):
    result = host.install(home=home)
    assert result.returncode == 1 and message in result.stderr, result.stderr
    assert host.calls("PIP") == [] and host.calls("VENV") == []


def test_bad_arguments_are_refused(host):
    for arguments, message in ((("--frobnicate",), "unknown option"), (("/a",), "one ROMULUS home")):
        result = host.install(*arguments)
        assert result.returncode == 1 and message in result.stderr, (arguments, result.stderr)
    assert host.install(python=False, home="").returncode == 1
    missing = host.install("--python", "no-such-python-anywhere", python=False)
    assert missing.returncode == 1 and "no such interpreter" in missing.stderr
    assert not host.home.exists()
    usage = host.install("--help")
    assert usage.returncode == 0 and "--allow-root" in usage.stdout and "--force" in usage.stdout
    assert "hunt stop" in usage.stdout and "set -eu" not in usage.stdout and "umask" not in usage.stdout


def test_root_is_refused_unless_allowed(host):
    result = host.install(as_root=True)
    assert result.returncode == 1 and "not as root" in result.stderr and "--allow-root" in result.stderr
    assert "Nothing was installed" in result.stderr and not host.home.exists()
    allowed = host.install("--allow-root", as_root=True)
    assert allowed.returncode == 0, allowed.stdout + allowed.stderr
    assert (host.home / "app" / "DEPLOYED_COMMIT").is_file()


@pytest.mark.skipif(os.name == "nt" or not hasattr(os, "geteuid") or os.geteuid() == 0,
                    reason="needs a directory another account owns")
def test_a_home_another_account_owns_is_refused(host):
    result = host.install(home="/usr")
    assert result.returncode == 1 and "does not belong to this account" in result.stderr
    assert host.calls("PIP") == [] and host.calls("VENV") == []


# ---------------------------------------------------------------------------------------------------------------
# refusals before anything is touched


def test_a_changed_file_is_refused_before_the_home_is_touched(host):
    wheel = host.bundle / "wheels" / "alpha-1.2-py3-none-any.whl"
    wheel.write_bytes(wheel.read_bytes() + b"x")
    result = host.install()
    assert result.returncode == 1, result.stdout + result.stderr
    assert "checksum verification failed; nothing was installed" in result.stderr
    assert "alpha-1.2-py3-none-any.whl" in result.stderr and "bundle verified" not in result.stdout
    assert not host.home.exists() and host.calls("PIP") == []


def test_a_wheel_that_is_not_listed_is_refused(host):
    make_wheel(host.bundle / "wheels", "alpha", "99.0")
    result = host.install()
    assert result.returncode == 1, result.stdout + result.stderr
    assert "not listed in SHA256SUMS: wheels/alpha-99.0-py3-none-any.whl" in result.stderr
    assert "nothing was installed" in result.stderr and not host.home.exists()


def test_a_bundle_with_a_file_missing_is_refused(host):
    (host.bundle / "app" / "content" / "mentions" / "a.yaml").unlink()
    result = host.install()
    assert result.returncode == 1, result.stdout + result.stderr
    assert "listed in SHA256SUMS but missing: app/content/mentions/a.yaml" in result.stderr
    assert not host.home.exists()
    (host.bundle / "SHA256SUMS").unlink()
    result = host.install()
    assert result.returncode == 1 and "not a complete bundle: SHA256SUMS is missing" in result.stderr


def test_a_link_or_special_file_in_the_bundle_is_refused(host):
    """A link is not a regular file, so SHA256SUMS neither lists nor checks it; pip would still follow one."""
    link = host.bundle / "wheels" / "extra-1.0-py3-none-any.whl"
    make = (f'ln -s /etc/hostname "{posix(link)}" && test -L "{posix(link)}" '
            f'|| {{ rm -f "{posix(link)}"; mkfifo "{posix(link)}"; }}')
    made = subprocess.run([host.shell, "-c", make], capture_output=True, text=True, check=False, env=_environment())
    odd = subprocess.run([host.shell, "-c", f'find "{posix(host.bundle)}" ! -type f ! -type d'], capture_output=True,
                         text=True, check=False, env=_environment()).stdout.strip()
    if made.returncode != 0 or not odd:
        pytest.skip("this machine can make neither a symbolic link nor a named pipe")
    result = host.install()
    assert result.returncode == 1, result.stdout + result.stderr
    assert "not regular files or directories" in result.stderr and "extra-1.0-py3-none-any.whl" in result.stderr
    assert not host.home.exists() and host.calls("PIP") == []


def test_another_python_version_is_refused(host):
    result = host.install(env={"STUB_HOST": "3.11 cpython x86_64 glibc 2.39"})
    assert result.returncode == 1, result.stdout + result.stderr
    assert "bundle verified" in result.stdout
    assert "this bundle is for Python 3.12, but" in result.stderr and "is Python 3.11" in result.stderr
    assert "Nothing was installed" in result.stderr and not host.home.exists()


@pytest.mark.parametrize(("reported", "message"), [
    ("3.12 pypy x86_64 glibc 2.39", "this bundle is for CPython"),
    ("3.12 cpython aarch64 glibc 2.39", "this bundle is for x86_64 hosts, but this host is aarch64"),
    ("3.12 cpython x86_64 glibc 2.17", "needs glibc 2.28 or later, and this host has glibc 2.17"),
    ("3.12 cpython x86_64 none 0", "needs glibc 2.28 or later, and this host has none"),
])
def test_another_kind_of_host_is_refused(host, reported, message):
    result = host.install(env={"STUB_HOST": reported})
    assert result.returncode == 1 and message in result.stderr, result.stderr
    assert "Nothing was installed" in result.stderr and not host.home.exists()


def test_a_real_interpreter_of_another_version_is_refused(tmp_path, shell):
    """The same refusal against this test run's own interpreter, with no stand-in for it."""
    other = Host(tmp_path, shell, python=f"3.{sys.version_info[1] + 1}")
    result = other.install("--python", posix(Path(sys.executable)), python=False)
    assert result.returncode == 1, result.stdout + result.stderr
    assert f"this bundle is for Python 3.{sys.version_info[1] + 1}, but" in result.stderr
    assert f"is Python 3.{sys.version_info[1]}" in result.stderr and not other.home.exists()


def test_running_from_inside_the_tree_it_replaces_is_refused(host):
    inside = host.home / "app" / "bundle"
    inside.parent.mkdir(parents=True)
    shutil.move(str(host.bundle), str(inside))
    result = host.install(directory=inside)
    assert result.returncode == 1 and "unpack the bundle outside" in result.stderr
    assert (inside / "SHA256SUMS").is_file() and not (host.home / "venv").exists()


# ---------------------------------------------------------------------------------------------------------------
# an upgrade


def test_upgrade_replaces_the_tree_and_keeps_everything_else(host):
    home = host.seed()
    (home / "stage" / "h1" / "events").write_text(KEPT["stage/h1/events"])
    result = host.install()
    assert result.returncode == 0, result.stdout + result.stderr
    assert_kept(home)
    assert_no_leftovers(home)
    assert (home / "app" / "DEPLOYED_COMMIT").read_text() == "abc1234\n" and not (home / "app" / "MARKER").exists()
    assert (home / "app.old" / "MARKER").read_text() == "previous tree\n"
    assert (home / "app.old" / "DEPLOYED_COMMIT").read_text() == "0ldc0mm1\n"
    assert host.calls("VENV") == []                                  # the venv is reused, not rebuilt
    # .env exists, so the install ends with doctor, against this home whatever the .env names
    assert host.calls("ROMULUS") == [["--help", "ROMULUS_HOME="],
                                     [f"--env-file {posix(home)}/.env doctor", f"ROMULUS_HOME={posix(home)}"]]
    assert f"sets ROMULUS_HOME=/somewhere, not {posix(home)}" in result.stdout
    installs = [call for call in host.calls("PIP") if call != ["--version"]]
    assert [call[-1] for call in installs] == ["requirements/extras.txt", f"{posix(home)}/app[anthropic]"]
    assert host.calls("PIPENV") == [["PIP_CONFIG_FILE=/dev/null"]] * len(host.calls("PIP"))


def test_doctor_failing_does_not_fail_the_install_and_can_be_skipped(host):
    home = host.seed()
    result = host.install(env={"STUB_DOCTOR": "1"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "The install is complete. Doctor reported failures (exit 1)" in result.stdout
    host.log.unlink()
    skipped = host.install("--no-doctor")
    assert skipped.returncode == 0 and host.calls("ROMULUS") == [["--help", "ROMULUS_HOME="]]
    assert (home / "app.old" / "DEPLOYED_COMMIT").read_text() == "abc1234\n"


@pytest.mark.parametrize(("failure", "message"), [
    ("editable", "ROMULUS did not install from the bundle"),
    ("help", "The installed romulus command does not run"),
    ("check", "does not find everything it ships with"),
])
def test_a_failed_upgrade_puts_the_previous_tree_back(host, failure, message):
    home = host.seed()
    result = host.install(env={"STUB_FAIL": failure})
    assert result.returncode == 1, result.stdout + result.stderr
    assert message in result.stderr and f"The previous application tree was put back at {posix(home)}/app" in result.stderr
    assert (home / "app" / "MARKER").read_text() == "previous tree\n"
    assert (home / "app" / "DEPLOYED_COMMIT").read_text() == "0ldc0mm1\n"
    # the tree before the previous one is only given up once a new tree is known to work
    assert (home / "app.old" / "MARKER").read_text() == "the tree before the previous one\n"
    assert_kept(home)
    assert_no_leftovers(home)
    assert "is installed in" not in result.stdout and not [call for call in host.calls("ROMULUS") if "doctor" in call[0]]
    # the venv is pointed back at the tree that was restored
    last = host.calls("PIP")[-1]
    assert last[-3:] == ["--no-deps", "-e", f"{posix(home)}/app"] and "--no-index" in last and "--isolated" in last


def test_a_dependency_failure_leaves_the_install_untouched(host):
    home = host.seed()
    result = host.install(env={"STUB_FAIL": "deps"})
    assert result.returncode == 1 and "was not touched" in result.stderr
    assert (home / "app" / "MARKER").read_text() == "previous tree\n"
    assert (home / "app.old" / "MARKER").read_text() == "the tree before the previous one\n"
    assert_kept(home)
    assert_no_leftovers(home)
    assert [call for call in host.calls("PIP") if "-e" in call] == []


def test_a_venv_of_another_python_is_refused(host):
    home = host.seed()
    result = host.install(env={"STUB_VENV_PYTHON": "3.11"})
    assert result.returncode == 1 and "runs Python 3.11, and this bundle is for Python 3.12" in result.stderr
    assert (home / "app" / "MARKER").is_file() and host.calls("PIP") == []
    assert_kept(home)


def test_one_install_at_a_time(host):
    home = host.seed()
    (home / ".install.lock").mkdir()
    result = host.install()
    assert result.returncode == 1 and "another install into" in result.stderr
    assert (home / ".install.lock").is_dir()                       # it is the other install's to remove
    assert (home / "app" / "MARKER").is_file() and host.calls("PIP") == []
    assert_kept(home)


def test_a_tree_left_by_a_killed_install_is_recovered(host):
    home = host.seed()
    (home / "app").rename(home / "app.prev")
    result = host.install("--no-doctor")
    assert result.returncode == 0, result.stdout + result.stderr
    assert (home / "app" / "DEPLOYED_COMMIT").read_text() == "abc1234\n"
    assert (home / "app.old" / "MARKER").read_text() == "previous tree\n"
    assert_no_leftovers(home)


# ---------------------------------------------------------------------------------------------------------------
# an upgrade under a running hunt or web UI

STOP_FIRST = "Stop running hunts"


def test_upgrade_is_refused_while_the_web_ui_runs(host):
    home = host.seed()
    held = f'sleep 60 & held=$!; echo $held > "{posix(home)}/web.pid"'
    result = host.install(before=held, after="kill $held 2>/dev/null")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "ROMULUS is running from" in result.stderr and "the web UI (pid " in result.stderr
    for advice in (STOP_FIRST, "hunt stop <id>", "stop the web UI", "hunt resume <id>", "restart the web UI",
                   "--force", "Nothing was installed"):
        assert advice in result.stderr, advice
    assert (home / "app" / "MARKER").is_file() and host.calls("PIP") == []
    assert_kept(home)
    assert_no_leftovers(home)

    forced = host.install("--force", "--no-doctor", before=held, after="kill $held 2>/dev/null")
    assert forced.returncode == 0, forced.stdout + forced.stderr
    assert "warning: upgrading under the web UI" in forced.stdout and "restart it with" in forced.stdout
    assert (home / "app" / "DEPLOYED_COMMIT").read_text() == "abc1234\n"


def test_a_stale_pid_file_does_not_block_an_upgrade(host):
    home = host.seed()
    (home / "web.pid").write_text("999999999\n")
    result = host.install("--no-doctor")
    assert result.returncode == 0, result.stdout + result.stderr
    assert (home / "app" / "DEPLOYED_COMMIT").read_text() == "abc1234\n"


def test_upgrade_is_refused_while_a_command_of_this_home_runs(host):
    home = host.seed()
    worker = write_script(home / "venv" / "bin" / "hunt-worker", "#!/bin/sh\nsleep 30 &\nwait\n")
    held = f'"{posix(worker)}" & held=$!; sleep 1'
    look = (f'{held}; tr "\\0" "\\n" < /proc/$held/cmdline 2>/dev/null | '
            f'grep -c -F "{posix(home)}/venv/bin/hunt-worker"; kill $held')
    seen = subprocess.run([host.shell, "-c", look], capture_output=True, text=True, check=False,
                          env=_environment()).stdout.strip()
    if seen in ("", "0"):
        pytest.skip("this machine does not show a process's command line under /proc")
    result = host.install(before=held, after="kill $held 2>/dev/null")
    assert result.returncode == 1, result.stdout + result.stderr
    assert f"processes started from {posix(home)}/venv (pid " in result.stderr and STOP_FIRST in result.stderr
    assert (home / "app" / "MARKER").is_file() and host.calls("PIP") == []
    assert_kept(home)

    forced = host.install("--force", "--no-doctor", before=held, after="kill $held 2>/dev/null")
    assert forced.returncode == 0, forced.stdout + forced.stderr
    assert "warning: upgrading under processes started from" in forced.stdout


def test_a_fresh_install_does_not_look_for_running_processes(host):
    host.home.mkdir()
    held = f'sleep 60 & held=$!; echo $held > "{posix(host.home)}/web.pid"'
    result = host.install(before=held, after="kill $held 2>/dev/null")
    assert result.returncode == 0, result.stdout + result.stderr
