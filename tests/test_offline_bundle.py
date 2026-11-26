"""The offline install bundle: its builder (scripts/build_offline_bundle.py), the installer it carries
(scripts/install-offline.sh) and the install check (scripts/install_check.py).

Nothing here reaches a package index. Wheels are small synthetic archives with real metadata, pip is a stand-in
where a download would happen, and the installer is only driven as far as its refusals, which need no Linux host.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


bundle = _load("romulus_build_offline_bundle", SCRIPTS / "build_offline_bundle.py")

PYPROJECT = """\
[project]
name = "romulus"
version = "9.9.9"
dependencies = ["alpha>=1", "winonly>=1; sys_platform == 'win32'"]

[project.optional-dependencies]
anthropic = ["beta[fast]>=2"]

[build-system]
requires = ["backend>=1"]
build-backend = "fake.backend"
"""
TRACKED = ["pyproject.toml", "README.md", ".env.example", "scripts/web-restart.sh", "scripts/install_check.py",
           "scripts/install-offline.sh", "scripts/deploy.ps1", "src/romulus/__init__.py",
           "src/romulus/agent/prompts/system.md", "content/mentions/a.yaml", "docs/OPERATOR_GUIDE.md",
           "tests/test_something.py"]
# present in the working tree and named by git, but never to be shipped
LOCAL_ONLY = ["CLAUDE.md", "CLAUDE.local.md", "ENGINEERING_MASTER_PROMPT.md", ".env", ".claude/agents/reviewer.md",
              ".notes.git/HEAD", "eval/gold.json"]


def make_wheel(directory: Path, name: str, version: str, requires: tuple[str, ...] = (),
               tags: str = "py3-none-any") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}-{version}-{tags}.whl"
    metadata = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n" + "".join(
        f"Requires-Dist: {requirement}\n" for requirement in requires)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"{name}/__init__.py", f"# {name}\n")
        archive.writestr(f"{name}-{version}.dist-info/METADATA", metadata)
    return path


def make_wheelhouse(directory: Path, arch: str = "x86_64", abi: str = "cp312") -> Path:
    make_wheel(directory, "alpha", "1.2", ("gamma>=1", "linuxonly>=1; sys_platform == 'linux'",
                                           "winonly>=1; sys_platform == 'win32'"))
    make_wheel(directory, "gamma", "1.0", tags=f"{abi}-{abi}-manylinux2014_{arch}.manylinux_2_17_{arch}")
    make_wheel(directory, "linuxonly", "1.0")
    make_wheel(directory, "beta", "2.0", ("delta>=1; extra == 'fast'", "never>=1; extra == 'slow'"))
    make_wheel(directory, "delta", "1.0", tags=f"cp310-abi3-manylinux_2_28_{arch}")
    make_wheel(directory, "backend", "1.0")
    make_wheel(directory, "stray", "3.0")
    return directory


def make_repo(root: Path) -> Path:
    for path in [*TRACKED, *LOCAL_ONLY]:
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(f"# {path}\n".encode())
    (root / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    (root / "scripts" / "web-restart.sh").write_bytes(b"#!/usr/bin/env bash\r\necho restart\r\n")
    (root / "scripts" / "install-offline.sh").write_bytes((SCRIPTS / "install-offline.sh").read_bytes())
    (root / ".env").write_bytes(b"ES_PASSWORD=not-for-a-bundle\n")
    return root


def build(tmp_path: Path, *, out: str = "out", target=None, **overrides):
    repo = tmp_path / "repo"
    if not repo.exists():
        make_repo(repo)
    options = {"root": repo, "out_dir": tmp_path / out, "target": target or bundle.Target(),
               "wheelhouse": tmp_path / "wheelhouse", "tracked": [*TRACKED, *LOCAL_ONLY], "commit": "abc1234",
               "mtime": 1_700_000_000, "check_build": False}
    options.update(overrides)
    if options["wheelhouse"] is not None and not options["wheelhouse"].exists():
        make_wheelhouse(options["wheelhouse"], options["target"].arch, options["target"].abi)
    return bundle.build_bundle(**options)


def unpack(built, dest: Path) -> Path:
    return bundle.unpack_archive(built.archive, dest)


# ---------------------------------------------------------------------------------------------------------------
# manifest, checksums and the verifier


def test_bundle_lists_every_file_with_its_digest_and_verifies(tmp_path):
    built = build(tmp_path)
    assert built.archive.name == "romulus-offline-9.9.9-abc1234-cp312-manylinux_2_28_x86_64.tar.gz"
    assert built.sha256 == hashlib.sha256(built.archive.read_bytes()).hexdigest()
    assert built.size == built.archive.stat().st_size
    assert Path(f"{built.archive}.sha256").read_text() == f"{built.sha256}  {built.archive.name}\n"

    directory = unpack(built, tmp_path / "unpacked")
    assert bundle.verify_bundle(directory) == []
    manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["format"] == bundle.FORMAT_VERSION and manifest["romulus_version"] == "9.9.9"
    assert manifest["source_commit"] == "abc1234" and manifest["extras"] == ["anthropic"]
    assert manifest["target"]["python"] == "3.12" and manifest["target"]["abi"] == "cp312"
    assert manifest["target"]["arch"] == "x86_64" and manifest["target"]["glibc"] == "2.28"
    on_disk = sorted(path.relative_to(directory).as_posix() for path in directory.rglob("*") if path.is_file())
    assert sorted(entry["path"] for entry in manifest["files"]) == sorted(
        set(on_disk) - {"MANIFEST.json", "SHA256SUMS"})
    for entry in manifest["files"]:
        data = (directory / entry["path"]).read_bytes()
        assert entry["sha256"] == hashlib.sha256(data).hexdigest() and entry["size"] == len(data)
    sums = dict(reversed(line.split("  ", 1)) for line in (directory / "SHA256SUMS").read_text().splitlines())
    assert sorted(sums) == sorted(set(on_disk) - {"SHA256SUMS"})
    assert sums["MANIFEST.json"] == hashlib.sha256((directory / "MANIFEST.json").read_bytes()).hexdigest()
    assert (directory / "TARGET").read_text() == (
        "format=1\nversion=9.9.9\ncommit=abc1234\npython=3.12\narch=x86_64\nglibc=2.28\nextras=anthropic\n")
    assert (directory / "requirements" / "runtime.txt").read_text().splitlines()[0] == "alpha>=1"
    assert (directory / "requirements" / "extras.txt").read_text() == "beta[fast]>=2\n"


def test_wheelhouse_holds_what_the_target_needs_and_nothing_else(tmp_path):
    built = build(tmp_path)
    # the Linux-only dependency is in, the Windows-only one is not asked for, an extra's own extra is followed
    assert [wheel["name"] for wheel in built.manifest["wheels"]] == ["alpha", "backend", "beta", "delta", "gamma",
                                                                     "linuxonly"]
    assert built.dropped == ["stray-3.0-py3-none-any.whl"]
    assert not any("stray" in member for member in built.members)
    without_extras = build(tmp_path, out="plain", extras=())
    assert [wheel["name"] for wheel in without_extras.manifest["wheels"]] == ["alpha", "backend", "gamma",
                                                                              "linuxonly"]
    assert without_extras.manifest["extras"] == []


def test_verifier_names_changed_missing_and_unlisted_files(tmp_path):
    directory = unpack(build(tmp_path), tmp_path / "unpacked")
    wheel = directory / "wheels" / "alpha-1.2-py3-none-any.whl"
    wheel.write_bytes(wheel.read_bytes() + b"x")
    (directory / "wheels" / "evil-1.0-py3-none-any.whl").write_bytes(b"not listed")
    (directory / "app" / "README.md").unlink()
    problems = bundle.verify_bundle(directory)
    assert "wheels/alpha-1.2-py3-none-any.whl: SHA-256 mismatch" in problems
    assert "wheels/evil-1.0-py3-none-any.whl: not listed in SHA256SUMS" in problems
    assert "app/README.md: listed but missing" in problems


def test_verifier_checks_the_manifest_against_the_files(tmp_path):
    directory = unpack(build(tmp_path), tmp_path / "unpacked")
    manifest_path = directory / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    assert bundle.verify_bundle(directory) == ["MANIFEST.json: SHA-256 mismatch"]
    # a manifest swapped together with its own checksum line still has to describe the files
    sums = directory / "SHA256SUMS"
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    sums.write_text(re.sub(r"[0-9a-f]{64}  MANIFEST\.json", f"{digest}  MANIFEST.json", sums.read_text()))
    assert bundle.verify_bundle(directory) == ["MANIFEST.json does not describe the files in the bundle"]
    sums.unlink()
    assert bundle.verify_bundle(directory) == ["SHA256SUMS is missing"]


def test_verify_command_reports_a_good_and_a_changed_bundle(tmp_path, capsys):
    built = build(tmp_path)
    assert bundle.main(["--verify", str(built.archive)]) == 0
    assert "bundle verifies" in capsys.readouterr().out
    directory = unpack(built, tmp_path / "unpacked")
    (directory / "install-offline.sh").write_bytes(b"#!/bin/sh\necho changed\n")
    assert bundle.main(["--verify", str(directory)]) == 1
    assert "FAIL install-offline.sh: SHA-256 mismatch" in capsys.readouterr().out


# ---------------------------------------------------------------------------------------------------------------
# wheels for the target, never the build machine


def failing_pip(stderr: str):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 1, "", stderr)

    return run, calls


@pytest.mark.parametrize("arch", ["x86_64", "aarch64"])
def test_no_binary_wheel_for_the_target_fails_naming_the_package(tmp_path, arch):
    run, calls = failing_pip(
        "ERROR: Could not find a version that satisfies the requirement alpha>=1 (from versions: none)\n"
        "ERROR: No matching distribution found for alpha>=1\n")
    with pytest.raises(bundle.BundleError) as raised:
        build(tmp_path, wheelhouse=None, run=run, target=bundle.Target(arch=arch))
    message = str(raised.value)
    assert "no binary wheel for CPython 3.12 on " + arch in message and ": alpha." in message
    assert "binary wheels only" in message
    assert not (tmp_path / "out").exists() or not list((tmp_path / "out").iterdir())

    command = calls[0]
    assert command[:4] == [sys.executable, "-m", "pip", "download"] and "--only-binary=:all:" in command
    assert command[command.index("--python-version") + 1] == "3.12"
    assert command[command.index("--abi") + 1] == "cp312" and command[command.index("--implementation") + 1] == "cp"
    platforms = [command[index + 1] for index, part in enumerate(command) if part == "--platform"]
    assert platforms[0] == f"manylinux_2_28_{arch}" and platforms[-1] == f"manylinux2014_{arch}"
    assert f"manylinux_2_17_{arch}" in platforms and all(tag.endswith(arch) for tag in platforms)
    assert command[command.index("--dest") + 2:] == ["alpha>=1", "winonly>=1; sys_platform == 'win32'",
                                                     "beta[fast]>=2", "backend>=1"]


def test_a_dependency_of_a_dependency_without_a_wheel_is_named(tmp_path):
    run, _ = failing_pip("ERROR: Could not find a version that satisfies the requirement native-thing>=3 "
                         "(from alpha) (from versions: none)\nERROR: No matching distribution found for "
                         "native-thing>=3\n")
    with pytest.raises(bundle.BundleError, match=r"no binary wheel for .*: native-thing\."):
        build(tmp_path, wheelhouse=None, run=run)


def test_a_pip_failure_that_names_no_package_is_still_loud(tmp_path):
    run, _ = failing_pip("ERROR: connection refused by the index\n")
    with pytest.raises(bundle.BundleError, match=r"(?s)pip download failed .*connection refused"):
        build(tmp_path, wheelhouse=None, run=run)


@pytest.mark.parametrize(("file", "why"), [
    ("alpha-1.2.tar.gz", "not a binary wheel"),
    ("gamma-1.0-cp312-cp312-win_amd64.whl", "cannot be installed on CPython 3.12 on x86_64"),
    ("gamma-1.0-cp311-cp311-manylinux_2_17_x86_64.whl", "cannot be installed"),
    ("gamma-1.0-cp312-cp312-manylinux_2_34_x86_64.whl", "cannot be installed"),
    ("gamma-1.0-cp312-cp312-manylinux_2_17_aarch64.whl", "cannot be installed"),
    ("gamma-1.0-cp312-cp312-musllinux_1_2_x86_64.whl", "cannot be installed"),
])
def test_a_source_distribution_or_a_wheel_for_another_platform_is_refused(tmp_path, file, why):
    wheelhouse = make_wheelhouse(tmp_path / "wheelhouse")
    for old in wheelhouse.glob("gamma-*"):
        old.unlink()
    if file.endswith(".whl"):
        name, version, tags = file[:-4].split("-", 2)
        make_wheel(wheelhouse, name, version, tags=tags)
    else:
        (wheelhouse / file).write_bytes(b"source")
    with pytest.raises(bundle.BundleError, match=why):
        build(tmp_path)


def test_a_gap_in_a_given_wheelhouse_is_judged_for_the_target_and_named(tmp_path):
    wheelhouse = make_wheelhouse(tmp_path / "wheelhouse")
    (wheelhouse / "linuxonly-1.0-py3-none-any.whl").unlink()
    with pytest.raises(bundle.BundleError) as raised:
        build(tmp_path)
    assert "linuxonly>=1 (needed by alpha)" in str(raised.value) and "winonly" not in str(raised.value)


def test_a_wheel_of_the_wrong_version_is_a_gap(tmp_path):
    wheelhouse = make_wheelhouse(tmp_path / "wheelhouse")
    (wheelhouse / "beta-2.0-py3-none-any.whl").unlink()
    make_wheel(wheelhouse, "beta", "1.0")
    with pytest.raises(bundle.BundleError, match=r"beta>=2 \(needed by the project; the wheelhouse has 1.0\)"):
        build(tmp_path)


def test_what_pip_left_out_for_the_build_machine_is_fetched_by_name(tmp_path):
    """pip judges environment markers for the machine it runs on: on Windows it skips a Linux-only dependency.
    The builder judges them for the target, so it notices the gap and downloads the package by name."""
    source = make_wheelhouse(tmp_path / "index")
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        dest = Path(command[command.index("--dest") + 1])
        wanted = command[command.index("--dest") + 2:]
        for wheel in source.iterdir():
            name = wheel.name.split("-")[0]
            by_name = any(re.match(r"[A-Za-z0-9_.]+", requirement).group(0) == name for requirement in wanted)
            if by_name if "--no-deps" in command else name not in ("linuxonly", "stray"):
                shutil.copyfile(wheel, dest / wheel.name)
        return subprocess.CompletedProcess(command, 0, "", "")

    built = build(tmp_path, wheelhouse=None, run=run)
    assert "linuxonly" in [wheel["name"] for wheel in built.manifest["wheels"]]
    assert len(calls) == 2 and "--no-deps" in calls[1] and calls[1][-1] == "linuxonly>=1"
    assert "--only-binary=:all:" in calls[1]


def test_target_platform_tags():
    default = bundle.Target()
    assert default.platform_tags[0] == "manylinux_2_28_x86_64" and default.platform_tags[-1] == "manylinux2014_x86_64"
    assert len(default.platform_tags) == 13 and default.abi == "cp312"
    arm = bundle.Target(python="3.13", arch="aarch64", glibc="2.34")
    assert arm.platform_tags[0] == "manylinux_2_34_aarch64" and arm.abi == "cp313"
    assert arm.environment()["platform_machine"] == "aarch64" and arm.environment()["sys_platform"] == "linux"
    explicit = bundle.Target.from_platforms("3.12", ["manylinux_2_31_aarch64", "manylinux2014_aarch64"])
    assert (explicit.arch, explicit.glibc) == ("aarch64", "2.31")
    assert explicit.platform_tags == ("manylinux_2_31_aarch64", "manylinux2014_aarch64")
    for bad in ({"python": "2.7"}, {"python": "3"}, {"arch": "x86-64; rm"}, {"glibc": "2.5"}, {"glibc": "musl"}):
        with pytest.raises(bundle.BundleError):
            bundle.Target(**bad)
    for tags in (["musllinux_1_2_x86_64"], ["manylinux_2_28_x86_64", "manylinux_2_28_aarch64"], ["win_amd64"]):
        with pytest.raises(bundle.BundleError):
            bundle.Target.from_platforms("3.12", tags)


# ---------------------------------------------------------------------------------------------------------------
# the archive


def test_archive_is_deterministic_and_ordered(tmp_path):
    first = build(tmp_path, out="first")
    second = build(tmp_path, out="second", tracked=list(reversed([*TRACKED, *LOCAL_ONLY])))
    assert first.archive.read_bytes() == second.archive.read_bytes()
    assert first.members == sorted(first.members)
    with tarfile.open(first.archive) as tar:
        members = tar.getmembers()
    assert [member.name for member in members] == [first.name, *first.members]
    assert all(member.name == first.name or member.name.startswith(first.name + "/") for member in members)
    assert {(member.uid, member.gid, member.uname, member.gname, member.mtime) for member in members} == {
        (0, 0, "", "", 1_700_000_000)}
    for member in members:
        expected = 0o755 if member.isdir() or member.name.endswith(".sh") else 0o644
        assert member.mode == expected, member.name
    assert first.archive.read_bytes()[4:8] == b"\0\0\0\0"          # no build time in the gzip header


def test_shell_scripts_are_lf_inside_the_archive(tmp_path):
    repo = make_repo(tmp_path / "repo")
    installer = repo / "scripts" / "install-offline.sh"
    installer.write_bytes(installer.read_bytes().replace(b"\n", b"\r\n"))
    directory = unpack(build(tmp_path), tmp_path / "unpacked")
    assert (directory / "app" / "scripts" / "web-restart.sh").read_bytes() == b"#!/usr/bin/env bash\necho restart\n"
    assert (directory / "install-offline.sh").read_bytes() == (SCRIPTS / "install-offline.sh").read_bytes()
    assert b"\r" not in (SCRIPTS / "install-offline.sh").read_bytes()
    assert b"\r" not in (SCRIPTS / "web-restart.sh").read_bytes()


# ---------------------------------------------------------------------------------------------------------------
# what never goes in

NEVER_SHIPPED = [".env", "CLAUDE.md", "CLAUDE.local.md", ".claude/agents/reviewer.md", ".claude/settings.json",
                 "docs/project/STATUS.md", "docs/adr/0001-store.md", "docs/design/agent.md",
                 "docs/research/sources.md", "docs/eval/run-01.md", "eval/gold.json", "content/research/notes.yaml",
                 "ENGINEERING_MASTER_PROMPT.md", ".notes.git/HEAD", ".notes.git/objects/aa/bb"]


@pytest.mark.parametrize("path", NEVER_SHIPPED)
def test_private_paths_are_recognised(path):
    assert bundle.private_reason(path)


def test_public_paths_are_not_private():
    for path in (".env.example", "README.md", "docs/OPERATOR_GUIDE.md", "content/attack/SOURCE.md",
                 "src/romulus/detect/environment.py", "content/mentions/tools.yaml", "scripts/web-restart.sh"):
        assert bundle.private_reason(path) is None, path


def test_private_files_outside_the_application_tree_are_omitted(tmp_path):
    built = build(tmp_path, tracked=[*TRACKED, *NEVER_SHIPPED[:5], "ENGINEERING_MASTER_PROMPT.md", "eval/gold.json",
                                     ".notes.git/HEAD"])
    shipped = [member.split("/", 1)[1] for member in built.members]
    assert not [path for path in shipped if bundle.private_reason(path.removeprefix("app/"))]
    for name in ("CLAUDE", ".claude", ".notes.git", "ENGINEERING", "eval/", "tests/", "deploy.ps1"):
        assert not [path for path in shipped if name in path], name
    assert "app/.env.example" in shipped and "app/.env" not in shipped
    with tarfile.open(built.archive) as tar:
        for member in tar.getmembers():
            if member.isfile():
                assert b"not-for-a-bundle" not in tar.extractfile(member).read(), member.name


@pytest.mark.parametrize("path", ["docs/project/STATUS.md", "docs/adr/0001-store.md", "docs/design/agent.md",
                                  "docs/research/sources.md", "docs/eval/run-01.md", "content/research/notes.yaml",
                                  "content/site.env", "src/romulus/.env", "docs/CLAUDE.md", "content/tls.key",
                                  "src/romulus/.claude/x.md", "content/a file.yaml"])
def test_a_private_file_inside_the_application_tree_stops_the_build(tmp_path, path):
    repo = make_repo(tmp_path / "repo")
    (repo / path).parent.mkdir(parents=True, exist_ok=True)
    (repo / path).write_bytes(b"private\n")
    with pytest.raises(bundle.BundleError, match="refusing to bundle"):
        build(tmp_path, tracked=[*TRACKED, path])
    assert not (tmp_path / "out").exists()


def test_the_checkout_selects_no_private_file():
    git = shutil.which("git")
    if git is None or not (ROOT / ".git").exists():
        pytest.skip("needs a git checkout")
    listed = subprocess.run([git, "-C", str(ROOT), "ls-files", "-z"], check=True, capture_output=True, text=True)
    files = bundle.select_app_files([path for path in listed.stdout.split("\0") if path])
    assert "src/romulus/cli.py" in files and "content/attack/SOURCE.md" in files
    assert "scripts/install_check.py" in files and "docs/OPERATOR_GUIDE.md" in files
    assert not [path for path in files if bundle.private_reason(path)]
    assert not [path for path in files if path.startswith(("tests/", ".claude/", "eval/"))]


def test_a_checkout_without_the_installer_or_a_needed_file_stops_the_build(tmp_path):
    repo = make_repo(tmp_path / "repo")
    with pytest.raises(bundle.BundleError, match="missing files the bundle needs: scripts/install_check.py"):
        build(tmp_path, tracked=[path for path in TRACKED if path != "scripts/install_check.py"])
    (repo / "scripts" / "install-offline.sh").unlink()
    with pytest.raises(bundle.BundleError, match="install-offline.sh is missing"):
        build(tmp_path)
    with pytest.raises(bundle.BundleError, match="no extra named nosuch"):
        build(tmp_path, extras=("nosuch",))


# ---------------------------------------------------------------------------------------------------------------
# the project's own packaging


def test_the_project_declares_what_the_bundle_downloads():
    project = bundle.read_project(ROOT)
    assert any(requirement.startswith("pydantic") for requirement in project.runtime)
    assert "anthropic" in project.extras
    assert any(requirement.startswith("hatchling") for requirement in project.build)
    assert any(requirement.startswith("editables") for requirement in project.build)


def test_no_forced_file_collides_with_a_package_file():
    """The build backend refuses a wheel in which a force-included file lands on a path the package already
    provides, so such an entry makes the project unbuildable."""
    project = bundle.read_project(ROOT)
    assert project.force_include.get("content/mentions") == "romulus/content/mentions"
    packaged = {path.relative_to(ROOT / "src").as_posix() for path in (ROOT / "src" / "romulus").rglob("*")
                if path.is_file()}
    for source, destination in project.force_include.items():
        base = ROOT / source
        assert base.exists(), source
        forced = ({f"{destination}/{path.relative_to(base).as_posix()}" for path in base.rglob("*") if path.is_file()}
                  if base.is_dir() else {destination})
        assert not forced & packaged, f"{source} is already packaged at {destination}"


def test_install_check_passes_on_the_checkout():
    environment = {key: value for key, value in os.environ.items()
                   if key not in ("ROMULUS_MENTION_DIR", "ROMULUS_INDICATOR_DIR")}
    environment["PYTHONPATH"] = str(ROOT / "src")
    command = [sys.executable, str(SCRIPTS / "install_check.py"), "--app", str(ROOT)]
    if all(importlib.util.find_spec(module) for module in ("anthropic", "httpx2")):
        command += ["--extra", "anthropic"]
    result = subprocess.run(command, capture_output=True, text=True, env=environment, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "install check passed" in result.stdout and "[FAIL]" not in result.stdout
    for name in ("package", "cli", "prompts", "mentions", "attack", "indicators", "network", "rule_tags",
                 "migrations", "web"):
        assert f"[OK  ] {name}: " in result.stdout, name


def test_install_check_fails_when_the_package_is_imported_from_elsewhere(tmp_path):
    environment = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    result = subprocess.run([sys.executable, str(SCRIPTS / "install_check.py"), "--app", str(tmp_path)],
                            capture_output=True, text=True, env=environment, check=False)
    assert result.returncode == 1 and "[FAIL] package: " in result.stdout
    assert "install check FAILED" in result.stdout


# ---------------------------------------------------------------------------------------------------------------
# the installer's refusals


def _shell() -> str | None:
    candidates = []
    if os.name == "nt":
        for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramW6432"), os.environ.get("LocalAppData")):
            if base:
                candidates += [str(Path(base) / "Git" / "bin" / "sh.exe"),
                               str(Path(base) / "Programs" / "Git" / "bin" / "sh.exe")]
        git = shutil.which("git")
        if git:
            candidates.append(str(Path(git).resolve().parents[1] / "bin" / "sh.exe"))
    else:
        candidates += [shutil.which("sh"), shutil.which("bash")]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            try:
                probe = subprocess.run([candidate, "-c", "command -v sha256sum >/dev/null && echo ok"],
                                       capture_output=True, text=True, timeout=30, check=False)
            except (OSError, subprocess.SubprocessError):
                continue
            if probe.stdout.strip() == "ok":
                return candidate
    return None


SHELL = _shell()
needs_shell = pytest.mark.skipif(SHELL is None, reason="needs a POSIX shell with sha256sum")


def _posix(path: Path) -> str:
    text = path.resolve().as_posix()
    return f"/{text[0].lower()}{text[2:]}" if os.name == "nt" and text[1:3] == ":/" else text


def run_installer(directory: Path, *arguments: str, python: str | None = None):
    command = [SHELL, _posix(directory / "install-offline.sh")]
    if python is not None:
        command += ["--python", python]
    environment = {key: value for key, value in os.environ.items() if not key.startswith("PIP_")}
    return subprocess.run([*command, *arguments], capture_output=True, text=True, timeout=120, check=False,
                          env=environment, cwd=str(directory.parent))


@pytest.fixture
def unpacked(tmp_path):
    def make(**target) -> Path:
        return unpack(build(tmp_path, target=bundle.Target(**target)), tmp_path / "unpacked")

    return make


HERE = f"{sys.version_info[0]}.{sys.version_info[1]}"
OTHER = f"3.{sys.version_info[1] + 1}"


@needs_shell
def test_installer_script_parses():
    result = subprocess.run([SHELL, "-n", _posix(SCRIPTS / "install-offline.sh")], capture_output=True, text=True,
                            check=False)
    assert result.returncode == 0, result.stderr


@needs_shell
def test_installer_refuses_a_changed_file_before_touching_the_home(tmp_path, unpacked):
    directory = unpacked(python=HERE)
    wheel = directory / "wheels" / "alpha-1.2-py3-none-any.whl"
    wheel.write_bytes(wheel.read_bytes() + b"x")
    home = tmp_path / "home"
    result = run_installer(directory, _posix(home), python=_posix(Path(sys.executable)))
    assert result.returncode == 1, result.stdout + result.stderr
    assert "checksum verification failed; nothing was installed" in result.stderr
    assert "alpha-1.2-py3-none-any.whl" in result.stderr and "bundle verified" not in result.stdout
    assert not home.exists()


@needs_shell
def test_installer_refuses_a_wheel_that_is_not_listed(tmp_path, unpacked):
    directory = unpacked(python=HERE)
    make_wheel(directory / "wheels", "alpha", "99.0")
    home = tmp_path / "home"
    result = run_installer(directory, _posix(home), python=_posix(Path(sys.executable)))
    assert result.returncode == 1, result.stdout + result.stderr
    assert "not listed in SHA256SUMS: wheels/alpha-99.0-py3-none-any.whl" in result.stderr
    assert "nothing was installed" in result.stderr and not home.exists()


@needs_shell
def test_installer_refuses_a_bundle_with_a_file_missing(tmp_path, unpacked):
    directory = unpacked(python=HERE)
    (directory / "app" / "content" / "mentions" / "a.yaml").unlink()
    home = tmp_path / "home"
    result = run_installer(directory, _posix(home), python=_posix(Path(sys.executable)))
    assert result.returncode == 1, result.stdout + result.stderr
    assert "listed in SHA256SUMS but missing: app/content/mentions/a.yaml" in result.stderr
    assert not home.exists()
    (directory / "SHA256SUMS").unlink()
    result = run_installer(directory, _posix(home))
    assert result.returncode == 1 and "not a complete bundle: SHA256SUMS is missing" in result.stderr


@needs_shell
def test_installer_refuses_a_python_the_bundle_was_not_built_for(tmp_path, unpacked):
    directory = unpacked(python=OTHER)
    home = tmp_path / "home"
    result = run_installer(directory, _posix(home), python=_posix(Path(sys.executable)))
    assert result.returncode == 1, result.stdout + result.stderr
    assert "bundle verified" in result.stdout
    assert f"this bundle is for Python {OTHER}, but" in result.stderr and f"is Python {HERE}" in result.stderr
    assert "Nothing was installed" in result.stderr and not home.exists()


@needs_shell
def test_installer_refuses_a_host_the_bundle_was_not_built_for(tmp_path, unpacked):
    directory = unpacked(python=HERE, arch="s390x")
    home = tmp_path / "home"
    result = run_installer(directory, _posix(home), python=_posix(Path(sys.executable)))
    assert result.returncode == 1, result.stdout + result.stderr
    assert ("this bundle installs on Linux" in result.stderr) or ("this bundle is for s390x hosts" in result.stderr)
    assert "Nothing was installed" in result.stderr and not home.exists()


@needs_shell
def test_installer_refuses_bad_arguments(tmp_path, unpacked):
    directory = unpacked(python=HERE)
    for arguments, message in ((("relative/home",), "absolute path"), ((), "usage:"),
                               (("--frobnicate", "/x"), "unknown option"), (("/a", "/b"), "one ROMULUS home"),
                               (("/has space/home",), "may hold only"), (("/",), "cannot be /"),
                               (("--python", "no-such-python-anywhere", _posix(tmp_path / "home")),
                                "no such interpreter")):
        result = run_installer(directory, *arguments)
        assert result.returncode == 1 and message in result.stderr, (arguments, result.stderr)
    assert not (tmp_path / "home").exists()
    help_text = run_installer(directory, "--help")
    assert help_text.returncode == 0 and "--no-extras" in help_text.stdout


@needs_shell
def test_installer_refuses_to_run_from_inside_the_tree_it_replaces(tmp_path, unpacked):
    directory = unpacked(python=HERE)
    home = tmp_path / "home"
    inside = home / "app" / "bundle"
    inside.parent.mkdir(parents=True)
    shutil.move(str(directory), str(inside))
    result = run_installer(inside, _posix(home), python=_posix(Path(sys.executable)))
    assert result.returncode == 1 and "unpack the bundle outside" in result.stderr
    assert (inside / "SHA256SUMS").is_file() and not (home / "venv").exists()
