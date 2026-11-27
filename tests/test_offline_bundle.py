"""The offline install bundle's builder (scripts/build_offline_bundle.py) and the install check
(scripts/install_check.py). The installer the bundle carries is covered in tests/test_offline_installer.py.

Nothing here reaches a package index. Wheels are small synthetic archives with real metadata, and pip is a stand-in
where a download would happen.
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

from tests.offline_bundle_support import (
    AGENT_NOTES,
    DECISION_RECORD,
    LOCAL_ONLY,
    MASTER_PROMPT,
    PROJECT_STATUS,
    ROOT,
    SCRIPTS,
    TRACKED,
    build,
    bundle,
    make_repo,
    make_wheel,
    make_wheelhouse,
    unpack,
)

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
    assert manifest["requirements"]["declared"] == {
        "runtime": ["alpha>=1", "winonly>=1; sys_platform == 'win32'"], "extras": ["beta[fast]>=2"],
        "build": ["backend>=1"]}


def test_the_installer_is_handed_one_exact_version_of_every_package(tmp_path):
    """The requirement files the installer installs from name exact versions, split so that an install without the
    optional groups gets none of their packages."""
    built = build(tmp_path)
    directory = unpack(built, tmp_path / "unpacked")
    assert (directory / "requirements" / "runtime.txt").read_text() == "alpha==1.2\ngamma==1.0\nlinuxonly==1.0\n"
    assert (directory / "requirements" / "extras.txt").read_text() == "beta==2.0\ndelta==1.0\n"
    assert (directory / "requirements" / "build.txt").read_text() == "backend==1.0\n"
    assert built.manifest["requirements"]["installed"] == {
        "runtime": ["alpha==1.2", "gamma==1.0", "linuxonly==1.0"], "extras": ["beta==2.0", "delta==1.0"],
        "build": ["backend==1.0"]}
    plain = unpack(build(tmp_path, out="plain", extras=()), tmp_path / "plain-unpacked")
    assert (plain / "requirements" / "extras.txt").read_text() == ""
    assert (plain / "requirements" / "runtime.txt").read_text() == "alpha==1.2\ngamma==1.0\nlinuxonly==1.0\n"


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
    assert command[command.index("--constraint") + 1] == str(tmp_path / "repo" / "requirements" / "constraints.txt")
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

SECRET_COPIES = ["content/.env.bak", "src/romulus/.env.local", "docs/.env.backup", "content/hunt.db.bak",
                 "content/.envrc", "docs/site.env.old", "content/tls.key.old", "content/cert.pem.1",
                 "src/romulus/store/romulus.db.2026", "content/indicators/tools.yaml.bak",
                 "src/romulus/config.py.orig"]
NEVER_SHIPPED = [".env", AGENT_NOTES, "CLAUDE.local.md", ".claude/agents/reviewer.md", ".claude/settings.json",
                 PROJECT_STATUS, DECISION_RECORD, "docs/design/agent.md",
                 "docs/research/sources.md", "docs/eval/run-01.md", "eval/gold.json", "content/research/notes.yaml",
                 MASTER_PROMPT, ".notes.git/HEAD", ".notes.git/objects/aa/bb"]


@pytest.mark.parametrize("path", [*NEVER_SHIPPED, *SECRET_COPIES])
def test_private_paths_are_recognised(path):
    assert bundle.private_reason(path)


def test_public_paths_are_not_private():
    for path in (".env.example", "README.md", "docs/OPERATOR_GUIDE.md", "content/attack/SOURCE.md",
                 "src/romulus/detect/environment.py", "content/mentions/tools.yaml", "scripts/web-restart.sh",
                 "src/romulus/store/db.py", "src/romulus/web/keys.py", "docs/environment.md",
                 "requirements/constraints.txt"):
        assert bundle.private_reason(path) is None, path


def test_private_files_outside_the_application_tree_are_omitted(tmp_path):
    built = build(tmp_path, tracked=[*TRACKED, *NEVER_SHIPPED[:5], MASTER_PROMPT, "eval/gold.json",
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


@pytest.mark.parametrize("path", [PROJECT_STATUS, DECISION_RECORD, "docs/design/agent.md",
                                  "docs/research/sources.md", "docs/eval/run-01.md", "content/research/notes.yaml",
                                  "content/site.env", "src/romulus/.env", "docs/" + AGENT_NOTES, "content/tls.key",
                                  "src/romulus/.claude/x.md", "content/a file.yaml", *SECRET_COPIES])
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
# pinned by default


def test_a_bundle_is_pinned_to_the_constraints_file_and_says_so(tmp_path):
    built = build(tmp_path)
    constraints = tmp_path / "repo" / "requirements" / "constraints.txt"
    assert built.manifest["constraints"] == {"file": "requirements/constraints.txt",
                                             "sha256": hashlib.sha256(constraints.read_bytes()).hexdigest()}
    assert "-latest" not in built.archive.name


def test_latest_is_unpinned_marked_in_the_name_and_recorded(tmp_path, capsys):
    (make_repo(tmp_path / "repo") / "requirements" / "constraints.txt").unlink()
    built = build(tmp_path, latest=True)
    assert built.archive.name == "romulus-offline-9.9.9-abc1234-latest-cp312-manylinux_2_28_x86_64.tar.gz"
    assert built.manifest["constraints"] == "none"
    # the versions installed are still exact: an unpinned build picks them, the installer does not
    assert built.manifest["requirements"]["installed"]["runtime"][0] == "alpha==1.2"
    with pytest.raises(bundle.BundleError, match="give one of them"):
        build(tmp_path, out="both", latest=True, constraints=tmp_path / "other.txt")


def test_a_pinned_build_needs_its_constraints_file(tmp_path):
    (make_repo(tmp_path / "repo") / "requirements" / "constraints.txt").unlink()
    with pytest.raises(bundle.BundleError, match=r"constraints\.txt is missing.*--refresh-constraints.*--latest"):
        build(tmp_path)
    assert not (tmp_path / "out").exists()


def test_a_wheel_the_constraints_do_not_pin_stops_a_pinned_build(tmp_path):
    repo = make_repo(tmp_path / "repo")
    constraints = repo / "requirements" / "constraints.txt"
    constraints.write_text(constraints.read_text().replace("linuxonly==1.0\n", ""), encoding="utf-8")
    with pytest.raises(bundle.BundleError, match=r"does not pin: linuxonly 1\.0 is not pinned"):
        build(tmp_path)
    assert not (tmp_path / "out").exists()


def test_a_wheelhouse_is_checked_against_the_constraints(tmp_path):
    """Nothing is downloaded from a wheelhouse, so pip never applies the constraints to it: the builder does."""
    wheelhouse = make_wheelhouse(tmp_path / "wheelhouse")
    (wheelhouse / "gamma-1.0-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl").unlink()
    make_wheel(wheelhouse, "gamma", "1.1", tags="cp312-cp312-manylinux_2_17_x86_64")
    with pytest.raises(bundle.BundleError, match=r"gamma 1\.1 is pinned to 1\.0"):
        build(tmp_path)
    other = tmp_path / "site-pins.txt"
    other.write_text("alpha==1.2\nbackend==1.0\nbeta==2.0\ndelta==1.0\ngamma==1.1\nlinuxonly==1.0\n", encoding="utf-8")
    built = build(tmp_path, constraints=other)
    assert built.manifest["constraints"]["file"] == "site-pins.txt"
    assert "gamma==1.1" in built.manifest["requirements"]["installed"]["runtime"]
    other.write_text("alpha==1.2\ngamma>=1\n", encoding="utf-8")       # a range pins nothing
    with pytest.raises(bundle.BundleError, match=r"gamma 1\.1 is not pinned"):
        build(tmp_path, out="ranged", constraints=other)
    assert build(tmp_path, out="unpinned", latest=True).manifest["constraints"] == "none"


def test_pins_are_read_from_exact_lines_only():
    pins = bundle.parse_pins("# a comment\nAlpha_Pkg==1.2  # why\n\nbeta>=2\ngamma @ file:///x\n-e ./here\n"
                             "delta == 3.0.post1\n")
    assert pins == {"alpha-pkg": "1.2", "delta": "3.0.post1"}


def fake_environment(source: Path, frozen: str):
    """A stand-in for pip: `freeze` prints `frozen`; `download` copies from `source` what the constraints allow."""
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if command[3] == "freeze":
            return subprocess.CompletedProcess(command, 0, frozen, "")
        pins = bundle.parse_pins(Path(command[command.index("--constraint") + 1]).read_text(encoding="utf-8"))
        dest = Path(command[command.index("--dest") + 1])
        newest: dict[str, Path] = {}
        for wheel in sorted(source.iterdir()):
            name, version = wheel.name.split("-")[:2]
            if pins.get(name, version) == version:
                newest[name] = wheel
        for wheel in newest.values():
            shutil.copyfile(wheel, dest / wheel.name)
        return subprocess.CompletedProcess(command, 0, "", "")

    return run, calls


def test_refresh_pins_the_environments_versions_and_keeps_pins_for_what_it_lacks(tmp_path):
    repo = make_repo(tmp_path / "repo")
    index = make_wheelhouse(tmp_path / "index")
    make_wheel(index, "alpha", "1.3", ("gamma>=1", "linuxonly>=1; sys_platform == 'linux'"))
    make_wheel(index, "backend", "1.1")
    make_wheel(index, "linuxonly", "1.5")
    constraints = repo / "requirements" / "constraints.txt"
    constraints.write_text("alpha==1.2\nbackend==1.0\ngamma==1.0\nold-and-gone==0.1\n", encoding="utf-8")
    # the environment has moved to alpha 1.3; it holds no build backend and nothing Linux-only
    run, calls = fake_environment(index, "alpha==1.3\nbeta==2.0\ndelta==1.0\ngamma==1.0\nlocal-tool==7\n"
                                         "editable-thing @ file:///somewhere\n")
    path, wheels = bundle.refresh_constraints(root=repo, run=run)
    assert path == constraints and len(wheels) == 6
    text = constraints.read_text(encoding="utf-8")
    assert text.startswith(bundle.CONSTRAINTS_HEADER) and "--refresh-constraints" in bundle.CONSTRAINTS_HEADER
    assert [line for line in text.splitlines() if line and not line.startswith("#")] == [
        "alpha==1.3",        # the environment's version
        "backend==1.0",      # not in the environment: its pin is kept, not moved to 1.1
        "beta==2.0", "delta==1.0", "gamma==1.0",
        "linuxonly==1.5",    # in neither: the newest release, pinned from now on
    ]
    assert calls[0][:4] == [sys.executable, "-m", "pip", "freeze"] and "--exclude-editable" in calls[0]
    assert bundle.parse_pins(text) == {wheel.name: wheel.version for wheel in wheels}
    # and the refreshed file is one a pinned build accepts
    (tmp_path / "wheelhouse").mkdir()
    for wheel in wheels:
        shutil.copyfile(index / wheel.file, tmp_path / "wheelhouse" / wheel.file)
    assert build(tmp_path).manifest["requirements"]["installed"]["runtime"][0] == "alpha==1.3"


def _installed(name: str) -> tuple[str, list[str]] | None:
    from importlib import metadata

    try:
        found = metadata.distribution(name)
    except metadata.PackageNotFoundError:
        return None
    return found.version, list(found.requires or [])


def test_the_checkouts_constraints_pin_everything_a_default_bundle_carries(tmp_path):
    """Resolve the project's real requirements for the default target against a wheelhouse that holds exactly the
    pinned versions, each with the requirements its installed copy declares. Every wheel the resolver keeps must
    be pinned, and nothing the target needs may be missing from the pins."""
    project = bundle.read_project(ROOT)
    pins = bundle.parse_pins((ROOT / bundle.CONSTRAINTS).read_text(encoding="utf-8"))
    canonicalize = bundle._packaging()[1]
    for requirement in [*project.runtime, *project.extras["anthropic"], *project.build]:
        assert canonicalize(re.match(r"[A-Za-z0-9._-]+", requirement).group(0)) in pins, requirement
    differing = []
    for name, version in pins.items():
        installed = _installed(name)
        if installed is not None and installed[0] != version:
            differing.append(f"{name} {installed[0]} (pinned {version})")
        make_wheel(tmp_path / "wheelhouse", name.replace("-", "_"), version,
                   tuple(installed[1]) if installed else ())
    if differing:
        pytest.skip("this environment does not run the pinned versions: " + ", ".join(differing[:5]))
    roots = [*project.runtime, *project.extras["anthropic"], *project.build]
    wheels, dropped = bundle.collect_wheels(roots, tmp_path / "kept", bundle.Target(),
                                            wheelhouse=tmp_path / "wheelhouse")
    assert bundle.unpinned_wheels(wheels, pins) == []
    assert len(wheels) >= len(project.runtime) + 2
    # the file pins nothing the bundle does not carry, except the build backend's own dependencies, whose
    # requirements this environment cannot show because it does not hold the backend
    backend_only = {"pathspec", "pluggy", "tomlkit", "trove-classifiers", "packaging"}
    assert {wheel.split("-")[0].replace("_", "-") for wheel in dropped} <= backend_only


def test_the_offline_proof_ignores_this_machines_pip_configuration(tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "repo")
    wheels = make_wheelhouse(tmp_path / "wheelhouse")
    monkeypatch.setenv("PIP_INDEX_URL", "https://mirror.invalid/simple")
    monkeypatch.setenv("PIP_FIND_LINKS", "/somewhere/else")
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs.get("env")))
        if command[3] == "wheel":
            out = Path(command[command.index("--wheel-dir") + 1])
            out.mkdir(parents=True)
            with zipfile.ZipFile(out / "romulus-9.9.9-py3-none-any.whl", "w") as archive:
                for path in (repo / "src").rglob("*"):
                    if path.is_file():
                        archive.write(path, path.relative_to(repo / "src").as_posix())
        return subprocess.CompletedProcess(command, 0, "", "")

    checked = bundle.check_offline_build(repo, wheels, bundle.read_project(repo), tmp_path / "scratch", run=run)
    assert checked["file"] == "romulus-9.9.9-py3-none-any.whl" and len(calls) == 2
    for command, environment in calls:
        assert "--isolated" in command and "--no-index" in command
        assert command[command.index("--find-links") + 1] == str(wheels)
        assert [key for key in environment if key.upper().startswith("PIP_")] == ["PIP_CONFIG_FILE"]
        assert environment["PIP_CONFIG_FILE"] == os.devnull
    assert calls[1][0][3] == "install" and "--dry-run" in calls[1][0] and "--editable" in calls[1][0]


def test_a_tracked_symbolic_link_stops_the_build(tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "repo")
    outside = tmp_path / "outside-secret.yaml"
    outside.write_text("secret: yes\n", encoding="utf-8")
    link = repo / "content" / "mentions" / "linked.yaml"
    try:
        link.symlink_to(outside)
    except OSError:
        # an account that may not create links (Windows without the privilege): a file reported as one
        link.write_text("secret: yes\n", encoding="utf-8")
        real = Path.is_symlink
        monkeypatch.setattr(Path, "is_symlink", lambda self: self.name == "linked.yaml" or real(self))
    with pytest.raises(bundle.BundleError, match="content/mentions/linked.yaml: it is a symbolic link"):
        build(tmp_path, tracked=[*TRACKED, "content/mentions/linked.yaml"])
    assert not (tmp_path / "out").exists()
