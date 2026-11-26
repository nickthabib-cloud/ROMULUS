#!/usr/bin/env python3
"""Build an offline install bundle: one archive that installs ROMULUS on a Linux host with no network access.

Run it on a connected machine (Windows or Linux), from a git checkout, with nothing but Python 3.11+ and pip:

    python scripts/build_offline_bundle.py                       # CPython 3.12, x86_64, glibc 2.28 or later
    python scripts/build_offline_bundle.py --arch aarch64
    python scripts/build_offline_bundle.py --python-version 3.13 --glibc 2.34 --no-extras
    python scripts/build_offline_bundle.py --constraint tested-versions.txt    # pin what the wheelhouse carries
    python scripts/build_offline_bundle.py --verify <bundle.tar.gz or unpacked directory>

The archive holds the application tree (the layout `scripts/deploy.ps1` ships: `src`, `content`, `scripts`,
the docs and `.env.example`), a wheelhouse with every dependency as a binary wheel for the *target* interpreter
and platform, `install-offline.sh`, and `MANIFEST.json`/`SHA256SUMS` over every file. Nothing is taken from the
build machine's own environment, and a dependency without a binary wheel for the target is an error that names
the package: the bundle never carries a source distribution a disconnected host would have to compile.

The installer installs the application tree in place (`pip install --no-index -e <home>/app`), as the deploy
script does, because the code reads `content/` beside `src/`. The wheelhouse therefore also carries the build
backend, and this script proves the offline build works from that wheelhouse alone before it writes the archive.
"""

from __future__ import annotations

import argparse
import email.parser
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

FORMAT_VERSION = 1
ROOT = Path(__file__).resolve().parents[1]
INSTALLER = "install-offline.sh"
MANIFEST = "MANIFEST.json"
CHECKSUMS = "SHA256SUMS"
TARGET_FILE = "TARGET"

# The application tree: tracked files only, from these places only.
APP_FILES = ("pyproject.toml", "README.md", ".env.example", "scripts/web-restart.sh", "scripts/install_check.py")
APP_DIRS = ("src/romulus/", "content/", "docs/")
REQUIRED_APP_FILES = (*APP_FILES, "src/romulus/__init__.py", "docs/OPERATOR_GUIDE.md")

# Never in a bundle, wherever they turn up: local notes, site setup, secrets and captured data.
PRIVATE_NAMES = frozenset({"CLAUDE.md", "CLAUDE.local.md", "ENGINEERING_MASTER_PROMPT.md", "Claude-Codex.md",
                           "DEPLOYED_COMMIT"})
PRIVATE_PARTS = frozenset({".claude", ".notes.git", ".git", ".venv", "__pycache__"})
PRIVATE_DIRS = ("docs/project", "docs/adr", "docs/design", "docs/research", "docs/eval", "eval", "content/research",
                "tests")
PRIVATE_SUFFIXES = (".env", ".pem", ".key", ".db", ".db-wal", ".db-shm", ".sqlite", ".pcap", ".pcapng")

SAFE_PATH = re.compile(r"[A-Za-z0-9._+-]+(/[A-Za-z0-9._+-]+)*")
SAFE_VALUE = re.compile(r"[A-Za-z0-9._+,-]*")
# what the build backend asks for on top of build-system.requires when it builds an editable install
EDITABLE_BACKEND_REQUIRES = {"hatchling.build": ("editables~=0.3",)}
GLIBC_OF_LEGACY_TAG = {"manylinux1": 5, "manylinux2010": 12, "manylinux2014": 17}
PIP_MISSING = re.compile(r"(?:No matching distribution found for|Could not find a version that satisfies the "
                         r"requirement)\s+([A-Za-z0-9][A-Za-z0-9._-]*)")


class BundleError(Exception):
    """The bundle cannot be built, or one that was built does not verify."""


# ---------------------------------------------------------------------------------------------------------------
# target


@dataclass(frozen=True)
class Target:
    """The interpreter and platform the bundle installs on: CPython `python` on `arch` Linux with glibc `glibc`+."""

    python: str = "3.12"
    arch: str = "x86_64"
    glibc: str = "2.28"
    platforms: tuple[str, ...] = ()

    def __post_init__(self):
        if not re.fullmatch(r"3\.\d{1,2}", self.python):
            raise BundleError(f"target Python must look like 3.12, not {self.python!r}")
        if not re.fullmatch(r"[a-z0-9_]+", self.arch):
            raise BundleError(f"target architecture must look like x86_64 or aarch64, not {self.arch!r}")
        if not re.fullmatch(r"2\.\d{1,3}", self.glibc) or self.glibc_minor < 17:
            raise BundleError(f"target glibc must be 2.17 or later, not {self.glibc!r}")
        for tag in self.platforms:
            if _tag_glibc_minor(tag, self.arch) is None:
                raise BundleError(f"platform tag {tag!r} is not a glibc (manylinux) tag for {self.arch}")

    @classmethod
    def from_platforms(cls, python: str, platforms: list[str]) -> Target:
        """A target named by explicit platform tags: the architecture and glibc floor are read from the tags."""
        arches = {match.group(1) for tag in platforms
                  if (match := re.fullmatch(r"manylinux(?:\d+|_\d+_\d+)_([a-z0-9_]+?)", tag))}
        if len(arches) != 1:
            raise BundleError("give --platform manylinux tags for one architecture, e.g. manylinux_2_28_aarch64")
        arch = arches.pop()
        minors = [_tag_glibc_minor(tag, arch) for tag in platforms]
        if None in minors:
            raise BundleError(f"only glibc (manylinux) platform tags are supported, got {platforms}")
        return cls(python=python, arch=arch, glibc=f"2.{max(minors)}", platforms=tuple(platforms))

    @property
    def minor(self) -> int:
        return int(self.python.split(".")[1])

    @property
    def abi(self) -> str:
        return "cp" + self.python.replace(".", "")

    @property
    def glibc_minor(self) -> int:
        return int(self.glibc.split(".")[1])

    @property
    def platform_tags(self) -> tuple[str, ...]:
        """Newest first, which is pip's order of preference. Every glibc level down to 2.17 is named because pip
        matches a wheel's tag literally: a wheel built for glibc 2.24 is not offered for a bare 2.28 tag."""
        if self.platforms:
            return self.platforms
        return (*(f"manylinux_2_{minor}_{self.arch}" for minor in range(self.glibc_minor, 16, -1)),
                f"manylinux2014_{self.arch}")

    @property
    def label(self) -> str:
        return f"CPython {self.python} on {self.arch} Linux (glibc {self.glibc} or later)"

    def environment(self) -> dict[str, str]:
        """The marker environment of the target, so `sys_platform == "win32"` and friends are judged for the host
        the bundle installs on and not for the machine that builds it."""
        full = f"{self.python}.0"
        return {"implementation_name": "cpython", "implementation_version": full, "os_name": "posix",
                "platform_machine": self.arch, "platform_python_implementation": "CPython", "platform_release": "",
                "platform_system": "Linux", "platform_version": "", "python_full_version": full,
                "python_version": self.python, "sys_platform": "linux"}


def _tag_glibc_minor(tag: str, arch: str) -> int | None:
    """The glibc 2.x level a manylinux platform tag needs, or None when the tag is for another platform."""
    if not tag.endswith("_" + arch):
        return None
    family = tag[: -len(arch) - 1]
    if family in GLIBC_OF_LEGACY_TAG:
        return GLIBC_OF_LEGACY_TAG[family]
    match = re.fullmatch(r"manylinux_2_(\d+)", family)
    return int(match.group(1)) if match else None


# ---------------------------------------------------------------------------------------------------------------
# what goes in


def private_reason(path: str) -> str | None:
    """Why a path may never be in a bundle, or None."""
    pure = PurePosixPath(path)
    if pure.name in PRIVATE_NAMES:
        return "a local working file"
    if pure.name != ".env.example" and pure.name.endswith(PRIVATE_SUFFIXES):
        return "a secret or captured-data file"
    if PRIVATE_PARTS.intersection(pure.parts):
        return "inside a local tooling directory"
    for directory in PRIVATE_DIRS:
        if path == directory or path.startswith(directory + "/"):
            return f"under {directory}/, which is never shipped"
    return None


def select_app_files(tracked: list[str]) -> list[str]:
    """The application tree, from the checkout's tracked files: an allowlist of places, then a refusal of anything
    private that an allowlisted place turns out to hold. Files outside the allowlist are simply not taken."""
    chosen = sorted(path for path in set(tracked) if path in APP_FILES or path.startswith(APP_DIRS))
    for path in chosen:
        if not SAFE_PATH.fullmatch(path):
            raise BundleError(f"refusing to bundle {path!r}: file names may hold only letters, digits and ._+-")
        reason = private_reason(path)
        if reason:
            raise BundleError(f"refusing to bundle {path}: {reason}")
    missing = [path for path in REQUIRED_APP_FILES if path not in chosen]
    if missing:
        raise BundleError(f"the checkout is missing files the bundle needs: {', '.join(missing)}")
    return chosen


@dataclass(frozen=True)
class Project:
    version: str
    runtime: tuple[str, ...]
    extras: dict[str, tuple[str, ...]]
    build: tuple[str, ...]
    force_include: dict[str, str]


def read_project(root: Path) -> Project:
    document = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project, build = document["project"], document.get("build-system", {})
    backend_extra = EDITABLE_BACKEND_REQUIRES.get(build.get("build-backend", ""), ())
    wheel = document.get("tool", {}).get("hatch", {}).get("build", {}).get("targets", {}).get("wheel", {})
    return Project(version=str(project["version"]), runtime=tuple(project.get("dependencies", ())),
                   extras={name: tuple(reqs) for name, reqs in project.get("optional-dependencies", {}).items()},
                   build=(*build.get("requires", ()), *backend_extra),
                   force_include=dict(wheel.get("force-include", {})))


# ---------------------------------------------------------------------------------------------------------------
# wheels


def _packaging():
    """`packaging` when it is installed, else the copy pip carries: this script needs only the stdlib and pip."""
    try:
        from packaging import requirements, utils, version
    except ImportError:
        from pip._vendor.packaging import requirements, utils, version
    return requirements.Requirement, utils.canonicalize_name, version.Version


@dataclass(frozen=True)
class Wheel:
    file: str
    name: str            # canonical
    version: str
    requires: tuple[str, ...]
    tags: tuple[str, str, str] = field(default=("py3", "none", "any"))


def read_wheel(path: Path) -> Wheel:
    """A wheel's identity and requirements from its own metadata. Anything that is not a wheel is refused: a
    source distribution in the wheelhouse would have to be compiled on the disconnected host."""
    _, canonicalize, _ = _packaging()
    if path.suffix != ".whl":
        raise BundleError(f"{path.name} is not a binary wheel; the bundle carries wheels only")
    parts = path.name[:-4].split("-")
    if len(parts) not in (5, 6):
        raise BundleError(f"{path.name} is not a valid wheel file name")
    try:
        with zipfile.ZipFile(path) as archive:
            metadata = next(name for name in archive.namelist()
                            if name.count("/") == 1 and name.endswith(".dist-info/METADATA"))
            message = email.parser.Parser().parsestr(archive.read(metadata).decode("utf-8"))
    except (zipfile.BadZipFile, StopIteration, KeyError, UnicodeDecodeError) as error:
        raise BundleError(f"{path.name} is not a readable wheel: {error!r}") from error
    return Wheel(file=path.name, name=canonicalize(message["Name"]), version=str(message["Version"]),
                 requires=tuple(message.get_all("Requires-Dist") or ()), tags=tuple(parts[-3:]))


def wheel_fits(wheel: Wheel, target: Target) -> bool:
    """Whether the target interpreter can install this wheel, by its file name tags."""
    pythons, abi, platforms = (part.split(".") for part in wheel.tags)
    own = f"cp3{target.minor}"

    def python_ok(tag: str) -> bool:
        if tag in ("py3", own):
            return True
        match = re.fullmatch(r"(py|cp)3(\d+)", tag)
        if not match or int(match.group(2)) > target.minor:
            return False
        return match.group(1) == "py" or "abi3" in abi          # an older CPython tag is installable only as abi3

    def platform_ok(tag: str) -> bool:
        minor = _tag_glibc_minor(tag, target.arch)
        return tag == "any" or (minor is not None and minor <= target.glibc_minor)

    return (any(python_ok(tag) for tag in pythons) and any(tag in ("none", "abi3", own) for tag in abi)
            and any(platform_ok(tag) for tag in platforms))


def scan_wheelhouse(directory: Path, target: Target) -> dict[str, Wheel]:
    """Every wheel in a directory by canonical project name. Two versions of one project, a file that is not a
    wheel, or a wheel the target cannot install, is an error naming the file."""
    wheels: dict[str, Wheel] = {}
    for path in sorted(directory.iterdir()):
        if not path.is_file():
            raise BundleError(f"unexpected entry in the wheelhouse: {path.name}")
        wheel = read_wheel(path)
        if not wheel_fits(wheel, target):
            raise BundleError(f"{wheel.file} cannot be installed on {target.label}: no binary wheel of "
                              f"{wheel.name} for the target was found")
        if wheel.name in wheels:
            raise BundleError(f"two wheels for {wheel.name}: {wheels[wheel.name].file} and {wheel.file}")
        wheels[wheel.name] = wheel
    return wheels


def target_closure(roots: list[str], wheels: dict[str, Wheel], target: Target) -> tuple[set[str], list[str]]:
    """Walk the requirements from `roots` through the wheels' own metadata, judging every environment marker for
    the target. Returns the projects the target needs and, as requirement strings, what the wheelhouse lacks."""
    requirement_type, canonicalize, version_type = _packaging()
    environment = target.environment()
    needed: set[str] = set()
    missing: dict[str, None] = {}
    seen: set[tuple[str, str]] = set()
    queue = [(requirement_type(text), "", "the project") for text in roots]
    while queue:
        requirement, active_extra, parent = queue.pop()
        if requirement.marker is not None and not requirement.marker.evaluate({**environment,
                                                                               "extra": active_extra}):
            continue
        name = canonicalize(requirement.name)
        wheel = wheels.get(name)
        plain = f"{requirement.name}{requirement.specifier}"
        if wheel is None:
            missing[f"{plain} (needed by {parent})"] = None
            continue
        if not requirement.specifier.contains(version_type(wheel.version), prereleases=True):
            missing[f"{plain} (needed by {parent}; the wheelhouse has {wheel.version})"] = None
            continue
        needed.add(name)
        for extra in ("", *sorted(requirement.extras)):
            if (name, extra) in seen:
                continue
            seen.add((name, extra))
            queue.extend((requirement_type(text), extra, wheel.name) for text in wheel.requires)
    return needed, list(missing)


def _run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=False, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", **kwargs)


def pip_download(requirements: list[str], dest: Path, target: Target, *, run=_run, no_deps: bool = False,
                 constraints: Path | None = None) -> None:
    """Download binary wheels for the target interpreter and platform. A requirement with no such wheel fails
    here, by name: `--only-binary=:all:` never lets pip fall back to a source distribution."""
    command = [sys.executable, "-m", "pip", "download", "--disable-pip-version-check", "--no-input",
               "--only-binary=:all:", "--implementation", "cp", "--python-version", target.python,
               "--abi", target.abi]
    for tag in target.platform_tags:
        command += ["--platform", tag]
    if no_deps:
        command.append("--no-deps")
    if constraints is not None:
        command += ["--constraint", str(constraints)]
    command += ["--dest", str(dest), *requirements]
    result = run(command)
    if result.returncode != 0:
        output = f"{result.stdout or ''}\n{result.stderr or ''}"
        names = sorted({match.group(1) for match in PIP_MISSING.finditer(output)})
        tail = "\n".join(line for line in output.splitlines() if line.strip())[-1500:]
        if names:
            raise BundleError(f"no binary wheel for {target.label}: {', '.join(names)}. The bundle carries binary "
                              f"wheels only, so it was not built. pip reported:\n{tail}")
        raise BundleError(f"pip download failed (exit {result.returncode}):\n{tail}")


def collect_wheels(roots: list[str], dest: Path, target: Target, *, wheelhouse: Path | None = None,
                   constraints: Path | None = None, run=_run) -> tuple[list[Wheel], list[str]]:
    """Fill `dest` with exactly the wheels the target needs for `roots`. With a `wheelhouse` nothing is
    downloaded and a gap is an error; otherwise pip downloads, and anything pip left out because it judged a
    marker for the build machine is fetched by name. Returns the wheels kept and the file names left out."""
    dest.mkdir(parents=True, exist_ok=True)
    if wheelhouse is not None:
        for path in sorted(wheelhouse.iterdir()):
            if path.is_file():
                shutil.copyfile(path, dest / path.name)
    else:
        pip_download(roots, dest, target, run=run, constraints=constraints)
    for _ in range(8):
        wheels = scan_wheelhouse(dest, target)
        needed, missing = target_closure(roots, wheels, target)
        if not missing:
            break
        if wheelhouse is not None:
            raise BundleError(f"the wheelhouse lacks what {target.label} needs: {'; '.join(missing)}")
        pip_download([entry.split(" (", 1)[0] for entry in missing], dest, target, run=run, no_deps=True,
                     constraints=constraints)
    else:
        raise BundleError(f"dependencies for {target.label} did not resolve: {'; '.join(missing)}")
    dropped = sorted(wheel.file for name, wheel in wheels.items() if name not in needed)
    for file in dropped:
        (dest / file).unlink()
    return sorted((wheels[name] for name in needed), key=lambda wheel: wheel.file), dropped


# ---------------------------------------------------------------------------------------------------------------
# checksums and manifest


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bundle_files(directory: Path) -> list[str]:
    """Every file under a bundle directory as a sorted POSIX path. A symlink or special file is refused."""
    found = []
    for path in directory.rglob("*"):
        relative = path.relative_to(directory).as_posix()
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise BundleError(f"{relative} is not a regular file or directory")
        if path.is_file():
            if not SAFE_PATH.fullmatch(relative):
                raise BundleError(f"unsafe file name in the bundle: {relative!r}")
            found.append(relative)
    return sorted(found)


def write_manifest(directory: Path, header: dict) -> dict:
    """Write MANIFEST.json (the header plus every other file's SHA-256 and size) and SHA256SUMS (every file but
    itself, the manifest included, in `sha256sum -c` format)."""
    for name in (MANIFEST, CHECKSUMS):
        (directory / name).unlink(missing_ok=True)
    files = bundle_files(directory)
    entries = [{"path": path, "sha256": sha256_file(directory / path), "size": (directory / path).stat().st_size}
               for path in files]
    manifest = {**header, "format": FORMAT_VERSION, "files": entries}
    (directory / MANIFEST).write_bytes((json.dumps(manifest, indent=1, sort_keys=True) + "\n").encode("utf-8"))
    sums = {entry["path"]: entry["sha256"] for entry in entries} | {MANIFEST: sha256_file(directory / MANIFEST)}
    (directory / CHECKSUMS).write_bytes("".join(f"{sums[path]}  {path}\n" for path in sorted(sums)).encode("ascii"))
    return manifest


def verify_bundle(directory: Path) -> list[str]:
    """Every way an unpacked bundle disagrees with its SHA256SUMS and MANIFEST.json; empty when it verifies."""
    problems: list[str] = []
    sums_path = directory / CHECKSUMS
    if not sums_path.is_file():
        return [f"{CHECKSUMS} is missing"]
    listed: dict[str, str] = {}
    for number, line in enumerate(sums_path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  (\S+)", line)
        if not match or not SAFE_PATH.fullmatch(match.group(2)) or match.group(2) in listed:
            problems.append(f"{CHECKSUMS} line {number} is malformed")
            continue
        listed[match.group(2)] = match.group(1)
    try:
        present = [path for path in bundle_files(directory) if path != CHECKSUMS]
    except BundleError as error:
        return [*problems, str(error)]
    problems += [f"{path}: not listed in {CHECKSUMS}" for path in present if path not in listed]
    problems += [f"{path}: listed but missing" for path in listed if path not in present]
    problems += [f"{path}: SHA-256 mismatch" for path in present
                 if path in listed and sha256_file(directory / path) != listed[path]]
    if MANIFEST not in listed:
        problems.append(f"{MANIFEST} is not listed in {CHECKSUMS}")
    elif not problems:
        try:
            manifest = json.loads((directory / MANIFEST).read_text(encoding="utf-8"))
            recorded = {entry["path"]: (entry["sha256"], entry["size"]) for entry in manifest["files"]}
        except (ValueError, KeyError, TypeError) as error:
            return [f"{MANIFEST} is unreadable: {error!r}"]
        if manifest.get("format") != FORMAT_VERSION:
            problems.append(f"{MANIFEST}: bundle format {manifest.get('format')!r} is not {FORMAT_VERSION}")
        actual = {path: (listed[path], (directory / path).stat().st_size) for path in present if path != MANIFEST}
        if recorded != actual:
            problems.append(f"{MANIFEST} does not describe the files in the bundle")
    return problems


# ---------------------------------------------------------------------------------------------------------------
# archive


def write_archive(directory: Path, name: str, archive: Path, mtime: int) -> list[str]:
    """Pack a bundle directory as `<name>/...` in a gzip-compressed tar with a fixed member order, owner, modes and
    times, so the same inputs give the same bytes on any build machine. Returns the member names in order."""
    files = bundle_files(directory)
    directories = sorted({parent.as_posix() for path in files for parent in PurePosixPath(path).parents} - {"."})
    members = sorted([(path, False) for path in files] + [(path, True) for path in directories])
    names = []
    archive.parent.mkdir(parents=True, exist_ok=True)
    with archive.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed, \
            tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as tar:
        root = tarfile.TarInfo(name)
        root.type, root.mode, root.mtime = tarfile.DIRTYPE, 0o755, mtime
        tar.addfile(root)
        for path, is_directory in members:
            info = tarfile.TarInfo(f"{name}/{path}")
            info.mtime, info.uid, info.gid, info.uname, info.gname = mtime, 0, 0, "", ""
            names.append(info.name)
            if is_directory:
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                tar.addfile(info)
                continue
            info.mode = 0o755 if path.endswith(".sh") else 0o644
            info.size = (directory / path).stat().st_size
            with (directory / path).open("rb") as source:
                tar.addfile(info, source)
    return names


def unpack_archive(archive: Path, dest: Path) -> Path:
    """Unpack a bundle archive for verification and return its single top-level directory."""
    with tarfile.open(archive, mode="r:gz") as tar:
        tar.extractall(dest, filter="data")
    tops = [path for path in dest.iterdir()]
    if len(tops) != 1 or not tops[0].is_dir():
        raise BundleError(f"{archive.name} does not hold a single bundle directory")
    return tops[0]


# ---------------------------------------------------------------------------------------------------------------
# build


def git(root: Path, *arguments: str) -> str:
    result = _run(["git", "-C", str(root), *arguments])
    if result.returncode != 0:
        raise BundleError(f"git {' '.join(arguments)} failed: {result.stderr.strip() or result.stdout.strip()}"
                          " (the bundle is built from a git checkout)")
    return result.stdout


def stage_app(root: Path, files: list[str], app: Path) -> None:
    """Copy the application tree. Shell scripts are written with LF line endings whatever the checkout has."""
    for path in files:
        data = (root / path).read_bytes()
        if path.endswith(".sh"):
            data = data.replace(b"\r\n", b"\n")
        target = app / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def check_offline_build(app: Path, wheels: Path, project: Project, scratch: Path, *, run=_run) -> dict:
    """Prove, with no index, that the wheelhouse can build the project: build its wheel and check that every
    package file and every force-included file is in it, then resolve the editable install the host will run."""
    # the build machine's interpreter stands in for the host's here, so its version is not held against the project
    offline = ["--disable-pip-version-check", "--no-input", "--no-index", "--no-cache-dir", "--find-links",
               str(wheels), "--no-deps", "--ignore-requires-python"]
    out = scratch / "project-wheel"
    built = run([sys.executable, "-m", "pip", "wheel", *offline, "--wheel-dir", str(out), str(app)])
    produced = sorted(out.glob("*.whl")) if out.is_dir() else []
    if built.returncode != 0 or len(produced) != 1:
        raise BundleError("the project wheel does not build offline from the bundle's wheelhouse:\n"
                          + f"{built.stdout}\n{built.stderr}"[-2000:])
    with zipfile.ZipFile(produced[0]) as archive:
        inside = set(archive.namelist())
    expected = {path.relative_to(app / "src").as_posix() for path in (app / "src").rglob("*") if path.is_file()}
    for source, destination in project.force_include.items():
        base = app / source
        expected |= ({f"{destination}/{path.relative_to(base).as_posix()}" for path in base.rglob("*")
                      if path.is_file()} if base.is_dir() else {destination})
    absent = sorted(expected - inside)
    if absent:
        raise BundleError(f"the built wheel lacks {len(absent)} file(s), e.g. {', '.join(absent[:5])}")
    editable = run([sys.executable, "-m", "pip", "install", *offline, "--dry-run", "--editable", str(app)])
    if editable.returncode != 0:
        raise BundleError("the editable install the host runs does not resolve offline from the bundle's "
                          "wheelhouse:\n" + f"{editable.stdout}\n{editable.stderr}"[-2000:])
    return {"file": produced[0].name, "files": len(inside)}


@dataclass(frozen=True)
class Bundle:
    archive: Path
    sha256: str
    size: int
    name: str
    manifest: dict
    members: list[str]
    dropped: list[str]


def build_bundle(*, root: Path = ROOT, out_dir: Path, target: Target, extras: tuple[str, ...] | None = None,
                 wheelhouse: Path | None = None, constraints: Path | None = None,
                 tracked: list[str] | None = None, commit: str | None = None,
                 mtime: int | None = None, check_build: bool = True, run=_run) -> Bundle:
    """Build the bundle archive and its `.sha256` side file under `out_dir`."""
    project = read_project(root)
    extras = tuple(sorted(project.extras)) if extras is None else tuple(extras)
    unknown = [extra for extra in extras if extra not in project.extras]
    if unknown:
        raise BundleError(f"pyproject.toml defines no extra named {', '.join(unknown)}")
    if tracked is None:
        tracked = [path for path in git(root, "ls-files", "-z").split("\0") if path]
    if commit is None:
        dirty = "+dirty" if git(root, "status", "--porcelain", "--untracked-files=no").strip() else ""
        commit = git(root, "rev-parse", "--short", "HEAD").strip() + dirty
    if mtime is None:
        mtime = int(os.environ.get("SOURCE_DATE_EPOCH") or git(root, "log", "-1", "--format=%ct").strip())
    if not SAFE_VALUE.fullmatch(commit) or not SAFE_VALUE.fullmatch(project.version):
        raise BundleError(f"unusable version or commit: {project.version!r} {commit!r}")
    files = select_app_files(tracked)
    installer = root / "scripts" / INSTALLER
    if not installer.is_file():
        raise BundleError(f"scripts/{INSTALLER} is missing from the checkout")

    name = (f"romulus-offline-{project.version}-{commit.replace('+', '-')}-{target.abi}-"
            f"manylinux_2_{target.glibc_minor}_{target.arch}")
    extra_requirements = [requirement for extra in extras for requirement in project.extras[extra]]
    roots = [*project.runtime, *extra_requirements, *project.build]
    with tempfile.TemporaryDirectory(prefix="romulus-bundle-") as scratch_name:
        scratch = Path(scratch_name)
        stage = scratch / name
        stage_app(root, files, stage / "app")
        (stage / INSTALLER).write_bytes(installer.read_bytes().replace(b"\r\n", b"\n"))
        wheels, dropped = collect_wheels(roots, stage / "wheels", target, wheelhouse=wheelhouse,
                                         constraints=constraints, run=run)
        (stage / "requirements").mkdir()
        (stage / "requirements" / "runtime.txt").write_bytes(("\n".join(project.runtime) + "\n").encode())
        (stage / "requirements" / "extras.txt").write_bytes(("\n".join(extra_requirements) + "\n").encode())
        (stage / "requirements" / "build.txt").write_bytes(("\n".join(project.build) + "\n").encode())
        facts = {"format": FORMAT_VERSION, "version": project.version, "commit": commit, "python": target.python,
                 "arch": target.arch, "glibc": target.glibc, "extras": ",".join(extras)}
        (stage / TARGET_FILE).write_bytes("".join(f"{key}={value}\n" for key, value in facts.items()).encode())
        project_wheel = (check_offline_build(stage / "app", stage / "wheels", project, scratch, run=run)
                         if check_build else None)
        expected = sorted([INSTALLER, TARGET_FILE, *(f"app/{path}" for path in files),
                           *(f"wheels/{wheel.file}" for wheel in wheels),
                           *(f"requirements/{part}.txt" for part in ("runtime", "extras", "build"))])
        if bundle_files(stage) != expected:
            stray = sorted(set(bundle_files(stage)) ^ set(expected))
            raise BundleError(f"the staged bundle does not hold exactly what was selected: {stray[:10]}")
        refused = [path for path in expected if private_reason(path.removeprefix("app/"))]
        if refused:
            raise BundleError(f"refusing to bundle private files: {refused[:10]}")
        manifest = write_manifest(stage, {
            "name": name, "romulus_version": project.version, "source_commit": commit, "source_commit_time": mtime,
            "target": {"implementation": "cpython", "python": target.python, "abi": target.abi,
                       "arch": target.arch, "glibc": target.glibc, "platform_tags": list(target.platform_tags)},
            "extras": list(extras),
            "install": "editable install of app/ from wheels/ (pip install --no-index --find-links wheels -e app)",
            "requirements": {"runtime": list(project.runtime), "extras": extra_requirements,
                             "build": list(project.build)},
            "wheels": [{"file": wheel.file, "name": wheel.name, "version": wheel.version} for wheel in wheels],
            "project_wheel_check": project_wheel,
        })
        problems = verify_bundle(stage)
        if problems:
            raise BundleError(f"the bundle does not verify: {problems[:10]}")
        archive = out_dir / f"{name}.tar.gz"
        members = write_archive(stage, name, archive, mtime)
    digest = sha256_file(archive)
    Path(f"{archive}.sha256").write_bytes(f"{digest}  {archive.name}\n".encode("ascii"))
    return Bundle(archive=archive, sha256=digest, size=archive.stat().st_size, name=name, manifest=manifest,
                  members=members, dropped=dropped)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build (or verify) the ROMULUS offline install bundle.")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "build" / "offline-bundle",
                        help="where the archive is written (default: build/offline-bundle, which git ignores)")
    parser.add_argument("--python-version", default="3.12", help="the target host's CPython, e.g. 3.12")
    parser.add_argument("--arch", default="x86_64", help="the target host's architecture: x86_64 or aarch64")
    parser.add_argument("--glibc", default="2.28", help="the oldest glibc the bundle must run on (default 2.28)")
    parser.add_argument("--platform", action="append", default=[], metavar="TAG",
                        help="an explicit manylinux platform tag (repeatable); replaces --arch and --glibc")
    parser.add_argument("--extras", default=None, help="comma-separated extras to carry (default: all defined)")
    parser.add_argument("--no-extras", action="store_true", help="carry the runtime dependencies only")
    parser.add_argument("--wheelhouse", type=Path, default=None,
                        help="take the wheels from this directory and download nothing")
    parser.add_argument("--constraint", type=Path, default=None, metavar="FILE",
                        help="a pip constraints file, to pin the dependency versions the bundle carries")
    parser.add_argument("--skip-build-check", action="store_true",
                        help="do not prove the offline build from the wheelhouse on this machine")
    parser.add_argument("--verify", type=Path, default=None, metavar="PATH",
                        help="verify a bundle archive or an unpacked bundle directory, then exit")
    options = parser.parse_args(argv)
    try:
        if options.verify is not None:
            with tempfile.TemporaryDirectory(prefix="romulus-verify-") as scratch:
                directory = (options.verify if options.verify.is_dir()
                             else unpack_archive(options.verify, Path(scratch)))
                problems = verify_bundle(directory)
            for problem in problems:
                print(f"FAIL {problem}")
            print("bundle verifies" if not problems else f"bundle does NOT verify ({len(problems)} problem(s))")
            return 1 if problems else 0
        target = (Target.from_platforms(options.python_version, options.platform) if options.platform
                  else Target(python=options.python_version, arch=options.arch, glibc=options.glibc))
        extras = () if options.no_extras else (None if options.extras is None else
                                               tuple(part for part in options.extras.split(",") if part))
        bundle = build_bundle(out_dir=options.out_dir, target=target, extras=extras,
                              wheelhouse=options.wheelhouse, constraints=options.constraint,
                              check_build=not options.skip_build_check)
    except BundleError as error:
        print(f"build_offline_bundle: {error}", file=sys.stderr)
        return 1
    manifest = bundle.manifest
    print(f"bundle   {bundle.archive}")
    print(f"size     {bundle.size} bytes ({bundle.size / 2**20:.1f} MiB)")
    print(f"sha256   {bundle.sha256}")
    print(f"target   {target.label}; extras: {', '.join(manifest['extras']) or 'none'}")
    print(f"contents {len(manifest['files'])} files, {len(manifest['wheels'])} wheels, "
          f"ROMULUS {manifest['romulus_version']} at {manifest['source_commit']}")
    if bundle.dropped:
        print(f"left out {len(bundle.dropped)} wheel(s) the target does not need: {', '.join(bundle.dropped)}")
    print(f"Carry the archive and {bundle.archive.name}.sha256 across, check the SHA-256 there, unpack, and run "
          f"`sh {INSTALLER} <romulus-home>`.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
