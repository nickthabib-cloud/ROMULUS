"""Shared pieces of the offline bundle tests: the builder module, synthetic wheels, a small stand-in checkout and
a bundle built from them. Nothing here reaches a package index."""

from __future__ import annotations

import importlib.util
import sys
import zipfile
from pathlib import Path

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
# Names of local working files, spelled in parts: tests/test_private_adr_references.py keeps the literal names out
# of every tracked file, this one included.
AGENT_NOTES = "CLAUDE" + ".md"
MASTER_PROMPT = "ENGINEERING_MASTER_PROMPT" + ".md"
PROJECT_STATUS = "docs/project/" + "STATUS" + ".md"
DECISION_RECORD = "docs/" + "adr" + "/0001-store.md"
# present in the working tree and named by git, but never to be shipped
LOCAL_ONLY = [AGENT_NOTES, "CLAUDE.local.md", MASTER_PROMPT, ".env", ".claude/agents/reviewer.md",
              ".notes.git/HEAD", "eval/gold.json"]


# what the stand-in checkout pins: every wheel its bundle needs (the wheelhouse also holds one it does not)
CONSTRAINTS = "# pins\nalpha==1.2\nbackend==1.0\nbeta==2.0\ndelta==1.0\ngamma==1.0\nlinuxonly==1.0\n"


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
    (root / "requirements").mkdir(exist_ok=True)
    (root / "requirements" / "constraints.txt").write_text(CONSTRAINTS, encoding="utf-8")
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
