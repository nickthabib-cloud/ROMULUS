#!/usr/bin/env python3
"""Check that an installed ROMULUS finds everything it ships with.

    <romulus-home>/venv/bin/python <romulus-home>/app/scripts/install_check.py [--app <dir>] [--extra anthropic]

It loads the shipped files the way a hunt, a report and the web UI do: the agent prompts, the mention patterns, the
ATT&CK data, the indicator lists, the network catalogs, the rule tags, the database migrations and the web
templates. An install that imports cleanly can still be missing some of these, and a missing indicator list is
silent (the hunt simply matches nothing), so the offline installer runs this before it calls an install good.

It reads no settings, opens no database and makes no network connection. Exit status 0 means every check passed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _package_location(app: str | None) -> str:
    import romulus

    where = Path(romulus.__file__).resolve().parent
    if app and not where.is_relative_to(Path(app).resolve()):
        raise RuntimeError(f"romulus is imported from {where}, not from {app}")
    return str(where)


def _cli() -> str:
    from romulus.cli import main

    return f"entry point {main.__module__}.{main.__name__}"


def _prompts() -> str:
    from importlib.resources import files

    prompts = [entry for entry in files("romulus.agent").joinpath("prompts").iterdir() if entry.name.endswith(".md")]
    if not prompts or not all(entry.read_text(encoding="utf-8").strip() for entry in prompts):
        raise RuntimeError("the agent prompts are missing or empty")
    return f"{len(prompts)} prompts"


def _mentions() -> str:
    from romulus.content.mention_patterns import load_mention_patterns

    patterns = load_mention_patterns()
    if not patterns.patterns:
        raise RuntimeError(f"no mention patterns in {patterns.directory}")
    return f"{len(patterns.patterns)} patterns in {len(patterns.files)} files"


def _attack() -> str:
    from romulus.catalog.attack import ICS_ATTACK_BUNDLE, ICS_PINNED_JSON_SHA256, load_attack_bundle

    enterprise = load_attack_bundle()
    ics = load_attack_bundle(ICS_ATTACK_BUNDLE, expected_sha256=ICS_PINNED_JSON_SHA256)
    if not enterprise.techniques or not ics.techniques:
        raise RuntimeError("an ATT&CK bundle holds no techniques")
    return f"{len(enterprise.techniques)} Enterprise and {len(ics.techniques)} ICS techniques"


def _indicators() -> str:
    from romulus.detect.indicators import indicator_dir, load_indicators

    loaded = load_indicators()
    if not loaded.indicators:
        raise RuntimeError(f"no indicators in {indicator_dir()}")
    return f"{len(loaded.indicators)} indicators in {len(loaded.files)} files"


def _network_catalogs() -> str:
    from romulus.detect.service_catalog import load_catalog
    from romulus.detect.smb_impact import note_names

    load_catalog()
    names, patterns = note_names()
    if not names:
        raise RuntimeError("the ransom-note catalog is empty")
    return f"service catalog loaded; {len(names)} note names and {len(patterns)} note patterns"


def _rule_tags() -> str:
    from romulus.catalog.browser import load_tags

    load_tags()
    return "rule tags loaded"


def _migrations() -> str:
    from romulus.store import db

    versions = [path for path in (Path(db.__file__).resolve().parent / "migrations" / "versions").glob("*.py")]
    if not versions:
        raise RuntimeError("no database migrations beside romulus.store")
    return f"{len(versions)} migrations"


def _web() -> str:
    import romulus.web.app as web

    here = Path(web.__file__).resolve().parent
    templates, static = list((here / "templates").rglob("*.html")), list((here / "static").iterdir())
    if not callable(web.create_app) or not templates or not static:
        raise RuntimeError("the web app factory, its templates or its static files are missing")
    return f"app factory, {len(templates)} templates, {len(static)} static files"


def _anthropic() -> str:
    import anthropic

    import romulus.agent.provider.claude_messages  # noqa: F401
    from romulus.agent.provider import sdk_installed

    if not sdk_installed():
        raise RuntimeError("the anthropic provider reports its SDK as not installed")
    return f"anthropic SDK {anthropic.__version__} and the provider module import"


EXTRAS = {"anthropic": _anthropic}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check that an installed ROMULUS finds everything it ships with.")
    parser.add_argument("--app", default=None, help="the application tree romulus must be imported from")
    parser.add_argument("--extra", action="append", default=[],
                        help="also check an installed optional dependency group, e.g. anthropic (repeatable)")
    options = parser.parse_args(argv)
    checks = [("package", lambda: _package_location(options.app)), ("cli", _cli), ("prompts", _prompts),
              ("mentions", _mentions), ("attack", _attack), ("indicators", _indicators),
              ("network", _network_catalogs), ("rule_tags", _rule_tags), ("migrations", _migrations),
              ("web", _web), *((f"extra[{extra}]", EXTRAS.get(extra, lambda: "no check is defined for this group"))
                for extra in options.extra)]
    failed = 0
    for name, check in checks:
        try:
            print(f"[OK  ] {name}: {check()}")
        except Exception as error:  # noqa: BLE001 - every failure is reported; one never hides the next
            failed += 1
            print(f"[FAIL] {name}: {type(error).__name__}: {error}")
    print("install check passed" if not failed else f"install check FAILED ({failed} of {len(checks)})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
