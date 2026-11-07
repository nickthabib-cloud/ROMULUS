"""ATT&CK for ICS mappings use the pinned ICS bundle, including retirement checks."""
import importlib.util
from pathlib import Path

import pytest

from romulus.catalog import build_catalog
from romulus.catalog.attack import ICS_ATTACK_BUNDLE, ICS_PINNED_JSON_SHA256, load_attack_bundle
from romulus.catalog.render import render_public
from romulus.detect.ics import RULES, WriteOrControlCommand


def test_ics_rules_validate_against_the_pinned_ics_domain():
    catalog=build_catalog(playbooks=RULES,strict=True)
    assert not catalog.invalid_attack_ids
    ics=load_attack_bundle(ICS_ATTACK_BUNDLE,expected_sha256=ICS_PINNED_JSON_SHA256)
    assert all(ics.technique(technique).revoked is False for cls in RULES for technique in cls.attack)
    text=render_public(catalog)
    assert '[ics.write_or_control_command]' in text


@pytest.mark.parametrize('technique,reason',[('T0855','revoked'),('T9999','unknown')])
def test_ics_unknown_and_revoked_ids_fail_the_real_catalog_check(technique,reason):
    class Bad(WriteOrControlCommand):
        id='ics.invalid_example'
        attack=(technique,)
    with pytest.raises(ValueError,match=reason):
        build_catalog(playbooks=[Bad],strict=True)


def test_public_matrix_includes_live_ics_coverage_and_generator_rejects_invalid(monkeypatch):
    text=render_public(build_catalog())
    assert 'ATT&CK for ICS 20.0' in text
    assert 'T1692.001' in text and 'ics.write_or_control_command' in text
    script=Path(__file__).resolve().parents[1]/'scripts/coverage_matrix.py'
    spec=importlib.util.spec_from_file_location('ics_coverage_script',script)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    class Bad(WriteOrControlCommand):
        id='ics.invalid_example'
        attack=('T0855',)
    bad=build_catalog(playbooks=[Bad])
    monkeypatch.setattr(module,'build_catalog',lambda:bad)
    assert module.main(['--check'])==1
