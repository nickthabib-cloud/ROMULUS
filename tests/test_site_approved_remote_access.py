"""Declared service IDs are immutable site facts, never suppression policy."""
import pytest

from romulus.site import (
    COLLECTION_SCHEMA,
    SiteValidationError,
    absent_site_facts,
    load_site_facts,
    save_site_facts,
    validate_site_content,
)


def test_approved_services_are_canonical_and_survive_save(tmp_path):
    facts = validate_site_content({"schema": COLLECTION_SCHEMA, "approved_remote_access": ["TeamViewer", "anydesk"]})
    assert facts.approved_remote_access == ("anydesk", "teamviewer")
    _, saved = save_site_facts(tmp_path, facts.content, "")
    assert load_site_facts(tmp_path).approved_remote_access == facts.approved_remote_access
    assert saved.digest == facts.digest


def test_omission_preserves_old_site_digest_and_empty_is_explicit():
    base = validate_site_content({"schema": COLLECTION_SCHEMA})
    assert base.approved_remote_access == () == absent_site_facts().approved_remote_access
    assert "approved_remote_access" not in base.content
    assert validate_site_content(base.content).digest == base.digest
    explicit = validate_site_content({"schema": COLLECTION_SCHEMA, "approved_remote_access": []})
    assert explicit.content["approved_remote_access"] == []
    assert explicit.digest != base.digest


@pytest.mark.parametrize("values", ["anydesk", None, [123], [True], ["anydesk", "ANYDESK"], [""],
                                     ["anydesk.com"], ["../anydesk"], ["*"], [" atera"], ["átera"],
                                     ["a" * 65], ["a"] * 1001])
def test_ambiguous_or_unbounded_approvals_are_rejected(values):
    with pytest.raises(SiteValidationError):
        validate_site_content({"schema": COLLECTION_SCHEMA, "approved_remote_access": values})
