"""Explicit directory roles keep host names separate from network addresses."""

from dataclasses import FrozenInstanceError

import pytest

from romulus.site import (
    COLLECTION_SCHEMA,
    SiteFacts,
    SiteValidationError,
    ensure_site_unchanged,
    load_site_facts,
    save_site_facts,
    validate_site_content,
)

FIELDS = ("management_hosts", "domain_controller_addresses", "directory_sync_hosts", "directory_sync_addresses")


def test_directory_roles_roundtrip_as_frozen_facts_with_canonical_addresses(tmp_path):
    content = {
        "schema": COLLECTION_SCHEMA,
        "management_hosts": [" SCCM.EXAMPLE.TEST. ", "10.0.0.8", "2001:0db8::1", "10.2.0.0/16"],
        "domain_controllers": [" DC01.EXAMPLE.TEST. "],
        "domain_controller_addresses": ["10.0.0.1", "2001:0db8::/64"],
        "directory_sync_hosts": [" SYNC01.EXAMPLE.TEST. "],
        "directory_sync_addresses": ["10.0.0.2", "2001:db8:1::/64"],
    }
    before, saved = save_site_facts(tmp_path, content, "")
    assert before.present is False
    assert saved.management_hosts == ("sccm.example.test", "10.0.0.8", "2001:db8::1", "10.2.0.0/16")
    assert saved.domain_controller_addresses == ("10.0.0.1", "2001:db8::/64")
    assert saved.directory_sync_hosts == ("sync01.example.test",)
    assert saved.directory_sync_addresses == ("10.0.0.2", "2001:db8:1::/64")
    assert saved.domain_controllers == ("dc01.example.test",)
    assert load_site_facts(tmp_path) == saved
    assert validate_site_content(saved.content) == saved
    assert ensure_site_unchanged(tmp_path, saved.manifest_entry()) == saved
    with pytest.raises(FrozenInstanceError):
        saved.directory_sync_hosts = ()
    changed = dict(content, directory_sync_addresses=["10.0.0.3"])
    _, after = save_site_facts(tmp_path, changed, saved.digest)
    assert after.digest != saved.digest
    assert saved.directory_sync_addresses == ("10.0.0.2", "2001:db8:1::/64")


def test_new_declarations_preserve_omitted_and_explicitly_empty_lists(tmp_path):
    absent = load_site_facts(tmp_path)
    legacy = SiteFacts(False, "", {}, (), (), (), (), ())
    assert absent == legacy
    omitted = validate_site_content({"schema": COLLECTION_SCHEMA})
    for field in FIELDS:
        assert getattr(omitted, field) == ()
        assert field not in omitted.content
    explicit = validate_site_content({"schema": COLLECTION_SCHEMA, **{field: [] for field in FIELDS}})
    for field in FIELDS:
        assert explicit.content[field] == []
    assert explicit.digest != omitted.digest
    assert "directory_sync_accounts" not in explicit.content
    _, saved = save_site_facts(tmp_path, explicit.content, "")
    assert saved == explicit


@pytest.mark.parametrize("field,guidance", [
    ("domain_controllers", "domain_controller_addresses"),
    ("directory_sync_hosts", "directory_sync_addresses"),
])
@pytest.mark.parametrize("address", ["10.0.0.1", "2001:db8::1", "10.0.0.0/24", "2001:db8::/64"])
def test_host_only_roles_reject_addresses_with_field_guidance(field, guidance, address):
    with pytest.raises(SiteValidationError, match=guidance):
        validate_site_content({"schema": COLLECTION_SCHEMA, field: [address]})


@pytest.mark.parametrize("field", ["domain_controller_addresses", "directory_sync_addresses"])
@pytest.mark.parametrize("value", ["dc01.example.test", "10.0.0.999", "10.0.0.1/99", "10.0.0.1/24",
                                  "2001:db8::/129", "fe80::1%eth0", "*", "", 123, None])
def test_address_declarations_reject_malformed_or_ambiguous_entries(field, value):
    with pytest.raises(SiteValidationError, match=field):
        validate_site_content({"schema": COLLECTION_SCHEMA, field: [value]})


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("value", ["dc01", None, {"host": "dc01"}])
def test_role_lists_require_lists(field, value):
    with pytest.raises(SiteValidationError, match=field):
        validate_site_content({"schema": COLLECTION_SCHEMA, field: value})


@pytest.mark.parametrize("field,values", [
    ("domain_controller_addresses", ["2001:db8::1", "2001:0db8::1"]),
    ("directory_sync_addresses", ["10.0.0.0/24", "10.0.0.0/24"]),
    ("directory_sync_hosts", ["SYNC01", "sync01."]),
    ("management_hosts", ["SCCM", "sccm."]),
])
def test_role_lists_reject_canonical_duplicates(field, values):
    with pytest.raises(SiteValidationError, match="duplicates"):
        validate_site_content({"schema": COLLECTION_SCHEMA, field: values})


@pytest.mark.parametrize("value", ["dc-*", "../host", ".dc01", "dc..example", "10.0.0.999", "fe80::1%eth0"])
def test_management_entries_require_exact_names_or_valid_addresses(value):
    with pytest.raises(SiteValidationError, match="management_hosts"):
        validate_site_content({"schema": COLLECTION_SCHEMA, "management_hosts": [value]})


@pytest.mark.parametrize("body", [b"\xff", b'schema: romulus-site-collection@1\n? [a, b]\n: value\n',
                                  b'schema: romulus-site-collection@1\nmanagement_hosts: ["\\ud800"]\n'])
def test_loading_invalid_bytes_yaml_keys_or_unicode_names_raises_site_error(tmp_path, body):
    path = tmp_path / "site" / "collection.yaml"
    path.parent.mkdir()
    path.write_bytes(body)
    with pytest.raises(SiteValidationError):
        load_site_facts(tmp_path)
