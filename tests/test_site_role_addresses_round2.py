"""Canonical address roles, strict ranges, and visible broad-prefix warnings."""
import pytest

from romulus.config import Settings
from romulus.detect.site_roles import address_member
from romulus.doctor import check_site
from romulus.site import (
    COLLECTION_SCHEMA,
    SiteValidationError,
    ensure_site_unchanged,
    load_site_facts,
    save_site_facts,
    validate_site_content,
)
from romulus.web import site_form
from tests import test_web_site_setup as site_support

site = site_support.site
FIELDS = ("domain_controller_addresses", "directory_sync_addresses", "management_hosts")


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("value,canonical", [
    ("::ffff:10.0.0.8", "10.0.0.8"),
    ("::ffff:a00:8/128", "10.0.0.8"),
    ("10.0.0.8/32", "10.0.0.8"),
    ("2001:0db8::1/128", "2001:db8::1"),
    ("::ffff:10.0.0.0/120", "10.0.0.0/24"),
    ("::ffff:0:0/96", "0.0.0.0/0"),
    ("::fffe:0:0/95", "::fffe:0:0/95"),
])
def test_role_address_aliases_have_one_frozen_canonical_identity(field, value, canonical, tmp_path):
    original = validate_site_content({"schema": COLLECTION_SCHEMA, field: [canonical]})
    facts = validate_site_content({"schema": COLLECTION_SCHEMA, field: [value]})
    assert getattr(facts, field) == (canonical,)
    assert facts.digest == original.digest
    _, saved = save_site_facts(tmp_path, facts.content, "")
    assert ensure_site_unchanged(tmp_path, saved.manifest_entry()) == facts


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("aliases", [
    ["10.0.0.8", "10.0.0.8/32"], ["10.0.0.8", "::ffff:10.0.0.8"],
    ["2001:db8::1", "2001:db8::1/128"],
    ["10.0.0.0/24", "::ffff:10.0.0.0/120"],
])
def test_equivalent_role_entries_are_duplicate_errors(field, aliases):
    with pytest.raises(SiteValidationError, match="duplicates"):
        validate_site_content({"schema": COLLECTION_SCHEMA, field: aliases})


@pytest.mark.parametrize("peer,declared,want", [
    ("10.0.0.8", "::ffff:10.0.0.8", True),
    ("::ffff:10.0.0.8", "10.0.0.8", True),
    ("10.0.0.8", "::ffff:10.0.0.0/120", True),
    ("::ffff:10.0.0.8", "10.0.0.0/24", True),
    ("10.0.1.8", "::ffff:10.0.0.0/120", False),
    ("::ffff:10.0.1.8", "10.0.0.0/24", False),
    ("2001:db8::8", "::ffff:10.0.0.0/120", False),
    ("10.0.0.8", "2001:db8::/64", False),
    ("10.0.0.8", "::ffff:10.0.0.5/120", False),
])
def test_mapped_role_declarations_and_peers_match_in_both_directions(peer, declared, want):
    assert address_member(peer, (declared,)) is want


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("value", ["10.0.0.5/24", "::ffff:10.0.0.5/120", "2001:db8::1/64"])
def test_host_bits_never_broaden_a_role_and_errors_explain_address_validation(field, value):
    with pytest.raises(SiteValidationError) as raised:
        validate_site_content({"schema": COLLECTION_SCHEMA, field: [value]})
    message = str(raised.value)
    assert field in message and "CIDR" in message and "host bits" in message
    assert "host names, not globs" not in message


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("value,broad", [
    ("10.0.0.0/23", True), ("10.0.0.0/24", False),
    ("2001:db8::/63", True), ("2001:db8::/64", False),
    ("::ffff:10.0.0.0/119", True), ("::ffff:10.0.0.0/120", False),
])
def test_broad_role_prefix_boundaries_warn_in_form_and_doctor(field, value, broad, tmp_path):
    _, facts = save_site_facts(tmp_path, {"schema": COLLECTION_SCHEMA, field: [value]}, "")
    warnings = site_form.view(facts.content)["role_address_warnings"]
    assert bool(warnings) is broad
    check = check_site(Settings(home=tmp_path))
    assert check.status == ("warn" if broad else "ok")
    assert check.data["warnings"] == warnings
    if broad:
        assert "broad" in check.detail.lower() and getattr(facts, field)[0] in check.detail
    assert load_site_facts(tmp_path) == facts


def test_warning_projection_keeps_omitted_and_empty_declarations_distinct():
    omitted = validate_site_content({"schema": COLLECTION_SCHEMA})
    empty = validate_site_content({"schema": COLLECTION_SCHEMA, **{field: [] for field in FIELDS}})
    assert omitted.digest != empty.digest
    for facts in (omitted, empty):
        before = facts.manifest_entry()
        assert site_form.view(facts.content)["role_address_warnings"] == []
        assert facts.manifest_entry() == before


def test_actual_site_page_shows_accepted_broad_role_warnings(site):
    settings, _, login = site
    content = {"schema": COLLECTION_SCHEMA, "management_hosts": ["10.2.0.0/23"],
               "domain_controller_addresses": ["10.0.0.0/23"],
               "directory_sync_addresses": ["2001:db8::/63"]}
    _, facts = save_site_facts(settings.home, content, "")
    response = login("lead1").get("/site")
    assert response.status_code == 200
    assert 'class="warn"' in response.text
    assert "broad" in response.text.lower()
    for value in ("10.2.0.0/23", "10.0.0.0/23", "2001:db8::/63"):
        assert value in response.text
    for warning in site_form.view(facts.content)["role_address_warnings"]:
        assert warning in response.text
    assert load_site_facts(settings.home) == facts


def test_rejected_site_form_escapes_input_and_keeps_broad_prefix_warning(site):
    settings, _, login = site
    client = login("lead1")
    page = client.get("/site")
    malicious = '<script>alert("test")</script>'
    response = client.post("/site", data={
        "csrf": site_support._csrf(page.text), "digest": site_support._digest(page.text),
        "group_count": "0", "management_hosts": "10.0.0.5/24\n" + malicious,
        "domain_controller_addresses": "10.0.0.0/23",
    })
    assert response.status_code == 400
    assert malicious not in response.text and "&lt;script&gt;" in response.text
    assert "host bits" in response.text and "broad" in response.text.lower()
    assert not load_site_facts(settings.home).present
