"""Site directory role fields survive actual browser form data and validation."""

import pytest
from starlette.datastructures import FormData

from romulus.site import (
    COLLECTION_SCHEMA,
    SiteValidationError,
    load_site_facts,
    save_site_facts,
    validate_site_content,
)
from romulus.web import site_form

FIELDS = ("management_hosts", "domain_controller_addresses", "directory_sync_hosts", "directory_sync_addresses")
LABELS = ("management hosts", "domain controller addresses", "directory sync hosts", "directory sync addresses")
VALUES = (["sccm.example.test", "10.2.0.0/16"], ["10.0.0.1", "2001:db8::/64"],
          ["sync01.example.test"], ["10.0.0.2", "2001:db8:1::/64"])


def form_for(content, **overrides):
    shown = site_form.view(content)
    values = {"group_count": "0", "domain_controllers": shown["domain_controllers"],
              "directory_sync_accounts": shown["directory_sync_accounts"],
              "internal_networks": shown["internal_networks"], "external_networks": shown["external_networks"]}
    for field in FIELDS:
        values[field] = shown[field]
        if shown[field + "_declared"]:
            values[field + "_declared"] = "1"
    if shown["directory_sync_accounts_declared"]:
        values["directory_sync_accounts_declared"] = "1"
    values.update(overrides)
    return FormData(list(values.items()))


def test_all_directory_role_lists_roundtrip_through_form_save_and_reload(tmp_path):
    original = validate_site_content({"schema": COLLECTION_SCHEMA,
                                     "domain_controllers": ["dc01.example.test"],
                                     **dict(zip(FIELDS, VALUES, strict=True))})
    submitted = form_for(original.content)
    assert isinstance(submitted, FormData)
    after = validate_site_content(site_form.parse_form(submitted))
    assert after.content == original.content and after.digest == original.digest
    assert site_form.describe_change(original.content, after.content) == []
    _, saved = save_site_facts(tmp_path, after.content, "")
    assert load_site_facts(tmp_path) == saved == original


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("declared", [False, True])
def test_optional_role_lists_keep_omitted_and_declared_empty_states(field, declared):
    content = {"schema": COLLECTION_SCHEMA}
    if declared:
        content[field] = []
    original = validate_site_content(content)
    after = validate_site_content(site_form.parse_form(form_for(original.content)))
    assert after.digest == original.digest
    assert (field in after.content) is declared


@pytest.mark.parametrize("field,label,values", tuple(zip(FIELDS, LABELS, VALUES, strict=True)))
def test_edited_role_values_get_precise_change_labels_and_empty_clears_are_retained(field, label, values):
    before = validate_site_content({"schema": COLLECTION_SCHEMA, field: values})
    cleared = validate_site_content(site_form.parse_form(form_for(before.content, **{field: ""})))
    assert cleared.content[field] == []
    assert site_form.describe_change(before.content, cleared.content) == [label]
    assert site_form.describe_change(cleared.content, before.content) == [label]


@pytest.mark.parametrize("field,label", tuple(zip(FIELDS, LABELS, strict=True)))
def test_presence_only_declaration_changes_are_named(field, label):
    before = validate_site_content({"schema": COLLECTION_SCHEMA})
    after = validate_site_content(site_form.parse_form(FormData([
        ("group_count", "0"), (field, ""), (field + "_declared", "1"),
    ])))
    assert after.content[field] == []
    assert before.digest != after.digest
    assert site_form.describe_change(before.content, after.content) == [label]
    assert site_form.describe_change(after.content, before.content) == [label]


def test_role_form_text_splits_lines_and_canonicalizes_only_through_public_validation():
    submitted = FormData([
        ("group_count", "0"), ("management_hosts", "  SCCM.EXAMPLE.TEST.\r\n10.2.0.0/16\n"),
        ("domain_controller_addresses", "10.0.0.1\n2001:0db8::/64"),
        ("directory_sync_hosts", " SYNC01.EXAMPLE.TEST. "),
        ("directory_sync_addresses", "10.0.0.2\n2001:db8:1::/64"),
    ])
    after = validate_site_content(site_form.parse_form(submitted))
    assert after.management_hosts == ("sccm.example.test", "10.2.0.0/16")
    assert after.domain_controller_addresses == ("10.0.0.1", "2001:db8::/64")
    assert after.directory_sync_hosts == ("sync01.example.test",)
    assert after.directory_sync_addresses == ("10.0.0.2", "2001:db8:1::/64")


@pytest.mark.parametrize("address", ["10.0.0.1", "2001:db8::1", "10.0.0.0/24"])
def test_dc_ip_in_host_name_form_field_gets_address_field_guidance(address):
    submitted = FormData([("group_count", "0"), ("domain_controllers", address)])
    with pytest.raises(SiteValidationError, match="domain_controller_addresses"):
        validate_site_content(site_form.parse_form(submitted))


def test_no_new_empty_textarea_attests_an_undeclared_list():
    content = site_form.parse_form(FormData([("group_count", "0"), *[(field, "") for field in FIELDS]]))
    assert all(field not in content for field in FIELDS)
