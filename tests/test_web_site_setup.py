"""Site setup page: lead-only editing of the site file, validated, concurrency-checked and audited; the form maps
the file losslessly; the internal-network definition is read from exactly one place."""
from __future__ import annotations

import re
import secrets
from ipaddress import ip_address

import pytest
from fastapi.testclient import TestClient
from starlette.datastructures import FormData

from romulus.config import Settings
from romulus.detect.netdef import SiteNetworks
from romulus.doctor import check_site_networks
from romulus.hunt import run as hunt_run
from romulus.site import COLLECTION_PATH, load_site_facts, validate_site_content
from romulus.store import schema as t
from romulus.web import site_form
from romulus.web.app import create_app
from romulus.web.auth import create_user
from tests.test_site_collection import VALID


def _csrf(html: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def _digest(html: str) -> str:
    return re.search(r'name="digest" value="([^"]*)"', html).group(1)


@pytest.fixture()
def site(tmp_path):
    settings = Settings(home=tmp_path, secret_key=secrets.token_urlsafe(32))
    app = create_app(settings)
    repo = hunt_run.open_repo(settings)
    passwords = {"lead1": secrets.token_urlsafe(18), "analyst1": secrets.token_urlsafe(18)}
    create_user(repo.engine, "lead1", passwords["lead1"], "lead")
    create_user(repo.engine, "analyst1", passwords["analyst1"], "analyst")

    def login(name: str) -> TestClient:
        client = TestClient(app)
        client.post("/login", data={"username": name, "password": passwords[name]}, follow_redirects=False)
        return client

    return settings, repo, login


def _form_from_view(content: dict, **overrides) -> FormData:
    """The fields the page would submit unchanged for `content`, as the browser sends them."""
    shown = site_form.view(content)
    fields: list[tuple[str, str]] = [("group_count", str(len(shown["groups"]) + 1))]
    for index, group in enumerate(shown["groups"]):
        prefix = f"g{index}."
        fields.append((prefix + "hosts", group["hosts"]))
        if group["sysmon_installed"]:
            fields.append((prefix + "sysmon_installed", "1"))
        fields += [(prefix + "sysmon_ids", str(item)) for item in sorted(group["sysmon_ids"])]
        fields.append((prefix + "sysmon_other", group["sysmon_other"]))
        if group["command_line"]:
            fields.append((prefix + "command_line", "1"))
        if group["script_block"]:
            fields.append((prefix + "script_block", "1"))
        fields += [(f"{prefix}audit.{position}", group["audit"][name])
                   for position, name in enumerate(shown["known_audit"])]
        for name, setting in group["audit_extra"]:
            fields += [(prefix + "audit_extra_name", name), (prefix + "audit_extra_setting", setting)]
        fields += [(prefix + "channels", channel) for channel in shown["known_channels"]
                   if channel.casefold() in group["channels"]]
        fields.append((prefix + "channels_other", group["channels_other"]))
    blank = len(shown["groups"])
    fields += [(f"g{blank}.new", "1"), (f"g{blank}.hosts", "")]
    for key in ("domain_controllers", "directory_sync_accounts", "internal_networks", "external_networks"):
        fields.append((key, shown[key]))
    replaced = dict(overrides)
    fields = [(key, replaced.pop(key, value)) for key, value in fields] + list(replaced.items())
    return FormData(fields)


def _post(form: FormData) -> dict[str, list[str]]:
    data: dict[str, list[str]] = {}
    for key, value in form.multi_items():
        data.setdefault(key, []).append(value)
    return data


def _write(home, text: str = VALID):
    path = home / COLLECTION_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="")


FACT_PROBES = [
    ("sysmon", {"event_id": 1}), ("sysmon", {"event_id": 3}), ("sysmon", {"event_id": 7}),
    ("security_4688_command_line", {}), ("powershell_script_block", {}),
    ("audit_policy", {"subcategory": "Process Creation", "outcome": "success"}),
    ("audit_policy", {"subcategory": "Logon", "outcome": "failure"}),
    ("audit_policy", {"subcategory": "Kerberos Service Ticket Operations", "outcome": "success"}),
    ("defender_operational", {}), ("task_scheduler_operational", {}),
    ("security_event_log", {}), ("system_event_log", {}),
    ("event_channel", {"channel": "Microsoft-Windows-PowerShell/Operational"}),
]


def test_an_unchanged_form_round_trips_every_attested_fact(tmp_path):
    _write(tmp_path, VALID.replace(
        "    system_event_log: true\n",
        "    system_event_log: true\n    event_channels: [Microsoft-Windows-PowerShell/Operational]\n"
        "  - hosts: all\n    audit_policy: {Kerberos Service Ticket Operations: both}\n",
    ))
    original = load_site_facts(tmp_path)

    again = validate_site_content(site_form.parse_form(_form_from_view(original.content)))

    for host in ("ws-22.example.test", "dc01", "elsewhere"):
        for fact, arguments in FACT_PROBES:
            assert again.attests(host, fact, **arguments) == original.attests(host, fact, **arguments), (
                host, fact, arguments)
    assert again.domain_controllers == original.domain_controllers
    assert again.directory_sync_accounts == original.directory_sync_accounts


def test_analysts_cannot_open_or_save_the_page_and_do_not_see_its_link(site):
    _settings, _repo, login = site
    analyst = login("analyst1")
    assert "Site setup" not in analyst.get("/").text
    assert analyst.get("/site").status_code == 403
    assert analyst.post("/site", data={"csrf": "x", "group_count": "0"}).status_code == 403
    assert "Site setup" in login("lead1").get("/").text


def test_lead_creates_the_site_file_and_the_change_is_audited(site):
    settings, repo, login = site
    lead = login("lead1")
    page = lead.get("/site").text
    assert _digest(page) == ""
    form = {
        "csrf": _csrf(page), "digest": "", "group_count": "1",
        "g0.new": "1", "g0.hosts": "ws-*\ndc01", "g0.sysmon_installed": "1",
        "g0.sysmon_ids": ["1", "3"], "g0.sysmon_other": "10, 22", "g0.command_line": "1",
        "g0.audit_new_name": "Process Creation", "g0.audit_new_setting": "success",
        "g0.channels": ["Security"], "g0.channels_other": "Microsoft-Windows-WinRM/Operational",
        "domain_controllers": "DC01.example.test", "directory_sync_accounts": "EXAMPLE\\SyncSvc",
        "internal_networks": "10.20.0.0/16\n192.168.5.0/24", "external_networks": "10.20.99.0/24",
    }
    response = lead.post("/site", data=form, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/site?saved=1"

    facts = load_site_facts(settings.home)
    assert facts.attests("ws-7", "sysmon", event_id=22) and not facts.attests("ws-7", "sysmon", event_id=7)
    assert facts.attests("dc01", "audit_policy", subcategory="process creation", outcome="success")
    assert facts.attests("dc01", "security_event_log")
    assert facts.attests("dc01", "event_channel", channel="microsoft-windows-winrm/operational")
    assert facts.domain_controllers == ("dc01.example.test",)
    networks = SiteNetworks.from_settings(settings)
    assert networks.is_internal(ip_address("10.20.1.1")) and not networks.is_internal(ip_address("10.20.99.1"))

    with repo.engine.connect() as connection:
        rows = connection.execute(t.audit_event.select().where(t.audit_event.c.action == "site.update")).mappings().all()
    assert len(rows) == 1 and rows[0]["actor"] == "web:lead1"
    detail = rows[0]["detail"]
    assert detail["before"] is None and detail["after_digest"] == facts.digest
    assert detail["changed"] == ["collection groups", "domain controllers", "directory sync accounts",
                                 "internal networks", "external networks"]
    assert "Saved." in lead.get("/site?saved=1").text


def test_a_stale_page_never_overwrites_a_newer_file(site):
    settings, _repo, login = site
    _write(settings.home)
    lead = login("lead1")
    page = lead.get("/site").text
    stale = _digest(page)
    _write(settings.home, VALID.replace("event_ids: [1, 3, 5]", "event_ids: [1]"))
    before = (settings.home / COLLECTION_PATH).read_text(encoding="utf-8")

    form = _form_from_view(load_site_facts(settings.home).content, csrf=_csrf(page), digest=stale)
    response = lead.post("/site", data=_post(form), follow_redirects=False)

    assert response.status_code == 409 and "changed since this page was loaded" in response.text
    assert (settings.home / COLLECTION_PATH).read_text(encoding="utf-8") == before


@pytest.mark.parametrize(("fields", "message"), [
    ({"internal_networks": "10.0.0.1/8"}, "not a CIDR network"),
    ({"internal_networks": "10.0.0.0/8", "external_networks": "172.16.0.0/24"}, "not inside any internal network"),
    ({"external_networks": "10.9.0.0/24"}, "external_networks needs internal_networks"),
    ({"g0.channels": "Security", "g0.channels_other": "security"}, "duplicate event channel"),
    ({"domain_controllers": "dc-*"}, "host names, not globs"),
])
def test_an_invalid_form_is_shown_back_with_the_reason_and_writes_nothing(site, fields, message):
    settings, repo, login = site
    _write(settings.home)
    lead = login("lead1")
    page = lead.get("/site").text
    content = load_site_facts(settings.home).content
    overrides = {"csrf": _csrf(page), "digest": _digest(page), **fields}
    before = (settings.home / COLLECTION_PATH).read_bytes()

    response = lead.post("/site", data=_post(_form_from_view(content, **overrides)))

    assert response.status_code == 400 and "Not saved." in response.text and message in response.text
    assert (settings.home / COLLECTION_PATH).read_bytes() == before
    assert not (settings.home / COLLECTION_PATH).with_name("collection.yaml.prev").exists()


def test_saving_keeps_the_previous_file_and_removes_a_group(site):
    settings, _repo, login = site
    _write(settings.home, VALID.replace("collection:\n", "collection:\n  - hosts: all\n    system_event_log: true\n"))
    lead = login("lead1")
    page = lead.get("/site").text
    form = _form_from_view(load_site_facts(settings.home).content, csrf=_csrf(page), digest=_digest(page))
    form = FormData([*form.multi_items(), ("g0.remove", "1")])

    assert lead.post("/site", data=_post(form), follow_redirects=False).status_code == 303

    facts = load_site_facts(settings.home)
    assert len(facts.groups) == 1 and facts.groups[0].hosts == ("ws-*.example.test", "dc01")
    assert (settings.home / COLLECTION_PATH).with_name("collection.yaml.prev").read_text(encoding="utf-8") == VALID.replace(
        "collection:\n", "collection:\n  - hosts: all\n    system_event_log: true\n")


def test_state_change_needs_csrf_and_telemetry_like_text_is_escaped(site):
    settings, _repo, login = site
    _write(settings.home, VALID.replace("    system_event_log: true\n",
                                        "    event_channels: ['<script>alert(1)</script>']\n"))
    lead = login("lead1")
    page = lead.get("/site").text
    assert "<script>alert(1)" not in page and "&lt;script&gt;alert(1)" in page
    assert lead.post("/site", data={"csrf": "forged", "group_count": "0"}).status_code == 403


def test_an_invalid_file_on_disk_is_reported_not_edited(site):
    settings, _repo, login = site
    lead = login("lead1")
    _write(settings.home, VALID.replace("installed: true", "installed: 1"))
    response = lead.get("/site")
    assert response.status_code == 409 and "Fix or remove the file" in response.text


def test_internal_networks_come_from_one_place_only(tmp_path):
    _write(tmp_path, VALID + "internal_networks: [10.1.0.0/16]\n")
    in_file = Settings(home=tmp_path)
    assert SiteNetworks.from_settings(in_file).configured
    assert SiteNetworks.from_settings(in_file) == SiteNetworks.from_lists(["10.1.0.0/16"])

    both = Settings(home=tmp_path, internal_networks=["10.2.0.0/16"])
    with pytest.raises(ValueError, match="set both in site/collection.yaml"):
        SiteNetworks.from_settings(both)
    check = check_site_networks(both, client=object())
    assert check.status == "fail" and "keep one" in check.detail

    _write(tmp_path)
    assert SiteNetworks.from_settings(both) == SiteNetworks.from_lists(["10.2.0.0/16"])
    assert not SiteNetworks.from_settings(Settings(home=tmp_path)).configured


def test_site_carve_outs_need_the_sites_own_ranges(tmp_path):
    _write(tmp_path, VALID + "external_networks: [10.9.0.0/24]\n")
    with pytest.raises(ValueError, match="external_networks needs internal_networks"):
        load_site_facts(tmp_path)
