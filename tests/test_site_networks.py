"""The per-site internal-network definition: the setting, its validation, lookups and its record.

Every address here is from a documentation range (RFC 5737, RFC 3849) or a private range; none is a real site's.
"""
import ipaddress

import pytest

from romulus.config import Settings, load_settings
from romulus.detect.netdef import DEFAULT_LABEL, SiteNetworks

# The list the definition replaced, kept here so the default can never drift from it.
PREVIOUS_DEFAULT = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    "::1/128", "fc00::/7", "fe80::/10")]
SAMPLES = ["10.0.0.1", "10.255.255.255", "11.0.0.0", "9.255.255.255", "172.15.255.255", "172.16.0.0",
           "172.31.255.255", "172.32.0.0", "192.168.0.1", "192.169.0.1", "127.0.0.1", "169.254.1.1", "100.64.0.1",
           "100.127.255.255", "100.128.0.0", "198.51.100.7", "203.0.113.1", "192.0.2.1", "0.0.0.0",
           "255.255.255.255", "224.0.0.1", "::1", "::", "fc00::1", "fd12:3456::1", "fe80::1", "fec0::1",
           "2001:db8::1", "::ffff:10.0.0.1", "ff02::1"]


def _previous(ip) -> bool:
    # an IPv4-mapped IPv6 address is the IPv4 host it names (the previous list read it as outside every range)
    ip = ip.ipv4_mapped or ip if ip.version == 6 else ip
    return any(ip in n for n in PREVIOUS_DEFAULT if n.version == ip.version)


@pytest.mark.parametrize(("mapped", "internal"), [("::ffff:10.1.2.3", True), ("::ffff:198.51.100.20", True),
                                                  ("::ffff:10.50.0.9", False), ("::ffff:203.0.113.9", False)])
def test_an_ipv4_mapped_address_is_judged_as_its_ipv4_address(mapped, internal):
    assert site().is_internal(ipaddress.ip_address(mapped)) is internal
    assert SiteNetworks.default().is_internal(ipaddress.ip_address("::ffff:10.1.2.3"))


def site(internal=("198.51.100.0/24", "10.0.0.0/8"), external=("10.50.0.0/16",)) -> SiteNetworks:
    return SiteNetworks.from_lists(list(internal), list(external))


# ---- item 1: the setting ---------------------------------------------------------------------------------

def test_unset_setting_is_the_labelled_default():
    definition = SiteNetworks.from_settings(Settings())
    assert definition.source == "default"
    assert definition.label == DEFAULT_LABEL == "default (RFC 1918 and reserved ranges)"
    assert definition.summary() == ("Internal networks: default (RFC 1918 and reserved ranges); not configured for "
                                    "this site")
    assert definition == SiteNetworks.default()


def test_default_definition_answers_as_the_previous_list_with_mapped_addresses_unmapped():
    default = SiteNetworks.default()
    for text in SAMPLES:
        ip = ipaddress.ip_address(text)
        assert default.is_internal(ip) is _previous(ip), text


def test_configured_setting_loads_from_the_environment(tmp_path):
    s = load_settings(env_file=tmp_path / "absent.env", environ={
        "ROMULUS_INTERNAL_NETWORKS": " 198.51.100.0/24, 10.0.0.0/8 ,2001:db8::/32",
        "ROMULUS_EXTERNAL_NETWORKS": "10.50.0.0/16"})
    assert s.internal_networks == ["198.51.100.0/24", "10.0.0.0/8", "2001:db8::/32"]
    assert s.external_networks == ["10.50.0.0/16"]
    definition = SiteNetworks.from_settings(s)
    assert definition.source == "configured"
    assert definition.summary() == "Internal networks: configured (3 ranges, 1 carve-out)"


@pytest.mark.parametrize("name", ["ROMULUS_INTERNAL_NETWORKS", "ROMULUS_EXTERNAL_NETWORKS"])
@pytest.mark.parametrize("value", ["10.0.0.0/33", "not-a-network", "10.1.2.3/8", "198.51.100.0/24;10.0.0.0/8",
                                   "2001:db8::/129", "10.0.0.0/8,,bogus"])
def test_a_malformed_cidr_is_a_startup_error(tmp_path, name, value):
    environ = {"ROMULUS_INTERNAL_NETWORKS": "10.0.0.0/8", name: value}
    with pytest.raises(ValueError, match=name):
        load_settings(env_file=tmp_path / "absent.env", environ=environ)


def test_a_carve_out_outside_every_internal_range_is_a_startup_error(tmp_path):
    with pytest.raises(ValueError, match="ROMULUS_EXTERNAL_NETWORKS"):
        load_settings(env_file=tmp_path / "absent.env", environ={
            "ROMULUS_INTERNAL_NETWORKS": "198.51.100.0/24", "ROMULUS_EXTERNAL_NETWORKS": "203.0.113.0/24"})


def test_a_carve_out_equal_to_an_internal_range_is_a_startup_error():
    with pytest.raises(ValueError, match="ROMULUS_EXTERNAL_NETWORKS"):
        Settings(internal_networks=["198.51.100.0/24"], external_networks=["198.51.100.0/24"])


def test_carve_outs_alone_keep_the_default_label_and_say_so():
    definition = SiteNetworks.from_settings(Settings(external_networks=["10.50.0.0/16"]))
    assert definition.source == "default"
    assert definition.summary() == ("Internal networks: default (RFC 1918 and reserved ranges), 1 carve-out; not "
                                    "configured for this site")
    assert not definition.is_internal(ipaddress.ip_address("10.50.3.4"))
    assert definition.is_internal(ipaddress.ip_address("10.51.3.4"))


# ---- item 2: one definition object -----------------------------------------------------------------------

def test_the_most_specific_prefix_wins():
    definition = SiteNetworks.from_lists(["10.0.0.0/8", "10.50.1.0/24", "2001:db8::/32", "2001:db8:ff:1::/64"],
                                         ["10.50.0.0/16", "2001:db8:ff::/48"])
    expect = {"10.1.1.1": True, "10.50.2.2": False, "10.50.1.9": True, "10.50.0.0": False, "10.49.255.255": True,
              "2001:db8::5": True, "2001:db8:ff::5": False, "2001:db8:ff:1::5": True, "2001:db9::1": False}
    for text, internal in expect.items():
        assert definition.is_internal(ipaddress.ip_address(text)) is internal, text


def test_a_public_space_site_is_internal_and_its_carved_out_partner_range_is_not():
    definition = site()
    assert definition.is_internal(ipaddress.ip_address("198.51.100.20"))
    assert not definition.is_internal(ipaddress.ip_address("10.50.0.9"))
    assert definition.is_internal(ipaddress.ip_address("10.60.0.9"))
    assert not definition.is_internal(ipaddress.ip_address("192.168.1.1"))   # RFC 1918, but not this site's
    assert not definition.is_internal(ipaddress.ip_address("203.0.113.9"))


def test_loopback_and_link_local_stay_internal_on_a_configured_site():
    definition = site()
    for text in ("127.0.0.1", "169.254.9.9", "::1", "fe80::1"):
        assert definition.is_internal(ipaddress.ip_address(text)), text


def test_the_digest_ignores_order_and_duplicates_and_changes_with_any_range():
    a = SiteNetworks.from_lists(["198.51.100.0/24", "10.0.0.0/8"], ["10.50.0.0/16"])
    b = SiteNetworks.from_lists(["10.0.0.0/8", "198.51.100.0/24", "10.0.0.0/8"], ["10.50.0.0/16"])
    assert a.digest == b.digest and a == b
    assert a.digest != SiteNetworks.from_lists(["198.51.100.0/24", "10.0.0.0/8"], ["10.51.0.0/16"]).digest
    assert a.digest != SiteNetworks.from_lists(["198.51.100.0/24", "10.0.0.0/8"], []).digest
    assert SiteNetworks.default().digest != SiteNetworks.from_lists(
        [str(n) for n in PREVIOUS_DEFAULT], []).digest          # the same ranges, but configured: a different record


def test_the_record_round_trips_and_a_record_that_does_not_match_its_digest_is_refused():
    record = site().record()
    assert record["source"] == "configured"
    assert record["internal"] == ["10.0.0.0/8", "198.51.100.0/24"] and record["external"] == ["10.50.0.0/16"]
    assert record["summary"] == "Internal networks: configured (2 ranges, 1 carve-out)"
    assert SiteNetworks.from_record(record) == site()
    assert SiteNetworks.from_record(None) == SiteNetworks.default()      # a hunt recorded before the setting
    with pytest.raises(ValueError, match="digest"):
        SiteNetworks.from_record({**record, "external": []})


def test_lookups_are_cached_per_definition():
    definition = site()
    ip = ipaddress.ip_address("198.51.100.20")
    assert definition.is_internal(ip) and definition.is_internal(ip)
    assert definition.cache_info().hits >= 1
    assert SiteNetworks.default().is_internal(ip) is False                # another definition, its own answer


def test_the_documented_example_file_leaves_the_setting_unset():
    from pathlib import Path
    s = load_settings(env_file=Path(__file__).resolve().parents[1] / ".env.example", environ={})
    assert s.internal_networks == [] and s.external_networks == []
    assert SiteNetworks.from_settings(s) == SiteNetworks.default()
