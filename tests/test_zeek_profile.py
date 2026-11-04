"""The source profile of a Zeek index: role and inventory from what the shipper wrote, never from field shape.

- A Malcolm index (Arkime's session fields beside Zeek's and Suricata's rows) is inventoried by (provider, dataset):
  Zeek rows by their log's dispatch token, Suricata rows by EVE event type, Arkime sessions as such; the profile says
  the index is mixed, and the sweep's families follow every row's normalizer.
- An Arkime index with no Zeek or Suricata provider keeps the profile it always had (protocols, no inventory key).
- An Elastic Zeek index whose kerberos and ntlm rows carry `user.*` fields is a network sensor's, not a host's.
- An inventory paged past its budget says so.
"""
from romulus.hunt import sweep as sw
from romulus.sources import profile as pf


def _mapping(*fields: str) -> dict:
    properties: dict = {}
    for field in fields:
        level = properties
        parts = field.split(".")
        for part in parts[:-1]:
            level = level.setdefault(part, {"properties": {}})["properties"]
        level[parts[-1]] = {"type": "date" if field in ("firstPacket", "lastPacket", "@timestamp") else "keyword"}
    return {"idx": {"mappings": {"properties": properties}}}


class _Client:
    version = "8.15.0"

    class settings:
        es_flavor = "opensearch"

    def __init__(self, fields, protocols, pages):
        self.fields, self.protocols, self.pages, self.bodies = fields, protocols, list(pages), []

    def mapping(self, _target):
        return _mapping(*self.fields)

    def search(self, _target, body):
        self.bodies.append(body)
        if "inventory" in body["aggs"]:
            page = self.pages.pop(0) if self.pages else {"buckets": []}
            return {"aggregations": {"inventory": page}}
        return {"hits": {"total": {"value": 100}}, "aggregations": {
            "tmin": {"value_as_string": "2024-11-18T14:00:00Z"}, "tmax": {"value_as_string": "2024-11-18T15:00:00Z"},
            "ds": {"buckets": [{"key": key, "doc_count": n} for key, n in self.protocols.items()]},
            "hosts": {"buckets": [{"key": "malcolm", "doc_count": 100}]}}}


MALCOLM_FIELDS = ("firstPacket", "lastPacket", "network.community_id", "event.provider", "event.dataset", "node",
                  "protocol", "source.ip", "destination.ip", "user.name")


def _bucket(provider, dataset, n):
    return {"key": {"provider": provider, "dataset": dataset}, "doc_count": n}


def test_a_malcolm_index_is_inventoried_by_provider_and_dataset():
    client = _Client(MALCOLM_FIELDS, {"tcp": 80, "dns": 20}, [
        {"buckets": [_bucket("zeek", "conn", 50), _bucket("zeek", "dns", 10), _bucket("zeek", "modbus", 3)],
         "after_key": {"provider": "zeek", "dataset": "modbus"}},
        {"buckets": [_bucket("suricata", "alert", 5), _bucket(None, None, 30), _bucket("arkime", None, 2)]},
        {"buckets": []},
    ])
    profile, contract = pf.build_profile(client, "arkime_sessions3-*")
    dumped = profile.model_dump(mode="json")
    assert dumped["kind"] == pf.MIXED_NETWORK_KIND and dumped["role"] == "network"
    assert dumped["datasets"] == {"arkime.session": 32, "suricata.eve.alert": 5, "zeek:conn": 50, "zeek:dns": 10,
                                  "zeek:modbus": 3}
    assert {"provider": "zeek", "dataset": "modbus", "records": 3} in dumped["inventory"]
    assert contract.time_field == "firstPacket" and contract.role == "network"
    families = sw.delivered_families(dumped, contract)
    assert {"net_flow", "dns_query", "net_session", "net_alert"} <= families
    assert not any(note.startswith("ds inventory truncated") for note in dumped["notes"])


def test_an_arkime_index_without_zeek_or_suricata_rows_keeps_its_profile():
    client = _Client(MALCOLM_FIELDS, {"tcp": 80}, [{"buckets": [_bucket(None, None, 80)]}])
    profile, _contract = pf.build_profile(client, "arkime_sessions3-*")
    dumped = profile.model_dump(mode="json")
    assert dumped["kind"] == "arkime_sessions" and dumped["datasets"] == {"tcp": 80}
    assert "inventory" not in dumped


def test_an_index_without_provider_fields_is_never_asked_for_a_provider_inventory():
    client = _Client(("firstPacket", "lastPacket", "network.community_id", "protocol", "node"), {"tcp": 80}, [])
    profile, _contract = pf.build_profile(client, "arkime_sessions3-*")
    assert not any("inventory" in body["aggs"] for body in client.bodies)
    assert "inventory" not in profile.model_dump(mode="json")


def test_an_elastic_zeek_index_with_user_fields_is_a_network_sensor():
    client = _Client(("@timestamp", "event.dataset", "source.ip", "destination.ip", "user.name", "user.domain",
                      "host.name"), {"zeek.kerberos": 40, "zeek.ntlm": 10}, [])
    profile, contract = pf.build_profile(client, "logs-zeek.kerberos-default")
    assert profile.role == "network" and contract.role == "network"
    assert sw.delivered_families(profile.model_dump(mode="json"), contract) == frozenset({"kerberos_tx", "ntlm_tx"})


def test_an_inventory_past_its_page_budget_is_named_truncated(monkeypatch):
    monkeypatch.setattr(pf, "PROVIDER_INVENTORY_PAGE_LIMIT", 2)
    pages = [{"buckets": [_bucket("zeek", f"log{i}", 1)], "after_key": {"provider": "zeek", "dataset": f"log{i}"}}
             for i in range(3)]
    profile, contract = pf.build_profile(_Client(MALCOLM_FIELDS, {"tcp": 1}, pages), "arkime_sessions3-*")
    dumped = profile.model_dump(mode="json")
    assert any(note.startswith("ds inventory truncated") for note in dumped["notes"])
    # a truncated inventory falls back to every family a network source can deliver
    assert sw.delivered_families(dumped, contract) == sw._ROLE_FAMILIES["network"]
