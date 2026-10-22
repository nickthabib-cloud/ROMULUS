"""The hunt's internal-network definition: installed from the hunt manifest, refused when the configuration
changed since the hunt was created, and checked against the addresses of the site's own hosts."""
from __future__ import annotations

import ipaddress

from romulus.config import Settings
from romulus.detect import netdef
from romulus.detect.correlation import routable_remote
from romulus.detect.netdef import EXTERNAL_SETTING, INTERNAL_SETTING, SiteNetworks
from romulus.hunt.pivot import _is_network
from romulus.sources.models import Window
from romulus.sources.profile import FieldContract


def install_for_hunt(settings: Settings, hunt_id: str, manifest: dict) -> SiteNetworks:
    """Install the definition the hunt recorded (a hunt recorded before the setting existed used the default).
    A configuration whose definition differs is refused: the hunt's sweep, coverage and findings were decided
    under the recorded one, so new work under another would mix two meanings of "internal"."""
    recorded = SiteNetworks.from_record(manifest.get("internal_networks"))
    now = SiteNetworks.from_settings(settings)
    if now != recorded:
        raise RuntimeError(
            f"hunt {hunt_id} was created with internal networks {recorded.summary().removeprefix('Internal networks: ')}"
            f" (digest {recorded.digest[:12]}); this configuration has "
            f"{now.summary().removeprefix('Internal networks: ')} (digest {now.digest[:12]}). Restore "
            f"{INTERNAL_SETTING} and its carve-outs, or start a new hunt over the same window instead of resuming.")
    netdef.install(recorded)
    return recorded


# ---- misconfiguration check: the site's own hosts outside the definition -----------------------------------

HOST_ADDRESS_FIELD = "host.ip"     # the shipper's addresses on host-log documents: always one of the site's assets
DISTINCT_CAP = 10_000              # distinct addresses kept per check; past it the counts are lower bounds
EXAMPLES = 10
PAGE_SIZE = 1000
MAX_PAGES = 100                    # composite pages per target; past it the counts are lower bounds


def _ip_order(text: str):
    address = ipaddress.ip_address(text)
    return (address.version, int(address))


def check_host_addresses(client, contracts: dict[str, FieldContract], definition: SiteNetworks,
                         window: Window | None) -> dict:
    """Distinct `host.ip` values in host telemetry (over `window`, or the whole index when None) that fall
    outside `definition`: routable addresses that are not internal. Host logs come from the site's own assets,
    so any such address is evidence that the definition is wrong for this site. Bounded: at most DISTINCT_CAP
    distinct addresses are kept and at most MAX_PAGES pages read per target; past either, counts are "at least"."""
    seen: set[str] = set()
    outside: set[str] = set()
    capped = False
    checked: list[str] = []
    unchecked: dict[str, str] = {}
    reasons: list[str] = []
    for target, contract in sorted(contracts.items()):
        if _is_network(target, contract):
            continue                                    # sensor and session indices: not host telemetry
        spec = contract.spec(HOST_ADDRESS_FIELD)
        if spec is None or not spec.aggregatable:
            unchecked[target] = f"no aggregatable {HOST_ADDRESS_FIELD} field"
            continue
        checked.append(target)
        query = ({"bool": {"filter": [{"range": {contract.time_field: {
            "gte": window.start.isoformat(), "lt": window.end.isoformat()}}}]}} if window else {"match_all": {}})
        composite: dict = {"size": PAGE_SIZE, "sources": [{"ip": {"terms": {"field": spec.native}}}]}
        for _page in range(MAX_PAGES):
            body = {"size": 0, "track_total_hits": False, "query": query,
                    "aggs": {"addresses": {"composite": composite}}}
            d = client.search(target, body)
            if d.get("timed_out"):
                reasons.append(f"{target}: timed out")
            if (d.get("_shards") or {}).get("failed"):
                reasons.append(f"{target}: shard failures")
            agg = (d.get("aggregations") or {}).get("addresses") or {}
            buckets = agg.get("buckets") or []
            for bucket in buckets:
                try:
                    address = ipaddress.ip_address(str((bucket.get("key") or {}).get("ip")).split("%", 1)[0])
                except ValueError:
                    continue
                canon = str(address)
                if canon not in seen:
                    if len(seen) < DISTINCT_CAP:
                        seen.add(canon)
                    else:
                        capped = True
                if canon not in outside and routable_remote(canon) and not definition.is_internal(address):
                    if len(outside) < DISTINCT_CAP:
                        outside.add(canon)
                    else:
                        capped = True
            after = agg.get("after_key")
            if not after or not buckets:
                break
            composite = {**composite, "after": after}
        else:
            reasons.append(f"{target}: stopped after {MAX_PAGES} pages of addresses")
    at_least = capped or bool(reasons)
    examples = sorted(outside, key=_ip_order)[:EXAMPLES]
    count = f"{'at least ' if at_least else ''}{len(outside)}"
    warning = (f"{count} distinct {HOST_ADDRESS_FIELD} address(es) in host telemetry are outside the internal-network "
               f"definition ({definition.summary().removeprefix('Internal networks: ')}), for example "
               f"{', '.join(examples)}. Host logs come from this site's own assets: set {INTERNAL_SETTING} (and "
               f"{EXTERNAL_SETTING} for partner or VPN ranges) to this site's address space."
               if outside else None)
    return {"field": HOST_ADDRESS_FIELD, "definition": definition.summary(), "digest": definition.digest,
            "checked_targets": checked, "unchecked_targets": unchecked, "addresses": len(seen),
            "outside": len(outside), "at_least": at_least, "examples": examples, "reasons": reasons,
            "warning": warning}
