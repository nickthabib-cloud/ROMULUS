"""The hunt's internal-network definition: installed from the hunt manifest, refused when the configuration
changed since the hunt was created, and checked against the addresses of the site's own hosts."""
from __future__ import annotations

import ipaddress
from collections.abc import Callable
from datetime import datetime, timedelta

from romulus.config import Settings
from romulus.detect import netdef
from romulus.detect.correlation import routable_remote
from romulus.detect.netdef import EXTERNAL_SETTING, INTERNAL_SETTING, SiteNetworks
from romulus.detect.registry import ALL_PLAYBOOKS
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
TERMS_SIZE = 1000                  # candidate outside addresses returned per target; past it counts are lower bounds
DISTINCT_CAP = 10_000              # distinct outside addresses kept across targets; past it counts are lower bounds
EXAMPLES = 10
CITED_EXAMPLES = 5                 # examples named in a coverage reason
DOCTOR_LOOKBACK = timedelta(days=7)    # doctor checks the week ending at each target's newest record


def _ip_order(text: str):
    address = ipaddress.ip_address(text)
    return (address.version, int(address))


def outside_candidates(field: str, definition: SiteNetworks) -> dict:
    """A query for addresses that may be outside `definition`: not in any internal range, or in a carve-out. It
    is a superset of what the definition reads as outside (a range nested inside a carve-out is internal again),
    so every candidate is judged locally with the definition itself."""
    internal = [str(n) for n in definition.effective_internal()]
    clauses: list[dict] = [{"bool": {"must_not": [{"terms": {field: internal}}]}}]
    if definition.external:
        clauses.append({"terms": {field: [str(n) for n in definition.external]}})
    return {"bool": {"should": clauses, "minimum_should_match": 1}}


def _recent_window(client, target: str, contract: FieldContract) -> dict | None:
    """The DOCTOR_LOOKBACK before the target's newest record, as a range clause; None for an empty target."""
    d = client.search(target, {"size": 0, "track_total_hits": False,
                               "aggs": {"newest": {"max": {"field": contract.time_field}}}})
    newest = ((d.get("aggregations") or {}).get("newest") or {}).get("value_as_string")
    if not newest:
        return None
    end = datetime.fromisoformat(newest.replace("Z", "+00:00"))
    return {"range": {contract.time_field: {"gte": (end - DOCTOR_LOOKBACK).isoformat(), "lte": end.isoformat()}}}


def check_host_addresses(client, contracts: dict[str, FieldContract], definition: SiteNetworks,
                         window: Window | None, *, heartbeat: Callable[[], None] = lambda: None) -> dict:
    """Distinct `host.ip` values in host telemetry that fall outside `definition`: routable addresses that are not
    internal. Host logs come from the site's own assets, so any such address is evidence that the definition is
    wrong for this site. Over `window` (the hunt's), or with None over the week ending at each target's newest
    record. One query per target returns at most TERMS_SIZE candidate addresses and an estimate of how many there
    are; at most DISTINCT_CAP are kept across targets; past either cap the count is "at least"."""
    outside: set[str] = set()
    capped = False
    present = 0
    estimate = 0
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
        heartbeat()
        checked.append(target)
        if window is not None:
            bounds = {"range": {contract.time_field: {"gte": window.start.isoformat(), "lt": window.end.isoformat()}}}
        else:
            bounds = _recent_window(client, target, contract)
            if bounds is None:
                continue
        body = {"size": 0, "track_total_hits": False, "query": {"bool": {"filter": [bounds]}},
                "aggs": {"present": {"value_count": {"field": spec.native}},
                         "outside": {"filter": outside_candidates(spec.native, definition), "aggs": {
                             "addresses": {"terms": {"field": spec.native, "size": TERMS_SIZE}},
                             "distinct": {"cardinality": {"field": spec.native}}}}}}
        d = client.search(target, body)
        if d.get("timed_out"):
            reasons.append(f"{target}: timed out")
        if (d.get("_shards") or {}).get("failed"):
            reasons.append(f"{target}: shard failures")
        aggs = d.get("aggregations") or {}
        present += int((aggs.get("present") or {}).get("value") or 0)
        found = aggs.get("outside") or {}
        terms = found.get("addresses") or {}
        estimate += int((found.get("distinct") or {}).get("value") or 0)
        if terms.get("sum_other_doc_count"):
            capped = True                               # more candidates than one answer returns
        for bucket in terms.get("buckets") or []:
            try:
                address = ipaddress.ip_address(str(bucket.get("key")).split("%", 1)[0])
            except ValueError:
                continue
            canon = str(address)
            if canon in outside or not routable_remote(canon) or definition.is_internal(address):
                continue
            if len(outside) < DISTINCT_CAP:
                outside.add(canon)
            else:
                capped = True
    at_least = capped or bool(reasons)
    examples = sorted(outside, key=_ip_order)[:EXAMPLES]
    broad = definition.broad_ranges()
    warnings = []
    if outside:
        warnings.append(
            f"{'at least ' if at_least else ''}{len(outside)} distinct {HOST_ADDRESS_FIELD} address(es) in host "
            f"telemetry are outside the internal-network definition "
            f"({definition.summary().removeprefix('Internal networks: ')}), for example {', '.join(examples)}. Host "
            f"logs come from this site's own assets: set {INTERNAL_SETTING} (and {EXTERNAL_SETTING} for partner or "
            f"VPN ranges) to this site's address space.")
    if broad:
        warnings.append(
            f"{INTERNAL_SETTING} includes very broad ranges ({', '.join(broad)}): almost every address reads as the "
            "site's, so rules about traffic crossing the site boundary see almost nothing. List the site's own ranges.")
    return {"field": HOST_ADDRESS_FIELD, "definition": definition.summary(), "digest": definition.digest,
            "window": "hunt" if window is not None else f"last {DOCTOR_LOOKBACK.days} days of each target",
            "checked_targets": checked, "unchecked_targets": unchecked, "values_present": present,
            "outside": len(outside), "at_least": at_least, "distinct_estimate": estimate, "examples": examples,
            "broad_ranges": broad, "reasons": reasons, "warning": " ".join(warnings) or None}


def contradiction_reason(check: dict) -> str | None:
    """Why the hunt's own telemetry leaves the definition unconfirmed: host addresses outside it, or a check that
    failed. None when the check ran and found every host inside, or found no host address at all."""
    if check.get("error"):
        return (f"the internal-network definition could not be checked against this hunt's host addresses "
                f"({check['error']}); direction-dependent negatives are not complete")
    if check.get("outside"):
        shown = ", ".join(check["examples"][:CITED_EXAMPLES])
        more = " and more" if check["outside"] > CITED_EXAMPLES or check.get("at_least") else ""
        return (f"{'at least ' if check.get('at_least') else ''}{check['outside']} distinct {HOST_ADDRESS_FIELD} "
                f"address(es) in this hunt's host telemetry are outside the internal-network definition ({shown}"
                f"{more}); direction-dependent negatives are not complete")
    return None


PARTIAL_STATE = {"no_match_complete": "evaluated_partial", "evaluated_complete": "evaluated_partial",
                 "matched": "match_on_partial"}


def narrow_direction_negatives(repo, hunt_id: str, reason: str, *, owner_token: str | None = None) -> int:
    """Make every window cell of a direction-dependent rule partial, naming `reason`. Returns how many cells
    changed. Partition cells keep their states; the window cell is the rule's whole-hunt answer."""
    changed = 0
    for rule_id in sorted(pb.id for pb in ALL_PLAYBOOKS if pb.direction_dependent):
        for cell in repo.rule_cells(hunt_id, rule_id=rule_id):
            if cell["target"] != "*" or cell["partition"] != "window":
                continue
            detail = dict(cell["detail"] or {})
            detail["reasons"] = [*(detail.get("reasons") or []), reason]
            repo.set_rule_cell(hunt_id, rule_id, cell["rule_version"], "*", "window",
                               PARTIAL_STATE.get(cell["state"], cell["state"]), cell["matched"] or 0,
                               cell["evaluated"] or 0, detail, owner_token=owner_token)
            changed += 1
    return changed
