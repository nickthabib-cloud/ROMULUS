"""Bounded preflight coverage of declared networks against observed network endpoints.

This is a configuration diagnostic, not an inference that every private address is
owned by the site. Partner and VPN carve-outs can explain uncovered observations.
"""
from __future__ import annotations

import ipaddress
from itertools import islice

from romulus.detect.netdef import INTERNAL_SETTING, SiteNetworks
from romulus.errors import SourceError
from romulus.sources.compile import epoch_ms_ceiling
from romulus.sources.models import Window
from romulus.sources.profile import FieldContract

TERMS_SIZE = 1000
DISTINCT_CAP = 10_000
TARGET_LIMIT = 1000
PREFIX_LIMIT = 20
# A missing range affecting more than one in ten observed private endpoints merits
# an operator check. Smaller omissions are still reported, never silently covered.
WARN_SHARE = 0.10
PRIVATE_RANGES = tuple(map(ipaddress.ip_network, (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7",
)))


def _private(address):
    return any(address.version == network.version and address in network for network in PRIVATE_RANGES)


def _order(address):
    return address.version, int(address)


def _field(contract, typed):
    """Only exact aggregate fields; alternative layouts cannot silently be omitted."""
    name = typed
    if contract.zeek_sensor:
        name = {"source.ip": "id.orig_h", "destination.ip": "id.resp_h"}[typed]
    spec = contract.spec(name)
    if spec is None or not spec.aggregatable or spec.alternatives or len(spec.natives) > 1:
        return None
    if spec.type not in {"ip", "keyword", "constant_keyword", "wildcard"}:
        return None
    return spec.aggregation_native or spec.native


def _query(contract, window):
    fields = {side: _field(contract, f"{side}.ip") for side in ("source", "destination")}
    if not all(fields.values()):
        return None
    body = {"size": 0, "track_total_hits": False, "timeout": "10s", "aggs": {
        side: {"terms": {"field": field, "size": TERMS_SIZE, "order": {"_key": "asc"}}}
        for side, field in fields.items()}}
    if window is not None:
        stamp = contract.spec(contract.time_field)
        if contract.zeek_sensor:
            bounds = {"gte": window.start.timestamp(), "lt": window.end.timestamp()}
        elif stamp is not None and stamp.type in {"date", "date_nanos"}:
            bounds = {"gte": window.start.isoformat(), "lt": window.end.isoformat()}
        elif contract.time_field == "firstPacket" and stamp is not None and stamp.type in {
            "long", "integer", "double", "float",
        }:
            bounds = {"gte": epoch_ms_ceiling(window.start), "lt": epoch_ms_ceiling(window.end)}
        else:
            return None
        body["query"] = {"bool": {"filter": [{"range": {contract.time_field: bounds}}]}}
    return body


def _summary(result):
    state = result["status"]
    if state == "not_applicable":
        return "No queryable network targets were configured; network-address coverage was not assessed."
    count, outside = result["private_addresses"], result["outside"]
    share = result["outside_share"]
    text = (f"Observed private network addresses: {outside} of {count} distinct retained addresses outside "
            f"the declared internal networks" + (f" ({share:.1%})" if share is not None else "") + ". ")
    if result["prefixes"]:
        text += ("Uncovered prefixes (IPv4 /16, IPv6 ULA /48): " + ", ".join(result["prefixes"])
                 + (f"; {result['prefixes_omitted']} more" if result["prefixes_omitted"] else "") + ". ")
    if state == "unknown":
        text += ("Coverage unknown: the bounded observation is incomplete; counts are lower bounds and its share "
                 "describes only retained addresses. " + "; ".join(result["reasons"]) + ". ")
    elif state == "no_private_observed":
        text += "No RFC 1918, RFC 6598 or ULA addresses were observed; this does not require declaring private ranges. "
    if outside:
        text += (f"Check {INTERNAL_SETTING}; a partner/VPN carve-out may be intentional. The definition was not "
                 "changed automatically. ")
    text += f"Warning threshold: more than {WARN_SHARE:.0%} of observed private addresses uncovered."
    return text


def check_network_addresses(client, contracts: dict[str, FieldContract | None], definition: SiteNetworks,
                            window: Window | None) -> dict:
    """One request per network target, with two capped terms aggregations, including Arkime session targets.

    The denominator is the union of distinct canonical private IP addresses, not
    term doc_count (which would count endpoint-record occurrences). The doctor
    checks the available indexed history; hunt creation uses its exact window.
    A cap, missing field or failed response makes coverage unknown, even when all
    retained addresses happen to lie in the declaration. The bounded diagnostic
    does not affect detection retention, direction semantics or site settings.
    """
    retained, covered = set(), set()
    checked, unchecked, reasons, arkime = [], {}, [], []
    invalid = considered = omitted = 0
    # Contracts are already held by the caller. Iterate without allocating an
    # unbounded sorted copy; final detail lists are bounded by TARGET_LIMIT.
    for target, contract in contracts.items():
        if contract is not None and contract.role != "network":
            continue
        considered += 1
        if considered > TARGET_LIMIT:
            omitted += 1
            continue
        if contract is None:
            unchecked[target] = "source contract unavailable"
            continue
        if contract.time_field == "firstPacket":
            arkime.append(target)
        body = _query(contract, window)
        if body is None:
            unchecked[target] = "source/destination addresses or the hunt clock cannot be aggregated exactly"
            continue
        checked.append(target)
        try:
            response = client.search(target, body)
        except SourceError:
            # Backend text can contain URL/auth details. The target and failed
            # operation are sufficient to identify this unresolved check.
            reasons.append(f"{target}: network-address query failed")
            continue
        if not isinstance(response, dict):
            reasons.append(f"{target}: malformed network-address response")
            continue
        if response.get("timed_out") is not False or response.get("terminated_early"):
            reasons.append(f"{target}: timed out, terminated early or timeout state unknown")
        shards = response.get("_shards")
        if (not isinstance(shards, dict) or shards.get("failed") != 0
                or not isinstance(shards.get("total"), int)
                or shards.get("successful") != shards.get("total")):
            reasons.append(f"{target}: shard completeness unknown or failed")
        aggregations = response.get("aggregations")
        if not isinstance(aggregations, dict):
            reasons.append(f"{target}: address aggregations missing")
            continue
        for side in ("source", "destination"):
            terms = aggregations.get(side)
            if not isinstance(terms, dict) or not isinstance(terms.get("buckets"), list):
                reasons.append(f"{target}: {side} address buckets missing")
                continue
            if (terms.get("sum_other_doc_count") != 0
                    or terms.get("doc_count_error_upper_bound") != 0
                    or len(terms["buckets"]) > TERMS_SIZE):
                reasons.append(f"{target}: {side} terms capped or completeness unknown")
            for bucket in islice(terms["buckets"], TERMS_SIZE):
                key = bucket.get("key") if isinstance(bucket, dict) else None
                try:
                    if not isinstance(key, str) or len(key) > 45:
                        raise ValueError("not a bounded IP address")
                    address = ipaddress.ip_address(key)
                    if address.version == 6 and address.ipv4_mapped:
                        address = address.ipv4_mapped
                except ValueError:
                    invalid += 1
                    continue
                if not _private(address) or address in retained:
                    continue
                is_covered = definition.is_internal(address)
                if len(retained) < DISTINCT_CAP:
                    retained.add(address)
                    if is_covered:
                        covered.add(address)
                else:
                    if "distinct private-address cap reached" not in reasons:
                        reasons.append("distinct private-address cap reached")
                    # Keep positive diagnostic evidence even if ordinary
                    # covered addresses filled the retained sample first.
                    if not is_covered and covered:
                        retained.remove(covered.pop())
                        retained.add(address)
    if invalid:
        reasons.append(f"{invalid} malformed address bucket(s)")
    if omitted:
        reasons.append(f"network target cap reached; {omitted} target(s) not checked")
    reasons.extend(f"{target}: {why}" for target, why in unchecked.items())
    outside = [address for address in retained if not definition.is_internal(address)]
    prefixes = sorted({ipaddress.ip_network(f"{address}/{16 if address.version == 4 else 48}", strict=False)
                       for address in outside}, key=lambda network: _order(network.network_address))
    share = len(outside) / len(retained) if retained else None
    state = ("unknown" if reasons else "not_applicable" if not checked else
             "uncovered" if outside else "covered" if retained else "no_private_observed")
    result = {
        "schema": "network-address-coverage@1", "status": state,
        "window": ({"start": window.start.isoformat(), "end": window.end.isoformat(), "semantics": "[start,end)"}
                   if window is not None else "available indexed history"),
        "count_scope": "distinct canonical private IP addresses retained across source and destination fields",
        "private_ranges": [str(network) for network in PRIVATE_RANGES],
        "private_addresses": len(retained), "outside": len(outside), "outside_share": share,
        "at_least": bool(reasons), "invalid_addresses": invalid, "warning_threshold": WARN_SHARE,
        "warn": bool(reasons) or (share is not None and share > WARN_SHARE),
        "prefixes": [str(network) for network in prefixes[:PREFIX_LIMIT]],
        "prefixes_omitted": max(0, len(prefixes) - PREFIX_LIMIT),
        "checked_targets": checked, "unchecked_targets": unchecked, "reasons": reasons,
        "targets_omitted": omitted,
        "limits": {"terms_per_field": TERMS_SIZE, "distinct_private_addresses": DISTINCT_CAP,
                   "network_targets": TARGET_LIMIT},
        "arkime": {"status": "checked" if arkime and state != "unknown" else "unknown", "targets": arkime,
                   "note": ("Arkime session indices are checked through the configured search backend."
                            if arkime else "No queryable Arkime session target was configured; viewer-only coverage is unknown.")},
    }
    result["summary"] = _summary(result)
    return result
