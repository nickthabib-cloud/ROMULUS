"""Bounded preflight coverage of declared networks against observed network endpoints.

This is a configuration diagnostic, not an inference that every private address is
owned by the site. Partner and VPN carve-outs can explain uncovered observations.
"""
from __future__ import annotations

import ipaddress
import math
from datetime import UTC, datetime, timedelta
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
# The largest precision a cardinality aggregation takes: counts up to it are near exact, larger ones approximate.
CARDINALITY_PRECISION = 40_000
DOCTOR_LOOKBACK = timedelta(days=7)    # doctor checks the week ending at each target's newest record
# A missing range affecting more than one in ten observed private endpoints merits
# an operator check. Smaller omissions are still reported, never silently covered.
WARN_SHARE = 0.10
PRIVATE_RANGES = tuple(map(ipaddress.ip_network, (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7",
)))
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _private(address):
    return any(address.version == network.version and address in network for network in PRIVATE_RANGES)


def _order(address):
    return address.version, int(address)


def outside_candidates(field: str, definition: SiteNetworks) -> dict:
    """A query for addresses that may be outside `definition`: not in any internal range, or in a carve-out. It
    is a superset of what the definition reads as outside (a range nested inside a carve-out is internal again),
    so every candidate is judged locally with the definition itself."""
    internal = [str(n) for n in definition.effective_internal()]
    clauses: list[dict] = [{"bool": {"must_not": [{"terms": {field: internal}}]}}]
    if definition.external:
        clauses.append({"terms": {field: [str(n) for n in definition.external]}})
    return {"bool": {"should": clauses, "minimum_should_match": 1}}


def _field(contract, typed):
    """Only exact aggregate fields; alternative layouts cannot silently be omitted. Returns the native field and
    whether it is an ip field (the only type address ranges can select from)."""
    name = typed
    if contract.zeek_sensor:
        name = {"source.ip": "id.orig_h", "destination.ip": "id.resp_h"}[typed]
    spec = contract.spec(name)
    if spec is None or not spec.aggregatable or spec.alternatives or len(spec.natives) > 1:
        return None
    if spec.type not in {"ip", "keyword", "constant_keyword", "wildcard"}:
        return None
    return spec.aggregation_native or spec.native, spec.type == "ip"


def _bounds(contract, start, end):
    """The [start, end) range clause on the target's own clock; None when that clock has no exact form."""
    stamp = contract.spec(contract.time_field)
    if contract.zeek_sensor:
        bounds = {"gte": start.timestamp(), "lt": end.timestamp()}
    elif stamp is not None and stamp.type in {"date", "date_nanos"}:
        bounds = {"gte": start.isoformat(), "lt": end.isoformat()}
    elif contract.time_field == "firstPacket" and stamp is not None and stamp.type in {
        "long", "integer", "double", "float",
    }:
        bounds = {"gte": epoch_ms_ceiling(start), "lt": epoch_ms_ceiling(end)}
    else:
        return None
    return {"range": {contract.time_field: bounds}}


def _side(field, is_ip, definition):
    """One side's aggregation. An ip field is narrowed in the cluster to the private ranges and then split into
    the addresses the definition may read as outside (listed, lowest first, and counted) and the rest (counted),
    so public peers and declared addresses never use the listing. Ranges cannot select from a keyword field: its
    lowest values are listed as they are and every one is judged locally."""
    listing = {"terms": {"field": field, "size": TERMS_SIZE, "order": {"_key": "asc"}}}
    if not is_ip:
        return listing
    distinct = {"cardinality": {"field": field, "precision_threshold": CARDINALITY_PRECISION}}
    candidates = outside_candidates(field, definition)
    return {"filter": {"terms": {field: [str(network) for network in PRIVATE_RANGES]}}, "aggs": {
        "covered": {"filter": {"bool": {"must_not": [candidates]}}, "aggs": {"distinct": distinct}},
        "outside": {"filter": candidates, "aggs": {"addresses": listing, "distinct": distinct}}}}


def _fields(contract):
    """Each side's (native field, is ip); None when a side or the target's clock cannot be queried exactly."""
    fields = {side: _field(contract, f"{side}.ip") for side in ("source", "destination")}
    if not all(fields.values()) or _bounds(contract, _EPOCH, _EPOCH) is None:
        return None
    return fields


def _query(contract, fields, definition, window):
    return {"size": 0, "track_total_hits": False, "timeout": "10s",
            "query": {"bool": {"filter": [_bounds(contract, window.start, window.end)]}},
            "aggs": {side: _side(field, is_ip, definition) for side, (field, is_ip) in fields.items()}}


def _incomplete(response):
    """Why a search answer cannot stand as a complete one; None when it can. The client asks the cluster for
    the failed shard count alone, so that count is the shard evidence."""
    if response.get("timed_out") is not False or response.get("terminated_early"):
        return "timed out, terminated early or timeout state unknown"
    shards = response.get("_shards")
    failed = shards.get("failed") if isinstance(shards, dict) else None
    if isinstance(failed, bool) or failed != 0:
        return "shard completeness unknown or failed"
    return None


def _recent_window(client, target, contract):
    """The DOCTOR_LOOKBACK ending at the target's newest record; None for a target with no record. Raises
    ValueError when the answer cannot be read as a complete one."""
    response = client.search(target, {"size": 0, "track_total_hits": False, "timeout": "10s",
                                      "aggs": {"newest": {"max": {"field": contract.time_field}}}})
    if not isinstance(response, dict) or _incomplete(response) is not None:
        raise ValueError("newest record time unknown")
    aggregations = response.get("aggregations")
    newest = aggregations.get("newest") if isinstance(aggregations, dict) else None
    value = newest.get("value") if isinstance(newest, dict) else math.nan    # no answer at all is not "no record"
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
        raise ValueError("newest record time unknown")
    try:
        # a max over a date field is epoch milliseconds, as is Arkime's numeric clock; a plain Zeek clock is seconds
        end = datetime.fromtimestamp(value if contract.zeek_sensor else value / 1000, UTC)
        # the range's end is exclusive, and the newest record itself belongs inside it
        return Window(start=end - DOCTOR_LOOKBACK, end=end + timedelta(milliseconds=1))
    except (OverflowError, OSError, ValueError) as error:
        raise ValueError("newest record time unknown") from error


def _count(node):
    """The value of the `distinct` cardinality under an aggregation; None when the answer does not carry one."""
    distinct = node.get("distinct") if isinstance(node, dict) else None
    value = distinct.get("value") if isinstance(distinct, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _summary(result):
    state = result["status"]
    if state == "not_applicable":
        return "No queryable network targets were configured; network-address coverage was not assessed."
    count, outside = result["private_addresses"], result["outside"]
    share = result["outside_share"]
    text = (f"Observed private network addresses: {'at least ' if result['at_least'] and outside else ''}{outside} "
            f"of {count} distinct counted addresses outside the declared internal networks"
            + (f" ({share:.1%})" if share is not None else "") + ". ")
    if result["prefixes"]:
        text += ("Uncovered prefixes (IPv4 /16, IPv6 ULA /48): " + ", ".join(result["prefixes"])
                 + (f"; {result['prefixes_omitted']} more" if result["prefixes_omitted"] else "") + ". ")
    if state == "unknown":
        text += ("Coverage unknown: the bounded observation is incomplete; counts are lower bounds and its share "
                 "describes only counted addresses. " + "; ".join(result["reasons"]) + ". ")
    elif state == "no_private_observed":
        text += "No RFC 1918, RFC 6598 or ULA addresses were observed; this does not require declaring private ranges. "
    if outside:
        text += (f"Check {INTERNAL_SETTING}; a partner/VPN carve-out may be intentional. The definition was not "
                 "changed automatically. ")
    text += f"Warning threshold: more than {WARN_SHARE:.0%} of observed private addresses uncovered."
    return text


def _result(window, state, *, outside=(), covered=0, reasons=(), checked=(), unchecked=None, omitted=0, invalid=0,
            arkime=(), estimate=None):
    """The recorded answer: `outside` holds the uncovered addresses that were listed, `covered` counts the rest."""
    prefixes = sorted({ipaddress.ip_network(f"{address}/{16 if address.version == 4 else 48}", strict=False)
                       for address in outside}, key=lambda network: _order(network.network_address))
    count = len(outside) + covered
    share = len(outside) / count if count else None
    result = {
        "schema": "network-address-coverage@2", "status": state,
        "window": ({"start": window.start.isoformat(), "end": window.end.isoformat(), "semantics": "[start,end)"}
                   if window is not None else f"last {DOCTOR_LOOKBACK.days} days of each target"),
        "count_scope": ("distinct canonical private IP addresses across source and destination fields: every "
                        "listed uncovered address, plus the largest number of covered addresses any one field "
                        "holds (a lower bound on their union)"),
        "private_ranges": [str(network) for network in PRIVATE_RANGES],
        "private_addresses": count, "outside": len(outside), "covered": covered, "outside_share": share,
        # how many distinct candidates one capped listing was drawn from: the size of what it left out
        "outside_estimate": estimate,
        "at_least": bool(reasons), "invalid_addresses": invalid, "warning_threshold": WARN_SHARE,
        "warn": bool(reasons) or (share is not None and share > WARN_SHARE),
        "prefixes": [str(network) for network in prefixes[:PREFIX_LIMIT]],
        "prefixes_omitted": max(0, len(prefixes) - PREFIX_LIMIT),
        "checked_targets": list(checked), "unchecked_targets": dict(unchecked or {}), "reasons": list(reasons),
        "targets_omitted": omitted,
        "limits": {"terms_per_field": TERMS_SIZE, "distinct_private_addresses": DISTINCT_CAP,
                   "network_targets": TARGET_LIMIT},
        "arkime": {"status": "checked" if arkime and state != "unknown" else "unknown", "targets": list(arkime),
                   "note": ("Arkime session indices are checked through the configured search backend."
                            if arkime else "No queryable Arkime session target was configured; viewer-only coverage is unknown.")},
    }
    result["summary"] = _summary(result)
    return result


def unknown_coverage(window: Window | None, reason: str) -> dict:
    """The answer for a check that could not run: coverage unknown, naming why."""
    return _result(window, "unknown", reasons=[reason])


def check_network_addresses(client, contracts: dict[str, FieldContract | None], definition: SiteNetworks,
                            window: Window | None) -> dict:
    """One coverage request per network target, including Arkime session targets, over `window` (the hunt's) or,
    with None, over the week ending at each target's newest record (one more request finds that record).

    An ip field is narrowed in the cluster to the private ranges before anything is listed, and the listing
    holds only addresses the definition may read as outside, so a site's public peers and its declared addresses
    never crowd an undeclared range out of the answer. Every listed address is judged here with the definition
    itself. Covered addresses are counted, not listed: the share's denominator is the listed uncovered addresses
    plus the largest covered count any one field holds, a lower bound on the union across fields and targets.

    More uncovered addresses than one listing returns, a missing field or a failed response makes coverage
    unknown and every count a lower bound; the uncovered prefixes that were seen are still named. The bounded
    diagnostic does not affect detection retention, direction semantics or site settings.
    """
    outside, inside = set(), set()
    checked, unchecked, reasons, arkime = [], {}, [], []
    invalid = considered = omitted = covered = 0
    estimate = None
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
        fields = _fields(contract)
        if fields is None:
            unchecked[target] = "source/destination addresses or the hunt clock cannot be aggregated exactly"
            continue
        checked.append(target)
        try:
            span = window or _recent_window(client, target, contract)
            if span is None:
                continue                                # a target with no record observed no address
            response = client.search(target, _query(contract, fields, definition, span))
        except SourceError:
            # Backend text can contain URL/auth details. The target and failed
            # operation are sufficient to identify this unresolved check.
            reasons.append(f"{target}: network-address query failed")
            continue
        except ValueError:
            reasons.append(f"{target}: newest record time unknown")
            continue
        if not isinstance(response, dict):
            reasons.append(f"{target}: malformed network-address response")
            continue
        if (problem := _incomplete(response)) is not None:
            reasons.append(f"{target}: {problem}")
        aggregations = response.get("aggregations")
        if not isinstance(aggregations, dict):
            reasons.append(f"{target}: address aggregations missing")
            continue
        for side, (_native, is_ip) in fields.items():
            found, terms, counted = None, aggregations.get(side), 0
            if is_ip:
                node = terms if isinstance(terms, dict) else {}
                found = node.get("outside")
                terms = found.get("addresses") if isinstance(found, dict) else None
                counted = _count(node.get("covered"))
                if counted is None:
                    reasons.append(f"{target}: {side} covered-address count missing")
                    counted = 0
            if not isinstance(terms, dict) or not isinstance(terms.get("buckets"), list):
                reasons.append(f"{target}: {side} address buckets missing")
                covered = max(covered, counted)
                continue
            if (terms.get("sum_other_doc_count") != 0
                    or terms.get("doc_count_error_upper_bound") != 0
                    or len(terms["buckets"]) > TERMS_SIZE):
                reasons.append(f"{target}: {side} terms capped or completeness unknown")
                if (more := _count(found)) is not None:
                    estimate = max(estimate or 0, more)
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
                if not _private(address):
                    continue
                # Covered and uncovered addresses are kept apart, so ordinary covered
                # addresses can never take the room an uncovered one needs.
                is_covered = definition.is_internal(address)
                kept = inside if is_covered else outside
                if address not in kept:
                    if len(kept) >= DISTINCT_CAP:
                        if "distinct private-address cap reached" not in reasons:
                            reasons.append("distinct private-address cap reached")
                        continue
                    kept.add(address)
                if is_covered and is_ip:
                    counted += 1    # a listed candidate the definition reads as internal: not in the covered count
            covered = max(covered, counted)
    covered = max(covered, len(inside))
    if invalid:
        reasons.append(f"{invalid} malformed address bucket(s)")
    if omitted:
        reasons.append(f"network target cap reached; {omitted} target(s) not checked")
    reasons.extend(f"{target}: {why}" for target, why in unchecked.items())
    state = ("unknown" if reasons else "not_applicable" if not checked else
             "uncovered" if outside else "covered" if covered else "no_private_observed")
    return _result(window, state, outside=outside, covered=covered, reasons=reasons, checked=checked,
                   unchecked=unchecked, omitted=omitted, invalid=invalid, arkime=arkime, estimate=estimate)
