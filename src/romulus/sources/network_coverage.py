"""Bounded preflight coverage of declared networks against observed network endpoints.

This is a configuration diagnostic, not an inference that every private address is
owned by the site. Partner and VPN carve-outs can explain uncovered observations.
"""
from __future__ import annotations

import ipaddress
import math
from datetime import UTC, datetime, timedelta
from itertools import islice

from romulus.detect.netdef import ALWAYS_INTERNAL, INTERNAL_SETTING, SiteNetworks
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
# Direction: whether the definition reads any of the observed traffic as the site's own, over every address (a site
# may use public space, which the private-address check above never sees). A sensor placed for a site records the
# site's traffic, so nearly every session it holds has a site endpoint: the destination of an inbound scan or brute
# force, the source of an outbound connection, both ends of lateral traffic. When fewer than one session in twenty of a
# target has an endpoint inside the definition, the definition is the likely fault there, and the rules that need an
# internal side (inbound, outbound and lateral traffic) evaluate little or nothing of it. Each target is judged on its
# own, so a well-covered one cannot hide another. Where a target's addresses cannot be selected by range in the
# cluster, its busiest addresses on each side are judged here instead.
MIN_INTERNAL_SHARE = 0.05
BUSIEST = 20                            # addresses per side, by session count, judged with the definition
BUSIEST_NAMED = 5                       # of those outside the definition, named in the summary
# Loopback and link-local are internal under every definition, and link-local chatter (neighbour discovery, mDNS,
# LLMNR) can be a real share of what a tap records: they never count as the site's own here, or they could mask a
# definition that names none of the site's ranges.
LOCAL_ONLY = tuple(map(ipaddress.ip_network, ALWAYS_INTERNAL))
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


def _inside(field, definition):
    """Documents whose `field` holds an address the definition may read as internal (an internal range outside every
    carve-out; a range nested inside a carve-out is counted outside, so the count never overstates), loopback and
    link-local aside."""
    return {"bool": {"must_not": [outside_candidates(field, definition),
                                  {"terms": {field: [str(network) for network in LOCAL_ONLY]}}]}}


def _site_address(address, definition) -> bool:
    """An address the definition reads as the site's own, loopback and link-local aside."""
    local = any(address.version == network.version and address in network for network in LOCAL_ONLY)
    return not local and definition.is_internal(address)


def _direction(fields, definition):
    """The sessions in the window, the busiest addresses on each side, and, when both sides are ip fields, the
    sessions with an endpoint inside the definition, counted in the cluster."""
    aggs = {"sessions": {"filter": {"match_all": {}}}}
    for side, (field, _is_ip) in fields.items():
        aggs[f"busiest_{side}"] = {"terms": {"field": field, "size": BUSIEST}}
    if all(is_ip for _field, is_ip in fields.values()):
        aggs["with_internal"] = {"filter": {"bool": {"should": [_inside(field, definition)
                                                                for field, _is_ip in fields.values()],
                                                     "minimum_should_match": 1}}}
    return aggs


def _query(contract, fields, definition, window):
    return {"size": 0, "track_total_hits": False, "timeout": "10s",
            "query": {"bool": {"filter": [_bounds(contract, window.start, window.end)]}},
            "aggs": {**{side: _side(field, is_ip, definition) for side, (field, is_ip) in fields.items()},
                     **_direction(fields, definition)}}


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


def _doc_count(node):
    value = node.get("doc_count") if isinstance(node, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _prefix(address):
    return ipaddress.ip_network(f"{address}/{16 if address.version == 4 else 48}", strict=False)


class _Direction:
    """What the targets' answers say about the share of sessions with an endpoint inside the definition, judged per
    target: one target whose sessions almost never touch the site (a DMZ or an enclave in space the definition
    misses) warns even when the others' pooled share looks fine."""

    def __init__(self):
        self.targets: list[dict] = []              # per target: sessions, counts and verdict
        self.outside = {}                          # prefix -> sessions, for the busiest addresses outside
        self.reasons = []

    def read(self, target, aggregations, fields, definition, incomplete):
        sessions = _doc_count(aggregations.get("sessions"))
        if sessions is None:
            self.reasons.append(f"{target}: session count missing")
            return
        if incomplete:
            self.reasons.append(f"{target}: {incomplete}")
        talkers, readable, unread = False, True, 0
        for side in fields:
            terms = aggregations.get(f"busiest_{side}")
            buckets = terms.get("buckets") if isinstance(terms, dict) else None
            if not isinstance(buckets, list):
                self.reasons.append(f"{target}: busiest {side} addresses missing")
                readable = False
                continue
            for bucket in islice(buckets, BUSIEST):
                key = bucket.get("key") if isinstance(bucket, dict) else None
                count = _doc_count(bucket) or 0
                try:
                    if not isinstance(key, str) or len(key) > 45:
                        raise ValueError("not a bounded IP address")
                    address = ipaddress.ip_address(key)
                except ValueError:
                    readable, unread = False, unread + 1
                    continue
                if address.version == 6 and address.ipv4_mapped:
                    address = address.ipv4_mapped
                if any(address.version == network.version and address in network for network in LOCAL_ONLY):
                    continue                     # neither the site's own nor a range worth naming
                if _site_address(address, definition):
                    talkers = True
                else:
                    prefix = _prefix(address)
                    self.outside[prefix] = self.outside.get(prefix, 0) + count
        if unread:
            self.reasons.append(f"{target}: {unread} busiest address value(s) not readable as IP addresses")
        entry = {"target": target, "sessions": sessions, "with_internal": None, "internal_share": None,
                 "method": "counted", "internal_talker": talkers, "complete": not incomplete, "low": False}
        if all(is_ip for _field, is_ip in fields.values()):        # counted in the cluster (see _direction)
            internal = _doc_count(aggregations.get("with_internal"))
            if internal is None:
                self.reasons.append(f"{target}: internal-endpoint count missing")
                return
            entry.update(with_internal=internal, internal_share=internal / sessions if sessions else None)
            entry["low"] = bool(sessions) and internal / sessions < MIN_INTERNAL_SHARE
        else:
            # judged on the busiest addresses alone: said to hold none of the site's only when all of them were read
            entry["method"] = "judged"
            entry["low"] = bool(sessions) and readable and not talkers
        self.targets.append(entry)

    def record(self, window_text, unchecked, reported=()) -> dict:
        counted = [t for t in self.targets if t["method"] == "counted"]
        judged = [t for t in self.targets if t["method"] == "judged"]
        sessions = sum(t["sessions"] for t in counted)
        internal = sum(t["with_internal"] for t in counted)
        share = internal / sessions if sessions else None
        low = [t for t in self.targets if t["low"]]
        seen = bool(internal) or any(t["internal_talker"] for t in self.targets)
        reasons = [*self.reasons, *(f"{target}: {why}" for target, why in unchecked.items())]
        if low:
            state = "rare" if seen else "none"
        elif not self.targets:
            state = "unknown" if reasons else "not_applicable"
        elif not any(t["sessions"] for t in self.targets):
            state = "unknown" if reasons else "no_sessions"
        elif reasons:
            # an answer cut short or a target not read is never taken for a fine one
            state = "partial" if seen else "unknown"
        else:
            state = "ok"
        # certain only when every target under the share was counted exactly and none of its sessions was internal
        certain = bool(low) and all(t["method"] == "counted" and t["complete"] and t["with_internal"] == 0
                                    for t in low)
        busiest = sorted(self.outside.items(), key=lambda item: (-item[1], _order(item[0].network_address)))
        out = {"status": state, "warn": state in ("none", "rare", "unknown", "partial"), "sessions": sessions,
               "with_internal": internal, "internal_share": share, "minimum_share": MIN_INTERNAL_SHARE,
               "window": window_text, "counted_targets": [t["target"] for t in counted],
               "judged_targets": [t["target"] for t in judged],
               "low_targets": [t["target"] for t in low],
               "judged_without_internal": [t["target"] for t in judged if t["low"]],
               "certain": certain, "busiest_per_side": BUSIEST,
               "per_target": [{k: t[k] for k in ("target", "sessions", "with_internal", "internal_share", "method",
                                                 "internal_talker", "low")} for t in self.targets],
               "busiest_outside": [{"prefix": str(prefix), "sessions": count}
                                   for prefix, count in busiest[:BUSIEST_NAMED]],
               "partial": bool(reasons), "reasons": reasons}
        out["summary"] = _direction_summary(out, set(reported))
        return out


def _direction_summary(d, reported: set) -> str:
    state = d["status"]
    if state == "not_applicable":
        return ""
    # reasons the coverage summary already names are not repeated here
    extra = [reason for reason in d["reasons"] if reason not in reported]
    partial = ""
    if d["partial"]:
        partial = "; partial: " + ("; ".join(extra) if extra else "the incomplete answers named above")
        if extra and len(extra) < len(d["reasons"]):
            partial += ", and those named above"
    where = (f"{d['window']}; {len(d['counted_targets']) + len(d['judged_targets'])} network target(s) checked"
             + partial)
    share = d["internal_share"]
    parts = []
    if d["counted_targets"]:
        parts.append(f"{d['with_internal']:,} of {d['sessions']:,} sessions"
                     + (f" ({share:.1%})" if share is not None else "")
                     + " had an endpoint inside the internal networks")
    if d["judged_targets"]:
        bare = d["judged_without_internal"]
        every = all(t["internal_talker"] for t in d["per_target"] if t["method"] == "judged")
        parts.append(f"in {len(d['judged_targets'])} target(s) whose addresses cannot be selected by range, the "
                     f"{d['busiest_per_side']} busiest addresses on each side were judged"
                     + (f", and none of them was internal in {', '.join(bare)}" if bare else
                        ", and an internal one was among them in each" if every else ""))
    found = "; ".join(parts)
    if state == "unknown":
        return f"Traffic direction unknown: {found or 'no session was counted'} ({where})."
    if state == "no_sessions":
        return f"Traffic direction: no session was recorded in the window ({where})."
    text = f"Traffic direction: {found} ({where})."
    if state == "partial":
        text += " The answer is partial, so the share is not confirmed."
    if state in ("none", "rare"):
        counted_low = [t for t in d["per_target"] if t["low"] and t["method"] == "counted"]
        if counted_low:
            text += (f" Fewer than {MIN_INTERNAL_SHARE:.0%} of sessions had an internal endpoint in: "
                     + ", ".join(f"{t['target']} ({t['with_internal']:,} of {t['sessions']:,})" for t in counted_low)
                     + ".")
        effect = "will evaluate almost nothing" if d["certain"] else "may evaluate little or nothing"
        text += (f" Rules that need an internal side (inbound, outbound and lateral traffic) {effect} there: check "
                 f"the internal networks (Site setup page or {INTERNAL_SETTING}).")
        if d["busiest_outside"]:
            text += (" Busiest prefixes outside the definition (the site's own or external peers): "
                     + ", ".join(f"{p['prefix']} ({p['sessions']:,} sessions)" for p in d["busiest_outside"]) + ".")
        text += (f" Warning threshold: fewer than {MIN_INTERNAL_SHARE:.0%} of a target's sessions with an internal "
                 "endpoint.")
    return text


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
            + (f" ({share:.1%})" if share is not None else ""))
    estimate = result["outside_estimate"]
    if estimate is not None and estimate > outside:
        # a listing that was cut short: the cluster's own count of what it was drawn from says how short
        text += f"; one address field alone holds about {estimate:,} that may be outside"
    text += ". "
    if result["prefixes"]:
        text += ("Uncovered prefixes (IPv4 /16, IPv6 ULA /48): " + ", ".join(result["prefixes"])
                 + (f"; {result['prefixes_omitted']} more" if result["prefixes_omitted"] else "") + ". ")
    if result["reasons"]:
        text += (("Coverage unknown: the" if state == "unknown" else "The") + " bounded observation is incomplete; "
                 "counts are lower bounds and its share describes only counted addresses. "
                 + "; ".join(result["reasons"]) + ". ")
    elif state == "no_private_observed":
        text += "No RFC 1918, RFC 6598 or ULA addresses were observed; this does not require declaring private ranges. "
    if outside:
        text += (f"Check {INTERNAL_SETTING}; a partner/VPN carve-out may be intentional. The definition was not "
                 "changed automatically. ")
    text += f"Warning threshold: more than {WARN_SHARE:.0%} of observed private addresses uncovered."
    return text


def _result(window, state, *, outside=(), covered=0, reasons=(), checked=(), unchecked=None, omitted=0, invalid=0,
            arkime=(), estimate=None, direction: _Direction | None = None):
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
        "arkime": {"status": "checked" if arkime and not reasons else "unknown", "targets": list(arkime),
                   "note": ("Arkime session indices are checked through the configured search backend."
                            if arkime else "No queryable Arkime session target was configured; viewer-only coverage is unknown.")},
    }
    if direction is not None:
        span = result["window"]
        result["direction"] = direction.record(
            f"{span['start']} to {span['end']}" if isinstance(span, dict) else span, unchecked or {},
            reported=result["reasons"])
        result["warn"] = result["warn"] or result["direction"]["warn"]
    result["summary"] = _summary(result)
    if (result.get("direction") or {}).get("summary"):
        result["summary"] += " " + result["direction"]["summary"]
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

    More uncovered addresses than one listing returns, a missing field or a failed response makes every count a
    lower bound (`at_least`) and warns. The answer is then `uncovered` when any uncovered address was listed,
    naming the prefixes that were seen, and `unknown` only when none was. The bounded diagnostic does not affect
    detection retention, direction semantics or site settings.
    """
    outside, inside = set(), set()
    checked, unchecked, reasons, arkime = [], {}, [], []
    invalid = considered = omitted = covered = 0
    estimate = None
    direction = _Direction()
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
            direction.reasons.append(reasons[-1])
            continue
        except ValueError:
            reasons.append(f"{target}: newest record time unknown")
            direction.reasons.append(reasons[-1])
            continue
        if not isinstance(response, dict):
            reasons.append(f"{target}: malformed network-address response")
            direction.reasons.append(reasons[-1])
            continue
        if (problem := _incomplete(response)) is not None:
            reasons.append(f"{target}: {problem}")
        aggregations = response.get("aggregations")
        if not isinstance(aggregations, dict):
            reasons.append(f"{target}: address aggregations missing")
            direction.reasons.append(reasons[-1])
            continue
        direction.read(target, aggregations, fields, definition, problem)
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
        direction.reasons.append(reasons[-1])
    reasons.extend(f"{target}: {why}" for target, why in unchecked.items())
    # An uncovered address that was seen is a finding whatever else is incomplete; only an incomplete observation
    # that saw none leaves the question open.
    state = ("uncovered" if outside else "unknown" if reasons else "not_applicable" if not checked else
             "covered" if covered else "no_private_observed")
    return _result(window, state, outside=outside, covered=covered, reasons=reasons, checked=checked,
                   unchecked=unchecked, omitted=omitted, invalid=invalid, arkime=arkime, estimate=estimate,
                   direction=direction)
