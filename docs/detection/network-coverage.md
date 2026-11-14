# Internal-network coverage checks

The internal-network definition is a site declaration. ROMULUS never changes it
from observed traffic. Public addresses may belong to the site, and partner or
VPN private ranges may intentionally be external.

`romulus doctor` compares the declaration with the source and destination
addresses in configured network indices, including Arkime session indices. It
reads the seven days ending at each target's newest record, so an older capture
is still checked and a large site is not read in full; one extra request per
target finds that record.
Hunt creation runs the same check over the hunt's inclusive-start,
exclusive-end window and freezes the result at `internal_networks.coverage` in
the hunt manifest. Reports show uncovered private addresses or an unknown result
in the coverage section; the executive report carries the same note. The check
is a diagnostic: if it fails for any reason the hunt is still created, and the
result is recorded as unknown.

The diagnostic includes the [RFC 1918 ranges](https://www.rfc-editor.org/rfc/rfc1918.html),
[RFC 6598 shared address space](https://www.rfc-editor.org/info/rfc6598/), and
[IPv6 ULA](https://www.rfc-editor.org/rfc/rfc4193.html). It counts **distinct
canonical private IP addresses**, not packets, sessions, records, or confirmed
physical machines. IPv4-mapped IPv6 addresses count as the
corresponding IPv4 address. Loopback, link-local, documentation and other reserved
ranges are not part of the count, and neither are public addresses, whether or
not the site declares them as internal.

## What is asked of the cluster

One search request per network target, with a ten-second server timeout. For
each of the source and destination address fields that is mapped as `ip`:

- the documents are narrowed to those whose address is in a private range;
- the addresses the declaration may read as outside (in no internal range, or
  in a carve-out) are listed, lowest first, at most 1,000 per field, and
  counted with a `cardinality` aggregation;
- the remaining, covered addresses are counted with a second `cardinality`
  aggregation and are not listed.

Public peers and declared addresses therefore never use the listing: a sensor
that saw thousands of internet addresses still names an undeclared private
range, and a sensor showing only internet addresses produces no
missing-private-range warning. Every listed address is judged again locally
with the declaration itself, so a range declared inside a carve-out counts as
covered.

An address field mapped as a keyword cannot be selected by range. Its lowest
1,000 values are listed as they are and judged locally; the answer is complete
only when that listing holds every value.

## The numbers

- **Uncovered** is the set of listed addresses outside the declaration,
  deduplicated across both fields and all checked targets.
- **Covered** is the largest covered count any one field of any one target
  holds. Fields and targets overlap, so this is a lower bound on the number of
  distinct covered addresses, and the uncovered share leans high rather than
  low. Counts above 40,000 are the backend's
  [cardinality estimate](https://www.elastic.co/docs/reference/aggregations/search-aggregations-metrics-cardinality-aggregation).
- The **share** is uncovered divided by uncovered plus covered.

A share **greater than 10%** uncovered produces a warning: an omitted range
covering more than one in ten observed private endpoints deserves an operator
check. Any smaller omission is still reported. IPv4 examples are grouped as
`/16` prefixes. ULA examples use `/48`, the site's global-ID prefix, rather than a
`/16` covering many unrelated ULA sites. These are examples to review, not ranges
to accept automatically.

## Results

| Result | Meaning |
|---|---|
| `covered` | Private addresses were observed and every one is inside the declaration. |
| `uncovered` | At least one observed private address is outside the declaration. The prefixes are named. |
| `no_private_observed` | The observation is complete and holds no private address. |
| `unknown` | The observation is incomplete and showed no uncovered address. |
| `not_applicable` | No queryable network target is configured. |

An uncovered address that was seen is reported as `uncovered` whatever else is
incomplete. When the observation is incomplete the result says `at_least`,
warns, and its counts are lower bounds: the share then describes only the
addresses that were counted. When a field holds more uncovered addresses than
its listing returns, the summary also gives the backend's count of them for
that field.

The observation is incomplete when a listing is cut short, a query fails or
times out, a shard fails, an address is malformed, an endpoint field or the
target's clock cannot be queried exactly, or a limit below is reached. An
incomplete observation is never reported as covered.

## Limits

The diagnostic checks at most 1,000 network targets, keeps at most 10,000
distinct uncovered addresses across targets, and lists at most 20 uncovered
prefixes. It reports omitted target and prefix counts. Plain Zeek declarations
use their native endpoint fields and epoch-second clock; Arkime uses
`firstPacket`, as a date or numeric epoch milliseconds. Host-address checks
remain separate.

Arkime coverage is through its configured search-backend session indices. A
viewer URL alone does not expose a queryable session index to this check; its
coverage is recorded as unknown. No extra viewer endpoint is contacted.
