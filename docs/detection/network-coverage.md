# Internal-network coverage checks

The internal-network definition is a site declaration. ROMULUS never changes it
from observed traffic. Public addresses may belong to the site, and partner or
VPN private ranges may intentionally be external.

`romulus doctor` compares the declaration with distinct source and destination
addresses in configured network indices, including Arkime session indices. It
uses the available indexed history so that an older capture is still checked.
Hunt creation runs the same check over the hunt's inclusive-start,
exclusive-end window and freezes the result at `internal_networks.coverage` in
the hunt manifest. Reports show uncovered private addresses or an unknown result
in the coverage section; the executive report carries the same note.

The diagnostic includes the [RFC 1918 ranges](https://www.rfc-editor.org/rfc/rfc1918.html),
[RFC 6598 shared address space](https://www.rfc-editor.org/info/rfc6598/), and
[IPv6 ULA](https://www.rfc-editor.org/rfc/rfc4193.html). Its percentage is the
union of **distinct canonical private IP addresses**, deduplicated across both
endpoints and all checked targets. It is not a percentage of packets, sessions,
records, or confirmed physical machines. IPv4-mapped IPv6 addresses count as the
corresponding IPv4 address. Loopback, link-local, documentation and other reserved
ranges are not added to this diagnostic's private-range denominator.

A share **greater than 10%** uncovered produces a warning: an omitted range
covering more than one in ten observed private endpoints deserves an operator
check. Any smaller omission is still reported. IPv4 examples are grouped as
`/16` prefixes. ULA examples use `/48`, the site's global-ID prefix, rather than a
`/16` covering many unrelated ULA sites. These are examples to review, not ranges
to accept automatically. A sensor showing only internet addresses does not
produce a missing-private-range warning.

One search request per network target contains source and destination `terms`
aggregations, each capped at 1,000 buckets, ordered by key, with a ten-second
server timeout. The diagnostic checks at most 1,000 network targets, retains at
most 10,000 distinct private addresses, and lists at most 20 uncovered prefixes.
It reports omitted target and prefix counts. Plain Zeek declarations use their
native endpoint fields and epoch-second clock; Arkime uses `firstPacket`, as a
date or numeric epoch milliseconds. Host-address checks remain separate.

Any cap, failed query, timeout, shard failure, malformed address, missing exact
endpoint mapping or unavailable clock makes coverage **unknown**, never covered.
The counts then describe retained observations and are lower bounds; the shown
share describes that bounded subset, not the full network. When the retained
address limit is reached, uncovered addresses take priority over covered
examples so that known gaps remain visible. This subset is not a random sample.
Returned bucket counts and omitted-bucket metadata follow the backend's
[terms-aggregation contract](https://www.elastic.co/docs/reference/aggregations/search-aggregations-bucket-terms-aggregation).

Arkime coverage is through its configured search-backend session indices. A
viewer URL alone does not expose a queryable session index to this check; its
coverage is recorded as unknown. No extra viewer endpoint is contacted. A
complete check with no private addresses says `no_private_observed`, and a
configuration without network targets says `not_applicable`.
