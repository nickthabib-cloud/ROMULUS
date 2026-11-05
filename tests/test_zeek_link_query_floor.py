"""A Zeek join never starts a fetch it cannot finish, one anchor's variants share one slot of the expansion budget,
and an unsearched host witness states no absence."""
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest

from romulus.hunt.expansion import _slot_groups_after
from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkWindow
from tests.fixtures import zeek_factory as zf
from tests.fixtures import zeek_logs as zl
from tests.test_zeek_link_regressions import host_hit, normalize, real_pivot


def _fetch(tmp_path, hits, anchor_hit, kind, cap, host_hits=()):
    with real_pivot(tmp_path, hits, list(host_hits)) as (_repo, pivot, backend):
        root = normalize("malcolm", anchor_hit)
        anchor = LinkAnchor(finding_id="f", ts=root.ts, events=[root], event_ids=[root.id])
        window = LinkWindow(label="t", start=root.ts - timedelta(minutes=5), end=root.ts + timedelta(minutes=5))
        return LinkFetcher(pivot, window.start, window.end).fetch(anchor, kind, window, query_cap=cap), backend


@pytest.mark.parametrize("cap,status", [(2, "partial"), (3, "complete"), (12, "complete")])
def test_a_join_below_one_physical_fetch_is_not_started(tmp_path, cap, status):
    conn = zf.malcolm(replace(zf.Conn(), uid="Csmall", ts=zl.FILES.ts), "small")
    http = zl.malcolm(replace(zl.HTTP.with_(uid="Csmall"), ts=zl.FILES.ts + 1), "small-http")
    result, backend = _fetch(tmp_path, [conn, http], conn, "zeek_uid", cap)
    assert result.status == status
    if status == "partial":
        assert backend.queries == [] and result.query_spend == 0
        assert any("below one physical fetch" in reason for reason in result.reasons)
    else:
        assert len(result.event_ids) == 1


@pytest.mark.parametrize("cap", [4, 5])
def test_an_unsearched_host_witness_states_no_absence(tmp_path, cap):
    lease = zl.DHCP.with_(assigned_addr=zf.Conn().orig_h, host_name="first", lease_time=1800)
    anchor = zf.malcolm(replace(zf.Conn(), ts=lease.ts + 60), "anchor")
    result, _ = _fetch(tmp_path, [zl.malcolm(lease, "lease"), anchor], anchor, "address_host", cap,
                       [host_hit("first", lease.ts + 30, 1)])
    assert result.status == "partial"
    assert not any("matches no host-telemetry host" in reason for reason in result.reasons)


def test_one_anchors_zeek_variants_count_as_one_budget_slot():
    def slot(anchor, kind):
        return SimpleNamespace(row={"id": anchor}, link_type=kind)
    slots = [*(slot("big", "zeek_uid") for _ in range(1000)), slot("big", "process_tree"), slot("small", "zeek_uid")]
    groups = _slot_groups_after(slots)
    assert groups[0] == 3 and groups[999] == 3 and groups[1000] == 2 and groups[1001] == 1
    plain = [slot("a", "process_tree") for _ in range(4)]
    assert _slot_groups_after(plain) == [4, 3, 2, 1]
