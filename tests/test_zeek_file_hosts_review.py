"""Single-host legacy file rows preserve both address indicator inputs."""
import pytest

from romulus.detect.indicators import Indicator, IndicatorMatch, IndicatorSet
from tests.fixtures import zeek_logs as zl
from tests.test_indicators import run as run_indicator
from tests.test_zeek_analyzers import normalize as normalize_analyzer


@pytest.mark.parametrize("shape", zl.SHAPES)
def test_single_old_file_hosts_remain_address_indicator_inputs_without_uid(shape):
    row = zl.FILES_50.without("conn_uids", "is_orig")
    event = normalize_analyzer(zl.WRITERS[shape](row, f"old-files-{shape}"))
    assert event.get("zeek.uid") is None
    assert event.get("source.ip") == zl.SERVER
    assert event.get("destination.ip") == zl.CLIENT
    for address in (zl.SERVER, zl.CLIENT):
        owner = IndicatorMatch(IndicatorSet([
            Indicator("test.address", "ip", (address,), "Synthetic address", "medium", "lead")]))
        try:
            assert run_indicator(owner, event)
        finally:
            owner.release_state()
