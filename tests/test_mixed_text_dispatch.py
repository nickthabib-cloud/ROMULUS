"""Synthetic mixed syslog/Windows exports follow their native envelopes.

https://www.rfc-editor.org/rfc/rfc5424#section-6
https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-systempropertiestype-complextype
"""
from copy import deepcopy

import pytest

from romulus.evidence.normalize import normalize_hits
from romulus.sources.profile import contract_from_types
from tests.test_syslog_header_host import hit


def contract(flag, *, role="host"):
    return contract_from_types("mixed-host", {"@timestamp": "date", "winlog.channel": "keyword",
        "message": "text", "log.file.path": "keyword"}, role=role, os_family="windows").model_copy(
            update={"linux_text_mixed": flag})


@pytest.mark.parametrize("flag", [True, None])
def test_mixed_or_unverified_host_still_types_independent_text(flag):
    events, skips, errors = normalize_hits([hit()], contract=contract(flag))
    assert not skips and not errors and len(events) == 1
    assert events[0].family == "auth" and events[0].host == "app01"


@pytest.mark.parametrize("flag,role", [(False, "host"), (True, "network"), (None, "network")])
def test_pure_windows_or_network_target_cannot_acquire_text_dispatch(flag, role):
    events, skips, errors = normalize_hits([hit()], contract=contract(flag, role=role))
    assert not events and not errors and sum(skips.values()) == 1


@pytest.mark.parametrize("marker", [{"winlog": {}}, {"Event": {"System": {}}},
    {"Channel": None}, {"EventID": None}, {"SourceName": None}])
def test_windows_markers_do_not_fall_into_linux_text(marker):
    row = deepcopy(hit())
    row["_source"].update(marker)
    events, skips, errors = normalize_hits([row], contract=contract(True))
    assert not events and (skips or errors)
