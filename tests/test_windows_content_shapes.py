"""Behavior content, rather than per-execution identity, controls fleet folding."""
from romulus.detect.windows_events import WindowsEventRule, signal
from tests.windows_event_support import event


def test_file_time_instances_fold_and_share_outcomes_remain_distinct_behavior_content():
    from romulus.detect.windows_endpoint_events import AdminShareTransfer
    from romulus.detect.windows_file_events import ExecutableCreationTimeChange
    from romulus.evidence.windows import normalize_windows
    from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL
    from tests.test_windows_normalizer_review import native
    rule = ExecutableCreationTimeChange()
    items = [normalize_windows(native(2, {"TargetFilename": r"C:\Temp\payload.dat", "Image": r"C:\Tools\writer.exe",
                   "PreviousCreationUtcTime": old, "CreationUtcTime": new},
                   channel=SYSMON_CHANNEL, provider=SYSMON)) for old, new in (
                       ("2020-01-01 00:00:00.000", "2021-01-01 00:00:00.000"),
                       ("2021-01-01 00:00:00.000", "2022-01-01 00:00:00.000"))]
    a, b = [rule.judge(item)[0] for item in items]
    assert rule._shape(items[0], a) == rule._shape(items[1], b)
    assert all({'file.previous_creation_time', 'file.creation_time'} <= {p.field for p in hit.predicate}
               for hit in (a, b))
    share = AdminShareTransfer()
    shares = []
    for outcome in ("success", "failure"):
        hit = native(5145, {"ShareName": r"\\*\ADMIN$", "RelativeTargetName": "payload.dat", "AccessMask": "0x2"})
        hit["_source"].setdefault("event", {})["outcome"] = outcome
        shares.append(normalize_windows(hit))
    a, b = [share.judge(item)[0] for item in shares]
    assert share._shape(shares[0], a) != share._shape(shares[1], b)


def test_pipe_template_common_text_and_wmi_actor_are_shared_truths():
    from romulus.detect.windows_endpoint_events import ToolNamedPipe, WmiSubscription
    first = event("pipe_event", 17, **{"pipe.name": "MSSE-1-server"})
    second = event("pipe_event", 17, native="second", **{"pipe.name": "MSSE-6546-server"})
    rule = ToolNamedPipe()
    a, b = rule.judge(first)[0], rule.judge(second)[0]
    assert rule._shape(first, a) == rule._shape(second, b)
    assert "MSSE-1-server" not in a.common and "msse-#-server" in a.common
    wmi = WmiSubscription()
    items = [event("wmi_subscription", 20, native=user, **{"wmi.user": user}) for user in ("alice", "bob")]
    a, b = [wmi.judge(item)[0] for item in items]
    assert wmi._shape(items[0], a) != wmi._shape(items[1], b)


def test_content_key_ignores_cited_instance_ids_and_preserves_payload_differences():
    rule = WindowsEventRule()
    rule.id = "test.content"
    first = event("process_access", 10, **{"source.pid": 1})
    second = event("process_access", 10, native="second", **{"source.pid": 2})
    a = signal(first, "access", "same behavior", (), ("source.pid",), content='image,mask,trace')
    b = signal(second, "access", "same behavior", (), ("source.pid",), content='image,mask,trace')
    c = signal(second, "access", "different behavior", (), ("source.pid",), content='image,other-mask,trace')
    assert rule._shape(first, a) == rule._shape(second, b)
    assert rule._shape(first, a) != rule._shape(second, c)
