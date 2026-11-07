"""New Linux audit families keep watched reads and module-operation evidence."""
import pytest

from romulus.evidence.normalize import normalize_hits
from tests.test_kernel_records import cwd, group, path, syscall


@pytest.mark.parametrize("key,expected", [("secrets", "file_access"), ("(null)", "process_observed"),
                                           ("", "process_observed"), ("-", "process_observed")])
def test_only_watched_read_opens_are_retained(key, expected):
    line = syscall(501, 257, "openat", a2="0").replace('key="persist"', f'key="{key}"')
    events, skips, errors = normalize_hits(group(line, path(501, 0, "/etc/shadow", "NORMAL"), cwd(501)))
    assert not errors and not skips
    assert events[0].family == expected
    if expected == "file_access":
        assert events[-1].family == "process_observed"
    if expected == "file_access":
        assert events[0].get("file.path") == "/etc/shadow"
        assert events[0].get("file.access") == "read" and events[0].get("audit.key") == "secrets"


def test_watched_read_missing_path_is_missing_not_a_negative():
    events, _, errors = normalize_hits(group(syscall(502, 257, "openat", a2="0", items=0)))
    assert not errors and events[0].family == "file_access"
    assert not events[0].has("file.path") and events[0].caveats


@pytest.mark.parametrize("number,name,op", [(175, "init_module", "load"), (313, "finit_module", "load"),
                                           (176, "delete_module", "unload")])
def test_module_syscalls(number, name, op):
    events, skips, errors = normalize_hits(group(
        syscall(503, number, name), path(503, 0, "/tmp/module.ko", "NORMAL"), cwd(503)))
    assert not errors and not skips and len(events) == 2
    assert events[0].family == "kernel_module" and events[0].get("module.op") == op
    assert events[0].get("process.pid") == 901
    if name == "finit_module":
        assert events[0].get("module.path") == "/tmp/module.ko"


def test_kernel_module_record_and_missing_path():
    events, _, errors = normalize_hits(group(
        syscall(504, 313, "finit_module", items=0),
        'type=KERN_MODULE msg=audit(1893920400.100:504): name="demo"'));
    assert not errors and events[0].family == "kernel_module"
    assert events[0].get("module.name") == "demo" and events[0].get("module.op") == "load"
    assert not events[0].has("module.path") and events[0].caveats


def test_kernel_module_record_without_syscall_retains_observed_name_and_operation():
    events, _, errors = normalize_hits(group(
        'type=KERN_MODULE msg=audit(1893920400.100:505): name="demo" op=load'));
    assert not errors and events[0].family == "kernel_module"
    assert events[0].get("module.name") == "demo" and events[0].get("module.op") == "load"


def test_host_ip_is_typed_for_sweep_alert_mapping():
    hits = group(syscall(506, 313, "finit_module", items=0))
    hits[0]["_source"]["host"]["ip"] = ["10.2.3.4", "127.0.0.1"]
    events, _, errors = normalize_hits(hits)
    assert not errors and events[0].get("host.ip") == ["10.2.3.4", "127.0.0.1"]


def test_name_only_module_record_does_not_invent_operation_or_success():
    from romulus.evidence.typed import Outcome
    events, _, errors = normalize_hits(group('type=KERN_MODULE msg=audit(1893920400.100:507): name="demo"'))
    assert not errors and events[0].family == "kernel_module"
    assert not events[0].has("module.op") and events[0].outcome == Outcome.unknown
    assert events[0].caveats
