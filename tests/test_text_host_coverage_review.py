"""Host-header gaps follow the actual query's reachable source shapes."""
from datetime import timedelta

from romulus.agent.models import EntityRef
from romulus.agent.tools import AuthActivityArgs, AuthActivityRequest, ProcessTreeArgs, ProcessTreeRequest
from romulus.detect.linux_direct import CredentialMaterialAccess
from romulus.hunt.expansion import ExpansionEngine
from romulus.hunt.links import LinkFetcher, LinkWindow
from romulus.hunt.pivot import _text_host_coverage
from romulus.sources.models import Window
from romulus.sources.profile import contract_from_types
from tests.test_bounded_host import ev
from tests.test_linux_text_pivots import _executor
from tests.throughput_fixture import HOST_TARGET, T0, Builder


def _mixed_executor(docs=()):
    executor = _executor(list(docs))
    executor.dataset_inventory = {HOST_TARGET: ("linux.audit", "linux.text")}
    return executor


def test_agent_process_tree_on_text_target_has_no_header_gap():
    executor = _mixed_executor()
    request = ProcessTreeRequest(tool="process_tree", arguments=ProcessTreeArgs(
        start=T0, end=T0 + timedelta(minutes=5), host="web1", process_id="123"))
    intents, coverage = executor.plan(request)
    assert intents
    assert not [cell for cell in coverage if "syslog header" in " ".join(cell.reasons)]


def test_auth_query_reaching_text_keeps_header_gap():
    executor = _mixed_executor()
    request = AuthActivityRequest(tool="auth_activity", arguments=AuthActivityArgs(
        start=T0, end=T0 + timedelta(minutes=5), entity=EntityRef(kind="host", value="web1", role="host")))
    intents, coverage = executor.plan(request)
    assert intents
    assert any("syslog header" in " ".join(cell.reasons) for cell in coverage)


def test_header_origin_anchor_keeps_gap_even_for_audit_only_lineage():
    executor = _mixed_executor()
    window = LinkWindow(label="lineage", start=T0, end=T0 + timedelta(minutes=5))
    intents = LinkFetcher(executor, window.start, window.end)._host_intents(
        window, {"process_exec"}, host="web1", os_family="linux")
    assert _text_host_coverage(executor.contracts, executor.dataset_inventory, intents, header_host=True)
    assert not _text_host_coverage(executor.contracts, executor.dataset_inventory, intents)


def test_windows_only_intent_on_mixed_target_has_no_header_gap():
    executor = _mixed_executor()
    fields = {"@timestamp": "date", "message": "text", "event.dataset": "keyword", "host.name": "keyword",
              "winlog.channel": "keyword", "winlog.event_id": "long", "winlog.computer_name": "keyword",
              "winlog.provider_name": "keyword", "event.code": "keyword", "log.file.path": "keyword"}
    executor.contracts[HOST_TARGET] = contract_from_types(HOST_TARGET, fields, role="host", os_family="windows",
        linux_text_mixed=True, hosts=("web1",))
    executor.dataset_inventory = {HOST_TARGET: ("windows.security", "linux.text")}
    window = LinkWindow(label="lineage", start=T0, end=T0 + timedelta(minutes=5))
    intents = LinkFetcher(executor, window.start, window.end)._host_intents(
        window, {"process_exec"}, host="web1", os_family="windows")
    assert intents
    assert not _text_host_coverage(executor.contracts, executor.dataset_inventory, intents)


def test_real_reader_lineage_on_text_target_routes_packaged_root_perl_to_lead():
    builder = Builder(11)
    pid = builder.exec_group("web1", T0, ["/usr/bin/perl", "-wT", "/usr/bin/zmpkg.pl", "start"],
                             ppid=1, copy=False)
    for row in builder.host:
        source = row["_source"]
        raw = source["message"].replace("auid=0", "auid=4294967295").replace("ses=4", "ses=4294967295")
        raw = raw.replace('AUID="root"', 'AUID="unset"').replace("tty=pts0", "tty=(none)")
        source["message"] = source["event"]["original"] = raw
    executor = _mixed_executor(builder.host)
    window = Window(start=T0, end=T0 + timedelta(minutes=10))
    read = ev("file_access", T0 + timedelta(seconds=1), host_name="web1", file__path="/etc/shadow",
              file__access="read", audit__key="shadow", process__executable="/usr/bin/perl",
              process__uid="0", process__pid=pid, process__ppid=1)
    engine = ExpansionEngine(executor.repo, "h1", window, fetcher=LinkFetcher(executor, window.start, window.end))
    ids, reason = engine._reader_lineage("anchor", ("web1", None, pid), read)
    assert reason is None
    lineage = engine._events(ids)
    assert lineage
    [match] = CredentialMaterialAccess().consume([*lineage, read])
    assert match.proposed_lane == "lead"
