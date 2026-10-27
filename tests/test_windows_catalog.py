"""Catalog and attestation coverage for Windows typed-event families."""

from __future__ import annotations

from romulus.evidence.windows_catalog import (
    COLLECTION_CHANGE_EVENTS,
    EVENT_CLASSES,
    SECURITY,
    SYSMON,
    SYSMON_CHANNEL,
    WINDOWS_CHANNELS,
    WINDOWS_DATASET_FAMILIES,
    WINDOWS_DATASETS,
    collection_requirements,
    lookup_event_class,
)

TASK_CHANNEL = "Microsoft-Windows-TaskScheduler/Operational"
TASK_PROVIDER = "Microsoft-Windows-TaskScheduler"
WMI_CHANNEL = "Microsoft-Windows-WMI-Activity/Operational"
WMI_PROVIDER = "Microsoft-Windows-WMI-Activity"
POWERSHELL_CHANNEL = "Microsoft-Windows-PowerShell/Operational"
POWERSHELL_PROVIDER = "Microsoft-Windows-PowerShell"
LEGACY_POWERSHELL_CHANNEL = "Windows PowerShell"
LEGACY_POWERSHELL_PROVIDER = "PowerShell"
DEFENDER_CHANNEL = "Microsoft-Windows-Windows Defender/Operational"
DEFENDER_PROVIDER = "Microsoft-Windows-Windows Defender"
RDP_RCM_CHANNEL = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
RDP_RCM_PROVIDER = "Microsoft-Windows-TerminalServices-RemoteConnectionManager"
RDP_LSM_CHANNEL = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
RDP_LSM_PROVIDER = "Microsoft-Windows-TerminalServices-LocalSessionManager"
WINRM_CHANNEL = "Microsoft-Windows-WinRM/Operational"
WINRM_PROVIDER = "Microsoft-Windows-WinRM"
BITS_CHANNEL = "Microsoft-Windows-Bits-Client/Operational"
BITS_PROVIDER = "Microsoft-Windows-Bits-Client"


EXPECTED_CLASSES = {
    "auth": {
        *(('Security', SECURITY, event_id) for event_id in (
            4624, 4625, 4634, 4647, 4648, 4672, 4768, 4769, 4770, 4771, 4776, 4778, 4779, 4964,
        )),
    },
    "account_change": {
        *(('Security', SECURITY, event_id) for event_id in (
            4704, 4705, 4720, 4722, 4724, 4725, 4726, 4728, 4729, 4732, 4733, 4738, 4740,
            4741, 4742, 4743, 4756, 4757, 4765, 4766, 4767, 4781, 4794,
        )),
    },
    "scheduled_task": {
        *(('Security', SECURITY, event_id) for event_id in (4698, 4699, 4700, 4701, 4702)),
        *((TASK_CHANNEL, TASK_PROVIDER, event_id) for event_id in (106, 129, 140, 141, 200, 201)),
    },
    "file_change": {
        *((SYSMON_CHANNEL, SYSMON, event_id) for event_id in (2, 11, 15, 23, 26)),
    },
    "process_access": {(SYSMON_CHANNEL, SYSMON, 10)},
    "image_load": {
        (SYSMON_CHANNEL, SYSMON, 6),
        (SYSMON_CHANNEL, SYSMON, 7),
    },
    "remote_thread": {(SYSMON_CHANNEL, SYSMON, 8)},
    "process_tampering": {(SYSMON_CHANNEL, SYSMON, 25)},
    "registry_change": {
        *((SYSMON_CHANNEL, SYSMON, event_id) for event_id in (12, 13, 14)),
        ('Security', SECURITY, 4657),
    },
    "object_access": {
        *(('Security', SECURITY, event_id) for event_id in (4656, 4663, 4670)),
    },
    "pipe_event": {
        *((SYSMON_CHANNEL, SYSMON, event_id) for event_id in (17, 18)),
    },
    "wmi_subscription": {
        *((SYSMON_CHANNEL, SYSMON, event_id) for event_id in (19, 20, 21)),
        (WMI_CHANNEL, WMI_PROVIDER, 5861),
    },
    "dns_lookup": {(SYSMON_CHANNEL, SYSMON, 22)},
    "script_block": {
        *((POWERSHELL_CHANNEL, POWERSHELL_PROVIDER, event_id) for event_id in (4103, 4104)),
        *((LEGACY_POWERSHELL_CHANNEL, LEGACY_POWERSHELL_PROVIDER, event_id)
          for event_id in (400, 403, 800)),
    },
    "directory_access": {('Security', SECURITY, 4662)},
    "directory_change": {
        *(('Security', SECURITY, event_id) for event_id in (5136, 5137, 5138, 5139, 5141)),
    },
    "share_access": {
        *(('Security', SECURITY, event_id) for event_id in (5140, 5145)),
    },
    "defender_event": {
        *((DEFENDER_CHANNEL, DEFENDER_PROVIDER, event_id) for event_id in (
            1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119, 5001, 5004, 5007, 5010, 5012, 5013,
        )),
    },
    "remote_access": {
        (RDP_RCM_CHANNEL, RDP_RCM_PROVIDER, 1149),
        *((RDP_LSM_CHANNEL, RDP_LSM_PROVIDER, event_id) for event_id in (21, 22, 24, 25)),
        *((WINRM_CHANNEL, WINRM_PROVIDER, event_id) for event_id in (6, 91)),
        *((BITS_CHANNEL, BITS_PROVIDER, event_id) for event_id in (3, 59, 60)),
    },
}


def test_every_required_event_triple_is_catalogued_in_its_typed_family():
    for family, triples in EXPECTED_CLASSES.items():
        for channel, provider, event_id in triples:
            event_class = lookup_event_class(channel, provider, event_id)
            assert event_class is not None, (family, channel, provider, event_id)
            assert event_class.family == family

    assert lookup_event_class("System", "Service Control Manager", 7040).family == "service_change"
    for event_id in (1100, 1104, 1108):
        assert lookup_event_class("Security", "Microsoft-Windows-Eventlog", event_id).family == "audit_config"


def test_every_catalog_row_has_an_event_specific_official_documentation_url():
    for event_class in EVENT_CLASSES:
        assert event_class.documentation_url.startswith("https://learn.microsoft.com/"), event_class
        assert str(event_class.event_id) in event_class.documentation_url, event_class


def test_catalog_triples_are_unique_and_case_insensitive():
    keys = [event_class.key for event_class in EVENT_CLASSES]
    assert len(keys) == len(set(keys))
    sample = lookup_event_class(DEFENDER_CHANNEL.swapcase(), DEFENDER_PROVIDER.swapcase(), "1116")
    assert sample is not None and sample.family == "defender_event"


def test_collection_change_events_cover_every_native_collection_break():
    assert {
        (SYSMON_CHANNEL.casefold(), SYSMON.casefold(), 4): "Sysmon service state changed",
        (SYSMON_CHANNEL.casefold(), SYSMON.casefold(), 16): "Sysmon configuration changed",
        (SYSMON_CHANNEL.casefold(), SYSMON.casefold(), 255): "Sysmon error",
        ("security", "microsoft-windows-eventlog", 1100): "event log service shut down",
        ("security", "microsoft-windows-eventlog", 1104): "security log full",
        ("security", "microsoft-windows-eventlog", 1108): "event logging error",
    }.items() <= COLLECTION_CHANGE_EVENTS.items()


def test_every_operational_channel_requires_its_generic_channel_attestation():
    for event_class in EVENT_CLASSES:
        if not event_class.channel.casefold().endswith("/operational"):
            continue
        if event_class.provider.casefold() == SYSMON.casefold():
            continue
        assert (
            "event_channel",
            {"channel": event_class.channel},
            f"event channel {event_class.channel}",
        ) in collection_requirements(event_class)


def test_collection_requirements_are_event_specific_for_security_and_sysmon():
    kerberos = lookup_event_class("Security", SECURITY, 4769)
    registry = lookup_event_class("Security", SECURITY, 4657)
    sysmon_dns = lookup_event_class(SYSMON_CHANNEL, SYSMON, 22)
    assert kerberos is not None and registry is not None and sysmon_dns is not None

    assert (
        "audit_policy",
        {"subcategory": "Kerberos Service Ticket Operations", "outcome": "success"},
        "audit policy Kerberos Service Ticket Operations success",
    ) in collection_requirements(kerberos)
    assert (
        "audit_policy",
        {"subcategory": "Registry", "outcome": "success"},
        "audit policy Registry success",
    ) in collection_requirements(registry)
    assert (
        "sysmon",
        {"event_id": 22},
        "Sysmon event id 22",
    ) in collection_requirements(sysmon_dns)


def test_every_sacl_dependent_security_class_requires_scoped_attestation():
    expected = {
        "object_access_sacl": {4656, 4657, 4663, 4670},
        "directory_service_sacl": {4662, 5136, 5137, 5138, 5139, 5141},
    }
    actual = {fact: set() for fact in expected}

    for event_class in EVENT_CLASSES:
        if event_class.channel.casefold() != "security":
            continue
        requirements = collection_requirements(event_class)
        for fact, event_ids in actual.items():
            if any(requirement == fact for requirement, _arguments, _label in requirements):
                event_ids.add(event_class.event_id)

    assert actual == expected


def test_share_access_collection_remains_audit_policy_only():
    for event_id in (5140, 5145):
        event_class = lookup_event_class("Security", SECURITY, event_id)
        assert event_class is not None
        facts = {fact for fact, _arguments, _label in collection_requirements(event_class)}
        assert facts == {"audit_policy"}


def test_powershell_module_logging_is_distinct_from_channel_availability():
    module_log = lookup_event_class(POWERSHELL_CHANNEL, POWERSHELL_PROVIDER, 4103)
    assert module_log is not None

    requirements = collection_requirements(module_log)
    assert ("powershell_module_logging", {}, "PowerShell module logging") in requirements
    assert (
        "event_channel",
        {"channel": POWERSHELL_CHANNEL},
        f"event channel {POWERSHELL_CHANNEL}",
    ) in requirements
    assert all(fact != "powershell_script_block" for fact, _arguments, _label in requirements)


def test_security_collection_requirements_cover_every_documented_emitting_outcome():
    expected = {
        4770: {("Kerberos Service Ticket Operations", "success")},
        4724: {
            ("User Account Management", "success"),
            ("User Account Management", "failure"),
        },
        4794: {
            ("User Account Management", "success"),
            ("User Account Management", "failure"),
        },
        4656: {
            (subcategory, outcome)
            for subcategory in ("File System", "Kernel Object", "Registry", "Removable Storage")
            for outcome in ("success", "failure")
        },
        4662: {
            ("Directory Service Access", "success"),
            ("Directory Service Access", "failure"),
        },
        4670: {
            ("File System", "success"),
            ("Registry", "success"),
            ("Authentication Policy Change", "success"),
            ("Authorization Policy Change", "success"),
        },
        5145: {
            ("Detailed File Share", "success"),
            ("Detailed File Share", "failure"),
        },
    }

    for event_id, expected_pairs in expected.items():
        event_class = lookup_event_class("Security", SECURITY, event_id)
        assert event_class is not None
        actual_pairs = {
            (details["subcategory"], details["outcome"])
            for kind, details, _description in collection_requirements(event_class)
            if kind == "audit_policy"
        }
        assert actual_pairs == expected_pairs


def test_dataset_and_channel_derivations_include_new_operational_families():
    expected_families = frozenset(EXPECTED_CLASSES)
    all_families = frozenset().union(*WINDOWS_DATASET_FAMILIES.values())
    assert expected_families <= all_families
    assert {
        TASK_CHANNEL,
        WMI_CHANNEL,
        POWERSHELL_CHANNEL,
        LEGACY_POWERSHELL_CHANNEL,
        DEFENDER_CHANNEL,
        RDP_RCM_CHANNEL,
        RDP_LSM_CHANNEL,
        WINRM_CHANNEL,
        BITS_CHANNEL,
    } <= set(WINDOWS_CHANNELS)
    assert {"winlog.winlog", "windows.powershell", "windows.windows_defender"} <= WINDOWS_DATASETS
    assert WINDOWS_DATASET_FAMILIES["windows.powershell"] == frozenset({"script_block"})
    assert WINDOWS_DATASET_FAMILIES["windows.windows_defender"] == frozenset({"defender_event"})
    assert expected_families <= WINDOWS_DATASET_FAMILIES["winlog.winlog"]
