"""The one table of Microsoft RPC interfaces and operations: one class for a call however a source names it.

Zeek's dce_rpc.log names a call by endpoint and operation names (its consts.zeek tables), host telemetry (the Windows
RPC ETW provider) by interface UUID and opnum: both lookups must resolve every listed call to the same class, Zeek's
"unknown-<n>" names (releases that have no name for an opnum or interface) by number, and anything the table does not
list to "other", never a guess. Every technique id must be a current technique of the pinned ATT&CK bundle.
"""
import pytest

from romulus.catalog.attack import load_attack_bundle
from romulus.evidence import rpc_catalog as rc

OPERATIONS = [(interface, op) for interface in rc.INTERFACES for op in interface.operations]


def test_the_table_covers_the_interfaces_lateral_movement_and_domain_abuse_use():
    names = {name for interface in rc.INTERFACES for name in interface.zeek_names}
    assert {"svcctl", "atsvc", "ITaskSchedulerService", "IWbemServices", "IRemoteSCMActivator", "drsuapi", "samr",
            "lsarpc", "srvsvc", "netlogon", "efsrpc", "efsrpc2", "netdfs", "FileServerVssAgent", "spoolss",
            "winreg", "wkssvc", "IRemoteWinspool", "InitShutdown", "WindowsShutdown"} <= names
    documents = {interface.document for interface in rc.INTERFACES}
    assert {"MS-SCMR", "MS-TSCH", "MS-WMI", "MS-DCOM", "MS-DRSR", "MS-SAMR", "MS-SRVS", "MS-NRPC", "MS-EFSR",
            "MS-DFSNM", "MS-FSRVP", "MS-RPRN", "MS-RRP", "MS-WKST", "MS-PAR", "MS-RSP"} <= documents


@pytest.mark.parametrize("endpoint,operation,op_class", [
    ("svcctl", "CreateServiceW", "service_create"), ("svcctl", "CreateServiceA", "service_create"),
    ("svcctl", "StartServiceW", "service_start"), ("svcctl", "ChangeServiceConfigW", "service_modify"),
    ("atsvc", "NetrJobAdd", "task_register"), ("ITaskSchedulerService", "SchRpcRegisterTask", "task_register"),
    ("ITaskSchedulerService", "SchRpcRun", "task_register"), ("IWbemServices", "ExecMethod", "wmi_dcom"),
    ("IWbemServices", "ExecQuery", "wmi_dcom"), ("IRemoteSCMActivator", "RemoteCreateInstance", "wmi_dcom"),
    ("drsuapi", "DRSGetNCChanges", "replication"), ("drsuapi", "DRSReplicaSync", "replication"),
    ("samr", "SamrEnumerateUsersInDomain", "enumeration"), ("lsarpc", "LsarLookupSids2", "enumeration"),
    ("srvsvc", "NetrShareEnum", "enumeration"), ("srvsvc", "NetrSessionEnum", "enumeration"),
    ("netlogon", "DsrEnumerateDomainTrusts", "enumeration"), ("wkssvc", "NetrWkstaUserEnum", "enumeration"),
    ("efsrpc", "EfsRpcOpenFileRaw", "coercion"), ("efsrpc2", "EfsRpcEncryptFileSrv", "coercion"),
    ("netdfs", "NetrDfsRemoveStdRoot", "coercion"), ("FileServerVssAgent", "IsPathSupported", "coercion"),
    ("spoolss", "RpcRemoteFindFirstPrinterChangeNotificationEx", "print_notification"),
    ("spoolss", "RpcRemoteFindFirstPrinterChangeNotification", "print_notification"),
    ("spoolss", "RpcAddPrinterDriverEx", "driver_install"),
    ("IRemoteWinspool", "RpcAsyncAddPrinterDriver", "driver_install"),
    ("winreg", "BaseRegSaveKey", "remote_registry"), ("winreg", "BaseRegSetValue", "remote_registry"),
    ("winreg", "BaseInitiateSystemShutdown", "remote_shutdown"),
    ("winreg", "BaseInitiateSystemShutdownEx", "remote_shutdown"), ("winreg", "BaseAbortSystemShutdown", "other"),
    ("InitShutdown", "BaseInitiateShutdown", "remote_shutdown"),
    ("WindowsShutdown", "WsdrInitiateShutdown", "remote_shutdown"),
    ("samr", "SamrAddMemberToAlias", "account_change"), ("lsarpc", "LsarRetrievePrivateData", "credential_access"),
    ("drsuapi", "DRSAddSidHistory", "sid_history"), ("lsarpc", "LsarAddAccountRights", "account_rights_change"),
    ("lsarpc", "LsarAddPrivilegesToAccount", "account_rights_change"),
    ("lsarpc", "LsarCreateAccount", "account_rights_change"), ("lsarpc", "LsarSetSecret", "secret_write"),
    ("lsarpc", "LsarStorePrivateData", "secret_write"), ("svcctl", "ControlService", "service_control"),
    ("svcctl", "DeleteService", "service_delete"), ("netlogon", "NetrServerReqChallenge", "secure_channel"),
    ("netlogon", "NetrServerAuthenticate3", "secure_channel"),
    ("netlogon", "NetrServerPasswordSet2", "secure_channel"),
])
def test_the_classes_of_the_calls_that_matter(endpoint, operation, op_class):
    assert rc.lookup_zeek(endpoint, operation).op_class == op_class


@pytest.mark.parametrize("interface,op", OPERATIONS,
                         ids=[f"{i.zeek_names[0]}-{op.opnum}-{op.name}" for i, op in OPERATIONS])
def test_every_listed_call_resolves_to_one_class_however_it_is_named(interface, op):
    by_number = rc.lookup_call(interface.uuid, op.opnum)
    assert (by_number.op_class, by_number.attack, by_number.operation) == (op.op_class, op.attack, op)
    variants = [(name, op.name) for name in interface.zeek_names] + [
        (interface.zeek_names[0], f"unknown-{op.opnum}"),               # a release with no name for the opnum
        (f"unknown-{interface.uuid}", op.name),                         # a release with no name for the interface
        (f"unknown-{interface.uuid}", f"unknown-{op.opnum}"),
        (interface.zeek_names[0].upper(), op.name.lower()),             # case, and padding, never change the call
        (f" {interface.zeek_names[0]} ", f" {op.name} ")]
    for endpoint, operation in variants:
        found = rc.lookup_zeek(endpoint, operation)
        assert (found.op_class, found.attack, found.interface) == (op.op_class, op.attack, interface), \
            (endpoint, operation)
    # the UUID as the Windows RPC ETW provider writes it: braces, uppercase
    assert rc.lookup_call("{" + interface.uuid.upper() + "}", op.opnum).op_class == op.op_class
    assert rc.zeek_uuid(interface.zeek_names[0]) == interface.uuid
    duplicated = sum(1 for other in interface.operations if other.name == op.name) > 1
    assert rc.zeek_opnum(interface.zeek_names[0], op.name) == (None if duplicated else op.opnum)
    assert rc.zeek_opnum(interface.zeek_names[0], f"unknown-{op.opnum}") == op.opnum


def test_a_name_zeek_gives_two_opnums_classes_both_and_names_neither():
    """Zeek's table names IWbemServices opnums 16 and 17 as 10 and 11: the class holds, the opnum is not told."""
    found = rc.lookup_zeek("IWbemServices", "DeleteClass")
    assert found.op_class == "wmi_dcom" and found.operation is None
    assert rc.zeek_opnum("IWbemServices", "DeleteClass") is None


@pytest.mark.parametrize("endpoint,operation", [
    ("svcctl", "OpenSCManagerW"), ("svcctl", "unknown-55"), ("svcctl", "NoSuchOperation"), ("NoSuchEndpoint", "X"),
    ("unknown-00000000-0000-0000-0000-000000000000", "unknown-0"), ("epmapper", "ept_map"),
    ("dssetup", "DsRolerGetPrimaryDomainInformation"), ("svcctl", None), (None, "CreateServiceW"), (7, 12),
    ("svcctl", "unknown-"), ("svcctl", "unknown-12x"), ("svcctl", "unknown-" + "1" * 6), ("svcctl", "unknown--1"),
    ("unknown-not-a-uuid", "CreateServiceW"), ("", ""),
])
def test_an_unknown_endpoint_or_operation_is_other_never_a_guess(endpoint, operation):
    assert rc.lookup_zeek(endpoint, operation).op_class == rc.OTHER


@pytest.mark.parametrize("uuid,opnum", [
    ("367abb81-9844-35f1-ad32-98f038001003", 0), ("367abb81-9844-35f1-ad32-98f038001003", True),
    ("367abb81-9844-35f1-ad32-98f038001003", "12"), ("367abb81-9844-35f1-ad32-98f038001003", None),
    ("367abb81-9844-35f1-ad32-98f03800100", 12), ("not a uuid", 12), (None, 12), ("g" * 36, 12),
])
def test_an_unlisted_or_malformed_call_by_number_is_other(uuid, opnum):
    assert rc.lookup_call(uuid, opnum).op_class == rc.OTHER


def test_zeeks_unknown_interface_name_still_gives_its_uuid():
    uuid = "12345678-90ab-cdef-1234-567890abcdef"
    assert rc.zeek_uuid(f"unknown-{uuid}") == uuid
    assert rc.zeek_uuid("NoSuchEndpoint") is None and rc.zeek_uuid("unknown-xyz") is None
    assert rc.zeek_opnum("NoSuchEndpoint", "unknown-7") == 7


def test_the_table_is_consistent():
    assert set(rc.CLASSES) >= {op.op_class for _interface, op in OPERATIONS}
    assert rc.OTHER not in {op.op_class for _interface, op in OPERATIONS}
    for interface in rc.INTERFACES:
        assert rc.canonical_uuid(interface.uuid) == interface.uuid
        assert len({op.opnum for op in interface.operations}) == len(interface.operations)
        assert all(0 <= op.opnum < 2**16 for op in interface.operations)
    assert len({interface.uuid for interface in rc.INTERFACES}) == len(rc.INTERFACES)


def test_every_technique_is_a_current_technique_of_the_pinned_attack_bundle():
    attack = load_attack_bundle()
    ids = {technique for _interface, op in OPERATIONS for technique in op.attack}
    for technique_id in sorted(ids):
        technique = attack.technique(technique_id)
        assert not technique.revoked and not technique.deprecated, technique_id
    for _interface, op in OPERATIONS:
        if op.op_class in rc.NON_ATTACK_CLASSES:
            assert not op.attack, op.name           # routine: the input of a rate rule, never a technique by itself
        else:
            assert op.attack or op.verify, op.name  # an attack class without a technique says why


def test_coercion_is_only_the_calls_no_routine_client_makes():
    """EFSR, DFSNM and FSRVP; the print spooler's notification is its own class (every print client sends it). Which
    operations reach a coerced authentication is public research, not the protocol documents: each says so."""
    documents = {interface.document for interface, op in OPERATIONS if op.op_class == "coercion"}
    assert documents == {"MS-EFSR", "MS-DFSNM", "MS-FSRVP"}
    for _interface, op in OPERATIONS:
        if op.op_class in ("coercion", "print_notification", "driver_install"):
            assert op.verify, op.name


def test_a_listed_operation_carries_a_technique_or_says_why():
    with pytest.raises(ValueError):
        rc.RpcOperation(1, "X", "service_control", ())
    with pytest.raises(ValueError):
        rc.RpcOperation(1, "X", "secure_channel", ("T1210",))
    with pytest.raises(ValueError):
        rc.RpcOperation(1, "X", rc.OTHER, ("T1210",))
