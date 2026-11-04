"""One table of the Microsoft RPC interfaces and operations ROMULUS classifies, for every source that names an RPC call.

A call is named two ways. Network sensors name it as Zeek's dce_rpc.log does: the endpoint (Zeek's name for the
interface UUID) and the operation (Zeek's name for the opnum). Host telemetry names it by the interface UUID and the
opnum (the Windows RPC ETW provider, Microsoft-Windows-RPC events 5 and 6, writes InterfaceUuid and ProcNum). Both
lookups below resolve to the same entry, so a rule reads one class whichever source saw the call: the Zeek normalizer
types `rpc.op_class` from `lookup_zeek`, and the Windows RPC ETW normalizer is to type it from `lookup_call` on this
same table, never a table of its own.

Classes (the operation's effect as its protocol document defines it, never the outcome of the call):

- ``service_create``, ``service_start``, ``service_modify``, ``service_control``, ``service_delete``: the Service
  Control Manager creates, starts, changes the configuration of, sends a control (stop, pause) to, or deletes a
  service ([MS-SCMR]).
- ``task_register``: a scheduled task or AT job is registered, run or enabled, or a task's account is set ([MS-TSCH]).
- ``wmi_dcom``: WMI calls and DCOM activation ([MS-WMI], [MS-DCOM]).
- ``replication``: directory replication between domain controllers ([MS-DRSR]).
- ``sid_history``: SID history is added to an account ([MS-DRSR] IDL_DRSAddSidHistory).
- ``enumeration``: accounts, groups, sessions, shares, trusts or the password policy are listed or looked up ([MS-SAMR],
  [MS-LSAT], [MS-LSAD], [MS-SRVS], [MS-NRPC], [MS-WKST], [MS-SCMR], [MS-DRSR]).
- ``coercion``: an operation that takes a path or name the server then authenticates to, and that no routine client
  sends to another host (EFSR, DFSNM, FSRVP): the forced-authentication shape.
- ``print_notification``: the print spooler's remote change notification ([MS-RPRN]
  RpcRemoteFindFirstPrinterChangeNotification(Ex)). The server opens a connection back to the client name the call
  gives, so it can force authentication as ``coercion`` does, but every print client sends it to its print server:
  it is a class of its own, never coercion by itself.
- ``driver_install``: a printer driver is installed on the server ([MS-RPRN] RpcAddPrinterDriverEx, [MS-PAR]
  RpcAsyncAddPrinterDriver), the call the PrintNightmare exploitation makes.
- ``remote_registry``: the remote registry ([MS-RRP]).
- ``remote_shutdown``: the host is told to shut down or restart ([MS-RRP] BaseInitiateSystemShutdown(Ex), [MS-RSP]).
- ``account_change``: an account is created, deleted, changed, given a password, or added to a group ([MS-SAMR]).
- ``account_rights_change``: an LSA account is created or given privileges or user rights ([MS-LSAD]).
- ``credential_access``: LSA secrets are read ([MS-LSAD]).
- ``secret_write``: an LSA secret is set or private data stored ([MS-LSAD]).
- ``secure_channel``: Netlogon's secure-channel setup and machine-password calls ([MS-NRPC] NetrServerReqChallenge,
  NetrServerAuthenticate*, NetrServerPasswordSet*). Not an attack class: every domain member makes these calls to its
  domain controllers as routine. It exists so that a rule over their rate (the Zerologon shape: many authentication
  attempts in a short time) reads the one table; it carries no technique.
- ``other``: every operation and interface this table does not list. An unknown endpoint, UUID, operation or opnum is
  ``other``, never a guess.

Sources. Every UUID, endpoint name, opnum and operation name below is Zeek's
(zeek/zeek tag v8.0.0, commit f07a59d32cbbefdd7706bbe47a053f350c36aed0, scripts/base/protocols/dce-rpc/consts.zeek:
``uuid_endpoint_map`` and ``operations``; Copyright (c) 1995-2025, The Regents of the University of California, through
Lawrence Berkeley National Laboratory and the International Computer Science Institute, BSD-3-Clause), and each
interface names the Microsoft Open Specifications document that defines it, whose interface UUID and opnums Zeek's
table follows. Zeek's names drop the "R" prefix MS-SCMR gives its methods (``CreateServiceW`` is MS-SCMR's
``RCreateServiceW``), and Zeek's table names IWbemServices opnums 16 and 17 ``DeleteClass``/``DeleteClassAsync`` where
MS-WMI names them DeleteInstance/DeleteInstanceAsync: the names here are Zeek's, as dce_rpc.log writes them. Zeek
releases before 6.1 have no name for some opnums (svcctl 56/60/64, ITaskSchedulerService 18/19, lsarpc 129/130/133,
drsuapi 25-30, samr 73, netdfs 23-25) and write ``unknown-<opnum>``; an interface Zeek has no name for is written
``unknown-<uuid>``. Both forms resolve here by number.

ATT&CK ids are Enterprise 20 technique ids. ``verify`` names what was not confirmed against a primary source: the
operation's class or its technique comes from public research on the technique, not from the protocol document, or no
technique fits.
"""
from __future__ import annotations

from dataclasses import dataclass

CLASSES = ("service_create", "service_start", "service_modify", "service_control", "service_delete", "task_register",
           "wmi_dcom", "replication", "sid_history", "enumeration", "coercion", "print_notification",
           "driver_install", "remote_registry", "remote_shutdown", "account_change", "account_rights_change",
           "credential_access", "secret_write", "secure_channel", "other")
# classes that are not an attack's on their own: their operations carry no technique
NON_ATTACK_CLASSES = frozenset({"secure_channel"})
OTHER = "other"


@dataclass(frozen=True)
class RpcOperation:
    opnum: int
    name: str                       # Zeek's name for the opnum, as dce_rpc.log writes it
    op_class: str
    attack: tuple[str, ...]
    verify: str = ""                # what is not confirmed against a primary source (empty: confirmed)

    def __post_init__(self):
        if self.op_class not in CLASSES or self.op_class == OTHER:
            raise ValueError(f"{self.name}: a listed operation has a class other than {OTHER!r}")
        if self.op_class in NON_ATTACK_CLASSES and self.attack:
            raise ValueError(f"{self.name}: a non-attack class carries no technique")
        if not self.attack and self.op_class not in NON_ATTACK_CLASSES and not self.verify:
            raise ValueError(f"{self.name}: an attack class without a technique must say why")


@dataclass(frozen=True)
class RpcInterface:
    uuid: str                       # lowercase, no braces
    zeek_names: tuple[str, ...]     # Zeek's endpoint name(s) for the UUID
    document: str                   # the Microsoft Open Specifications document that defines the interface
    title: str
    operations: tuple[RpcOperation, ...]
    note: str = ""


@dataclass(frozen=True)
class RpcClass:
    """What a lookup resolved: the class, the techniques, and the interface and operation it matched (None when the
    call is not in the table)."""
    op_class: str
    attack: tuple[str, ...] = ()
    interface: RpcInterface | None = None
    operation: RpcOperation | None = None


def _ops(op_class: str, attack: tuple[str, ...], spec: str, verify: str = "") -> tuple[RpcOperation, ...]:
    """Operations of one class from "opnum:Name opnum:Name ..." (Zeek's names)."""
    out = []
    for item in spec.split():
        opnum, _sep, name = item.partition(":")
        out.append(RpcOperation(int(opnum), name, op_class, attack, verify))
    return tuple(out)


_DRIVER_RESEARCH = ("a driver install is the PrintNightmare exploitation's call (remote code execution and privilege "
                    "escalation as SYSTEM); T1547.012 names print processors, the nearest technique to a print "
                    "driver's DLL")
_COERCION_RESEARCH = ("which operations reach the coerced authentication is public research (PetitPotam, DFSCoerce, "
                      "ShadowCoerce), not the protocol document")

INTERFACES: tuple[RpcInterface, ...] = (
    RpcInterface("367abb81-9844-35f1-ad32-98f038001003", ("svcctl",), "MS-SCMR", "Service Control Manager Remote", (
        *_ops("service_create", ("T1543.003", "T1569.002"),
              "12:CreateServiceW 24:CreateServiceA 44:CreateServiceWOW64A 45:CreateServiceWOW64W 60:CreateWowService"),
        *_ops("service_start", ("T1569.002",), "19:StartServiceW 31:StartServiceA"),
        *_ops("service_modify", ("T1543.003",),
              "11:ChangeServiceConfigW 23:ChangeServiceConfigA 36:ChangeServiceConfig2A 37:ChangeServiceConfig2W"),
        *_ops("enumeration", ("T1007",),
              "14:EnumServicesStatusW 26:EnumServicesStatusA 41:EnumServicesStatusExA 42:EnumServicesStatusExW"),
        *_ops("service_control", ("T1489",), "1:ControlService 50:ControlServiceExA 51:ControlServiceExW",
              "a control can stop, pause or interrogate a service; dce_rpc.log does not say which"),
        *_ops("service_delete", ("T1489",), "2:DeleteService",
              "a remote service is also deleted after its own run (the PsExec pattern), which is not T1489"),
    )),
    RpcInterface("1ff70682-0a51-30e8-076d-740be8cee98b", ("atsvc",), "MS-TSCH", "ATSvc (AT jobs)",
                 _ops("task_register", ("T1053.002",), "0:NetrJobAdd")),
    RpcInterface("378e52b0-c0a9-11cf-822d-00aa0051e40f", ("sasec",), "MS-TSCH", "SASec (task account information)",
                 _ops("task_register", ("T1053.005",), "0:SASetAccountInformation",
                      "the account set for a task file copied to the Tasks share: the technique is inferred from "
                      "its use with that file")),
    RpcInterface("86d35949-83c9-4044-b424-db363231fd0c", ("ITaskSchedulerService",), "MS-TSCH",
                 "ITaskSchedulerService", _ops("task_register", ("T1053.005",),
                                               "1:SchRpcRegisterTask 12:SchRpcRun 19:SchRpcEnableTask")),
    RpcInterface("9556dc99-828c-11cf-a37e-00aa003240c7", ("IWbemServices",), "MS-WMI", "IWbemServices",
                 _ops("wmi_dcom", ("T1047",),
                      "3:OpenNamespace 4:CancelAsyncCall 5:QueryObjectSink 6:GetObject 7:GetObjectAsync 8:PutClass "
                      "9:PutClassAsync 10:DeleteClass 11:DeleteClassAsync 12:CreateClassEnum 13:CreateClassEnumAsync "
                      "14:PutInstance 15:PutInstanceAsync 16:DeleteClass 17:DeleteClassAsync 18:CreateInstanceEnum "
                      "19:CreateInstanceEnumAsync 20:ExecQuery 21:ExecQueryAsync 22:ExecNotificationQuery "
                      "23:ExecNotificationQueryAsync 24:ExecMethod 25:ExecMethodAsync"),
                 note="Zeek names opnums 16 and 17 as 10 and 11 (MS-WMI: DeleteInstance, DeleteInstanceAsync)"),
    RpcInterface("f309ad18-d86a-11d0-a075-00c04fb68820", ("IWbemLevel1Login",), "MS-WMI", "IWbemLevel1Login",
                 _ops("wmi_dcom", ("T1047",), "3:EstablishPosition 4:RequestChallenge 5:WBEMLogin 6:NTLMLogin")),
    RpcInterface("000001a0-0000-0000-c000-000000000046", ("IRemoteSCMActivator",), "MS-DCOM",
                 "IRemoteSCMActivator (impacket's ISystemActivator)",
                 _ops("wmi_dcom", ("T1021.003",), "3:RemoteGetClassObject 4:RemoteCreateInstance")),
    RpcInterface("4d9f4ab8-7d1c-11cf-861e-0020af6e7c57", ("IActivation",), "MS-DCOM", "IActivation",
                 _ops("wmi_dcom", ("T1021.003",), "0:RemoteActivation")),
    RpcInterface("e3514235-4b06-11d1-ab04-00c04fc2dcd2", ("drsuapi",), "MS-DRSR", "drsuapi (directory replication)", (
        *_ops("replication", ("T1003.006",), "3:DRSGetNCChanges"),
        *_ops("replication", ("T1207",), "2:DRSReplicaSync 5:DRSReplicaAdd 17:DRSAddEntry",
              "the technique of these replication calls (a rogue domain controller pushing changes) is ATT&CK's "
              "description of DCShadow, not the protocol document"),
        *_ops("enumeration", ("T1018",), "16:DRSDomainControllerInfo"),
        *_ops("sid_history", ("T1134.005",), "20:DRSAddSidHistory"),
    )),
    RpcInterface("12345778-1234-abcd-ef00-0123456789ac", ("samr",), "MS-SAMR", "Security Account Manager Remote", (
        *_ops("enumeration", ("T1087.002",),
              "6:SamrEnumerateDomainsInSamServer 13:SamrEnumerateUsersInDomain 17:SamrLookupNamesInDomain "
              "18:SamrLookupIdsInDomain 36:SamrQueryInformationUser 40:SamrQueryDisplayInformation "
              "47:SamrQueryInformationUser2 48:SamrQueryDisplayInformation2 51:SamrQueryDisplayInformation3"),
        *_ops("enumeration", ("T1069.002",),
              "11:SamrEnumerateGroupsInDomain 25:SamrGetMembersInGroup 39:SamrGetGroupsForUser"),
        *_ops("enumeration", ("T1069.001",),
              "15:SamrEnumerateAliasesInDomain 16:SamrGetAliasMembership 33:SamrGetMembersInAlias"),
        *_ops("enumeration", ("T1201",),
              "8:SamrQueryInformationDomain 44:SamrGetUserDomainPasswordInformation 46:SamrQueryInformationDomain2 "
              "56:SamrGetDomainPasswordInformation"),
        *_ops("account_change", ("T1136",), "12:SamrCreateUserInDomain 50:SamrCreateUser2InDomain"),
        *_ops("account_change", ("T1098",),
              "37:SamrSetInformationUser 58:SamrSetInformationUser2 38:SamrChangePasswordUser "
              "54:SamrOemChangePasswordUser2 55:SamrUnicodeChangePasswordUser2 63:SamrUnicodeChangePasswordUser3 "
              "73:SamrUnicodeChangePasswordUser4 66:SamrSetDSRMPassword"),
        *_ops("account_change", ("T1098.007",),
              "22:SamrAddMemberToGroup 31:SamrAddMemberToAlias 52:SamrAddMultipleMembersToAlias"),
        *_ops("account_change", ("T1531",), "35:SamrDeleteUser"),
    )),
    RpcInterface("12345778-1234-abcd-ef00-0123456789ab", ("lsarpc",), "MS-LSAT, MS-LSAD", "Local Security Authority", (
        *_ops("enumeration", ("T1087.002",),
              "14:LsarLookupNames 15:LsarLookupSids 57:LsarLookupSids2 58:LsarLookupNames2 68:LsarLookupNames3 "
              "76:LsarLookupSids3 77:LsarLookupNames4"),
        *_ops("enumeration", ("T1482",),
              "13:LsarEnumerateTrustedDomains 26:LsarQueryInfoTrustedDomain 39:LsarQueryTrustedDomainInfo "
              "48:LsarQueryTrustedDomainInfoByName 50:LsarEnumerateTrustedDomainsEx 73:LsarQueryForestTrustInformation"),
        *_ops("credential_access", ("T1003.004",), "30:LsarQuerySecret 43:LsarRetrievePrivateData"),
        *_ops("account_rights_change", ("T1098",),
              "10:LsarCreateAccount 19:LsarAddPrivilegesToAccount 37:LsarAddAccountRights"),
        *_ops("secret_write", (), "29:LsarSetSecret 42:LsarStorePrivateData",
              "no ATT&CK technique describes writing an LSA secret: none is given"),
    )),
    RpcInterface("4b324fc8-1670-01d3-1278-5a47bf6ee188", ("srvsvc",), "MS-SRVS", "Server Service Remote", (
        *_ops("enumeration", ("T1135",), "15:NetrShareEnum 16:NetrShareGetInfo 36:NetrShareEnumSticky"),
        *_ops("enumeration", ("T1049",), "8:NetrConnectionEnum 9:NetrFileEnum 12:NetrSessionEnum"),
        *_ops("enumeration", ("T1082",), "21:NetrServerGetInfo"),
        *_ops("enumeration", ("T1124",), "28:NetrRemoteTOD"),
    )),
    RpcInterface("12345678-1234-abcd-ef00-01234567cffb", ("netlogon",), "MS-NRPC", "Netlogon Remote", (
        *_ops("enumeration", ("T1482",),
              "19:NetrEnumerateTrustedDomains 36:NetrEnumerateTrustedDomainsEx 40:DsrEnumerateDomainTrusts "
              "43:DsrGetForestTrustInformation 44:NetrGetForestTrustInformation"),
        *_ops("secure_channel", (),
              "4:NetrServerReqChallenge 5:NetrServerAuthenticate 6:NetrServerPasswordSet 15:NetrServerAuthenticate2 "
              "26:NetrServerAuthenticate3 30:NetrServerPasswordSet2"),
    ), note="secure_channel is every domain member's routine: it is the input of a rate rule, not a finding"),
    RpcInterface("6bffd098-a112-3610-9833-46c3f87e345a", ("wkssvc",), "MS-WKST", "Workstation Service Remote", (
        *_ops("enumeration", ("T1033",), "2:NetrWkstaUserEnum"),
        *_ops("enumeration", ("T1082",), "0:NetrWkstaGetInfo"),
    ), note="Zeek does not log NetrWkstaGetInfo by default (DCE_RPC::ignored_operations)"),
    RpcInterface("c681d488-d850-11d0-8c52-00c04fd90f7e", ("efsrpc2",), "MS-EFSR",
                 "Encrypting File System Remote (over the lsarpc pipe)", (
                     *_ops("coercion", ("T1187",),
                           "0:EfsRpcOpenFileRaw 4:EfsRpcEncryptFileSrv 5:EfsDecryptFileSrv 6:EfsRpcQueryUsersOnFile "
                           "7:EfsRpcQueryRecoveryAgents 8:EfsRpcRemoveUsersFromFile 9:EfsRpcAddUsersToFile "
                           "12:EfsRpcFileKeyInfo 13:EfsRpcDuplicateEncryptionInfoFile 15:EfsRpcAddUsersToFileEx",
                           _COERCION_RESEARCH),
                     *_ops("coercion", ("T1187",),
                           "16:EfsRpcFileKeyInfoEx 18:EfsRpcGetEncryptedFileMetadata 19:EfsRpcSetEncryptedFileMetadata "
                           "21:EfsRpcEncryptFileExServ 22:EfsRpcQueryProtectors",
                           "a file-name operation of MS-EFSR not named by the public coercion research"),
                 )),
    RpcInterface("df1941c5-fe89-4e79-bf10-463657acf44d", ("efsrpc",), "MS-EFSR",
                 "Encrypting File System Remote (over the efsrpc pipe)", (
                     *_ops("coercion", ("T1187",),
                           "0:EfsRpcOpenFileRaw 4:EfsRpcEncryptFileSrv 5:EfsDecryptFileSrv 6:EfsRpcQueryUsersOnFile "
                           "7:EfsRpcQueryRecoveryAgents 8:EfsRpcRemoveUsersFromFile 9:EfsRpcAddUsersToFile "
                           "12:EfsRpcFileKeyInfo 13:EfsRpcDuplicateEncryptionInfoFile 15:EfsRpcAddUsersToFileEx",
                           _COERCION_RESEARCH),
                     *_ops("coercion", ("T1187",),
                           "16:EfsRpcFileKeyInfoEx 18:EfsRpcGetEncryptedFileMetadata 19:EfsRpcSetEncryptedFileMetadata "
                           "21:EfsRpcEncryptFileExServ 22:EfsRpcQueryProtectors",
                           "a file-name operation of MS-EFSR not named by the public coercion research"),
                 )),
    RpcInterface("4fc742e0-4a10-11cf-8273-00aa004ae673", ("netdfs",), "MS-DFSNM", "DFS Namespace Management",
                 _ops("coercion", ("T1187",), "12:NetrDfsAddStdRoot 13:NetrDfsRemoveStdRoot", _COERCION_RESEARCH)),
    RpcInterface("a8e0653c-2744-4389-a61d-7373df8b2292", ("FileServerVssAgent",), "MS-FSRVP",
                 "File Server Remote VSS", _ops("coercion", ("T1187",), "8:IsPathSupported 9:IsPathShadowCopied",
                                                _COERCION_RESEARCH)),
    RpcInterface("12345678-1234-abcd-ef00-0123456789ab", ("spoolss",), "MS-RPRN", "Print System Remote",
                 (*_ops("print_notification", ("T1187",),
                        "62:RpcRemoteFindFirstPrinterChangeNotification "
                        "65:RpcRemoteFindFirstPrinterChangeNotificationEx",
                        "the printer bug: these calls can force authentication, and every print client makes them"),
                  *_ops("driver_install", ("T1068", "T1210", "T1547.012"), "89:RpcAddPrinterDriverEx",
                        _DRIVER_RESEARCH)),
                 note="Zeek does not log RpcSplOpenPrinter or RpcClosePrinter by default "
                      "(DCE_RPC::ignored_operations)"),
    RpcInterface("76f03f96-cdfd-44fc-a22c-64950a001209", ("IRemoteWinspool",), "MS-PAR",
                 "Print System Asynchronous Remote",
                 _ops("driver_install", ("T1068", "T1210", "T1547.012"), "39:RpcAsyncAddPrinterDriver",
                      _DRIVER_RESEARCH)),
    RpcInterface("338cd001-2244-31f1-aaaa-900038001003", ("winreg",), "MS-RRP", "Windows Remote Registry", (
        *_ops("remote_registry", ("T1012",),
              "0:OpenClassesRoot 1:OpenCurrentUser 2:OpenLocalMachine 3:OpenPerformanceData 4:OpenUsers "
              "5:BaseRegCloseKey 9:BaseRegEnumKey 10:BaseRegEnumValue 11:BaseRegFlushKey 12:BaseRegGetKeySecurity "
              "14:BaseRegNotifyChangeKeyValue 15:BaseRegOpenKey 16:BaseRegQueryInfoKey 17:BaseRegQueryValue "
              "26:BaseRegGetVersion 27:OpenCurrentConfig 28:OpenDynData 29:BaseRegQueryMultipleValues "
              "32:OpenPerformanceText 33:OpenPerformanceNlsText 34:BaseRegQueryMultipleValues2"),
        *_ops("remote_registry", ("T1112",),
              "6:BaseRegCreateKey 7:BaseRegDeleteKey 8:BaseRegDeleteValue 13:BaseRegLoadKey 18:BaseRegReplaceKey "
              "19:BaseRegRestoreKey 21:BaseRegSetKeySecurity 22:BaseRegSetValue 23:BaseRegUnLoadKey "
              "35:BaseRegDeleteKeyEx"),
        *_ops("remote_registry", ("T1003.002", "T1003.004"), "20:BaseRegSaveKey 31:BaseRegSaveKeyEx",
              "a saved hive is credential material only when it is SAM or SECURITY, which dce_rpc.log does not name"),
        *_ops("remote_shutdown", ("T1529",), "24:BaseInitiateSystemShutdown 30:BaseInitiateSystemShutdownEx"),
    ), note="Zeek does not log BaseRegCloseKey, BaseRegGetVersion, BaseRegOpenKey, BaseRegQueryValue, "
            "BaseRegDeleteKeyEx, OpenLocalMachine, BaseRegEnumKey or OpenClassesRoot by default "
            "(DCE_RPC::ignored_operations); an aborted shutdown (25) stays other"),
    RpcInterface("894de0c0-0d55-11d3-a322-00c04fa321a1", ("InitShutdown",), "MS-RSP", "Remote Shutdown (InitShutdown)",
                 _ops("remote_shutdown", ("T1529",), "0:BaseInitiateShutdown 2:BaseInitiateShutdownEx")),
    RpcInterface("d95afe70-a6d5-4259-822e-2c84da1ddb0d", ("WindowsShutdown",), "MS-RSP",
                 "Remote Shutdown (WindowsShutdown)", _ops("remote_shutdown", ("T1529",), "0:WsdrInitiateShutdown")),
    RpcInterface("3919286a-b10c-11d0-9ba8-00c04fd92ef5", ("dssetup",), "MS-DSSP", "Directory Services Setup", (),
                 note="listed so the UUID is named correctly (it is not an LSA interface); no operation classified"),
)

_BY_UUID: dict[str, RpcInterface] = {}
_BY_NAME: dict[str, RpcInterface] = {}
for _interface in INTERFACES:
    if _interface.uuid in _BY_UUID:
        raise ValueError(f"duplicate RPC interface {_interface.uuid}")
    _BY_UUID[_interface.uuid] = _interface
    for _name in _interface.zeek_names:
        if _name.casefold() in _BY_NAME:
            raise ValueError(f"duplicate Zeek endpoint name {_name}")
        _BY_NAME[_name.casefold()] = _interface
    _opnums = [op.opnum for op in _interface.operations]
    if len(_opnums) != len(set(_opnums)):
        raise ValueError(f"{_interface.zeek_names}: an opnum is listed twice")
_OPS: dict[tuple[str, int], RpcOperation] = {(i.uuid, op.opnum): op for i in INTERFACES for op in i.operations}
# Zeek's operation names per interface: a name Zeek gives two opnums (IWbemServices' DeleteClass) maps to both
_NAMES: dict[tuple[str, str], tuple[RpcOperation, ...]] = {}
for _interface in INTERFACES:
    for _op in _interface.operations:
        _key = (_interface.uuid, _op.name.casefold())
        _NAMES[_key] = (*_NAMES.get(_key, ()), _op)
        if len({(op.op_class, op.attack) for op in _NAMES[_key]}) != 1:
            raise ValueError(f"{_op.name}: one Zeek name with two classes")

_UNKNOWN = "unknown-"
_OPNUM_DIGITS = 5                   # opnums are 16-bit (DCE 1.1 RPC request PDU): at most 65535


def canonical_uuid(text: object) -> str | None:
    """A UUID as this table keys it (lowercase, no braces), or None when the text is not one."""
    if not isinstance(text, str) or len(text) > 40:
        return None
    value = text.strip().strip("{}").lower()
    parts = value.split("-")
    if [len(part) for part in parts] != [8, 4, 4, 4, 12] or not all(
            part and all(c in "0123456789abcdef" for c in part) for part in parts):
        return None
    return value


def _opnum(text: str) -> int | None:
    """The opnum in Zeek's name for an opnum it has no name for ("unknown-<opnum>")."""
    if not text.startswith(_UNKNOWN):
        return None
    digits = text[len(_UNKNOWN):]
    if not digits.isdigit() or not digits.isascii() or len(digits) > _OPNUM_DIGITS:
        return None
    return int(digits)


def zeek_uuid(endpoint: object) -> str | None:
    """The interface UUID a Zeek endpoint name denotes: the listed interface's, or the one in Zeek's
    "unknown-<uuid>"; None for any other name (Zeek's names of interfaces this table does not list are not resolved)."""
    interface = interface_for_endpoint(endpoint)
    if interface is not None:
        return interface.uuid
    if isinstance(endpoint, str) and endpoint.strip().startswith(_UNKNOWN):
        return canonical_uuid(endpoint.strip()[len(_UNKNOWN):])
    return None


def zeek_opnum(endpoint: object, operation: object) -> int | None:
    """The opnum a Zeek operation name denotes: Zeek's "unknown-<opnum>", or a listed operation's (a name Zeek gives
    two opnums denotes neither); None otherwise."""
    if not isinstance(operation, str):
        return None
    number = _opnum(operation.strip())
    if number is not None:
        return number
    found = lookup_zeek(endpoint, operation)
    return found.operation.opnum if found.operation is not None else None


def interface_for_endpoint(endpoint: object) -> RpcInterface | None:
    """The interface a Zeek endpoint name denotes: its name, or Zeek's "unknown-<uuid>" for a UUID it has no name
    for. None when the table does not list it."""
    if not isinstance(endpoint, str):
        return None
    text = endpoint.strip()
    if text.startswith(_UNKNOWN):
        uuid = canonical_uuid(text[len(_UNKNOWN):])
        return _BY_UUID.get(uuid) if uuid is not None else None
    return _BY_NAME.get(text.casefold())


def lookup_call(uuid: object, opnum: object) -> RpcClass:
    """The class of a call named by interface UUID and opnum (host telemetry's naming)."""
    key = canonical_uuid(uuid)
    interface = _BY_UUID.get(key) if key is not None else None
    if interface is None or isinstance(opnum, bool) or not isinstance(opnum, int):
        return RpcClass(OTHER, (), interface)
    op = _OPS.get((interface.uuid, opnum))
    if op is None:
        return RpcClass(OTHER, (), interface)
    return RpcClass(op.op_class, op.attack, interface, op)


def lookup_zeek(endpoint: object, operation: object) -> RpcClass:
    """The class of a call named as Zeek's dce_rpc.log names it (endpoint, operation). Zeek's "unknown-<uuid>"
    endpoint and "unknown-<opnum>" operation resolve by number; any other name the table does not list is other."""
    interface = interface_for_endpoint(endpoint)
    if interface is None or not isinstance(operation, str):
        return RpcClass(OTHER, (), interface)
    text = operation.strip()
    number = _opnum(text)
    if number is not None:
        return lookup_call(interface.uuid, number)
    ops = _NAMES.get((interface.uuid, text.casefold()))
    if not ops:
        return RpcClass(OTHER, (), interface)
    return RpcClass(ops[0].op_class, ops[0].attack, interface, ops[0] if len(ops) == 1 else None)
