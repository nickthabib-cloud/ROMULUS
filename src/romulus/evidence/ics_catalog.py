"""Typed ICS operation catalog and native retrieval inputs.

Code/field sources (transcribed tables, not packet data):
- zeek/zeek f07a59d32cbbefdd7706bbe47a053f350c36aed0 (BSD):
  scripts/base/protocols/{modbus,dnp3}/{main,consts}.zeek.
- cisagov/icsnpp-modbus 6dd3dab173169e454a73925d0426d3c019104852:
  scripts/{main,consts}.zeek (diagnostics and MEI names).
- cisagov/icsnpp-dnp3 b31dbadeceb1cbcda16aef89c650559cd177dd7e:
  scripts/{main,consts}.zeek (control and object records).
- cisagov/icsnpp-s7comm 102a35c8f967f20640bd2427bb28a7c609b37493:
  scripts/consts.zeek; scripts/icsnpp/s7comm/main.zeek.
- cisagov/icsnpp-enip 3fbd32e3d2838d5e2bcd6c9ed79f036d23a0642e:
  scripts/consts.zeek; scripts/icsnpp/enip/main.zeek.
- cisagov/icsnpp-bacnet a04c08110328a57514383c626e5d4ad53aad57b1:
  scripts/consts.zeek; scripts/icsnpp/bacnet/main.zeek.
  All ICSNPP sources are BSD-3-Clause.
- CIP tag services are vendor specific, never universal 0x4c/0x4d:
  Rockwell 1756-PM020I-EN-P (September 2025), pp.16-18,24:
  https://literature.rockwellautomation.com/idc/groups/literature/documents/pm/1756-pm020_-en-p.pdf
  Only an explicit Symbol class (0x6b) permits those classifications here.

Shipper placement:
- cisagov/Malcolm 541160e513de90ed4ea5af1d1ed7a8a64758bf8d (Apache-2.0),
  logstash/pipelines/zeek/{1001_zeek_parse,1011_zeek_bacnet,1019_zeek_dnp3,
  1022_zeek_enip,1037_zeek_modbus,1051_zeek_s7comm,1200_zeek_mutate}.conf.
  Packet source/destination replace id.*, whose copies are deleted. Modbus
  detail func/tid/unit/exception/MEI move into zeek.modbus. BACnet subsidiary
  service moves into zeek.bacnet. No connection opener is inferred from ECS.
- elastic/integrations 8518218716a47fdd55b5e766f15e9fed1e5c3fe2 (ELv2),
  packages/zeek/data_stream/{modbus,dnp3}/elasticsearch/ingest_pipeline/default.yml:
  Modbus func -> zeek.modbus.function; DNP3 fc_* -> function.request/reply,
  iin is removed (only event.original can retain it).
- Security-Onion-Solutions/securityonion 742649a33797ceb85a111402fb48cd3839d2fcbb,
  salt/elasticsearch/files/ingest/zeek.{modbus,dnp3,common}:
  Modbus retains function+exception, DNP3 fc_request/fc_reply/iin. Common
  removes parsed message2; no structured Modbus pdu_type/tid/unit survives.
"""
from __future__ import annotations

from dataclasses import dataclass

MAX_VALUES = 128  # a fixed evidence preview; truncation is explicit, never a detection predicate
NOT_NORMALIZED_LOGS = frozenset({
    "bsap", "ecat", "genisys", "ge_srtp", "hart_ip", "omron_fins", "roc_plus",
    "profinet", "synchrophasor", "iec104", "c1222", "opcua_binary",
})


@dataclass(frozen=True)
class Function:
    code: int | None
    name: str
    op_class: str
    program_direction: str | None = None


def _table(rows):
    return {code: Function(code, name, op, direction[0] if direction else None)
            for code, name, op, *direction in rows}


MODBUS = _table((
    (1, "READ_COILS", "read"), (2, "READ_DISCRETE_INPUTS", "read"),
    (3, "READ_HOLDING_REGISTERS", "read"), (4, "READ_INPUT_REGISTERS", "read"),
    (5, "WRITE_SINGLE_COIL", "write"), (6, "WRITE_SINGLE_REGISTER", "write"),
    (8, "DIAGNOSTICS", "diagnostic"), (15, "WRITE_MULTIPLE_COILS", "write"),
    (16, "WRITE_MULTIPLE_REGISTERS", "write"), (17, "REPORT_SLAVE_ID", "discovery"),
    (22, "MASK_WRITE_REGISTER", "write"), (23, "READ_WRITE_MULTIPLE_REGISTERS", "write"),
    (43, "ENCAP_INTERFACE_TRANSPORT", "other"),
))
DNP3 = _table((
    (0, "CONFIRM", "other"), (1, "READ", "read"), (2, "WRITE", "write"),
    (3, "SELECT", "control"), (4, "OPERATE", "control"),
    (5, "DIRECT_OPERATE", "control"), (6, "DIRECT_OPERATE_NR", "control"),
    (7, "IMMED_FREEZE", "control"), (8, "IMMED_FREEZE_NR", "control"),
    (9, "FREEZE_CLEAR", "control"), (10, "FREEZE_CLEAR_NR", "control"),
    (11, "FREEZE_AT_TIME", "control"), (12, "FREEZE_AT_TIME_NR", "control"),
    (13, "COLD_RESTART", "restart"), (14, "WARM_RESTART", "restart"),
    (15, "INITIALIZE_DATA", "control"), (16, "INITIALIZE_APPL", "control"),
    (17, "START_APPL", "mode_change"), (18, "STOP_APPL", "mode_change"),
    (19, "SAVE_CONFIG", "control"), (20, "ENABLE_UNSOLICITED", "control"),
    (21, "DISABLE_UNSOLICITED", "control"), (22, "ASSIGN_CLASS", "control"),
    (23, "DELAY_MEASURE", "diagnostic"), (24, "RECORD_CURRENT_TIME", "control"),
    (25, "OPEN_FILE", "other"), (26, "CLOSE_FILE", "other"),
    (27, "DELETE_FILE", "write"), (28, "GET_FILE_INFO", "discovery"),
    (29, "AUTHENTICATE_FILE", "other"), (30, "ABORT_FILE", "control"),
    (31, "ACTIVATE_CONFIG", "control"), (32, "AUTHENTICATE_REQ", "other"),
    (33, "AUTHENTICATE_REQ_NR", "other"), (129, "RESPONSE", "other"),
    (130, "UNSOLICITED_RESPONSE", "other"), (131, "AUTHENTICATE_RESP", "other"),
))
S7COMM = _table((
    (4, "Read Variable", "read"), (5, "Write Variable", "write"),
    (26, "Request Download", "program_transfer", "download"),
    (27, "Download Block", "program_transfer", "download"),
    (28, "Download Ended", "program_transfer", "download"),
    (29, "Start Upload", "program_transfer", "upload"),
    (30, "Upload", "program_transfer", "upload"),
    (31, "End Upload", "program_transfer", "upload"),
    (40, "PLC Control", "control"), (41, "PLC Stop", "mode_change"),
))
S7COMM_PLUS = _table((
    (0x4bb, "Explore", "discovery"), (0x4ca, "Create Object", "control"),
    (0x4d4, "Delete Object", "control"), (0x4f2, "Set Variable", "write"),
    (0x524, "Get Link", "read"), (0x542, "Set Multi Variables", "write"),
    (0x54c, "Get Multi Variables", "read"), (0x556, "Begin Sequence", "other"),
    (0x560, "End Sequence", "other"), (0x56b, "Invoke", "control"),
    (0x586, "Get Variable Sub Streamed", "read"),
))
ENIP = _table(((4, "List Services", "discovery"), (99, "List Identity", "discovery")))
CIP = _table((
    (1, "Get Attributes All", "read"), (2, "Set Attributes All", "write"),
    (3, "Get Attribute List", "read"), (4, "Set Attribute List", "write"),
    (5, "Reset", "restart"), (6, "Start", "mode_change"), (7, "Stop", "mode_change"),
    (14, "Get Attributes Single", "read"), (16, "Set Attributes Single", "write"),
))
BACNET = _table((
    (6, "atomic_read_file", "program_transfer", "upload"),
    (7, "atomic_write_file", "program_transfer", "download"),
    (12, "read_property", "read"), (14, "read_property_multiple", "read"),
    (15, "write_property", "write"), (16, "write_property_multiple", "write"),
    (17, "device_communication_control", "mode_change"), (20, "reinitialize_device", "restart"),
))
BACNET_UNCONFIRMED = _table(((0, "i_am", "other"), (7, "who_has", "discovery"),
                              (8, "who_is", "discovery")))
TABLES = {"modbus": MODBUS, "dnp3": DNP3, "s7comm": S7COMM, "s7comm_plus": S7COMM_PLUS,
          "enip": ENIP, "cip": CIP, "bacnet": BACNET}


def _key(name):
    return str(name).strip().lower().replace("-", "_").replace(" ", "_")


def lookup_function(protocol: str, code: int | None = None, *, name: str | None = None,
                    subfunction: int | str | None = None, mei: int | str | None = None,
                    class_id: int | None = None, userdata: bool = False) -> Function:
    """Exact native code/name lookup; unknown names remain evidence with class other."""
    native = name or (f"function-{code}" if code is not None else "unknown")
    key = _key(native).removesuffix("_exception")
    if protocol == "bacnet":
        key = key.removeprefix("error:_")
        for suffix in ("_request", "_ack"):
            key = key.removesuffix(suffix)
        if code is None:
            for item in (*BACNET.values(), *BACNET_UNCONFIRMED.values()):
                if _key(item.name) == key:
                    return item
    table = TABLES.get(protocol, {})
    if code is None:
        if protocol == "modbus" and key == "report_server_id":
            code = 17
        else:
            code = next((n for n, item in table.items() if _key(item.name) == key), None)
    if protocol == "s7comm" and userdata:
        # ROSCTR 7 has an independent function-group namespace.
        if code is not None and code & 0xf == 4 and subfunction == 1:
            return Function(code, "Read SZL", "discovery")
        return Function(code, native, "other")
    if protocol == "s7comm" and code == 40 and subfunction == "P_PROGRAM":
        return Function(40, "PLC Control", "mode_change")
    if protocol == "cip" and class_id == 0x6b:
        tags = {0x4c: ("Read Tag", "read"), 0x4d: ("Write Tag", "write"),
                0x52: ("Read Tag Fragmented", "read"), 0x53: ("Write Tag Fragmented", "write")}
        if code in tags:
            return Function(code, *tags[code])
    found = table.get(code)
    if found is None:
        return Function(code, native, "other")
    if protocol == "modbus":
        if code == 8:
            sub = _key(subfunction)
            if isinstance(subfunction, str) and subfunction.lower().startswith("0x"):
                try:
                    subfunction = int(subfunction, 16)
                except ValueError:
                    pass
            if subfunction == 1 or sub == "restart_communications_option":
                return Function(8, found.name, "restart")
            if subfunction == 4 or sub == "force_listen_only_mode":
                return Function(8, found.name, "mode_change")
        if code == 43 and (mei == 14 or _key(mei) == "read_device_identification"):
            return Function(43, "Read Device Identification", "discovery")
    return found


@dataclass(frozen=True)
class RetrievalSelection:
    """Exclude exact routine-read values only; unknowns and missing functions stay selected.

    Parent retrieval must OR exceptions back in. Numeric exception fields require
    nonzero tests, not exists (zero is normal). A missing/unfilterable necessary
    field requires the existing unfiltered fallback.
    """
    read_fields: tuple[str, ...] = ()
    read_values: tuple[str | int, ...] = ()
    exception_fields: tuple[str, ...] = ()
    nonzero_exception_fields: tuple[str, ...] = ()


def retrieval_selection(log: str, shape: str) -> RetrievalSelection:
    prefix = f"zeek.{log}." if shape == "malcolm" else ""
    native = lambda field: prefix + field
    modreads = tuple(f.name for f in MODBUS.values() if f.op_class == "read")
    if log.startswith("modbus"):
        field = "zeek.modbus.func" if shape == "malcolm" else (
            "zeek.modbus.function" if shape == "elastic" else "modbus.function" if shape == "security_onion" else "func")
        exc = "zeek.modbus.exception" if shape in ("malcolm", "elastic") else (
            "modbus.exception" if shape == "security_onion" else "exception" if log == "modbus" else "exception_code")
        return RetrievalSelection((field,), modreads, (exc,))
    if log == "dnp3":
        field = {"malcolm": "zeek.dnp3.fc_request", "plain": "fc_request",
                 "elastic": "zeek.dnp3.function.request", "security_onion": "dnp3.fc_request"}[shape]
        # Elastic deletes iin; no indexed exception predicate can preserve exceptional reads.
        if shape == "elastic":
            return RetrievalSelection()
        iin = {"malcolm": "zeek.dnp3.iin", "plain": "iin", "security_onion": "dnp3.iin"}[shape]
        return RetrievalSelection((field,), ("READ",), (), (iin,))
    if log == "dnp3_control":
        return RetrievalSelection((native("function_code"),), ("READ",), (native("status_code"),))
    if log == "dnp3_objects":
        return RetrievalSelection()  # RESPONSE alone carries no request operation or response error
    if log == "s7comm":
        # Names avoid ROSCTR user-data's overlapping numeric namespace.
        return RetrievalSelection((native("function_name"),), ("Read Variable",),
                                  (), (native("error_code"), native("error_class")))
    if log == "s7comm_plus":
        return RetrievalSelection((native("function_name"),),
                                  tuple(f.name for f in S7COMM_PLUS.values() if f.op_class == "read"))
    if log == "cip":
        return RetrievalSelection((native("cip_service_code"),), ("0x01", "0x03", "0x0e"),
                                  (), (native("cip_status_code"),))
    if log in ("bacnet", "bacnet_property"):
        field = "zeek.bacnet.pdu_service" if shape == "malcolm" else "pdu_service"
        reads = ("read_property", "read_property_multiple", "read-property-request", "read-property-ack",
                 "read-property-multiple-request", "read-property-multiple-ack")
        # ERROR_PDU/error services are different native values, never excluded here.
        return RetrievalSelection((field,), reads)
    return RetrievalSelection()

