"""Synthetic ICS rows in published layouts, never copied traffic.

Sources and pinned commits: romulus.evidence.ics_catalog. Each writer reproduces
Malcolm 1001/10xx/1200 field moves, Elastic modbus/dnp3 ingest, or SO zeek.*
ingest. ICSNPP-only logs have no invented Elastic or Security Onion shape.
"""
from __future__ import annotations

import copy
import json

from tests.fixtures import zeek_logs as zl

SHAPES_BY_LOG = {
    **{n: zl.SHAPES for n in ("modbus", "dnp3")},
    **{n: ("malcolm", "plain") for n in (
        "modbus_detailed", "modbus_mask_write_register", "modbus_read_device_identification",
        "modbus_read_write_multiple_registers", "dnp3_control", "dnp3_objects",
        "s7comm", "s7comm_plus", "s7comm_read_szl", "s7comm_upload_download", "cotp",
        "enip", "cip", "cip_identity", "cip_io", "bacnet", "bacnet_discovery",
        "bacnet_property", "bacnet_device_control")},
}


def row(log, **fields):
    native = {"uid": "Cics000000000001", "id.orig_h": zl.CLIENT, "id.orig_p": 45000,
              "id.resp_h": zl.SERVER, "id.resp_p": 502}
    if log not in ("modbus", "modbus_detailed", "dnp3"):
        native.update(is_orig=True, source_h=zl.CLIENT, source_p=45000,
                      destination_h=zl.SERVER, destination_p=502)
    return zl.Row(log, {**native, **fields})


ROWS = {r.log: r for r in (
    row("modbus", func="WRITE_SINGLE_REGISTER", pdu_type="REQ", tid=7, unit=1),
    row("modbus_detailed", func="WRITE_SINGLE_REGISTER", tid=7, unit=1, address=12,
        quantity=1, request_values=[42], response_values=[42], matched=True),
    row("modbus_mask_write_register", func="MASK_WRITE_REGISTER", tid=7, unit=1,
        request_response="REQUEST", address=12, and_mask=255, or_mask=1),
    row("modbus_read_device_identification", func="ENCAP_INTERFACE_TRANSPORT", tid=7, unit=1,
        request_response="REQUEST", mei_type="READ-DEVICE-IDENTIFICATION"),
    row("modbus_read_write_multiple_registers", func="READ_WRITE_MULTIPLE_REGISTERS", tid=7, unit=1,
        request_response="REQUEST", write_start_address=12, write_registers=[42], read_quantity=1),
    row("dnp3", fc_request="OPERATE", fc_reply="RESPONSE", iin=0),
    row("dnp3_control", function_code="OPERATE", index_number=12),
    row("dnp3_objects", function_code="READ", object_count=1, range_low=12),
    row("s7comm", function_code="0x05", function_name="Write Variable", rosctr_code=1,
        rosctr_name="Job-Request", pdu_reference=7),
    row("s7comm_plus", function_code="0x04f2", function_name="Set Variable", opcode="0x31"),
    row("s7comm_read_szl", method="Request", pdu_reference=7, szl_id="0x0011"),
    row("s7comm_upload_download", rosctr="Job-Request", pdu_reference=7,
        function_name="Request Download", session_id=1),
    row("cotp", pdu_code="0xe", pdu_name="CR Connection Request"),
    row("enip", enip_command_code="0x63", enip_command="List Identity", enip_status="Success"),
    row("cip", cip_service_code="0x10", cip_service="Set Attributes Single",
        direction="request", cip_sequence_count=7, class_id="0x01"),
    row("cip_identity", product_name="Synthetic controller"),
    row("cip_io", sequence_number=7, io_data="01020304", data_length=4),
    row("bacnet", pdu_type="CONFIRMED_REQUEST", pdu_service="write_property", invoke_id=7),
    row("bacnet_discovery", pdu_service="who-is"),
    row("bacnet_property", pdu_service="write-property", invoke_id=7,
        property="present-value", instance_number=12, value="42"),
    row("bacnet_device_control", pdu_service="reinitialize_device", invoke_id=7, device_state="coldstart"),
)}


def hit(record, shape="malcolm", nid="ics-1", *, text=False, sensor=zl.SENSOR):
    if shape not in SHAPES_BY_LOG[record.log]:
        raise ValueError("shipper does not carry this log")
    if shape == "plain":
        return zl.plain(record, nid)
    log, cols = record.log, copy.deepcopy(record.json())
    stamp = zl.iso_ms(record.ts)
    source = {"@timestamp": stamp, "event": {"dataset": log}, "observer": {"name": sensor}}
    if shape == "malcolm":
        source.update(event={"provider": "zeek", "dataset": log}, node=sensor,
                      zeek={"uid": cols.pop("uid"), "ts": stamp})
        z = cols
        packet = "source_h" in z and "destination_h" in z
        source["source"] = {"ip": z.pop("source_h" if packet else "id.orig_h"),
                            "port": z.pop("source_p" if packet else "id.orig_p")}
        source["destination"] = {"ip": z.pop("destination_h" if packet else "id.resp_h"),
                                 "port": z.pop("destination_p" if packet else "id.resp_p")}
        for name in ("id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "ts"):
            z.pop(name, None)
        if "is_orig" in z:
            source["network"] = {"is_orig": z.pop("is_orig")}
        if "password" in z:
            source["related"] = {"password": z.pop("password")}
        if log.startswith("modbus"):
            if log == "modbus":
                if "pdu_type" in z:
                    z["network_direction"] = {"REQ": "request", "RESP": "response"}[z.pop("pdu_type")]
            else:
                for a, b in (("tid", "trans_id"), ("unit", "unit_id"),
                             ("request_response", "network_direction")):
                    if a in z:
                        z[b] = z.pop(a)
            source["zeek"][log] = z
            if log != "modbus":
                common = source["zeek"].setdefault("modbus", {})
                for name in ("func", "unit_id", "trans_id", "network_direction", "mei_type"):
                    if name in z:
                        common[name] = z.pop(name)
                if "exception_code" in z:
                    common["exception"] = z.pop("exception_code")
                if log == "modbus_mask_write_register" and "address" in z:
                    source["zeek"].setdefault("modbus_detailed", {})["address"] = z.pop("address")
        elif log.startswith("bacnet"):
            source["zeek"][log] = z
            if log != "bacnet":
                common = source["zeek"].setdefault("bacnet", {})
                if "pdu_service" in z:
                    common["pdu_service"] = z.pop("pdu_service")
                if log == "bacnet_device_control" and "invoke_id" in z:
                    common["invoke_id"] = z.pop("invoke_id")
        else:
            if log == "s7comm_upload_download" and "rosctr" in z:
                z["rosctr_name"] = z.pop("rosctr")
            source["zeek"][log] = z
        if text:
            def textual(v):
                if isinstance(v, dict):
                    return {k: textual(x) for k, x in v.items()}
                if isinstance(v, list):
                    return ",".join(str(x) for x in v)
                return "T" if v is True else "F" if v is False else str(v)
            source["zeek"][log] = textual(source["zeek"][log])
            for obj in ("modbus", "modbus_detailed", "bacnet"):
                if obj in source["zeek"] and obj != log:
                    source["zeek"][obj] = textual(source["zeek"][obj])
        return {"_id": nid, "_index": zl.INDEX[shape], "_source": source}
    source.update(event={"module": "zeek", "dataset": f"zeek.{log}"},
                  source={"ip": cols.pop("id.orig_h"), "port": cols.pop("id.orig_p")},
                  destination={"ip": cols.pop("id.resp_h"), "port": cols.pop("id.resp_p")})
    uid = cols.pop("uid")
    cols.pop("ts")
    if shape == "elastic":
        source["event"].pop("module", None)
        source["data_stream"] = {"dataset": f"zeek.{log}"}
        source["agent"] = {"name": sensor}
        source["zeek"] = {"session_id": uid, log: cols}
        if log == "modbus" and "func" in cols:
            cols["function"] = cols.pop("func")
        elif log == "dnp3":
            cols["function"] = {k: cols.pop(v) for k, v in (("request", "fc_request"), ("reply", "fc_reply"))
                                if v in cols}
            cols.pop("iin", None)
        source["event"]["original"] = json.dumps(record.json())
    else:
        source["data_stream"] = {"dataset": "zeek"}
        source["log"] = {"id": {"uid": uid}}
        kept = {"function": cols["func"]} if log == "modbus" and "func" in cols else {}
        if log == "modbus" and "exception" in cols:
            kept["exception"] = cols["exception"]
        if log == "dnp3":
            kept = {k: v for k, v in cols.items() if k in ("fc_request", "fc_reply", "iin")}
        source[log] = kept
    return {"_id": nid, "_index": zl.INDEX[shape], "_source": source}
