"""ICS normalization proof over source-supported carriage only."""
import json

import pytest

from romulus.evidence.typed import NETWORK_OBSERVER_FAMILIES
from romulus.evidence.zeek import normalize_plain_zeek, normalize_zeek, scrub_zeek_source, zeek_record
from romulus.evidence.zeek_catalog import lookup_log
from tests.fixtures import zeek_ics as zi
from tests.fixtures import zeek_logs as zl


def normalize(row, shape="plain", **kw):
    h = zi.hit(row, shape, **kw)
    return normalize_plain_zeek(h, sensor=zl.SENSOR) if shape == "plain" else normalize_zeek(h, zeek_record(h["_source"]))


@pytest.mark.parametrize("log", zi.ROWS)
def test_real_carriage(log):
    assert "ics_tx" in NETWORK_OBSERVER_FAMILIES
    row = zi.ROWS[log]
    reference = normalize(row)
    for shape in zi.SHAPES_BY_LOG[log]:
        assert lookup_log(shape, log) is not None
        event = normalize(row, shape)
        assert event.family == "ics_tx"
        assert event.get("ics.protocol")
        assert event.get("ics.op_class")
        for name in ("ics.protocol", "ics.function_code", "ics.function_name", "ics.op_class",
                     "ics.program_direction"):
            assert event.get(name) == reference.get(name), (log, shape, name)
        assert ("host", zl.SENSOR, "observer") in event.entities()
    for shape in set(zl.SHAPES) - set(zi.SHAPES_BY_LOG[log]):
        assert lookup_log(shape, log) is None


@pytest.mark.parametrize("log", [n for n, s in zi.SHAPES_BY_LOG.items() if s == ("malcolm", "plain")])
def test_malcolm_text_equals_json(log):
    a, b = normalize(zi.ROWS[log], "malcolm"), normalize(zi.ROWS[log], "malcolm", text=True)
    assert {k: v.value for k, v in a.fields.items()} == {k: v.value for k, v in b.fields.items()}


@pytest.mark.parametrize("log,fields,protocol,code,op", [
    ("modbus", {"func": "WRITE_SINGLE_REGISTER", "pdu_type": "REQ"}, "modbus", 6, "write"),
    ("modbus", {"func": "VENDOR_UNKNOWN"}, "modbus", None, "other"),
    ("modbus_detailed", {"func": "DIAGNOSTICS", "request_subfunction_code": "Restart Communications Option"}, "modbus", 8, "restart"),
    ("modbus_detailed", {"func": "DIAGNOSTICS", "request_subfunction_code": "Force Listen Only Mode"}, "modbus", 8, "mode_change"),
    ("dnp3_control", {"function_code": "COLD_RESTART"}, "dnp3", 13, "restart"),
    ("s7comm", {"function_code": "0x29", "function_name": "PLC Stop"}, "s7comm", 41, "mode_change"),
    ("s7comm_upload_download", {"function_name": "Start Upload"}, "s7comm", 29, "program_transfer"),
    ("enip", {"enip_command_code": "0x63"}, "enip", 99, "discovery"),
    ("cip", {"cip_service_code": "0x05"}, "cip", 5, "restart"),
    ("bacnet", {"pdu_service": "atomic_write_file"}, "bacnet", 7, "program_transfer"),
    ("bacnet_discovery", {"pdu_service": "who-is"}, "bacnet", 8, "discovery"),
])
def test_function_catalog(log, fields, protocol, code, op):
    e = normalize(zi.ROWS[log].with_(**fields))
    assert (e.get("ics.protocol"), e.get("ics.function_code"), e.get("ics.op_class")) == (protocol, code, op)
    if fields.get("func") == "VENDOR_UNKNOWN":
        assert e.get("ics.function_name") == "VENDOR_UNKNOWN"


@pytest.mark.parametrize("shape", ("malcolm", "plain"))
def test_packet_direction_and_transaction(shape):
    row = zi.ROWS["s7comm"].with_(is_orig=False, source_h=zl.SERVER, source_p=502,
                                 destination_h=zl.CLIENT, destination_p=45000,
                                 rosctr_code=3, rosctr_name="ACK-Data", error_class="No error", error_code="0x00")
    e = normalize(row, shape)
    assert e.get("ics.sender") == zl.SERVER and e.get("ics.receiver") == zl.CLIENT
    assert e.get("ics.is_request") is False and e.get("ics.exception") is False
    assert e.get("ics.transaction_id") == 7 and e.get("zeek.uid") == "Cics000000000001"
    assert not e.has("tcp.opened_by_orig")
    assert e.get("conn.orig_h") == (zl.CLIENT if shape == "plain" else None)


@pytest.mark.parametrize("shape", ("malcolm", "elastic", "plain"))
def test_modbus_request_response_exception_pairing_fields(shape):
    request = normalize(zi.ROWS["modbus"], shape)
    response = normalize(zi.ROWS["modbus"].with_(pdu_type="RESP"), shape)
    failure = normalize(zi.ROWS["modbus"].with_(pdu_type="RESP",
                                             func="WRITE_SINGLE_REGISTER_EXCEPTION", exception="ILLEGAL_DATA_VALUE"), shape)
    assert request.get("ics.is_request") is True
    assert response.get("ics.is_request") is False and response.get("ics.exception") is False
    assert failure.get("ics.exception") is True
    assert failure.get("ics.function_code") == request.get("ics.function_code") == 6
    assert request.get("ics.transaction_id") == response.get("ics.transaction_id") == failure.get("ics.transaction_id") == 7
    assert response.get("ics.sender") == zl.SERVER


def test_no_invented_direction_or_ack_for_summary_and_dropped_fields():
    for row in (zi.ROWS["modbus"].without("pdu_type"), zi.ROWS["dnp3"], zi.ROWS["modbus_detailed"]):
        e = normalize(row)
        assert e.get("ics.is_request") is None
    onion = normalize(zi.ROWS["modbus"], "security_onion")
    assert onion.get("ics.transaction_id") is None and onion.get("ics.is_request") is None


def test_s7_userdata_code_space_does_not_alias_parameter_write():
    e = normalize(zi.ROWS["s7comm"].with_(rosctr_code=7, function_code="0x45",
                                        function_name="Request: Security", subfunction_code="0x01"))
    assert e.get("ics.op_class") == "other"


def test_values_are_bounded_numeric_and_honestly_truncated():
    from romulus.evidence.ics_catalog import MAX_VALUES
    e = normalize(zi.ROWS["modbus_detailed"].with_(request_values=list(range(MAX_VALUES + 50))))
    assert e.get("ics.values") == list(range(MAX_VALUES))
    assert e.get("ics.values_truncated") is True
    assert any("values" in c and "truncat" in c for c in e.caveats)


@pytest.mark.parametrize("shape", ("plain", "malcolm"))
def test_no_ics_password_or_key_reaches_typed_or_stored(shape):
    secrets = {"protection_password": "SECRET_S7_987", "secure_auth_key": "SECRET_DNP3_987",
               "password": "SECRET_BAC_987"}
    row = zi.ROWS["s7comm"].with_(**secrets)
    h = zi.hit(row, shape)
    event = normalize(row, shape)
    stored = scrub_zeek_source(h["_source"])
    assert all(s not in event.model_dump_json() + json.dumps(stored) for s in secrets.values())


def test_class_specific_cip_codes_never_become_tags_unconditionally():
    from romulus.evidence.ics_catalog import lookup_function
    assert lookup_function("cip", 0x4d, class_id=0x6b).op_class == "write"
    assert lookup_function("cip", 0x4d, class_id=0x01).op_class == "other"


def test_source_catalog_inventories_and_retrieval_inputs():
    from romulus.evidence.ics_catalog import NOT_NORMALIZED_LOGS, retrieval_selection
    from romulus.evidence.zeek_catalog import ICS_LOGS
    assert {l.name for l in ICS_LOGS} == set(zi.SHAPES_BY_LOG)
    assert "opcua_binary" in NOT_NORMALIZED_LOGS
    selection = retrieval_selection("modbus", "malcolm")
    assert selection.read_fields == ("zeek.modbus.func",)
    assert "READ_HOLDING_REGISTERS" in selection.read_values
    assert "WRITE_SINGLE_REGISTER" not in selection.read_values
    assert selection.exception_fields == ("zeek.modbus.exception",)

@pytest.mark.parametrize("log,fields,is_request,exception,op", [
    ("dnp3_control", {"function_code": "RESPONSE", "status_code": "Success"}, False, False, "other"),
    ("dnp3_control", {"function_code": "RESPONSE", "status_code": "Not Authorized"}, False, True, "other"),
    ("dnp3", {"fc_request": None, "fc_reply": "RESPONSE", "iin": 1}, None, True, "other"),
    ("dnp3", {"fc_request": None, "fc_reply": "RESPONSE", "iin": 0x200}, None, False, "other"),
    ("s7comm", {"is_orig": False, "rosctr_code": 3, "rosctr_name": "ACK-Data",
                "error_class": "Access error", "error_code": "0x01"}, False, True, "write"),
    ("s7comm", {"is_orig": False, "rosctr_code": 3, "rosctr_name": "ACK-Data",
                "error_class": "Access error", "error_code": "0x00"}, False, True, "write"),
    ("s7comm_read_szl", {"method": "Response", "return_code": "0xff"}, False, False, "discovery"),
    ("s7comm_read_szl", {"method": "Response", "return_code": "0x05"}, False, True, "discovery"),
    ("cip", {"direction": "response", "is_orig": False, "cip_status_code": "0x00"}, False, False, "write"),
    ("cip", {"direction": "response", "is_orig": False, "cip_status_code": "0x05"}, False, True, "write"),
    ("enip", {"is_orig": False, "enip_status": "Success"}, False, False, "discovery"),
    ("enip", {"is_orig": False, "enip_status": "Invalid/Unsupported Command"}, False, True, "discovery"),
    ("bacnet", {"pdu_type": "SIMPLE_ACK"}, False, False, "write"),
    ("bacnet", {"pdu_type": "ERROR_PDU", "pdu_service": "error", "result_code": "write-access-denied"}, False, True, "other"),
    ("bacnet_property", {"pdu_service": "read-property-multiple-ack"}, False, False, "read"),
    ("bacnet_property", {"pdu_service": "ERROR: write_property"}, False, True, "write"),
])
@pytest.mark.parametrize("shape", ("malcolm", "plain"))
def test_native_responses_and_exceptions(log, fields, is_request, exception, op, shape):
    e = normalize(zi.ROWS[log].with_(**fields), shape)
    assert e.get("ics.is_request") is is_request
    assert e.get("ics.exception") is exception
    assert e.get("ics.op_class") == op


@pytest.mark.parametrize("log,fields,code,op,direction", [
    ("modbus_read_device_identification", {"mei_type": "READ-DEVICE-IDENTIFICATION"}, 43, "discovery", None),
    ("modbus", {"func": "REPORT_SLAVE_ID"}, 17, "discovery", None),
    ("modbus_detailed", {"func": "DIAGNOSTICS", "request_subfunction_code": "0x0001"}, 8, "restart", None),
    ("modbus_detailed", {"func": "ENCAP_INTERFACE_TRANSPORT", "mei_type": "CANopen General Reference"}, 43, "other", None),
    ("dnp3_control", {"function_code": "DIRECT_OPERATE_NR"}, 6, "control", None),
    ("dnp3_control", {"function_code": "WARM_RESTART"}, 14, "restart", None),
    ("dnp3", {"fc_request": "START_APPL"}, 17, "mode_change", None),
    ("dnp3", {"fc_request": "OPEN_FILE"}, 25, "other", None),
    ("s7comm", {"function_code": "0x28", "function_name": "PLC Control", "subfunction_code": "_N_LOGIN_"}, 40, "control", None),
    ("s7comm", {"rosctr_code": 7, "function_code": "0x44", "function_name": "Request: CPU Functions", "subfunction_code": "0x01"}, 68, "discovery", None),
    ("s7comm_upload_download", {"function_name": "End Upload"}, 31, "program_transfer", "upload"),
    ("s7comm_upload_download", {"function_name": "Download Block"}, 27, "program_transfer", "download"),
    ("cip", {"cip_service_code": "0x4d", "class_id": "0x6b"}, 77, "write", None),
    ("cip", {"cip_service_code": "0x4c", "class_id": "0x01"}, 76, "other", None),
    ("bacnet", {"pdu_service": "atomic_read_file"}, 6, "program_transfer", "upload"),
    ("bacnet", {"pdu_service": "device_communication_control"}, 17, "mode_change", None),
    ("bacnet", {"pdu_service": "reinitialize_device"}, 20, "restart", None),
])
def test_protocol_namespaces_and_program_directions(log, fields, code, op, direction):
    e = normalize(zi.ROWS[log].with_(**fields))
    assert (e.get("ics.function_code"), e.get("ics.op_class"), e.get("ics.program_direction")) == (code, op, direction)


@pytest.mark.parametrize("values", ([-1], ["key-bytes"], [True], [65536], {"bad": 1}))
def test_malformed_values_never_become_evidence_values(values):
    e = normalize(zi.ROWS["modbus_detailed"].with_(request_values=values, response_values=None))
    assert not e.has("ics.values") and e.has("parse.malformed")


def test_scrub_keys_from_nested_ics_fields_kept_original_and_failure_path():
    payload = {"_path": "s7comm", "ts": "invalid", "auth": {"session_key": "SECRET_KEY_999"},
               "protection_password": "SECRET_PASSWORD_999"}
    h = zi.hit(zi.ROWS["s7comm"], "malcolm")
    h["_source"]["zeek"]["s7comm"]["auth"] = payload["auth"]
    h["_source"]["event"]["original"] = json.dumps(payload)
    h["_source"]["@timestamp"] = "invalid"
    h["_source"]["zeek"]["ts"] = "invalid"
    for source in (payload, h["_source"]):
        stored = json.dumps(scrub_zeek_source(source))
        assert "SECRET_KEY_999" not in stored and "SECRET_PASSWORD_999" not in stored


def test_read_selectors_include_bacnet_multiple_shapes_and_preserve_no_indexed_iin():
    from romulus.evidence.ics_catalog import retrieval_selection
    for shape in ("plain", "malcolm"):
        assert "read-property-multiple-request" in retrieval_selection("bacnet_property", shape).read_values
    assert not retrieval_selection("dnp3", "elastic").read_fields

@pytest.mark.parametrize("shape", ("malcolm", "plain"))
@pytest.mark.parametrize("subfunction,op", [
    ("Restart Communications Option", "restart"), ("Force Listen Only Mode", "mode_change")])
def test_modbus_diagnostics_summary_proves_a_request_without_inventing_packet_direction(shape, subfunction, op):
    row = zi.ROWS["modbus_detailed"].with_(func="DIAGNOSTICS", request_values=None, response_values=None,
                                          request_subfunction_code=subfunction, matched=False)
    e = normalize(row, shape)
    assert e.get("ics.op_class") == op
    assert e.get("ics.request_observed") is True
    assert "request_subfunction_code" in e.fields["ics.request_observed"].origin
    assert e.get("ics.is_request") is None and e.get("ics.sender") is None and e.get("ics.receiver") is None
    assert e.get("conn.orig_h") == zl.CLIENT and e.get("conn.resp_h") == zl.SERVER
    assert e.get("ics.exception") is None


@pytest.mark.parametrize("shape", ("malcolm", "plain"))
@pytest.mark.parametrize("func", ("WRITE_SINGLE_COIL", "WRITE_SINGLE_REGISTER",
                                  "WRITE_MULTIPLE_COILS", "WRITE_MULTIPLE_REGISTERS"))
def test_modbus_write_summary_request_values_prove_request_observation(shape, func):
    e = normalize(zi.ROWS["modbus_detailed"].with_(func=func, request_values=[42], matched=False), shape)
    assert e.get("ics.request_observed") is True and e.get("ics.is_request") is None
    assert "request_values" in e.fields["ics.request_observed"].origin


@pytest.mark.parametrize("shape", ("malcolm", "plain"))
def test_modbus_response_or_function_only_summary_never_proves_a_request(shape):
    row = zi.ROWS["modbus_detailed"].with_(func="DIAGNOSTICS", request_values=None,
                                          response_subfunction_code="Restart Communications Option",
                                          matched=False)
    e = normalize(row, shape)
    assert e.get("ics.request_observed") is None and e.get("ics.is_request") is None


@pytest.mark.parametrize("shape", ("malcolm", "plain"))
@pytest.mark.parametrize("service,state", [("reinitialize_device", "coldstart"),
                                           ("device_communication_control", "disable")])
def test_bacnet_control_state_is_explicit_request_evidence_from_either_packet_direction(shape, service, state):
    row = zi.ROWS["bacnet_device_control"].with_(pdu_service=service, device_state=state,
        is_orig=False, source_h=zl.SERVER, destination_h=zl.CLIENT, result=None, password="SECRET_BAC_CTL_123")
    h = zi.hit(row, shape)
    e = normalize(row, shape)
    assert e.get("ics.is_request") is True and e.get("ics.device_state") == state
    assert "device_state" in e.fields["ics.is_request"].origin
    assert e.get("ics.sender") == zl.SERVER and e.get("ics.receiver") == zl.CLIENT
    assert e.get("ics.exception") is None
    assert "SECRET_BAC_CTL_123" not in e.model_dump_json() + json.dumps(scrub_zeek_source(h["_source"]))


@pytest.mark.parametrize("shape", ("malcolm", "plain"))
@pytest.mark.parametrize("result,exception", [("SUCCESS", False), ("ERROR", True),
                                             ("REJECT", True), ("ABORT", True)])
def test_bacnet_control_result_tokens_are_response_evidence(shape, result, exception):
    row = zi.ROWS["bacnet_device_control"].with_(device_state=None, result=result)
    e = normalize(row, shape)
    assert e.get("ics.is_request") is False and e.get("ics.exception") is exception
    assert "result" in e.fields["ics.is_request"].origin


@pytest.mark.parametrize("shape", ("malcolm", "plain"))
def test_bacnet_control_service_alone_does_not_imply_request(shape):
    e = normalize(zi.ROWS["bacnet_device_control"].with_(device_state=None, result=None), shape)
    assert e.get("ics.is_request") is None
    assert e.get("ics.exception") is None



