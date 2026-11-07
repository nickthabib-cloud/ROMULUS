"""Native normalization regressions for the supported source layouts."""
import json

import pytest

from romulus.evidence.ics_catalog import lookup_function
from romulus.evidence.zeek import normalize_plain_zeek, normalize_zeek, scrub_zeek_source, zeek_record
from tests.fixtures import zeek_ics as zi
from tests.fixtures import zeek_logs as zl


def normalize(row, shape="plain"):
    hit = zi.hit(row, shape)
    return (normalize_plain_zeek(hit, sensor=zl.SENSOR) if shape == "plain"
            else normalize_zeek(hit, zeek_record(hit["_source"])))



@pytest.mark.parametrize("shape", zi.SHAPES_BY_LOG["modbus"])
@pytest.mark.parametrize("func,code", [("WRITE_SINGLE_REGISTER", 6), ("WRITE_MULTIPLE_COILS", 15),
                                      ("WRITE_SINGLE_REGISTER_EXCEPTION", 6)])
def test_base_modbus_without_pdu_type_proves_nonread_request_only(shape, func, code):
    row = zi.ROWS["modbus"].with_(func=func, pdu_type=None)
    event = normalize(row, shape)
    assert event.get("ics.function_code") == code
    assert event.get("ics.request_observed") is True
    assert event.get("ics.is_request") is None
    assert event.get("ics.sender") is None and event.get("ics.receiver") is None
    assert event.get("conn.orig_h") == zl.CLIENT and event.get("conn.resp_h") == zl.SERVER
    assert "func" in event.fields["ics.request_observed"].origin


@pytest.mark.parametrize("shape", zi.SHAPES_BY_LOG["modbus"])
@pytest.mark.parametrize("func", ["READ_COILS", "READ_HOLDING_REGISTERS", "READ_INPUT_REGISTERS"])
def test_base_modbus_polling_without_pdu_does_not_gain_request_observation(shape, func):
    event = normalize(zi.ROWS["modbus"].with_(func=func, pdu_type=None), shape)
    assert event.get("ics.op_class") == "read"
    assert event.get("ics.request_observed") is None


@pytest.mark.parametrize("log", ["dnp3_control", "s7comm", "cip", "bacnet_device_control"])
@pytest.mark.parametrize("is_orig", [True, False])
def test_missing_packet_endpoints_use_only_explicit_connection_roles_and_is_orig(log, is_orig):
    row = zi.ROWS[log].without("source_h", "source_p", "destination_h", "destination_p").with_(is_orig=is_orig)
    event = normalize(row)
    expected = (zl.CLIENT, zl.SERVER) if is_orig else (zl.SERVER, zl.CLIENT)
    assert (event.get("ics.sender"), event.get("ics.receiver")) == expected
    assert (event.get("source.ip"), event.get("destination.ip")) == expected
    assert event.get("ics.endpoint_basis") == "is_orig+connection_roles"
    assert any("is_orig" in note and "connection roles" in note for note in event.caveats)
    assert "id." in event.fields["ics.sender"].origin and "is_orig" in event.fields["ics.sender"].origin
    assert not event.has("tcp.opened_by_orig")


def test_one_missing_packet_endpoint_preserves_the_native_peer():
    row = zi.ROWS["s7comm"].without("destination_h").with_(source_h="192.0.2.40", is_orig=False)
    event = normalize(row)
    assert event.get("ics.sender") == "192.0.2.40"
    assert event.get("ics.receiver") == zl.CLIENT
    assert "source_h" in event.fields["ics.sender"].origin


@pytest.mark.parametrize("removed", [
    ("is_orig",), ("id.orig_h", "id.resp_h"), ("is_orig", "id.orig_h", "id.resp_h")])
def test_missing_endpoint_inputs_never_use_source_ip_as_connection_originator(removed):
    row = zi.ROWS["s7comm"].without("source_h", "destination_h", *removed)
    event = normalize(row)
    assert event.get("ics.sender") is None and event.get("ics.receiver") is None
    assert event.get("ics.endpoint_basis") is None


@pytest.mark.parametrize("code,op,name", [(0x4d, "write", "Write Tag"), (0x53, "write", "Write Tag Fragmented"),
                                         (0x4c, "read", "Read Tag"), (0x52, "read", "Read Tag Fragmented")])
@pytest.mark.parametrize("shape", ("plain", "malcolm"))
def test_symbolic_cip_without_class_id_uses_vendor_convention_with_caveat(code, op, name, shape):
    row = zi.ROWS["cip"].with_(cip_service_code=f"0x{code:02x}", class_id=None)
    event = normalize(row, shape)
    assert lookup_function("cip", code).op_class == op
    assert (event.get("ics.op_class"), event.get("ics.function_name")) == (op, name)
    assert "vendor tag service on a symbolic path" in event.caveats


@pytest.mark.parametrize("class_id", ["0x01", "not-a-code"])
def test_cip_explicit_other_or_malformed_class_is_not_symbolic(class_id):
    event = normalize(zi.ROWS["cip"].with_(cip_service_code="0x4d", class_id=class_id))
    assert event.get("ics.op_class") == "other"
    assert "vendor tag service on a symbolic path" not in event.caveats


@pytest.mark.parametrize("code,name,op", [
    (20, "READ_FILE_RECORD", "read"), (21, "WRITE_FILE_RECORD", "write"), (24, "READ_FIFO_QUEUE", "read")])
def test_standard_modbus_file_and_fifo_functions(code, name, op):
    event = normalize(zi.ROWS["modbus"].with_(func=name))
    assert lookup_function("modbus", code).name == name
    assert (event.get("ics.function_code"), event.get("ics.op_class")) == (code, op)


def test_s7_confirmed_cpu_group_is_not_relabelled_as_programmer_controls():
    other = normalize(zi.ROWS["s7comm"].with_(rosctr_code=7, function_code="0x44",
        function_name="Request: CPU Functions", subfunction_code="0x09"))
    szl = normalize(zi.ROWS["s7comm"].with_(rosctr_code=7, function_code="0x44",
        function_name="Request: CPU Functions", subfunction_code="0x01"))
    assert other.get("ics.op_class") == "other"
    assert szl.get("ics.op_class") == "discovery"


@pytest.mark.parametrize("shape", ("malcolm", "plain"))
@pytest.mark.parametrize("service,state", [("reinitialize_device", "coldstart"),
                                           ("device_communication_control", "disable")])
def test_bacnet_password_presence_is_typed_without_the_value(shape, service, state):
    row = zi.ROWS["bacnet_device_control"].with_(pdu_service=service, device_state=state,
                                                password="NATIVE_BAC_SECRET_987")
    event = normalize(row, shape)
    stored = scrub_zeek_source(zi.hit(row, shape)["_source"])
    assert event.get("auth.cleartext_credentials_present") is True
    assert "NATIVE_BAC_SECRET_987" not in event.model_dump_json() + json.dumps(stored)
