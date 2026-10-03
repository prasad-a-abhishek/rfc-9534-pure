"""Tests for RFC 9534 serializer — additional coverage."""

import pytest

from rfc9534pure import (
    parse_micro_session_tlv,
    parse_tlv_list,
    serialize_micro_session_tlv,
    serialize_tlv_list,
    MicroSessionIDTLV,
)


# ─── serialize_tlv_list ──────────────────────────────────────────────────────

def test_serialize_tlv_list_basic():
    """Serialize a list of two TLVs."""
    tlv1 = MicroSessionIDTLV(flags=0, sender_id=1, reflector_id=2, parsed_length=8)
    tlv2 = MicroSessionIDTLV(flags=0, sender_id=3, reflector_id=4, parsed_length=8)
    data = serialize_tlv_list([tlv1, tlv2])
    assert len(data) == 16
    assert data == serialize_micro_session_tlv(1, 2) + serialize_micro_session_tlv(3, 4)


def test_serialize_tlv_list_single():
    """Serialize a single-element list."""
    tlv = MicroSessionIDTLV(flags=0, sender_id=10, reflector_id=20, parsed_length=8)
    data = serialize_tlv_list([tlv])
    assert data == serialize_micro_session_tlv(10, 20)


def test_serialize_tlv_list_empty():
    """Serialize an empty list."""
    data = serialize_tlv_list([])
    assert data == b""


def test_serialize_tlv_list_with_flags():
    """Serialize TLVs with non-zero flags."""
    tlv = MicroSessionIDTLV(flags=0x07, sender_id=1, reflector_id=2, parsed_length=8)
    data = serialize_tlv_list([tlv])
    assert data[0] == 0x07


def test_serialize_tlv_list_wrong_type():
    """serialize_tlv_list rejects non-MicroSessionIDTLV objects."""
    with pytest.raises(TypeError):
        serialize_tlv_list([{"sender_id": 1, "reflector_id": 2}])


def test_serialize_tlv_list_not_list():
    """serialize_tlv_list rejects non-list input."""
    with pytest.raises(TypeError):
        serialize_tlv_list(serialize_micro_session_tlv(1, 2))


def test_serialize_tlv_list_item_not_tlv():
    """serialize_tlv_list rejects tuple instead of TLV object."""
    with pytest.raises(TypeError):
        serialize_tlv_list([(1, 2)])


# ─── Big-endian byte order verification ─────────────────────────────────────

def test_serialize_big_endian_sender_high():
    """sender_id=256 (0x0100) should encode as 01 00, not 00 01."""
    data = serialize_micro_session_tlv(256, 0)
    assert data[4] == 0x01
    assert data[5] == 0x00


def test_serialize_big_endian_reflector_high():
    """reflector_id=256 (0x0100) should encode as 01 00, not 00 01."""
    data = serialize_micro_session_tlv(0, 256)
    assert data[6] == 0x01
    assert data[7] == 0x00


def test_parse_big_endian_sender_high():
    """sender_id encoded as 01 00 should decode as 256."""
    data = bytes([0x00, 0x0B, 0x00, 0x04, 0x01, 0x00, 0x00, 0x01])
    tlv = parse_micro_session_tlv(data)
    assert tlv.sender_id == 256


def test_parse_big_endian_reflector_high():
    """reflector_id encoded as 01 00 should decode as 256."""
    data = bytes([0x00, 0x0B, 0x00, 0x04, 0x00, 0x01, 0x01, 0x00])
    tlv = parse_micro_session_tlv(data)
    assert tlv.reflector_id == 256


# ─── Round-trip exhaustive ────────────────────────────────────────────────────

def test_roundtrip_many_values():
    """Test round-trip for a range of values."""
    values = [0, 1, 2, 127, 128, 255, 256, 511, 512, 1023, 1024, 4095, 4096, 16383, 16384, 32767, 32768, 65534, 65535]
    for sender in values:
        for reflector in values:
            data = serialize_micro_session_tlv(sender, reflector)
            tlv = parse_micro_session_tlv(data)
            assert tlv.sender_id == sender, f"sender mismatch for {sender},{reflector}"
            assert tlv.reflector_id == reflector, f"reflector mismatch for {sender},{reflector}"


def test_roundtrip_single_value_all_zeros():
    """Round-trip for 0,0."""
    data = serialize_micro_session_tlv(0, 0)
    tlv = parse_micro_session_tlv(data)
    assert tlv.sender_id == 0
    assert tlv.reflector_id == 0


# ─── parse_tlv_list with mixed valid/invalid ─────────────────────────────

def test_parse_tlv_list_stops_on_short():
    """parse_tlv_list stops when fewer than 8 bytes remain."""
    tlv = serialize_micro_session_tlv(1, 2)  # 8 bytes
    # 8 bytes (valid) + 4 bytes (truncated) -> 1 TLV
    tlvs = parse_tlv_list(tlv + b"\x00\x0b\x00")
    assert len(tlvs) == 1


def test_parse_tlv_list_three_tlvs():
    """Parse three consecutive TLVs."""
    tlvs_in = [
        MicroSessionIDTLV(flags=0, sender_id=1, reflector_id=2, parsed_length=8),
        MicroSessionIDTLV(flags=0, sender_id=3, reflector_id=4, parsed_length=8),
        MicroSessionIDTLV(flags=0, sender_id=5, reflector_id=6, parsed_length=8),
    ]
    data = serialize_tlv_list(tlvs_in)
    tlvs_out = parse_tlv_list(data)
    assert len(tlvs_out) == 3
    assert tlvs_out[0].sender_id == 1
    assert tlvs_out[1].sender_id == 3
    assert tlvs_out[2].sender_id == 5


# ─── Wire format compliance (RFC 9534 §3) ──────────────────────────────────

def test_wire_length_exactly_8():
    """RFC 9534: Micro-session ID TLV MUST be exactly 8 octets."""
    for sender in [0, 1, 65535]:
        for reflector in [0, 1, 65535]:
            data = serialize_micro_session_tlv(sender, reflector)
            assert len(data) == 8, f"wire length {len(data)} != 8 for {sender},{reflector}"


def test_wire_type_field_is_11():
    """RFC 9534: Type field MUST be 11."""
    data = serialize_micro_session_tlv(0, 0)
    assert data[1] == 11


def test_wire_length_field_is_4():
    """RFC 9534: Length field MUST be 4 (big-endian 00 04)."""
    data = serialize_micro_session_tlv(0, 0)
    assert data[2] == 0x00
    assert data[3] == 0x04


# ─── Constant values ────────────────────────────────────────────────────────

def test_micro_session_tlv_type_constant():
    """MICRO_SESSION_TLV_TYPE must be 11."""
    from rfc9534pure import MICRO_SESSION_TLV_TYPE
    assert MICRO_SESSION_TLV_TYPE == 11


def test_expected_value_length_constant():
    """EXPECTED_VALUE_LENGTH must be 4."""
    from rfc9534pure import EXPECTED_VALUE_LENGTH
    assert EXPECTED_VALUE_LENGTH == 4


def test_wire_length_constant():
    """WIRE_LENGTH must be 8."""
    from rfc9534pure import WIRE_LENGTH
    assert WIRE_LENGTH == 8


# ─── CLI serialize wire_bytes ─────────────────────────────────────────────

def test_cli_serialize_wire_bytes_field():
    """CLI serialize output includes wire_bytes as list of ints."""
    import io, sys, json
    from rfc9534pure.__main__ import cmd_serialize
    import argparse
    ns = argparse.Namespace(sender_id="1", reflector_id="2", flags=None, compact=False)
    old = sys.stdout
    sys.stdout = io.StringIO()
    rc = cmd_serialize(ns)
    out = sys.stdout.getvalue()
    sys.stdout = old
    assert rc == 0
    data = json.loads(out)
    assert data["wire_bytes"] == [0, 11, 0, 4, 0, 1, 0, 2]


# ─── Reflector ID zero semantics ─────────────────────────────────────────

def test_reflector_id_zero_is_valid():
    """Reflector ID = 0 means 'do not verify' per RFC 9534."""
    data = bytes([0x00, 0x0B, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00])
    tlv = parse_micro_session_tlv(data)
    assert tlv.reflector_id == 0
    assert tlv.sender_id == 1


def test_roundtrip_reflector_id_zero():
    """Serialize and parse round-trip for reflector_id=0."""
    data = serialize_micro_session_tlv(1, 0)
    tlv = parse_micro_session_tlv(data)
    assert tlv.reflector_id == 0


# ─── TLV class __slots__ ─────────────────────────────────────────────────

def test_tlv_has_slots():
    """MicroSessionIDTLV uses __slots__."""
    tlv = MicroSessionIDTLV(flags=0, sender_id=1, reflector_id=2, parsed_length=8)
    # __slots__ means no __dict__
    assert not hasattr(tlv, "__dict__")


def test_tlv_no_extra_attributes():
    """MicroSessionIDTLV rejects unknown attributes."""
    tlv = MicroSessionIDTLV(flags=0, sender_id=1, reflector_id=2, parsed_length=8)
    with pytest.raises(AttributeError):
        tlv.extra_attr = 123


# ─── CLI: wire_hex matches round-trip ─────────────────────────────────────

def test_cli_parse_wire_hex_is_valid():
    """Parsed output wire_hex is valid serialized TLV."""
    import io, sys, json
    from rfc9534pure.__main__ import cmd_parse
    import argparse
    ns = argparse.Namespace(input="000b000400010002", compact=False)
    old = sys.stdout
    sys.stdout = io.StringIO()
    rc = cmd_parse(ns)
    out = sys.stdout.getvalue()
    sys.stdout = old
    assert rc == 0
    data = json.loads(out)
    # Verify wire_hex round-trips correctly
    wire_bytes = bytes.fromhex(data["wire_hex"])
    tlv = parse_micro_session_tlv(wire_bytes)
    assert tlv.sender_id == 1
    assert tlv.reflector_id == 2


# ─── Malformed JSON byte array input ───────────────────────────────────────

def test_cli_parse_malformed_json():
    """Malformed JSON returns error."""
    import io, sys, json
    from rfc9534pure.__main__ import cmd_parse
    import argparse
    ns = argparse.Namespace(input="[0,11,0,4,not_int,2]", compact=False)
    old = sys.stdout
    sys.stdout = io.StringIO()
    rc = cmd_parse(ns)
    out = sys.stdout.getvalue()
    sys.stdout = old
    assert rc == 1
    data = json.loads(out)
    assert data["ok"] is False


def test_cli_parse_json_not_byte_list():
    """JSON that's not a byte list returns error."""
    import io, sys, json
    from rfc9534pure.__main__ import cmd_parse
    import argparse
    ns = argparse.Namespace(input='"string"', compact=False)
    old = sys.stdout
    sys.stdout = io.StringIO()
    rc = cmd_parse(ns)
    out = sys.stdout.getvalue()
    sys.stdout = old
    assert rc == 1


def test_cli_parse_json_negative_byte():
    """JSON byte list with negative value returns error."""
    import io, sys, json
    from rfc9534pure.__main__ import cmd_parse
    import argparse
    ns = argparse.Namespace(input="[0,11,0,4,-1,1,0,2]", compact=False)
    old = sys.stdout
    sys.stdout = io.StringIO()
    rc = cmd_parse(ns)
    out = sys.stdout.getvalue()
    sys.stdout = old
    assert rc == 1


def test_cli_parse_json_overflow_byte():
    """JSON byte list with value > 255 returns error."""
    import io, sys, json
    from rfc9534pure.__main__ import cmd_parse
    import argparse
    ns = argparse.Namespace(input="[0,11,0,4,256,1,0,2]", compact=False)
    old = sys.stdout
    sys.stdout = io.StringIO()
    rc = cmd_parse(ns)
    out = sys.stdout.getvalue()
    sys.stdout = old
    assert rc == 1


# ─── __init__.py exports ──────────────────────────────────────────────────

def test_init_exports_all_public_symbols():
    """All public symbols are exported from __init__."""
    from rfc9534pure import (
        parse_micro_session_tlv,
        parse_tlv_list,
        serialize_micro_session_tlv,
        serialize_tlv_list,
        MicroSessionIDTLV,
        MICRO_SESSION_TLV_TYPE,
        EXPECTED_VALUE_LENGTH,
        WIRE_LENGTH,
    )
    assert True  # if import succeeds, test passes


def test_version_available():
    """__version__ is available."""
    from rfc9534pure import __version__
    assert __version__ == "0.1.0"
