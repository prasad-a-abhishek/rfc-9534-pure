"""Tests for RFC 9534 parser — edge cases and error handling."""

import pytest

from rfc9534pure import (
    parse_micro_session_tlv,
    parse_tlv_list,
    serialize_micro_session_tlv,
    MicroSessionIDTLV,
)


# ─── Error: data too short ───────────────────────────────────────────────────

def test_parse_short_empty():
    with pytest.raises(ValueError, match="too short"):
        parse_micro_session_tlv(b"")


def test_parse_short_1_byte():
    with pytest.raises(ValueError, match="too short"):
        parse_micro_session_tlv(b"\x00")


def test_parse_short_7_bytes():
    with pytest.raises(ValueError, match="too short"):
        parse_micro_session_tlv(b"\x00\x0b\x00\x04\x00\x01\x02")


def test_parse_short_just_header():
    with pytest.raises(ValueError, match="too short"):
        parse_micro_session_tlv(b"\x00\x0b\x00\x04")


# ─── Error: wrong type ───────────────────────────────────────────────────────

def test_parse_wrong_type_0():
    """Type 0 is not Micro-session ID TLV."""
    data = bytes([0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02])
    with pytest.raises(ValueError, match="wrong TLV type"):
        parse_micro_session_tlv(data)


def test_parse_wrong_type_1():
    """Type 1 is not Micro-session ID TLV."""
    data = bytes([0x00, 0x01, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02])
    with pytest.raises(ValueError, match="wrong TLV type"):
        parse_micro_session_tlv(data)


def test_parse_wrong_type_10():
    """Type 10 is one less than Micro-session ID TLV."""
    data = bytes([0x00, 0x0A, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02])
    with pytest.raises(ValueError, match="wrong TLV type"):
        parse_micro_session_tlv(data)


def test_parse_wrong_type_12():
    """Type 12 is one more than Micro-session ID TLV."""
    data = bytes([0x00, 0x0C, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02])
    with pytest.raises(ValueError, match="wrong TLV type"):
        parse_micro_session_tlv(data)


def test_parse_wrong_type_255():
    """Type 255 (0xFF) should be rejected."""
    data = bytes([0x00, 0xFF, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02])
    with pytest.raises(ValueError, match="wrong TLV type"):
        parse_micro_session_tlv(data)


# ─── Error: wrong length ─────────────────────────────────────────────────────

def test_parse_length_0():
    """Length field is 0, not 4."""
    data = bytes([0x00, 0x0B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02])
    with pytest.raises(ValueError, match="invalid TLV length"):
        parse_micro_session_tlv(data)


def test_parse_length_1():
    """Length field is 1, not 4."""
    data = bytes([0x00, 0x0B, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02])
    with pytest.raises(ValueError, match="invalid TLV length"):
        parse_micro_session_tlv(data)


def test_parse_length_3():
    """Length field is 3, not 4."""
    data = bytes([0x00, 0x0B, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02])
    with pytest.raises(ValueError, match="invalid TLV length"):
        parse_micro_session_tlv(data)


def test_parse_length_5():
    """Length field is 5, not 4."""
    data = bytes([0x00, 0x0B, 0x00, 0x05, 0x00, 0x01, 0x00, 0x02])
    with pytest.raises(ValueError, match="invalid TLV length"):
        parse_micro_session_tlv(data)


def test_parse_length_65535():
    """Length field is 65535 (0xFFFF), not 4."""
    data = bytes([0x00, 0x0B, 0xFF, 0xFF, 0x00, 0x01, 0x00, 0x02])
    with pytest.raises(ValueError, match="invalid TLV length"):
        parse_micro_session_tlv(data)


# ─── Error: reserved flag bits ───────────────────────────────────────────────

def test_parse_reserved_bit_3():
    """Flag bit 3 set to 1 raises error."""
    data = bytes([0x08, 0x0B, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02])
    with pytest.raises(ValueError, match="reserved flag bits"):
        parse_micro_session_tlv(data)


def test_parse_reserved_bit_4():
    """Flag bit 4 set to 1 raises error."""
    data = bytes([0x10, 0x0B, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02])
    with pytest.raises(ValueError, match="reserved flag bits"):
        parse_micro_session_tlv(data)


def test_parse_reserved_bit_5():
    """Flag bit 5 set to 1 raises error."""
    data = bytes([0x20, 0x0B, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02])
    with pytest.raises(ValueError, match="reserved flag bits"):
        parse_micro_session_tlv(data)


def test_parse_reserved_bit_6():
    """Flag bit 6 set to 1 raises error."""
    data = bytes([0x40, 0x0B, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02])
    with pytest.raises(ValueError, match="reserved flag bits"):
        parse_micro_session_tlv(data)


def test_parse_reserved_bit_7():
    """Flag bit 7 set to 1 raises error."""
    data = bytes([0x80, 0x0B, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02])
    with pytest.raises(ValueError, match="reserved flag bits"):
        parse_micro_session_tlv(data)


def test_parse_reserved_bits_all():
    """All reserved bits set raises error."""
    data = bytes([0xF8, 0x0B, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02])
    with pytest.raises(ValueError, match="reserved flag bits"):
        parse_micro_session_tlv(data)


def test_parse_valid_U_flag():
    """U flag (bit 0) is actually valid, but our flag mask only checks bits 3-7.

    Per RFC 8972, U=1 means "Unrecognized" but only applies at Reflector.
    For sender, U=0 is normal. We accept U=0 only (bits 3-7 must be 0).
    """
    data = bytes([0x00, 0x0B, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02])
    tlv = parse_micro_session_tlv(data)
    assert tlv.flags == 0


# ─── Error: None and type ─────────────────────────────────────────────────────

def test_parse_none_raises():
    with pytest.raises(ValueError, match="must be bytes"):
        parse_micro_session_tlv(None)


def test_parse_string_raises():
    with pytest.raises(TypeError, match="must be bytes"):
        parse_micro_session_tlv("00110 0004 00010002")


def test_parse_int_raises():
    with pytest.raises(TypeError, match="must be bytes"):
        parse_micro_session_tlv(int("0x00110 0004 00010002".replace(" ", ""), 16))


def test_parse_bytearray():
    """bytearray input is accepted."""
    data = bytearray([0x00, 0x0B, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02])
    tlv = parse_micro_session_tlv(data)
    assert tlv.sender_id == 1
    assert tlv.reflector_id == 2


# ─── Error: serialize out of range IDs ───────────────────────────────────────

def test_serialize_sender_id_negative():
    with pytest.raises(ValueError, match="out of range"):
        serialize_micro_session_tlv(-1, 1)


def test_serialize_sender_id_too_large():
    with pytest.raises(ValueError, match="out of range"):
        serialize_micro_session_tlv(65536, 1)


def test_serialize_sender_id_65535_ok():
    """65535 is the maximum valid ID."""
    data = serialize_micro_session_tlv(65535, 0)
    assert data[4:6] == bytes([0xFF, 0xFF])


def test_serialize_reflector_id_negative():
    with pytest.raises(ValueError, match="out of range"):
        serialize_micro_session_tlv(1, -1)


def test_serialize_reflector_id_too_large():
    with pytest.raises(ValueError, match="out of range"):
        serialize_micro_session_tlv(1, 65536)


# ─── Error: serialize reserved flag bits ─────────────────────────────────────

def test_serialize_reserved_bit_3():
    with pytest.raises(ValueError, match="reserved flag bits"):
        serialize_micro_session_tlv(1, 2, flags=0x08)


def test_serialize_reserved_bit_4():
    with pytest.raises(ValueError, match="reserved flag bits"):
        serialize_micro_session_tlv(1, 2, flags=0x10)


def test_serialize_reserved_bit_5():
    with pytest.raises(ValueError, match="reserved flag bits"):
        serialize_micro_session_tlv(1, 2, flags=0x20)


def test_serialize_reserved_bit_6():
    with pytest.raises(ValueError, match="reserved flag bits"):
        serialize_micro_session_tlv(1, 2, flags=0x40)


def test_serialize_reserved_bit_7():
    with pytest.raises(ValueError, match="reserved flag bits"):
        serialize_micro_session_tlv(1, 2, flags=0x80)


# ─── Error: serialize type errors ────────────────────────────────────────────

def test_serialize_sender_id_string():
    with pytest.raises(TypeError, match="sender_id must be int"):
        serialize_micro_session_tlv("1", 2)


def test_serialize_sender_id_float():
    with pytest.raises(TypeError, match="sender_id must be int"):
        serialize_micro_session_tlv(1.0, 2)


def test_serialize_sender_id_bool():
    with pytest.raises(TypeError, match="sender_id must be int"):
        serialize_micro_session_tlv(True, 2)


def test_serialize_reflector_id_string():
    with pytest.raises(TypeError, match="reflector_id must be int"):
        serialize_micro_session_tlv(1, "2")


def test_serialize_flags_string():
    with pytest.raises(TypeError, match="flags must be int"):
        serialize_micro_session_tlv(1, 2, flags="0")


def test_serialize_flags_bool():
    with pytest.raises(TypeError, match="flags must be int"):
        serialize_micro_session_tlv(1, 2, flags=True)


# ─── parse_tlv_list edge cases ──────────────────────────────────────────────

def test_parse_tlv_list_truncated_incomplete():
    """Only 4 bytes left — not enough for a full TLV."""
    tlv = serialize_micro_session_tlv(1, 2)
    tlvs = parse_tlv_list(tlv + b"\x00\x0b\x00")
    assert len(tlvs) == 1  # only the complete one


def test_parse_tlv_list_invalid_second_tlv():
    """First TLV valid, second has wrong type — stops."""
    tlv1 = serialize_micro_session_tlv(1, 2)
    tlv2 = bytes([0x00, 0xFF, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04])
    tlvs = parse_tlv_list(tlv1 + tlv2)
    assert len(tlvs) == 1


def test_parse_tlv_list_invalid_length():
    """First TLV valid, second has wrong length — stops."""
    tlv1 = serialize_micro_session_tlv(1, 2)
    tlv2 = bytes([0x00, 0x0B, 0x00, 0x05, 0x00, 0x03, 0x00, 0x04])
    tlvs = parse_tlv_list(tlv1 + tlv2)
    assert len(tlvs) == 1


# ─── Edge: boundary values ───────────────────────────────────────────────────

def test_parse_id_boundary_zero():
    """sender_id=0 is valid per RFC 9534."""
    data = bytes([0x00, 0x0B, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01])
    tlv = parse_micro_session_tlv(data)
    assert tlv.sender_id == 0


def test_parse_id_boundary_max():
    """sender_id=65535 is valid per RFC 9534."""
    data = bytes([0x00, 0x0B, 0x00, 0x04, 0xFF, 0xFF, 0x00, 0x01])
    tlv = parse_micro_session_tlv(data)
    assert tlv.sender_id == 65535


def test_parse_reflector_zero():
    """reflector_id=0 is valid (means "do not verify" per RFC 9534)."""
    data = bytes([0x00, 0x0B, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00])
    tlv = parse_micro_session_tlv(data)
    assert tlv.reflector_id == 0
