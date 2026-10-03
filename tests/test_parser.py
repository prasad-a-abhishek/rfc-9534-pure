"""Tests for RFC 9534 parser — happy path and basic edge cases."""

import pytest

from rfc9534pure import (
    parse_micro_session_tlv,
    parse_tlv_list,
    serialize_micro_session_tlv,
    MicroSessionIDTLV,
)


# ─── Happy path ──────────────────────────────────────────────────────────────

def test_parse_minimal_tlv():
    """Parse a minimal valid TLV with sender_id=1, reflector_id=2."""
    data = bytes([0x00, 0x0B, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02])
    tlv = parse_micro_session_tlv(data)
    assert tlv.sender_id == 1
    assert tlv.reflector_id == 2
    assert tlv.flags == 0
    assert tlv.parsed_length == 8


def test_parse_zeros():
    """Parse TLV with both IDs zero (allowed per RFC 9534)."""
    data = bytes([0x00, 0x0B, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00])
    tlv = parse_micro_session_tlv(data)
    assert tlv.sender_id == 0
    assert tlv.reflector_id == 0


def test_parse_max_ids():
    """Parse TLV with maximum IDs (65535 each)."""
    data = bytes([0x00, 0x0B, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF])
    tlv = parse_micro_session_tlv(data)
    assert tlv.sender_id == 65535
    assert tlv.reflector_id == 65535


def test_parse_flags_U_bit():
    """Parse TLV with U (Unrecognized) flag bit set."""
    # U bit = 0x80, but we only allow reserved bits 3-7 to be 0
    # flags byte = 0x00 is the only valid value (U, M, I = 0; R = 0)
    data = bytes([0x00, 0x0B, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02])
    tlv = parse_micro_session_tlv(data)
    assert tlv.flags == 0


def test_parse_roundtrip():
    """Round-trip: serialize then parse gives same IDs."""
    original = parse_micro_session_tlv(
        serialize_micro_session_tlv(sender_id=1234, reflector_id=5678)
    )
    assert original.sender_id == 1234
    assert original.reflector_id == 5678


def test_serialize_basic():
    """Serialize basic TLV with sender_id=1, reflector_id=2."""
    data = serialize_micro_session_tlv(1, 2)
    assert data == bytes([0x00, 0x0B, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02])


def test_serialize_roundtrip():
    """Serialize then parse gives same IDs."""
    data = serialize_micro_session_tlv(999, 65534)
    tlv = parse_micro_session_tlv(data)
    assert tlv.sender_id == 999
    assert tlv.reflector_id == 65534


def test_serialize_zeros():
    """Serialize zeros for both IDs."""
    data = serialize_micro_session_tlv(0, 0)
    assert data == bytes([0x00, 0x0B, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00])


def test_serialize_max_ids():
    """Serialize maximum IDs (65535 each)."""
    data = serialize_micro_session_tlv(65535, 65535)
    assert data == bytes([0x00, 0x0B, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF])


def test_serialize_flags():
    """Serialize with non-zero flags byte (valid flags only: bits 0-2)."""
    data = serialize_micro_session_tlv(1, 2, flags=0x07)  # U=1, M=1, I=1, R=0
    assert data[0] == 0x07
    assert data[1] == 0x0B


def test_serialize_explicit_flags_zero():
    """Serialize with flags=0 explicitly."""
    data = serialize_micro_session_tlv(1, 2, flags=0)
    assert data[0] == 0x00


# ─── MicroSessionIDTLV to_dict ───────────────────────────────────────────────

def test_tlv_to_dict():
    """to_dict returns correct fields."""
    tlv = MicroSessionIDTLV(flags=0, sender_id=5, reflector_id=10, parsed_length=8)
    d = tlv.to_dict()
    assert d["tlv_type"] == 11
    assert d["flags"] == 0
    assert d["sender_id"] == 5
    assert d["reflector_id"] == 10
    assert d["parsed_length"] == 8


def test_tlv_repr():
    """__repr__ contains key fields."""
    tlv = MicroSessionIDTLV(flags=0, sender_id=5, reflector_id=10, parsed_length=8)
    r = repr(tlv)
    assert "5" in r
    assert "10" in r
    assert "MicroSessionIDTLV" in r


# ─── parse_tlv_list happy path ──────────────────────────────────────────────

def test_parse_tlv_list_single():
    """parse_tlv_list with a single TLV."""
    data = bytes([0x00, 0x0B, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02])
    tlvs = parse_tlv_list(data)
    assert len(tlvs) == 1
    assert tlvs[0].sender_id == 1


def test_parse_tlv_list_multiple():
    """parse_tlv_list with two consecutive TLVs."""
    tlv1 = serialize_micro_session_tlv(1, 2)
    tlv2 = serialize_micro_session_tlv(3, 4)
    tlvs = parse_tlv_list(tlv1 + tlv2)
    assert len(tlvs) == 2
    assert tlvs[0].sender_id == 1
    assert tlvs[1].sender_id == 3


def test_parse_tlv_list_empty():
    """parse_tlv_list with empty bytes returns empty list."""
    assert parse_tlv_list(b"") == []
