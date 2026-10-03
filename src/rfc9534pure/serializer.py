"""RFC 9534 STAMP LAG Micro-session ID TLV serializer (pure stdlib)."""

from .parser import EXPECTED_VALUE_LENGTH, MICRO_SESSION_TLV_TYPE, WIRE_LENGTH

__all__ = ["serialize_micro_session_tlv", "serialize_tlv_list"]


def serialize_micro_session_tlv(sender_id: int, reflector_id: int, flags: int = 0) -> bytes:
    """Serialize an RFC 9534 Micro-session ID TLV to bytes.

    Args:
        sender_id: LAG member link identifier at sender side (0-65535).
        reflector_id: LAG member link identifier at reflector side (0-65535).
        flags: STAMP TLV flags byte (default 0). RFC 8972 §4 defines flag bits.

    Returns:
        8-byte serialized TLV.

    Raises:
        ValueError: ID out of range, or reserved flag bits set.
        TypeError: arguments are not integers.
    """
    for name, val in [("sender_id", sender_id), ("reflector_id", reflector_id), ("flags", flags)]:
        if not isinstance(val, int) or isinstance(val, bool):
            raise TypeError(f"{name} must be int, got {type(val).__name__}")

    if not (0 <= sender_id <= 0xFFFF):
        raise ValueError(f"sender_id out of range: {sender_id} (valid: 0-65535)")
    if not (0 <= reflector_id <= 0xFFFF):
        raise ValueError(f"reflector_id out of range: {reflector_id} (valid: 0-65535)")
    if flags & 0xF8:  # reserved bits 3-7 MUST be 0
        raise ValueError(f"reserved flag bits set: flags=0x{flags:02x}")

    header = bytes([flags, MICRO_SESSION_TLV_TYPE]) + EXPECTED_VALUE_LENGTH.to_bytes(2, "big")
    value = sender_id.to_bytes(2, "big") + reflector_id.to_bytes(2, "big")
    return header + value


def serialize_tlv_list(tlvs: list) -> bytes:
    """Serialize a list of MicroSessionIDTLV objects to concatenated bytes."""
    if not isinstance(tlvs, list):
        raise TypeError(f"tlvs must be list, got {type(tlvs).__name__}")
    result = b""
    for tlv in tlvs:
        if not hasattr(tlv, "sender_id") or not hasattr(tlv, "reflector_id"):
            raise TypeError(f"tlv must be MicroSessionIDTLV, got {type(tlv).__name__}")
        result += serialize_micro_session_tlv(tlv.sender_id, tlv.reflector_id, getattr(tlv, "flags", 0))
    return result
