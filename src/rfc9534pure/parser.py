"""RFC 9534 STAMP LAG Micro-session ID TLV parser (pure stdlib)."""

__all__ = ["parse_micro_session_tlv", "parse_tlv_list", "MicroSessionIDTLV",
           "MICRO_SESSION_TLV_TYPE", "WIRE_LENGTH", "EXPECTED_VALUE_LENGTH"]

MICRO_SESSION_TLV_TYPE = 11   # IANA assigned
EXPECTED_VALUE_LENGTH = 4     # 2-byte sender + 2-byte reflector
WIRE_LENGTH = 8               # 1 flag + 1 type + 2 length + 4 value


class MicroSessionIDTLV:
    __slots__ = ("flags", "sender_id", "reflector_id", "parsed_length")

    def __init__(self, flags: int, sender_id: int, reflector_id: int, parsed_length: int):
        self.flags = flags
        self.sender_id = sender_id
        self.reflector_id = reflector_id
        self.parsed_length = parsed_length

    def to_dict(self) -> dict:
        return {
            "tlv_type": MICRO_SESSION_TLV_TYPE,
            "flags": self.flags,
            "sender_id": self.sender_id,
            "reflector_id": self.reflector_id,
            "parsed_length": self.parsed_length,
        }

    def __repr__(self) -> str:
        return (f"MicroSessionIDTLV(flags={self.flags}, sender_id={self.sender_id}, "
                f"reflector_id={self.reflector_id}, parsed_length={self.parsed_length})")


def parse_micro_session_tlv(data: bytes) -> MicroSessionIDTLV:
    """Parse an RFC 9534 Micro-session ID TLV from bytes.

    Args:
        data: Raw TLV bytes (at least 8 bytes).

    Returns:
        MicroSessionIDTLV with sender_id, reflector_id, flags, parsed_length.

    Raises:
        ValueError: data too short, wrong type, length != 4, reserved flags set.
        TypeError: data is not bytes.
    """
    if data is None:
        raise ValueError("data must be bytes, not None")
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"data must be bytes, got {type(data).__name__}")
    if len(data) < WIRE_LENGTH:
        raise ValueError(f"data too short: got {len(data)} bytes, need >= {WIRE_LENGTH}")

    flags = data[0]
    tlv_type = data[1]
    length = int.from_bytes(data[2:4], "big")

    if tlv_type != MICRO_SESSION_TLV_TYPE:
        raise ValueError(f"wrong TLV type: expected {MICRO_SESSION_TLV_TYPE}, got {tlv_type}")
    if length != EXPECTED_VALUE_LENGTH:
        raise ValueError(f"invalid TLV length: expected {EXPECTED_VALUE_LENGTH}, got {length}")
    if flags & 0xF8:  # reserved bits 3-7 MUST be 0
        raise ValueError(f"reserved flag bits set: flags=0x{flags:02x}")

    sender_id = int.from_bytes(data[4:6], "big")
    reflector_id = int.from_bytes(data[6:8], "big")

    return MicroSessionIDTLV(flags=flags, sender_id=sender_id,
                              reflector_id=reflector_id, parsed_length=WIRE_LENGTH)


def parse_tlv_list(data: bytes) -> list[MicroSessionIDTLV]:
    """Parse a concatenated series of Micro-session ID TLVs from a buffer.

    Stops at the first TLV that fails to parse.
    """
    if not data:
        return []
    result = []
    offset = 0
    while offset + WIRE_LENGTH <= len(data):
        try:
            result.append(parse_micro_session_tlv(data[offset:offset + WIRE_LENGTH]))
            offset += WIRE_LENGTH
        except (ValueError, TypeError):
            break
    return result
