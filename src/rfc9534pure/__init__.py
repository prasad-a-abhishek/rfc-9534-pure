"""RFC 9534 STAMP LAG Micro-session ID TLV — zero-dependency Python library.

This package provides a pure-stdlib parser and serializer for RFC 9534
STAMP LAG Micro-session ID TLVs (Type=11).

Basic usage:

    from rfc9534pure import parse_micro_session_tlv, serialize_micro_session_tlv

    # Parse a TLV
    data = bytes.fromhex("00110 0004 00010002".replace(" ", ""))
    tlv = parse_micro_session_tlv(data)
    print(tlv.sender_id)      # 1
    print(tlv.reflector_id)   # 2

    # Serialize a TLV
    data = serialize_micro_session_tlv(sender_id=1, reflector_id=2)
    print(data.hex())         # "00110 000400010002"
"""

from .parser import (
    EXPECTED_VALUE_LENGTH,
    MICRO_SESSION_TLV_TYPE,
    MicroSessionIDTLV,
    parse_micro_session_tlv,
    parse_tlv_list,
    WIRE_LENGTH,
)
from .serializer import (
    serialize_micro_session_tlv,
    serialize_tlv_list,
)

__all__ = [
    # Parser
    "parse_micro_session_tlv",
    "parse_tlv_list",
    "MicroSessionIDTLV",
    # Serializer
    "serialize_micro_session_tlv",
    "serialize_tlv_list",
    # Constants
    "MICRO_SESSION_TLV_TYPE",
    "EXPECTED_VALUE_LENGTH",
    "WIRE_LENGTH",
]

__version__ = "0.1.0"
