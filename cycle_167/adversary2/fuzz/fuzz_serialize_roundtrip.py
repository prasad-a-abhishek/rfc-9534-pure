"""Fuzz harness: serialize -> parse roundtrip property.

Surface: rfc9534pure.serializer.serialize_micro_session_tlv (encode path)
Strategy: the fuzzer provides three little-endian uint16-like slices that
          we coerce into the three integer arguments of the serializer. The
          serializer rejects out-of-range IDs and reserved flag bits; the
          roundtrip property is: serialize(parse(bytes)) == bytes for any
          well-formed input.

Adversary2 (post-F-1-fix) rebuild of cycle_167/adversary/T2's
fuzz_serialize_roundtrip. serializer.py unchanged by the F-1 fix.

ASan/UBSan: safe. Serialization is pure-Python bytes concatenation; roundtrip
uses the parser which we already vetted. No heap allocations outside CPython.

Run::

    PYTHONPATH=src python3 cycle_167/adversary2/fuzz/fuzz_serialize_roundtrip.py \\
        -atheris_timeout=5
"""
import struct
import sys

import atheris

_PROJECT_ROOT = "/root/projects/rfc-9534-pure/.worktrees/t_cycle167-adversary-02"
sys.path.insert(0, _PROJECT_ROOT + "/src")

from rfc9534pure.parser import parse_micro_session_tlv  # noqa: E402
from rfc9534pure.serializer import serialize_micro_session_tlv  # noqa: E402


def TestOneInput(data: bytes) -> None:
    """Atheris entry: build three uint16 from the seed, roundtrip."""
    # Coerce arbitrary bytes into three uint16 values.
    if len(data) < 6:
        return  # not enough entropy; skip
    sender_id = struct.unpack("<H", data[0:2])[0]
    reflector_id = struct.unpack("<H", data[2:4])[0]
    flags = data[4]  # 0-255; serializer accepts only lower 5 bits valid
    try:
        wire = serialize_micro_session_tlv(
            sender_id=sender_id,
            reflector_id=reflector_id,
            flags=flags,
        )
    except (ValueError, TypeError):
        return  # serializer rejected — acceptable

    try:
        parsed = parse_micro_session_tlv(wire)
    except (ValueError, TypeError) as e:
        # If serialize succeeded, parse must succeed too.
        raise AssertionError(
            f"roundtrip failed: serialize({sender_id},{reflector_id},"
            f"{flags}) -> {wire!r}, parse raised {e!r}"
        )

    assert parsed.sender_id == sender_id, (
        f"sender_id mismatch: {parsed.sender_id} != {sender_id}"
    )
    assert parsed.reflector_id == reflector_id, (
        f"reflector_id mismatch: {parsed.reflector_id} != {reflector_id}"
    )
    # Serializer rejects flags with bits 3-7 set; parse accepts flags 0-7.
    # So equality holds only on the lower 5 bits.
    assert parsed.flags & 0x07 == flags & 0x07, (
        f"flags mismatch: {parsed.flags} != {flags}"
    )


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()