"""Fuzz harness: Invariant 21 boundary conditions (total exception safety).

Invariant 21 (from project memory): parser must reject None, empty bytes,
oversized input, and non-bytes-like objects WITHOUT crashing. Specifically:
  - data is None                  -> ValueError
  - data is not bytes/bytearray   -> TypeError
  - data < WIRE_LENGTH (8 bytes)  -> ValueError
  - oversized data must not OOM the process.

Adversary2 (post-F-1-fix) rebuild of cycle_167/adversary/T2's
fuzz_invariant21_boundaries. parser.py + serializer.py unchanged by the
F-1 fix; this harness is a regression-detector with one enhancement: it
additionally exercises `serialize_tlv_list` (the multi-item serializer)
which was under-covered by the pre-fix chain.

ASan/UBSan: safe. No native code is reached except CPython's allocator.

Run::

    PYTHONPATH=src python3 cycle_167/adversary2/fuzz/fuzz_invariant21_boundaries.py \\
        -atheris_timeout=5
"""
import sys

import atheris

_PROJECT_ROOT = "/root/projects/rfc-9534-pure/.worktrees/t_cycle167-adversary-02"
sys.path.insert(0, _PROJECT_ROOT + "/src")

from rfc9534pure.parser import (  # noqa: E402
    parse_micro_session_tlv,
    parse_tlv_list,
    WIRE_LENGTH,
)
from rfc9534pure.serializer import (  # noqa: E402
    serialize_micro_session_tlv,
    serialize_tlv_list,
)
from rfc9534pure import MicroSessionIDTLV  # noqa: E402

ALLOWED = (ValueError, TypeError)


def _truth_parse(data):
    """Assert the documented exception contract for parse_micro_session_tlv.
    None -> ValueError, non-bytes -> TypeError, short bytes -> ValueError,
    oversized/odd-shaped -> ValueError or success.
    """
    if data is None:
        try:
            parse_micro_session_tlv(data)  # type: ignore[arg-type]
        except ValueError:
            return
        raise AssertionError("None did not raise ValueError")
    if not isinstance(data, (bytes, bytearray)):
        try:
            parse_micro_session_tlv(data)  # type: ignore[arg-type]
        except TypeError:
            return
        raise AssertionError(f"{type(data).__name__} did not raise TypeError")
    if len(data) < WIRE_LENGTH:
        try:
            parse_micro_session_tlv(data)
        except ValueError:
            return
        raise AssertionError(f"{len(data)}B did not raise ValueError")
    try:
        parse_micro_session_tlv(data)
    except ALLOWED:
        return


def TestOneInput(data: bytes) -> None:
    """Atheris entry: exercise invariant-21 boundary shapes."""
    # 1. None
    _truth_parse(None)
    # 2. Empty
    _truth_parse(b"")
    # 3. Short
    if data:
        _truth_parse(data[: WIRE_LENGTH - 1])
    # 4. Oversized (cap at 4x to keep fuzzer memory bounded)
    big = data * 4 if len(data) < 1_000_000 else data
    _truth_parse(big)
    # 5. parse_tlv_list across the same shapes
    for shape in (None, b"", data[: 2 * WIRE_LENGTH + 3], big):
        try:
            parse_tlv_list(shape)  # type: ignore[arg-type]
        except ALLOWED:
            continue
    # 6. serializer type validation (rejects bool as int)
    try:
        serialize_micro_session_tlv(sender_id=True, reflector_id=1)  # type: ignore[arg-type]
    except TypeError:
        pass
    else:
        raise AssertionError("serializer accepted bool sender_id")

    # 7. NEW (adversary2): serialize_tlv_list type-stress — covers the
    # `tlvs must be list` / `tlv must be MicroSessionIDTLV` paths and the
    # successful round-trip via real MicroSessionIDTLV objects.
    try:
        serialize_tlv_list(None)  # type: ignore[arg-type]
    except TypeError:
        pass
    else:
        raise AssertionError("serialize_tlv_list accepted None")

    try:
        serialize_tlv_list(["not a tlv"])  # type: ignore[list-item]
    except TypeError:
        pass
    else:
        raise AssertionError("serialize_tlv_list accepted non-TLV list")

    # Happy path: round-trip a valid MicroSessionIDTLV through serialize_tlv_list
    # and back through parse_tlv_list. The result must be one TLV with the
    # original sender/reflector IDs.
    if len(data) >= 4:
        sender_id = (data[0] << 8) | data[1]
        if sender_id <= 0xFFFF:
            reflector_id = (data[2] << 8) | data[3] if len(data) >= 4 else 0
            if reflector_id <= 0xFFFF:
                tlv = MicroSessionIDTLV(flags=0, sender_id=sender_id,
                                        reflector_id=reflector_id, parsed_length=8)
                try:
                    wire = serialize_tlv_list([tlv])
                    parsed = parse_tlv_list(wire)
                except ALLOWED:
                    pass
                else:
                    assert len(parsed) == 1
                    assert parsed[0].sender_id == sender_id
                    assert parsed[0].reflector_id == reflector_id


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()