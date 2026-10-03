"""Fuzz harness: parse_tlv_list multi-TLV list parser.

Surface: rfc9534pure.parser.parse_tlv_list
Fuzz target: arbitrary bytes input (empty, partial TLVs, multiple TLVs, TLV
             with wrong type/length in middle to verify the early-break
             behavior is robust under pathological inputs).
Expected: always returns a list; never crashes, never recurses unbounded,
          never allocates runaway memory.

ASan/NOTE: implementation is a flat while-loop bounded by len(data) /
WIRE_LENGTH. No recursion. No external calls. Safe to run with ASan / UBSan.

Adversary2 (post-F-1-fix) rebuild of cycle_167/adversary/T2's
fuzz_parse_tlv_list. parser.py unchanged by the F-1 fix; this harness is a
regression-detector.

Run::

    PYTHONPATH=src python3 cycle_167/adversary2/fuzz/fuzz_parse_tlv_list.py \\
        -atheris_timeout=5
"""
import sys

import atheris

_PROJECT_ROOT = "/root/projects/rfc-9534-pure/.worktrees/t_cycle167-adversary-02"
sys.path.insert(0, _PROJECT_ROOT + "/src")

from rfc9534pure.parser import parse_tlv_list  # noqa: E402


def TestOneInput(data: bytes) -> None:
    """Atheris entry: pass arbitrary fuzzer bytes to parse_tlv_list."""
    try:
        result = parse_tlv_list(data)
    except (ValueError, TypeError):
        return
    # Cheap structural assertion: every returned item has sender_id +
    # reflector_id attributes (Invariant 21 contract).
    for item in result:
        _ = item.sender_id
        _ = item.reflector_id


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()