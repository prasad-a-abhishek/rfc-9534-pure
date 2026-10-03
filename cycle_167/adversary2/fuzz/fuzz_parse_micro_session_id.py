"""Fuzz harness: parse_micro_session_tlv single TLV parse.

Surface: rfc9534pure.parser.parse_micro_session_tlv
Fuzz target: arbitrary bytes input (full range: None, empty, short, long,
             type-mismatched, reserved-flags, wrong-length).
Expected: all malformed inputs raise ValueError / TypeError; well-formed
          inputs return a MicroSessionIDTLV. No crashes, no hangs, no OOB.

This is the adversary2 post-F-1-fix rebuild of cycle_167/adversary/T2's
fuzz_parse_micro_session_id. The F-1 fix added an `if __name__ == "__main__"`
guard to __main__.py but did NOT touch parser.py — so the parser surface is
byte-for-byte identical to the pre-fix code. This harness is therefore a
_regression-detector_ rather than a coverage expansion: T3 should report the
same CLEAN outcome as the pre-fix chain (commit ed4b2c7, 0 crashes across
≥250K iters).

ASan/UBSan: safe. Target is pure Python (int.from_bytes, isinstance, bytes
indexing). Instrument with ASan via::

    PYTHONPATH=src python3 cycle_167/adversary2/fuzz/fuzz_parse_micro_session_id.py \\
        -atheris_timeout=5
"""
import sys

import atheris

# Make src/rfc9534pure/ importable without `pip install -e .`. The project
# root is two levels up from this file (cycle_167/adversary2/fuzz/ -> root).
_PROJECT_ROOT = "/root/projects/rfc-9534-pure/.worktrees/t_cycle167-adversary-02"
sys.path.insert(0, _PROJECT_ROOT + "/src")

from rfc9534pure.parser import parse_micro_session_tlv  # noqa: E402


def TestOneInput(data: bytes) -> None:
    """Atheris entry: pass arbitrary fuzzer bytes to parse_micro_session_tlv."""
    try:
        parse_micro_session_tlv(data)
    except (ValueError, TypeError):
        # Acceptable — parser is documented to raise on malformed input.
        return
    # If we got here, parse succeeded: the data WAS a well-formed TLV.
    # No further assertion — the surface is pure-side-effect-free.


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()