"""Atheris fuzzing harnesses for rfc-9534-pure (cycle_167/adversary2/T2).

Five self-contained harnesses covering the post-F-1-fix public surface:

  - fuzz_parse_micro_session_id   single TLV parse           (parser.py)
  - fuzz_parse_tlv_list           multi-TLV list parse      (parser.py)
  - fuzz_serialize_roundtrip      serialize -> parse         (serializer.py)
  - fuzz_cli_main                 `python -m rfc9534pure`   (__main__.py)
  - fuzz_invariant21_boundaries   None/empty/oversized/type-stress

Run from the project root:

    PYTHONPATH=src python3 cycle_167/adversary2/fuzz/fuzz_<name>.py

Bound runtime with the standard libFuzzer flags Atheris passes through:

    PYTHONPATH=src python3 cycle_167/adversary2/fuzz/fuzz_parse_micro_session_id.py \\
        -atheris_timeout=5 -runs=100000

All harnesses are safe under ASan / UBSan (no native code is reached
except CPython's allocator and Atheris's pybind11 shim).
"""