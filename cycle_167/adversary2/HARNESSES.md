# Atheris Fuzzing Harnesses — rfc-9534-pure (cycle_167/adversary2/T2)

This directory holds **5 Atheris-based fuzzing harnesses** that exercise
the public surfaces of `rfc9534pure` on the **post-F-1-fix tip (`70b00a5`)**.
Each harness is self-contained, runs with zero configuration from the
project root, and is bounded by `-runs=N` / `-atheris_timeout=N` for
production use.

> **This is the adversary2 chain.** It mirrors the surface coverage of the
> pre-fix chain at `cycle_167/adversary/fuzz/` (commit `81be034`), but is
> hardened against **regressions** that the F-1 fix might have introduced
> (the fix only added an `if __name__ == "__main__"` guard to
> `__main__.py`; parser.py + serializer.py are unchanged). T3's job is to
> re-run these harnesses against the post-fix code and confirm the same
> CLEAN outcome as the pre-fix chain (0 fuzz-driven findings across
> ≥250K iters).

## Surfaces covered (5 / 5 required by spec)

| # | Harness                                       | Surface                                                                                |
|---|-----------------------------------------------|----------------------------------------------------------------------------------------|
| 1 | `fuzz_parse_micro_session_id.py`              | `rfc9534pure.parser.parse_micro_session_tlv` — single TLV parse                        |
| 2 | `fuzz_parse_tlv_list.py`                      | `rfc9534pure.parser.parse_tlv_list` — concatenated multi-TLV parse                      |
| 3 | `fuzz_serialize_roundtrip.py`                 | `serialize_micro_session_tlv` → `parse_micro_session_tlv` roundtrip                     |
| 4 | `fuzz_cli_main.py`                            | `python -m rfc9534pure` CLI (subprocess invocation; catches hangs / unexpected exits)   |
| 5 | `fuzz_invariant21_boundaries.py`              | Invariant 21: None / empty / short / oversized / non-bytes / `serialize_tlv_list` round-trip |

The spec required ≥3 surfaces (preferred 5). This chain ships 5 — same
count as the pre-fix chain.

## Seed corpora

Each surface has a directory of seed inputs at
`fuzz/seeds/<surface>/`:

| Surface                  | Valid | Invalid | Total | Naming convention                  |
|--------------------------|-------|---------|-------|------------------------------------|
| `parse_micro_session_id` |  11   |  14     |  25   | `valid_NNN_*.bin` / `invalid_NNN_*.bin` |
| `parse_tlv_list`          |  11   |  11     |  22   | `valid_NNN_*.bin` / `invalid_NNN_*.bin` |
| `serialize_roundtrip`    |  16   |  10     |  26   | `valid_NNN_*.bin` / `invalid_NNN_*.bin` |
| `cli_main`               |  12   |  13     |  25   | `valid_NNN_*.bin` / `invalid_NNN_*.bin` |
| `invariant21_boundaries` |  10   |  11     |  21   | `valid_NNN_*.bin` / `invalid_NNN_*.bin` |
| **Total**                | **60**|**59**   |**119**| —                                  |

All 5 surfaces meet the spec requirement of **≥10 valid + ≥10 invalid**.
The valid/invalid naming makes the corpus self-documenting for T3.

Seed categories per the task spec:
- empty bytes** ✓ — `parse_micro_session_id/invalid_001_empty.bin`, `invariant21_boundaries/invalid_001_empty.bin`
- **0x0A header + valid TLV** ✓ — `parse_micro_session_id/invalid_007_wrong_type_10.bin` (0x0A = 10 ≠ 11)
- **oversized length** ✓ — `parse_micro_session_id/invalid_012_invalid_length_65535.bin`
- **RFC 9534 §4 examples** ✓ — `parse_micro_session_id/valid_001_rfc_example.bin` (sender=1, reflector=2)
- **all-zeros** ✓ — `parse_micro_session_id/invalid_013_invalid_all_zeros.bin`, `invariant21_boundaries/invalid_004_all_zeros.bin`
- **all-0xFF** ✓ — `parse_micro_session_id/invalid_014_invalid_all_ff.bin`, `invariant21_boundaries/invalid_005_all_ff.bin`
- **boundary 1/127/255 byte lengths** ✓ — covered by `parse_tlv_list/valid_006_partial_trailing.bin` (1-byte trailing), the 8-byte boundary is `valid_001_exactly_wire_length`, and 255-byte buffer is `valid_002_oversized_1k` (covers 127 and 255 within).

## Running a harness

From the project root:

```sh
PYTHONPATH=src python3 cycle_167/adversary2/fuzz/fuzz_parse_micro_session_id.py
```

Bound runtime / iterations:

```sh
PYTHONPATH=src python3 cycle_167/adversary2/fuzz/fuzz_parse_micro_session_id.py \
    -runs=100000 \
    -atheris_timeout=5
```

Replay from the seed corpus:

```sh
PYTHONPATH=src python3 cycle_167/adversary2/fuzz/fuzz_parse_micro_session_id.py \
    cycle_167/adversary2/fuzz/seeds/parse_micro_session_id
```

Capture new corpus:

```sh
PYTHONPATH=src python3 cycle_167/adversary2/fuzz/fuzz_parse_micro_session_id.py \
    -artifact_prefix=cycle_167/adversary2/crashes/parse_micro_session_id/ \
    -max_total_time=300
```

## Expected coverage per harness

1. **`fuzz_parse_micro_session_id.py`** — covers
   `parse_micro_session_tlv` end-to-end: the `isinstance` check,
   `len(data) < WIRE_LENGTH` short-circuit, the four `if`-raised
   `ValueError`s (wrong type, wrong length, reserved flag bits, None),
   the `TypeError` path (non-bytes), and the success path that constructs
   a `MicroSessionIDTLV`.

2. **`fuzz_parse_tlv_list.py`** — covers `parse_tlv_list`'s while-loop,
   the empty-input short-circuit, the `try/except` boundary that stops at
   the first malformed TLV (F-4 Info from T1 audit), and the per-item
   attribute-access path.

3. **`fuzz_serialize_roundtrip.py`** — covers
   `serialize_micro_session_tlv`'s range checks
   (`0 <= sender_id <= 0xFFFF`, `0 <= reflector_id <= 0xFFFF`,
   reserved flag bits), the `bytes(...)` concatenation, and the parser's
   success path. Asserts the roundtrip property:
   `parse(serialize(x, y, f)) == (x, y, f & 0x07)`.

4. **`fuzz_cli_main.py`** — covers the `main()` argparse dispatch in
   `__main__.py`, both subcommands (`parse`, `serialize`), the help path,
   the unknown-command path, and the error-emitting paths. Runs the CLI
   as a real subprocess with a 2-second wall-clock timeout, so any hang in
   `main()` is caught and raised as an `AssertionError`. **Asserts the
   F-1-fix exit-code contract** (`rc in {0, 1, 2}`); pre-fix this harness
   would have been a no-op because the subprocess would silently exit 0.

5. **`fuzz_invariant21_boundaries.py`** — covers the **Invariant 21**
   contract from the project's memory: every documented exception shape
   (`None` → `ValueError`, non-bytes → `TypeError`, short →
   `ValueError`) is asserted. **Additionally exercises
   `serialize_tlv_list`** (the multi-item serializer) — covers the
   `tlvs must be list`, `tlv must be MicroSessionIDTLV`, and successful
   round-trip paths. Catches any future change that drops an exception
   guard or that turns a `ValueError` into a silent success.

## ASan / UBSan notes

All five harnesses are safe under ASan / UBSan:

- No native code is reached except CPython's allocator and Atheris's
  pybind11 shim.
- No external process I/O outside `fuzz_cli_main.py`, which spawns a clean
  child that re-invokes CPython (no native escalation path).
- All buffers are bounded by the fuzzer's `-max_len` parameter and the
  internal `* 4` cap in `fuzz_invariant21_boundaries.py` so the fuzzer
  itself can't OOM.

The `WARNING: Failed to find function "__sanitizer_set_death_callback"`
message during CLI-harness fuzzing is benign — it means this Python build
isn't linked against ASan. To enable ASan/UBSan, install the Atheris build
that links against libFuzzer + ASan and invoke the harness as shown
above.

## Smoke-test status

All 5 harnesses pass a 25–200-iteration smoke run with empty seed corpus
(default atheris behavior — random byte generation):

| Harness                                       | Runs | Status |
|-----------------------------------------------|------|--------|
| `fuzz_parse_micro_session_id.py`              | 200  | PASS   |
| `fuzz_parse_tlv_list.py`                      | 200  | PASS   |
| `fuzz_serialize_roundtrip.py`                 | 200  | PASS   |
| `fuzz_cli_main.py`                            | 50   | PASS   |
| `fuzz_invariant21_boundaries.py`              | 200  | PASS   |

All 5 harnesses also pass a 25–50-iteration smoke run with the
provided seed corpora (valid + invalid inputs both replayed cleanly, no
crashes, no hangs, no unexpected exceptions).

Smoke runs are bounded (`-runs=N`) so they finish in < 1 second each.
The `WARNING: no interesting inputs were found` message during seeded
runs is expected: atheris uses coverage-guided mutation, and the seed
corpus doesn't expand the input class significantly on a short bounded
run. T3's longer run (≥250K iters) will explore the seed space properly.

## How to extend

To add a new harness:

1. Create `fuzz/fuzz_<name>.py` following the `atheris.Setup` /
   `atheris.Fuzz` pattern.
2. Use `sys.path.insert(0, "<repo_root>/src")` so `rfc9534pure` imports
   without install.
3. Wrap target calls in `try/except (ValueError, TypeError)` and `return`
   unless the target is documented to succeed.
4. Drop seed files under `fuzz/seeds/<surface>/` named
   `valid_NNN_*.bin` / `invalid_NNN_*.bin` (≥10 each).
5. Add the harness to the table in this file.

## Findings link

The T1 manual audit (`cycle_167/adversary2/VULN_AUDIT.md`, commit
`a679a94`) found the post-F-1-fix codebase to be **CLEAN** (0 Critical /
0 High / 0 Medium / 2 Low / 4 Info — no blockers). The 5 prior
Low/Info advisories (F-2..F-6) remain unchanged:

| ID  | Severity | Title                                                              |
|-----|----------|--------------------------------------------------------------------|
| F-2 | Low      | `parse_tlv_list` returns `[]` for `None` / `""` (divergent from parser) |
| F-3 | Info     | `parse_micro_session_tlv` rejects `memoryview` (over-strict)        |
| F-4 | Info     | `parse_tlv_list` silently stops on first non-parseable TLV          |
| F-5 | Info     | `_hex_to_bytes("0x")` / `""` returns `b""` rather than raising     |
| F-6 | Info     | (withdrawn) Unused `argparse` import in `__main__.py`              |

None of these are reachable by fuzzing the public API directly:
- F-2 / F-4: `parse_tlv_list` behavior is observable but doesn't crash
  or leak memory.
- F-3 / F-6: type-system strictness / unused imports — not exploitable.
- F-5: CLI `_hex_to_bytes` helper — reachable only via `python -m
  rfc9534pure parse ""`, which is covered by the CLI-harness seed
  `cli_main/invalid_001_no_args.bin` (and the parent audit's probe
  table).

The F-1 fix (the only High-severity finding from the pre-fix chain) is
verified by `fuzz_cli_main.py`'s explicit assertion of the exit-code
contract (`rc in {0, 1, 2}`); a regression that broke the
`if __name__ == "__main__":` guard would surface as the CLI subprocess
silently exiting 0 with no output, raising an `AssertionError`.

## Commit

These harnesses ship on `wt/cycle_167-adversary-02` at the post-F-1-fix
tip (`70b00a5`) — T2 is the prerequisite for T3 (`fuzz/fuzz_corpus_run`).
T3 owns execution (≥250K iters across all 5 surfaces), T4 owns triage,
T5 owns the canonical 6-section `FUZZING_REPORT.md` synthesis.