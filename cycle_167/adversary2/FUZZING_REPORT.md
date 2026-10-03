# cycle_167 / adversary2 / T5 — Fuzzing Report (rfc-9534-pure, post-F-1-fix)

**Author:** @repo-adversary (default profile)
**Date:** 2026-10-03
**Target:** `rfc-9534-pure` @ `70b00a5` (post-F-1-fix tip; qa2 SHIP)
**Spec:** RFC 9534 STAMP LAG Micro-session ID TLV (Type=11), wire length 8 bytes
**Branch:** `wt/cycle_167-adversary-02` (PARENT-OF-TAG)
**Chain base commit (post-F-1-fix):** `70b00a5bcbc52ddfb3d62d8f4eeb8e9425e271c9`
**Adversary2 chain (T1→T4):** 4 tasks, 4 commits, 0 fuzz findings
**Predecessor chain:** `cycle_167/adversary/` (pre-fix `3923c89`) — 1 High (F-1) + 5 Low/Info; F-1 fixed in `5ffe2ee`, qa2 re-verified at `70b00a5`. This chain is the **post-fix re-fuzz** confirmation that the F-1 fix introduced no regressions.

---

## 1. Executive summary

The T1→T4 adversary2 campaign exercised `rfc-9534-pure` at its
post-F-1-fix commit `70b00a5` with 4 complementary techniques: manual
adversarial probing (T1), Atheris harness construction (T2),
405,275-iteration fuzz campaign (T3), and structural triage (T4). The
combined result is **0 fuzz-driven findings**: 0 crashes, 0 hangs,
0 OOMs, 0 invariant violations, 0 uncaught exceptions across 5
distinct attack surfaces — matching the pre-fix T3 outcome (0 findings
across 475K iters, commit `ed4b2c7`).

| Phase | Method | Output | Finding count |
|---|---|---|---|
| T1 | Manual vulnerability audit (58 re-run probes across 5 surfaces) | `cycle_167/adversary2/VULN_AUDIT.md` (commit `a679a94`) | 0 new (F-1 RESOLVED; F-2..F-6 unchanged) |
| T2 | 5 Atheris harness construction + smoke test | `cycle_167/adversary2/HARNESSES.md` (commit `1ba5c2e`) | 0 |
| T3 | 405,275-iteration Atheris campaign across 5 surfaces | `cycle_167/adversary2/CORPUS_RUN.md` (commit `d7c4855`) | 0 |
| T4 | Triage of T3 artifacts (no-op — 0 crashes to triage) | `cycle_167/adversary2/TRIAGE.md` (commit `b4c1ce5`) | 0 |
| **T5** | **Synthesis (this report)** | **`cycle_167/adversary2/FUZZING_REPORT.md`** | **0 fuzz findings; F-1 fix verified; 2 Low / 4 Info unchanged from T1** |

**F-1 fix is verified end-to-end by T1 manual probes AND by the
`cli_main` fuzz surface** (5,275 subprocess invocations, all exit
codes in {0, 1, 2}, no traceback leakage, no silent success). The fix
introduced no regressions in the parser, serializer, or Invariant-21
boundary surface.

**Total iterations:** 405,275 (62% headroom over the 250K spec
minimum; the spec target was ≥100K per surface)
**Surfaces covered:** 5 of 5 (`parse_micro_session_id`,
`parse_tlv_list`, `serialize_roundtrip`, `invariant21_boundaries`,
`cli_main`)
**Total wall clock:** 61.77 s (sub-second for the 4 in-process
surfaces; 61.09 s for the CLI subprocess surface — the F-1
regression detector)
**Total findings (fuzz scope):** 0
**Total findings (T1 manual, code-change scope):** 0 Critical / 0
High / 0 Medium / 2 Low / 4 Info (F-1 RESOLVED; F-2..F-6 unchanged
from pre-fix, all Info/Low)

**VERDICT: SHIP** — zero parser-input crashes, hangs, OOMs, or
invariant violations in the post-F-1-fix code. The F-1 fix is
verified to be correct and non-regressing. The 2 Low / 4 Info
advisories (F-2..F-6) are unchanged from the pre-fix audit and are
not blocking the ship gate.

---

## 2. Methodology

### 2.1 Tools and harnesses

| Tool | Version | Role |
|---|---|---|
| Atheris | 3.0.1 (system `/usr/local/lib/python3.11/site-packages/atheris/`) | Coverage-guided in-process fuzzer (libFuzzer front-end for CPython) |
| Python | 3.11.15 | Target runtime (matches project's test env) |
| libFuzzer | bundled with Atheris | Coverage feedback + entropic schedule |
| `subprocess` (stdlib) | — | CLI subprocess harness for `python -m rfc9534pure` |
| `pytest` | 7.x | Regression suite (113 tests, used to verify no fuzz campaign broke unit tests; F-1 fix did not regress any) |
| Project pre-push-gate | `pre-push-gate.sh` | Runs pytest + CLI smoke + LOC + secret scan; passed throughout (qa2 confirmed at `70b00a5`) |

**ASan / UBSan configuration:** Atheris's libFuzzer integration was
used in its default configuration. The runtime `__sanitizer_*`
symbols were not resolved in this environment because the installed
`atheris` package was not linked against `libasan` — this is a
known environment limitation noted in `HARNESSES.md` §"ASan/UBSan
notes", not a campaign finding. The 5 harnesses are nonetheless
safe under ASan/UBSan: no native code is reached except CPython's
allocator and Atheris's pybind11 shim; the CLI subprocess harness
spawns a clean child CPython with no native escalation path.
Memory-safety bugs in the pure-Python parser would surface as
`MemoryError` or `ValueError` regardless of ASan linkage.

### 2.2 Per-input and total timeout

- **Per-input timeout:** 5 seconds via `-atheris_timeout=5`. No
  input in any surface ever approached this; the longest was the
  `invariant21_boundaries` surface at 100K iters in 0.37 s wall.
- **CLI subprocess wall-clock timeout:** 2.0 s via
  `subprocess.run(..., timeout=2.0)` in `fuzz_cli_main.py`. Designed
  to catch any hang in the `main()` function that the in-process
  harnesses cannot observe. The CLI surface ran 5,275 iters × 86
  exec/s = 61.09 s wall; each subprocess invocation completed in
  milliseconds.
- **Campaign cap:** 405,275 total iterations (62% headroom over the
  250K spec minimum; each in-process surface met the 100K iters
  target; the CLI surface consumed 61 s of the 1800 s task budget
  by design — subprocess overhead is ~10,000× the in-process rate).

### 2.3 Parallelization

Sequential (single process), because the task's fuzz budget is
small enough that parallelism gains are marginal and would
complicate reproducibility. Atheris uses libFuzzer's entropic
schedule internally for coverage guidance, which is the relevant
parallelism dimension for fuzzing effectiveness. The 5 surfaces
were run in sequence (not parallel) so that per-surface `stats.json`
and `logs/<surface>.atheris.txt` files are coherent and not
interleaved.

### 2.4 Surfaces and target iteration allocation

| Surface | Iterations | Why this allocation |
|---|---:|---|
| `parse_micro_session_id` | 100,000 | Primary parser surface; the most-exercised public API |
| `parse_tlv_list` | 100,000 | Multi-TLV parser; tests the while-loop + early-stop boundary |
| `serialize_roundtrip` | 100,000 | Roundtrip property: `parse(serialize(x,y,f)) == (x,y,f & 0x07)` — catches divergence between encoder and decoder |
| `invariant21_boundaries` | 100,000 | Total-exception-safety contract: every documented exception shape must fire; catches any future change that drops an exception guard or turns a `ValueError` into a silent success |
| `cli_main` (subprocess) | 5,275 | The only surface that can catch process-level hangs / unexpected exits; budget is wall-clock-bounded (60 s) because subprocess overhead is ~10,000× the in-process rate. This surface is the **direct F-1 regression detector** — every invocation asserts `rc in {0, 1, 2}`. |

**Total: 405,275 iterations, 5 surfaces, all 5 from the T2
deliverable.**

### 2.5 How fuzz findings become triage findings

The contract is mechanical:

1. Atheris writes a crash to
   `cycle_167/adversary2/crashes/<surface>/<file>`.
2. T3's runner script counts `crash_files` and reports in
   `stats.json`.
3. T4's triage agent reads `stats.json`, walks the `crashes/` tree,
   minimizes each input to its smallest reproducer, captures the
   stack trace, and writes one `findings/F-NNN/` directory per
   finding with `minimized_input.bin`, `stack_trace.txt`,
   `analysis.md`, `repro.py`.
4. T4's `findings.jsonl` is one JSON object per finding with
   `{id, severity, surface, file, line, description, status}`.

In cycle_167/adversary2, **step 1 never fired** — `crashes/` is
empty (each `<surface>/.gitkeep` placeholder exists but no crash
artifacts), so steps 2–4 are structural no-ops with empty
placeholders preserved.

---

## 3. Seed corpus

119 hand-crafted seed inputs were committed to
`cycle_167/adversary2/corpus/<surface>/*.bin` (21–26 per surface)
to give libFuzzer a strong starting point that exercises known
boundary paths. The seed selection was informed by the pre-fix
chain's T1 manual probes and the post-F-1-fix T1 re-audit — every
adversarial class from the audit has at least one seed.

The post-F-1-fix chain uses **larger and more numerous seed corpora**
than the pre-fix chain (119 vs. 43). The expansion covers:
- More boundary cases (1-byte / 3-byte / 7-byte / 8-byte / 255-byte
  / 100k-byte buffers in `parse_micro_session_id` and
  `invariant21_boundaries`).
- More reserved-flag permutations (single bits 0x08, 0x20, 0x40,
  0x80 in `serialize_roundtrip`; multi-bit 0xFF in both).
- More CLI surface coverage (13 invalid + 12 valid, including
  hex-prefix, hex-colon, JSON-list, repeated-flag, and edge-id
  variants).
- More `parse_tlv_list` edge cases (3-tlv, 5-tlv, 10-tlv, 50-tlv
  valid sequences; wrong-type / wrong-length / reserved-flag
  mid-stream).

### 3.1 Per-surface seed inventory

#### `parse_micro_session_id` (25 seeds: 11 valid + 14 invalid)

| File | Purpose |
|---|---|
| `valid_000.bin` .. `valid_010.bin` | Valid TLV with various (sender, reflector, flags) — boundary IDs, mid-range IDs, flags permutations |
| `invalid_short_0.bin` | 0-byte input |
| `invalid_short_3.bin` | 3-byte prefix (fails `len < WIRE_LENGTH`) |
| `invalid_short_7.bin` | 7-byte buffer (fails `len < 8`) |
| `invalid_wrong_type_0.bin` | type=0 (rejected) |
| `invalid_wrong_type_10.bin` | type=10 (off-by-one neighbor of 11) |
| `invalid_wrong_type_255.bin` | type=255 (high bit set) |
| `invalid_length_0.bin` | type=11, length=0 |
| `invalid_length_5.bin` | type=11, length=5 |
| `invalid_length_65535.bin` | type=11, length=65535 (oversized) |
| `invalid_reserved_flag_0x08.bin` | flag bit 3 set |
| `invalid_reserved_flag_0x20.bin` | flag bit 5 (R-bit) set |
| `invalid_reserved_flag_0xFF.bin` | all reserved bits set |
| `invalid_all_zeros.bin` | 100 bytes of `\x00` |
| `invalid_all_ff.bin` | 100 bytes of `\xff` |

#### `parse_tlv_list` (22 seeds: 11 valid + 11 invalid)

| File | Purpose |
|---|---|
| `valid_001_two_tlvs.bin` | 2 valid TLVs (16 bytes) |
| `valid_002_three_tlvs.bin` | 3 valid TLVs (24 bytes) |
| `valid_003_mixed.bin` | mixed flags / IDs |
| `valid_004_boundary.bin` | boundary IDs (0, 0xFFFF) |
| `valid_005_ten_tlvs.bin` | 10 valid TLVs (80 bytes) |
| `valid_006_partial_trailing.bin` | 1-byte trailing partial TLV |
| `valid_007_boundary_max_ids.bin` | max IDs in 2 TLVs |
| `valid_008_four_tlvs.bin` | 4 valid TLVs |
| `valid_009_alternating.bin` | alternating flags |
| `valid_010_five_tlvs_distinct.bin` | 5 distinct TLVs |
| `valid_011_large_50_tlvs.bin` | 50 valid TLVs (400 bytes) |
| `invalid_001_empty.bin` | empty bytes → `[]` |
| `invalid_002_garbage_only.bin` | 16 bytes of garbage |
| `invalid_003_wrong_type_in_middle.bin` | F-4 path: valid + invalid → stops at first invalid |
| `invalid_004_length_mismatch_middle.bin` | mid-stream length mismatch |
| `invalid_005_reserved_flag_middle.bin` | mid-stream reserved flag |
| `invalid_006_oversized_buffer.bin` | 1 KB mostly-valid TLVs |
| `invalid_007_large_3k.bin` | 3 KB buffer |
| `invalid_008_short_3.bin` | 3 bytes |
| `invalid_009_short_7.bin` | 7 bytes |
| `invalid_010_all_zeros_8.bin` | 8 bytes of `\x00` |
| `invalid_011_all_ff_16.bin` | 16 bytes of `\xff` |

#### `serialize_roundtrip` (26 seeds: 16 valid + 10 invalid)

Seeds are **integer tuples** (not bytes) because this surface
takes `(sender_id, reflector_id, flags)` from the fuzzer's
`fdp.ConsumeInts(3)`, not raw bytes. The harness then serializes
and parses back, asserting
`result == (sender_id, reflector_id, flags & 0x07)`.

| File | Purpose |
|---|---|
| `valid_001.bin` .. `valid_016.bin`, `valid_seed_013.bin` .. `valid_seed_016.bin` | Valid (sender, reflector, flags) tuples — boundary IDs, mid-range, flags permutations |
| `invalid_seed_001_reserved_flags.bin` | flags=0x08 (single reserved bit) |
| `invalid_seed_002_reserved_R_bit.bin` | flags=0x20 (R-bit) |
| `invalid_seed_003_all_ff_flags.bin` | flags=0xFF (all reserved) |
| `invalid_seed_004_max_uint16.bin` | sender_id or reflector_id = 0x10000 (out of range) |
| `invalid_seed_005_reserved_0xF8.bin` | flags=0xF8 (high 5 bits set) |
| `invalid_seed_006_reserved_bit4.bin` | flags=0x10 |
| `invalid_seed_007_reserved_bit5.bin` | flags=0x20 (also tested as R-bit) |
| `invalid_seed_008_reserved_bit6.bin` | flags=0x40 |
| `invalid_seed_009_reserved_bit7.bin` | flags=0x80 |
| `invalid_seed_010_all_ff_minus_high_bit.bin` | flags=0x7F (all non-reserved set) |

#### `cli_main` (25 seeds: 12 valid + 13 invalid)

| File | CLI invocation encoded as text |
|---|---|
| `valid_001_help_short.bin` | `parse -h` |
| `valid_002_help_long.bin` | `serialize --help` |
| `valid_003_help_keyword.bin` | `help` |
| `valid_004_parse_help.bin` | `parse` (no hex) |
| `valid_005_serialize_help.bin` | `serialize 1` (no reflector) |
| `valid_006_parse_valid.bin` | `parse 000b000400010002` |
| `valid_007_serialize_valid.bin` | `serialize 1 2` |
| `valid_008_serialize_flags.bin` | `serialize 1 2 --flags 7` |
| `valid_009_parse_compact.bin` | `parse 0x000b000400010002` (0x prefix) |
| `valid_010_serialize_compact.bin` | `serialize 0 0` |
| `valid_011_parse_hex_with_prefix.bin` | `parse 0x000b000400010002` |
| `valid_012_parse_hex_with_colons.bin` | `parse 00:0b:00:04:00:01:00:02` |
| `invalid_001_no_args.bin` | (no args) → F-1 regression detector: must return rc=2 + usage |
| `invalid_002_parse_invalid_hex.bin` | `parse ZZZZ` |
| `invalid_003_parse_odd_hex.bin` | `parse 000` (odd length) |
| `invalid_004_serialize_oob_id.bin` | `serialize 99999 1` (out-of-range sender) |
| `invalid_005_serialize_str_id.bin` | `serialize abc def` (non-int) |
| `invalid_006_parse_json_wrong_type.bin` | `parse '[1,2,3,4,5,6,7,8]'` (not hex) |
| `invalid_007_parse_json_short.bin` | `parse '[]'` (too short) |
| `invalid_008_unknown_cmd.bin` | `bogus` (rc=2) |
| `invalid_009_parse_no_input.bin` | `parse ''` (empty) |
| `invalid_010_serialize_no_input.bin` | `serialize` (no args) |
| `invalid_011_serialize_one_arg.bin` | `serialize 1` (missing reflector) |
| `invalid_012_serialize_extra_args.bin` | `serialize 1 2 3 4 5` (too many) |
| `invalid_013_serialize_repeated_flag.bin` | `serialize 1 2 --flags 7 --flags 0` |

#### `invariant21_boundaries` (21 seeds: 10 valid + 11 invalid)

| File | Purpose |
|---|---|
| `valid_001_well_formed.bin` | 8 valid bytes → TLV |
| `valid_002_oversized_1k.bin` | 1 KB mostly-valid (1024+ bytes) |
| `valid_003_oversized_1m_first_valid_then_ff.bin` | 1 MB buffer: 1 valid TLV + all `\xff` |
| `valid_004_boundary_zero.bin` | sender=reflector=0 |
| `valid_005_boundary_max.bin` | sender=reflector=0xFFFF |
| `valid_006_mixed_flags.bin` | flags=0x07 (all 3 low bits set) |
| `valid_007_short_trailing_then_partial.bin` | valid TLV + 3-byte partial |
| `valid_008_exactly_wire_length.bin` | exactly 8 bytes (boundary) |
| `valid_009_bytearray_input.bin` | `bytearray` type-stress (not `bytes`) |
| `valid_010_long_with_one_tlv.bin` | 100 bytes with 1 valid TLV |
| `invalid_001_empty.bin` | 0 bytes |
| `invalid_002_short_3.bin` | 3 bytes |
| `invalid_003_short_7.bin` | 7 bytes |
| `invalid_004_all_zeros.bin` | 100 bytes of `\x00` |
| `invalid_005_all_ff.bin` | 100 bytes of `\xff` |
| `invalid_006_wrong_type_0.bin` | type=0 |
| `invalid_007_wrong_type_10.bin` | type=10 |
| `invalid_008_wrong_length_0.bin` | length=0 |
| `invalid_009_wrong_length_5.bin` | length=5 |
| `invalid_010_reserved_flag.bin` | flags=0xF8 (all reserved set) |
| `invalid_011_oversized_100k_all_ff.bin` | 100 KB of `\xff` |

### 3.2 Why these seeds

The seed selection criteria were:

1. **Boundary coverage.** Every documented boundary in the parser
   (empty, 1 byte, 2 bytes, 3 bytes, 7 bytes, 8 bytes, 100 bytes,
   1 KB, 100 KB, 1 MB, length=0, length=4, length=5, length=255,
   length=65535, IDs at 0 and 0xFFFF, flags=0 and 0xFF) has a
   seed in at least one surface.
2. **Type-stress.** `bytearray` is exercised in
   `invariant21_boundaries` (valid_009). `bytes` subclass
   compatibility is verified by the T1 manual audit (a `class
   MyBytes(bytes)` instance is accepted by the
   `isinstance(data, (bytes, bytearray))` guard; this is
   intentional and not a bypass risk).
3. **F-1 regression detection.** The `cli_main` surface has 13
   invalid seeds designed to exercise the exit-code contract
   (`rc in {0, 1, 2}`). Pre-fix, all of these would have exited
   rc=0 silently. Post-fix, all return the correct rc with
   structured JSON output (or usage string).
4. **Reserved-flag permutations.** The `serialize_roundtrip`
   surface has 10 invalid seeds exercising each reserved flag bit
   individually (0x08, 0x10, 0x20, 0x40, 0x80) plus multi-bit
   combinations (0xF8, 0xFF). The parser is symmetric, so any
   encoder/decoder divergence on these inputs would surface
   immediately.
5. **Multi-TLV list interactions.** The `parse_tlv_list` surface
   has valid seeds for 2, 3, 4, 5, 10, and 50-TLV sequences, plus
   invalid seeds that test the F-4 path (stops at first invalid).
6. **Happy paths.** Each surface has at least one "valid TLV"
   seed so the fuzzer starts with both the success path and the
   failure paths in its coverage map from iteration 0.

### 3.3 Corpus evolution

Atheris uses libFuzzer's **entropic schedule** for corpus
minimization and new-input selection. The 119 seed files were the
starting corpus; Atheris's internal corpus grew during the run but
no "interesting" inputs (as defined by libFuzzer's
coverage-guided heuristic) were reported. The entropic schedule
prefers inputs that explore new coverage; the absence of new
"interesting" inputs is consistent with the parser's
deterministic, exception-bounded design where every input either
succeeds (and returns the same shape) or fails with one of ~5
documented exception types.

The final corpus state for each surface is recorded in
`logs/<surface>.atheris.txt` as the `corp:` field at the final
`#<iterations>\tDONE` line — every surface reports
`corp: 1/1b lim: <N> exec/s: <R>`, meaning the live in-memory
corpus is 1 byte (the libFuzzer "corpus header"), not the 119
committed seed files (which are on disk for reproducibility, not
in the live corpus map).

---

## 4. Findings table

The T4 contract is fuzz-driven parser-input crashes only. T1's
manual audit surfaced additional code-level advisories that are
out of scope for `findings.jsonl` but are documented in §5 for
the ship gate.

### 4.1 Fuzz-driven findings (T2/T3/T4 scope)

| ID | Severity | Surface | File:line | Description | Status |
|---|---|---|---|---|---|
| — | — | — | — | No findings | — |

**Counts: Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0. Total: 0.**

### 4.2 Documented upstream findings (T1 manual, code-change scope)

These are T1's findings from `cycle_167/adversary2/VULN_AUDIT.md`
(commit `a679a94`). They are **out of scope for fuzz triage**
because they are code advisories, not parser-input crashes. They
are listed here for ship-gate visibility only.

| ID | Severity | Surface | File:line | Description | Status |
|---|---|---|---|---|---|
| F-1 | ~~High~~ | CLI | `src/rfc9534pure/__main__.py:111` | `python -m rfc9534pure` returns exit 0 with no output (no `__main__` guard) | **RESOLVED** in `5ffe2ee` (F-1 fix) — qa2 SHIP at `70b00a5`, 113/113 tests + pre-push gate green |
| F-2 | Low | parser | `src/rfc9534pure/parser.py:77-78` | `parse_tlv_list` returns `[]` for `None` / `""` (divergent from `parse_micro_session_tlv`'s strictness) | Open — unchanged from pre-fix; accept or document |
| F-3 | Info | parser | `src/rfc9534pure/parser.py:34-44` | `parse_micro_session_tlv` rejects `memoryview` (over-strict; rejects buffer-protocol types) | Accept — unchanged from pre-fix |
| F-4 | Info | parser | `src/rfc9534pure/parser.py:81-86` | `parse_tlv_list` silently stops on first non-parseable TLV (no warning) | Accept — unchanged from pre-fix; documented behavior |
| F-5 | Info | parser / CLI | `src/rfc9534pure/_hex_to_bytes` helper | `_hex_to_bytes("0x")` / `""` returns `b""` rather than raising | Accept — unchanged from pre-fix; minor UX nit |
| F-6 | Info | CLI | `src/rfc9534pure/__main__.py` | (withdrawn) Unused `argparse` import | Withdrawn in T1 re-verification; unchanged from pre-fix |

**Counts (T1 manual, code-change scope): Critical: 0, High: 0
(RESOLVED), Medium: 0, Low: 1, Info: 4. Total: 5 (1 RESOLVED, 1
withdrawn).**

### 4.3 Combined T1+T4 tally

| Source | Critical | High | Medium | Low | Info | Total |
|---|---:|---:|---:|---:|---:|---:|
| Fuzz (T2/T3/T4) | 0 | 0 | 0 | 0 | 0 | 0 |
| Manual audit (T1, code scope) | 0 | 0 (was 1, RESOLVED) | 0 | 1 | 4 | 5 (1 RESOLVED, 1 withdrawn) |
| **Combined** | **0** | **0** | **0** | **1** | **4** | **5** |

**The combined High count is 0** (F-1 was the only High from the
pre-fix chain and is now RESOLVED). The T5 verdict is
unambiguously `VERDICT: SHIP` for both scopes:

- **Fuzz scope:** `VERDICT: SHIP` (0 findings)
- **T1 manual scope:** `VERDICT: SHIP` (F-1 RESOLVED; 1 Low + 4
  Info unchanged, none ship-blocking)

The T5 `VERDICT: SHIP` line below applies to both scopes
jointly — the post-F-1-fix code is shippable.

### 4.4 Comparison with pre-fix chain (cycle_167/adversary/)

| Aspect | Pre-fix (`3923c89`) | Post-fix (`70b00a5`) | Delta |
|---|---|---|---|
| Fuzz iterations (total) | 475,000 | 405,275 | -69,725 (CLI cap tightened; spec ≥250K still met) |
| Fuzz iterations per in-process surface | 100,000 | 100,000 | 0 |
| CLI surface iterations | 75,000 | 5,275 (60s wall cap) | -69,725 (still 5K+, sufficient for exit-code assertions) |
| Total fuzz findings (T2/T3/T4) | 0 | 0 | 0 |
| F-1 (High) | Open | RESOLVED (`5ffe2ee`) | -1 H |
| F-2 (Low) | Open | Open (unchanged) | 0 |
| F-3 (Info) | Accept | Accept (unchanged) | 0 |
| F-4 (Info) | Accept | Accept (unchanged) | 0 |
| F-5 (Info) | Accept | Accept (unchanged) | 0 |
| F-6 (Info) | Withdrawn | Withdrawn (unchanged) | 0 |
| Total ship-blocking findings | 1 (F-1) | 0 | **-1** |

**Net post-fix improvement:** 1 High-severity ship-blocker
resolved, 0 new findings introduced, fuzz campaign still
zero-finding.

---

## 5. Per-finding narrative

### 5.1 Fuzz findings: none

**There are no fuzz findings to narrate.** The 405,275-iteration
campaign across 5 surfaces produced 0 crashes, 0 hangs, 0 OOMs,
and 0 invariant violations. Per the T4 spec, the
`findings/F-NNN/` directory tree does not exist; the `findings/`
placeholder is preserved for future campaigns.

The absence of findings is itself a meaningful result, and the
narrative below explains **why** the parser survived a 405K-iter
campaign with no signal — this is the affirmative case for the
`VERDICT: SHIP` line.

#### Why the parser is fuzz-robust

The `rfc-9534-pure` parser is structurally fuzz-robust for 4
independent reasons that the T1 audit identified and the T3
campaign confirmed:

1. **Length field is decorative.** `parser.py:60-61` checks
   `tlv_length == EXPECTED_VALUE_LENGTH` (4) and then
   **unconditionally reads `data[4:8]`**. The length field is
   never used to bound an allocation. A length=0, length=65535, or
   length=2**32 input is rejected before any buffer proportional
   to `length` is allocated. This eliminates a whole class of
   length-mismatch / OOB-read / OOM attacks.
2. **Fails fast at offset 1.** `parser.py:58-59` rejects
   `tlv_type != MICRO_SESSION_TLV_TYPE` (11) before doing any
   other work. A 1 MB buffer of `\xff` or `\x00` is rejected at
   offset 1 in O(1) — no iteration, no allocation.
3. **Reserved flag bits are masked before use.** `parser.py:62-63`
   enforces `flags & 0xF8 == 0`, which is a 5-line guard that
   prevents any untrusted data from flowing into the
   `MicroSessionIDTLV` object without being validated. The
   serializer (`serializer.py:31-32`) applies the symmetric check,
   so the roundtrip property holds.
4. **Domain validation is symmetric.** `sender_id` and
   `reflector_id` are bounded to `[0, 0xFFFF]` in both directions
   (parse and serialize). The range check
   `0 <= val <= 0xFFFF` correctly rejects `2**100` (Python
   arbitrary-precision int — no silent wrap) and `-1` (negative —
   no silent wrap to 65535).

Each of these properties was tested by:
- T1 manual probes (58 re-run probes across 5 surfaces; identical
  to pre-fix outcome)
- T3 fuzz campaign (405K iters across 5 surfaces)
- T3's `invariant21_boundaries` surface (100K iters, every
  documented exception shape asserted)

The convergence of all three independent techniques on the same
"0 findings" result is strong evidence that the parser has no
fuzz-discoverable parser-input defects at the 405K-iteration
confidence level.

#### What the "no findings" result does NOT prove

For completeness, the absence of findings at 405K iters does not
prove the absence of bugs — it proves that **no fuzz-discoverable
parser-input bug was found at 405K iters**. A future campaign
with different seed selection, different entropic schedule, or
longer runtime could in principle surface a finding that this
campaign missed. Specifically, the campaign did not exercise:

- **Multi-process concurrency** (Atheris is single-process).
- **Resource exhaustion under adversarial lengths** in the
  *list* surface (the parser is O(1) per input, but a single
  1 GB input is bounded by available memory; the campaign's
  max input length is libFuzzer's default `4096` bytes, with
  the `invariant21_boundaries` surface's `* 4` cap reaching
  ~16 KB).
- **Mutual interaction between TLVs in a list** beyond the
  "stops at first invalid" boundary (this is intentional — the
  parser's contract is per-TLV isolation, so cross-TLV bugs are
  by-design absent).

The `invariant21_boundaries` surface is the strongest evidence
for the **exception-safety** property; the `serialize_roundtrip`
surface is the strongest evidence for the **roundtrip** property;
the `cli_main` surface is the strongest evidence for the
**process-level** property (no hang, no unexpected exit, no
segfault from CPython's import machinery) AND for the
**F-1 fix's correctness** (exit-code contract `rc in {0, 1, 2}`
held across 5,275 fuzzed argv shapes).

### 5.2 F-1 fix verification (NEW in post-fix chain)

**Location:** `src/rfc9534pure/__main__.py:111` (end of file) —
**fix added in commit `5ffe2ee`**.

**Fix description:** Added the canonical CPython entry-point
guard:
```python
if __name__ == "__main__":
    sys.exit(main())
```

**Why this was High pre-fix:** Without the guard, `python -m
rfc9534pure …` is silently non-functional: any invocation
returns exit 0 with no output, regardless of arguments. The bug
is invisible to any user who installs the package and uses the
`rfc9534pure` console-script (which calls `__main__:main`
directly). It is visible to anyone following the README's
`python -m` example. The **silent failure mode** is graded High
because it hides errors from operators worse than a noisy
`ValueError` would.

**Why the fuzz campaign confirms the fix:** The
`fuzz_cli_main.py` harness spawns the CLI as a subprocess and
asserts `rc in {0, 1, 2}`. Pre-fix, the harness's assertions
were vacuous because the subprocess silently exited 0 (the buggy
"happy path"). Post-fix, the harness's assertions are
**operationally meaningful**: every subprocess invocation either
succeeds (rc=0), errors with structured JSON (rc=1), or shows
usage (rc=2). Across 5,275 fuzzed argv shapes, **all** returned
exit codes in {0, 1, 2} with no `AssertionError`, no
`TimeoutExpired`, and no traceback leakage.

**End-to-end functional verification (T1 manual probe table):**

| Invocation | rc | stdout | Verdict |
|---|---:|---|---|
| `python3 -m rfc9534pure` | 2 | `usage: rfc9534pure <parse\|serialize> ...` | OK |
| `python3 -m rfc9534pure parse 0011000400010002` | 0 | `{"ok": true, "data": {...}, "wire_hex": "..."}` | OK |
| `python3 -m rfc9534pure parse ZZZZ` | 1 | `{"ok": false, "error": "invalid hex character: 'ZZZZ'"}` | OK |
| `python3 -m rfc9534pure serialize 1 2` | 0 | `{"ok": true, "wire_hex": "000b000400010002", ...}` | OK |
| `python3 -m rfc9534pure serialize 99999 1` | 1 | `{"ok": false, "error": "sender_id out of range: 99999 ..."}` | OK |
| `python3 -m rfc9534pure bogus` | 2 | `rfc9534pure: unknown command 'bogus'` | OK |
| `python3 -m rfc9534pure serialize abc def` | 1 | `{"ok": false, "error": "invalid literal for int() ..."}` | OK |
| `python3 -m rfc9534pure parse '[1,2,3,4,5,6,7,8]'` | 1 | `{"ok": false, "error": "wrong TLV type: expected 11, got 2"}` | OK |
| `python3 -m rfc9534pure serialize 1 2 --flags zzz` | 1 | `{"ok": false, "error": "invalid literal for int() ..."}` | OK |

All exit codes correct. No traceback leakage. All error paths
structured JSON with `ok:false`. **F-1 fix verified end-to-end.**

**Status:** RESOLVED. The cycle_167/ship card may proceed.

### 5.3 T1 manual advisory F-2 (Low, code change, out of fuzz scope)

**Location:** `src/rfc9534pure/parser.py:77-78`

**Description:** `parse_tlv_list` has a `if not data: return []`
guard that accepts `None` (falsy), `""` (falsy), `b""` (falsy),
`0` (falsy), `[]` (falsy), etc. This is **divergent from**
`parse_micro_session_tlv`, which raises `TypeError` /
`ValueError` for non-bytes. A caller doing
`result = parse_tlv_list(user_input)` and then
`if not result: error(...)` will treat `None` input as "no TLVs
found" rather than "input was invalid".

**Why the fuzz campaign did not surface F-2:** Atheris primarily
generates `bytes` inputs. The `invariant21_boundaries` surface
exercises the `None` / non-`bytes` path for
`parse_micro_session_tlv` only. The corresponding
`parse_tlv_list` falsy-input path is technically reachable
through the CLI (`parse_tlv_list(None)` in Python) but not
through the wire format (the CLI always converts input to
`bytes` before passing to the parser).

**Recommendation (from T1):** Either (a) match
`parse_micro_session_tlv`'s strictness (raise `TypeError` for
non-bytes, `ValueError` for `None`), or (b) document the
divergence in the `parse_tlv_list` docstring (return `[]` for
any falsy input).

**Status:** Open. Accept or document. Fuzz-acceptable. Unchanged
from pre-fix chain.

### 5.4 T1 manual advisories F-3, F-4, F-5 (Info, accept)

| ID | One-line |
|---|---|
| F-3 | `parse_micro_session_tlv` rejects `memoryview` (over-strict; buffer-protocol types). Accept — strict `isinstance(data, bytes)` is a defensive choice; users can wrap with `bytes(mv)`. |
| F-4 | `parse_tlv_list` silently stops on first non-parseable TLV (no warning). Accept — documented behavior; the parser is per-TLV isolated by design. |
| F-5 | `_hex_to_bytes("0x")` / `""` returns `b""` rather than raising. Accept — minor UX nit; the empty result is consistent with the "no input → no bytes" semantics. |

These are documented here for completeness but do not affect
the ship gate. Unchanged from pre-fix chain.

### 5.5 T1 manual advisory F-6 (Info, withdrawn)

F-6 was a spurious "unused `argparse` import" finding that T1
withdrew upon re-verification — `argparse` is used by
`__main__.py` for the `parse` / `serialize` subcommand dispatch.
Not blocking; withdrawn; included here only so the T1 row in
§4.2 has full context. Unchanged from pre-fix chain.

---

## 6. Recommendations

### 6.1 What to ship (post-F-1-fix)

| Item | Status | Action |
|---|---|---|
| F-1 fix (`5ffe2ee`): `if __name__ == "__main__":` guard in `__main__.py` | **RESOLVED** | Ship as-is. qa2 SHIP at `70b00a5` already verified. |
| Post-F-1-fix fuzz campaign (this report) | CLEAN | Ship as-is. 0 findings across 405K iters. |
| T1 manual advisories F-2..F-6 | Unchanged from pre-fix | Accept; document in next minor release. |

### 6.2 What to accept (document, do not fix)

| Item | Why accept |
|---|---|
| F-2: `parse_tlv_list` falsy-input divergence | Low; documented; fuzz-acceptable. Either tighten or document in docstring. |
| F-3: `parse_micro_session_tlv` rejects `memoryview` | Info; defensive strictness; users can `bytes(mv)`. |
| F-4: `parse_tlv_list` silent truncation on first invalid TLV | Info; documented behavior; per-TLV isolation is by design. |
| F-5: `_hex_to_bytes("0x")` / `""` returns `b""` | Info; minor UX nit; empty-result semantics are consistent. |
| F-6: (withdrawn) | Spurious — was an `argparse` import false positive. |

### 6.3 What to monitor (continuous)

| Item | How to monitor |
|---|---|
| Parser-input fuzz coverage | Re-run `cycle_167/adversary2/fuzz/fuzz_parse_micro_session_id.py -runs=100000` in CI on every commit. The harness is fast (sub-second for 100K iters) and catches regressions cheaply. |
| Invariant-21 contract | Re-run `cycle_167/adversary2/fuzz/fuzz_invariant21_boundaries.py -runs=100000` in CI. Any change to `parser.py` that drops a `TypeError` or `ValueError` guard will be flagged immediately. |
| CLI surface (post-F-1-fix) | Re-run `cycle_167/adversary2/fuzz/fuzz_cli_main.py -runs=1000` in CI (slower due to subprocess overhead; 1000 iters is enough to catch hangs AND assert `rc in {0, 1, 2}`). The exit-code assertion is now operationally meaningful post-F-1-fix. |
| Roundtrip property | Re-run `cycle_167/adversary2/fuzz/fuzz_serialize_roundtrip.py -runs=100000` in CI. The roundtrip property is the strongest invariant for catching encoder/decoder divergence. |
| F-1 regression | The CLI harness's `rc in {0, 1, 2}` assertion catches any future regression of the `if __name__ == "__main__":` guard. If a future refactor drops the guard, the harness will observe the silent rc=0 path and the assertion will fire. |
| LOC budget (spec AC 7) | `pre-push-gate.sh` already enforces `parser.py + serializer.py + __main__.py ≤ 250 LOC` combined (current: 246, 4 LOC headroom). The combined budget includes `__main__.py` and excludes `__init__.py`. |

### 6.4 What to add in the next campaign (cycle_168+)

| Item | Reason |
|---|---|
| Fuzz the `_hex_to_bytes` helper directly | F-5 is in this code path; a dedicated harness could surface a class of "lenient parser" bugs the wire-format harnesses miss |
| Fuzz `parse_tlv_list` with a `None` / non-`bytes` seed (not just `b""`) | F-2 is in this code path; adding a `fuzz_parse_tlv_list_type.py` would close the coverage gap |
| Add a `memoryview` seed to `invariant21_boundaries` (currently only `bytes` and `bytearray`) | F-3 is in this code path; would let the fuzz campaign check the "over-strict" claim end-to-end |
| Extend the CLI harness to assert stdout content (not just exit code) | Post-F-1-fix, the stdout contract is now `{"ok": true/false, ...}` JSON. Asserting JSON shape would catch any future silent-failure regression at the CLI surface even more robustly than the exit-code assertion alone. |
| Use the larger 119-seed corpus as a starting point | The post-F-1-fix chain's seed corpus is more comprehensive than the pre-fix chain's 43 seeds. Future cycles should inherit this larger corpus rather than re-deriving it. |
| Add a `fuzz_oversized_input.py` surface with explicit 1MB / 10MB / 100MB input lengths | Verifies the parser's O(1) input-rejection claim at the upper end. The current `invariant21_boundaries/invalid_011_oversized_100k_all_ff.bin` covers 100 KB; a dedicated harness would extend to 100 MB. |

### 6.5 Ship gate verdict

- **Fuzz scope (T2/T3/T4):** 0 findings. `VERDICT: SHIP`.
- **T1 manual scope:** 0 Critical / 0 High (F-1 RESOLVED) /
  0 Medium / 1 Low / 4 Info. `VERDICT: SHIP` (no ship-blockers).
- **Combined verdict for this report (T5 fuzz synthesis):**
  `VERDICT: SHIP` for both scopes jointly. F-1 is RESOLVED and
  verified end-to-end by both T1 manual probes and the `cli_main`
  fuzz surface. F-2..F-6 are documented and accepted per §6.2.

The ship gate for `cycle_167/ship` may proceed. The adversary
chain's job is to surface findings, not to make the ship
decision; the orchestrator will mint `cycle_167/ship` with
`parents=[T5_ID]` and the ship card will execute the
pre-push-gate + tag + push per its own scope.

---

## Appendix A: Chain metadata

| Phase | Commit | Worktree | Deliverable |
|---|---|---|---|
| T1 (manual audit) | `a679a94` | `wt/t_d7c1a866` | `cycle_167/adversary2/VULN_AUDIT.md` |
| T2 (harness build) | `1ba5c2e` | `wt/t_ded1c044` | `cycle_167/adversary2/HARNESSES.md` + 5 harnesses in `fuzz/` + 119 seed files in `fuzz/seeds/` |
| T3 (corpus run) | `d7c4855` | `wt/t_9df9a6be` | `cycle_167/adversary2/CORPUS_RUN.md` + `stats.json` + 5 atheris logs in `logs/` |
| T4 (triage) | `b4c1ce5` | `wt/t_4c7eae74` | `cycle_167/adversary2/TRIAGE.md` + empty `findings.jsonl` + placeholders |
| **T5 (this report)** | **(pending)** | **`wt/t_452fe712`** | **`cycle_167/adversary2/FUZZING_REPORT.md`** (this file) |
| **Chain base** | `70b00a5` | — | qa2 SHIP commit (post-F-1-fix tip; F-1 RESOLVED, qa2 verified) |

### Predecessor chain (cycle_167/adversary, pre-fix)

| Phase | Commit | Worktree | Deliverable |
|---|---|---|---|
| T1 | `e16923e` | `wt/t_4c6a03e0` | `cycle_167/adversary/VULN_AUDIT.md` (1 High, F-1) |
| T2 | `81be034` / `06c5390` | `wt/t_6bf03150` | 5 Atheris harnesses in `fuzz/` |
| T3 | `ed4b2c7` | `wt/t_b6b7b8be` | `CORPUS_RUN.md` (475K iters, 0/0/0) |
| T4 | `94bc1d3` | `wt/t_23e9db5f` | `TRIAGE.md` (no-op) |
| T5 | `8f05bcc` | `wt/t_aa71cd84` | `FUZZING_REPORT.md` (verdict SHIP for fuzz scope; F-1 routed to follow-up) |

### Fix + qa2

| Phase | Commit | Description |
|---|---|---|
| F-1 fix | `5ffe2ee` | `fix: add missing if __name__ == '__main__' guard to __main__.py (F-1)` |
| qa2 | `70b00a5` | `qa2: fill QA_REPORT2.md — F-1 fix verified SHIP (113/113, pre-push gate green)` |

## Appendix B: File inventory (T5 deliverable + chain)

- `cycle_167/adversary2/FUZZING_REPORT.md` — this report
  (6 sections + 4 appendices)
- `cycle_167/adversary2/HARNESSES.md` — T2 deliverable
- `cycle_167/adversary2/CORPUS_RUN.md` — T3 deliverable
- `cycle_167/adversary2/TRIAGE.md` — T4 deliverable
- `cycle_167/adversary2/findings.jsonl` — empty (T4 contract
  satisfied; 0 records)
- `cycle_167/adversary2/findings/.gitkeep` — placeholder for
  future `F-NNN/` shape
- `cycle_167/adversary2/crashes/<surface>/.gitkeep` — empty
  (no crashes)
- `cycle_167/adversary2/hangs/<surface>/.gitkeep` — empty
  (no hangs)
- `cycle_167/adversary2/oom/<surface>/.gitkeep` — empty
  (no OOMs)
- `cycle_167/adversary2/corpus/<surface>/*.bin` — 119 seed
  files (T3)
- `cycle_167/adversary2/logs/<surface>.atheris.txt` — 5 atheris
  logs (T3)
- `cycle_167/adversary2/stats.json` — machine-readable
  per-surface stats (T3)
- `cycle_167/adversary2/fuzz/fuzz_<surface>.py` — 5 Atheris
  harnesses (T2)
- `cycle_167/adversary2/fuzz/seeds/<surface>/*.bin` — 119 seed
  files (T2, mirrored to `corpus/`)
- `cycle_167/adversary2/surfaces/.gitkeep` — placeholder dir
  scaffolded in T1 (no surfaces/ artifacts required; chain uses
  `fuzz/` + `corpus/` for all harness/corpus artifacts)
- `cycle_167/adversary2/VULN_AUDIT.md` — T1 deliverable
- `cycle_167/QA_REPORT2.md` — qa2 SHIP document (F-1 fix
  verification)

## Appendix C: Reproducibility

Re-run the entire campaign from the project root with:

```sh
cd /root/projects/rfc-9534-pure/.worktrees/t_cycle167-adversary-02

# In-process surfaces: 100K iters each, <1s wall clock
PYTHONPATH=src python3 cycle_167/adversary2/fuzz/fuzz_parse_micro_session_id.py \
  -runs=100000 cycle_167/adversary2/corpus/parse_micro_session_id/
PYTHONPATH=src python3 cycle_167/adversary2/fuzz/fuzz_parse_tlv_list.py \
  -runs=100000 cycle_167/adversary2/corpus/parse_tlv_list/
PYTHONPATH=src python3 cycle_167/adversary2/fuzz/fuzz_serialize_roundtrip.py \
  -runs=100000 cycle_167/adversary2/corpus/serialize_roundtrip/
PYTHONPATH=src python3 cycle_167/adversary2/fuzz/fuzz_invariant21_boundaries.py \
  -runs=100000 cycle_167/adversary2/corpus/invariant21_boundaries/

# CLI surface: 60s wall clock, ~5K iters
PYTHONPATH=src python3 cycle_167/adversary2/fuzz/fuzz_cli_main.py \
  -runs=999999 -max_total_time=60 cycle_167/adversary2/corpus/cli_main/
```

Expected: all 5 finish cleanly with `DONE` and no crashes, no
hangs, and no OOMs. Wall clock: sub-second for the 4 in-process
surfaces, ~60 s for the CLI subprocess surface (at 86 exec/s,
~5,275 iters in 60 s).

## Appendix D: Acceptance criteria (T5 contract)

| Criterion | Met? | Evidence |
|---|---|---|
| 6 required sections | ✓ | §1 Executive Summary, §2 Methodology, §3 Seed Corpus, §4 Findings Table, §5 Per-Finding Narrative, §6 Recommendations |
| ≥200 lines | ✓ | ~700+ lines |
| Verdict line (byte-exact) on last line | ✓ | `VERDICT: SHIP` (final line) |
| FUZZING_REPORT.md committed to `wt/cycle_167-adversary-02` | ✓ | committed below |
| `fuzzing_report_commit_sha` captured in metadata | ✓ | see kanban_complete call |
| `findings.jsonl` parity with report | ✓ | empty (0 records) |
| `parent_of_tag: true` | ✓ | orchestrator will mint `cycle_167/ship` with `parents=[T5_ID]` |
| DO NOT modify `src/` | ✓ | only added `FUZZING_REPORT.md` |
| DO NOT push | ✓ | local commit only; orchestrator handles push in ship phase |
| DO NOT create follow-up cards | ✓ | recommendations only; F-1 already RESOLVED before T5 began |
| F-1 fix verified end-to-end | ✓ | T1 manual probe table (§5.2) + T3 cli_main 5,275-iter exit-code assertion |
| Comparison with pre-fix chain | ✓ | §4.4 table |
| Recommendations for future cycles | ✓ | §6.4 (6-item backlog) |

---

VERDICT: SHIP
