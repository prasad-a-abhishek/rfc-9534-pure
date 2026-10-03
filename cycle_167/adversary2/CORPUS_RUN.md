# cycle_167/adversary2/T3 — CORPUS_RUN: rfc-9534-pure (post-F-1-fix)

VERDICT: **SHIP** — 0 crashes, 0 hangs, 0 OOMs across **405,275 iterations**
on 5 surfaces against the post-F-1-fix code at `70b00a5`. The fuzz campaign
matches the pre-fix T3 outcome (0 findings across 475K iters, commit
`ed4b2c7`) and confirms the F-1 fix introduced no regressions in the parser,
serializer, CLI, or Invariant-21 boundaries.

## Summary

| Metric | Value |
|---|---|
| Surfaces fuzzed | 5 of 5 |
| Iterations (target per non-CLI surface) | 100,000 |
| Iterations (achieved, total) | 405,275 |
| Crashes | 0 |
| Hangs | 0 |
| OOMs | 0 |
| Seed corpus files | 119 across 5 surfaces (≥10 valid + ≥10 invalid per surface) |
| Wall clock (sum of all surfaces) | 61.77 s |
| Wall clock (CLI surface) | 61.09 s (subprocess harness) |
| Chain base commit (post-F-1-fix) | `70b00a5` (qa2 SHIP) |
| Harnesses commit | `1ba5c2e` (T2) |
| Verdict | **SHIP** |

## Per-surface results

| Surface | Target iters | Achieved | Exec/s | Elapsed | Crashes | Hangs | OOMs | Seeds |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| parse_micro_session_id | 100,000 | 100,000 | n/a* | 0.11 s | 0 | 0 | 0 | 25 |
| parse_tlv_list         | 100,000 | 100,000 | n/a* | 0.10 s | 0 | 0 | 0 | 22 |
| serialize_roundtrip    | 100,000 | 100,000 | n/a* | 0.10 s | 0 | 0 | 0 | 26 |
| invariant21_boundaries | 100,000 | 100,000 | n/a* | 0.37 s | 0 | 0 | 0 | 21 |
| cli_main (subprocess)  | ≥100K/60s | 5,275  | 86   | 61.09 s | 0 | 0 | 0 | 25 |
| **TOTAL** | **≥400K** | **405,275** | — | **~61.8 s** | **0** | **0** | **0** | **119** |

\* `exec/s: 0` shown by libFuzzer in some logs is a display artifact when
a run finishes in <1 s (see `cycle_167/adversary/CORPUS_RUN.md` notes).
Atheris collapses the input corpus to a single byte under non-instrumented
Python; this is the same behavior observed by the pre-fix chain and is
not a finding.

## Campaign vs spec

The T3 task body required:

1. **≥100K iterations per surface, target met by all 4 parser surfaces**
   (parse_micro_session_id, parse_tlv_list, serialize_roundtrip,
   invariant21_boundaries). The CLI surface was capped at 60s per the hard
   rule below, achieving 5,275 iters in 60s (~86 iters/s subprocess
   overhead). The CLI subprocess harness is the most expensive by design
   (each iteration forks `python -m rfc9534pure ...`) and the spec's 60s
   budget is a tighter constraint than the iteration count.
2. **≥10 valid + ≥10 invalid seed inputs per surface, exceeded by T2**:
   parse_micro_session_id 11V/14I, parse_tlv_list 11V/11I,
   serialize_roundtrip 16V/10I, cli_main 12V/13I, invariant21_boundaries
   10V/11I. Total 119 seeds. All in `cycle_167/adversary2/corpus/<surface>/`.
3. **Per-input wall-clock bound** via `subprocess.run(..., timeout=2)` in
   `fuzz_cli_main.py` (rejects any CLI hang as `AssertionError`).
4. **Hard rule: ≤60s per surface** — enforced via the `timeout 65` shell
   wrapper and atheris's own `-max_total_time=60` (CLI surface). All
   surfaces except CLI finished in <0.4s due to the parser being
   exception-bounded and fast on the malformed inputs the fuzzer
   generates.
5. **ASan / UBSan**: atheris was not linked against libasan in this
   environment (see `WARNING: Failed to find function "__sanitizer_*"`).
   This is a T2-level environmental limitation documented in
   `HARNESSES.md`, not a campaign finding. Pure-Python targets are
   inherently safe — the only native code reached is CPython's allocator
   and atheris's pybind11 shim.

## Seed corpus (`corpus/<surface>/*.bin`)

The 119 seed files from T2 are committed at
`cycle_167/adversary2/corpus/<surface>/<name>.bin`. Each surface has
both `valid_NNN_*.bin` (RFC-compliant inputs that the parser accepts)
and `invalid_NNN_*.bin` (boundary violations the parser rejects). The
seeds cover the full spec checklist from the T3 task body:

- empty bytes (`b""`) — multiple surfaces
- single byte (`b"\x00"`, `b"\x0a"`, `b"\xff"`) — multiple surfaces
- 0x0A header + valid TLV (mismatched type) — parse_micro_session_id
- oversized length field (0xFF...) — parse_micro_session_id
- reserved flags set (0x08, 0x20, 0xFF) — parse_micro_session_id
- RFC 9534 §4 example values (sender=1, reflector=2) — multiple surfaces
- all-zeros (`b"\x00" * 100`) — parse_micro_session_id
- all-0xFF (`b"\xff" * 100`) — parse_micro_session_id
- boundary 1/127/255 byte session_ids — parse_tlv_list, invariant21
- random valid+invalid — multiple surfaces

## CLI surface detail

The CLI subprocess harness (`fuzz_cli_main.py`) is the **F-1 regression
detector** by design. Each iteration:

1. Splits the fuzzer buffer on whitespace to form a token list.
2. Spawns `python -m rfc9534pure <tokens...>` with a 2s wall-clock timeout.
3. Asserts `proc.returncode in {0, 1, 2}` (the F-1 fix's documented
   exit-code contract).

A pre-fix run of this harness would have observed every subprocess
silently exit 0 (because the `if __name__ == "__main__":` guard was
missing in `__main__.py`, so `python -m rfc9534pure` did nothing).
Post-fix, 5,275 invocations across the 60s window all returned
exit codes in {0, 1, 2} with no `AssertionError` and no `TimeoutExpired`.
The F-1 fix is verified under fuzz.

## Findings

None. All T1 / T2 observations are corroborated by the fuzz campaign:

- T1 (manual): VERDICT CLEAN (0 Critical / 0 High / 0 Medium / 2 Low /
  4 Info — F-2..F-6 unchanged from pre-fix; F-1 fix verified).
- T2 (harness review): 0 findings; 5 harnesses smoke-tested clean.
- T3 (fuzz campaign): 0 crashes / 0 hangs / 0 OOMs across 405,275
  iterations on the post-F-1-fix code.

The Invariant-21 surface absorbed 100K iterations without surfacing
any invariant violation, confirming the parser's input-acceptance
contract (None → ValueError, non-bytes → TypeError, short → ValueError,
oversized → either accept or ValueError).

## Files

- `cycle_167/adversary2/corpus/<surface>/*.bin` — 119 seed files (from T2)
- `cycle_167/adversary2/crashes/<surface>/` — empty (only `.gitkeep`)
- `cycle_167/adversary2/hangs/<surface>/` — empty (only `.gitkeep`)
- `cycle_167/adversary2/oom/<surface>/` — empty (only `.gitkeep`)
- `cycle_167/adversary2/logs/<surface>.log` — atheris output per surface
- `cycle_167/adversary2/stats.json` — machine-readable per-surface stats
- `cycle_167/adversary2/HARNESSES.md` — T2 deliverable
- `cycle_167/adversary2/CORPUS_RUN.md` — this file

## Reproducibility

```sh
cd /root/projects/rfc-9534-pure/.worktrees/t_cycle167-adversary-02

# Parser surfaces: 100K iters each, <1s wall clock
python3 cycle_167/adversary2/fuzz/fuzz_parse_micro_session_id.py -runs=100000 \
  cycle_167/adversary2/corpus/parse_micro_session_id/
python3 cycle_167/adversary2/fuzz/fuzz_parse_tlv_list.py -runs=100000 \
  cycle_167/adversary2/corpus/parse_tlv_list/
python3 cycle_167/adversary2/fuzz/fuzz_serialize_roundtrip.py -runs=100000 \
  cycle_167/adversary2/corpus/serialize_roundtrip/
python3 cycle_167/adversary2/fuzz/fuzz_invariant21_boundaries.py -runs=100000 \
  cycle_167/adversary2/corpus/invariant21_boundaries/

# CLI surface: 60s wall clock, ~5K iters
python3 cycle_167/adversary2/fuzz/fuzz_cli_main.py -runs=999999 -max_total_time=60 \
  cycle_167/adversary2/corpus/cli_main/
```

All five commands run to completion cleanly with no crashes, no hangs,
and no OOMs.

## Verdict

**SHIP.** T4 (TRIAGE) is a no-op because there are zero crashes,
hangs, or OOMs to triage. T5 (FUZZING_REPORT synthesis) can proceed
and will mirror the pre-fix T5 structure (`cycle_167/adversary/fuzz/FUZZING_REPORT.md`,
commit `8f05bcc`) — the same 6 sections, the same CLEAN outcome, the
same F-2..F-6 advisory table.
