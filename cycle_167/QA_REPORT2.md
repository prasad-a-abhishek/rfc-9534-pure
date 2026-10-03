# QA Report — rfc-9534-pure v0.1.0 (cycle_167/qa2 post-fix re-verification)

## Summary
Re-verification of the F-1 (__main__ guard) fix on branch `wt/t_5f6770e1` at commit
`5ffe2ee`. The 2-line `if __name__ == "__main__": sys.exit(main())` guard is correctly
applied at the end of `src/rfc9534pure/__main__.py`. All 113 tests pass, the pre-push
gate returns VERDICT:SHIP, the CLI smoke for `python -m rfc9534pure` returns rc=2 with
the expected usage string, and import of the package produces zero stdout/stderr.
No regressions introduced. Zero new dependencies.

## F-1 Fix Verification

### Fix applied correctly
- `src/rfc9534pure/__main__.py` last 4 lines:
  ```
  if __name__ == "__main__":
      sys.exit(main())
  ```
- File: `src/rfc9534pure/__main__.py:109-110`
- Commit: `5ffe2ee6d5d4a58dd069e8aa4f686f27745c8422`
- Message: "fix: add missing if __name__ == '__main__' guard to __main__.py (F-1)"
- Honest, names the fix — meets commit message standard.

## Test Results
- Tests total: 113 (collected)
- Tests passed: 113 (100%)
- Tests failed: 0
- Coverage gaps: None — fix is purely a CLI entry-point guard; no new logic introduced.

## Adversarial Findings

### Critical (block SHIP): 0

### High: 0 — F-1 is resolved.

### Medium / Low: 0

## Spec Compliance (all acceptance criteria)

- [x] AC-1: F-1 fix applied correctly — last 4 lines of `__main__.py` are the guard.
- [x] AC-2: No regression — 113/113 pytest pass (same count as pre-fix baseline).
- [x] AC-3: CLI smoke:
  - `python -m rfc9534pure` (no args) → rc=2, usage on stdout (F-1 BUG FIXED).
  - `python -m rfc9534pure serialize 0 65535` → parses and prints JSON (rc=0).
  - Import guard verified: `import rfc9534pure` produces zero stdout/stderr (pre-push gate "Import sanity check: OK").
- [x] AC-4: Adversary artifacts: branch is `wt/t_5f6770e1` based on the QA commit (3923c89).
- [x] AC-5: Pre-push gate: `./pre-push-gate.sh` returns 0 with "VERDICT: SHIP".
- [x] AC-6: LOC budget: 298 total project LOC (≤250 for src/ only — src/ is 236, within budget).
- [x] AC-7: Commit message honest: names the F-1 fix, not a test-count boast.

## Contract Checks

- **Zero dependencies**: `pyproject.toml` confirms `dependencies = []`.
- **Test floor ≥100**: 113 tests, same as pre-fix.
- **Invariant 21 (exception safety)**: import is silent — guard prevents main() side-effects.
- **Invariant 16 README architecture**: unchanged.
- **No scratch/debug files**: repo root is clean (only project files).
- **No test edits**: no test changes on this branch.

## Smoke Verification

- [x] `pip install -e .` — works (pre-push gate runs it implicitly)
- [x] `pytest -v` — 113/113 green
- [x] `python -m rfc9534pure --help` → rc=0 + usage string
- [x] `python -m rfc9534pure` (no args) → rc=2 + usage string
- [x] `python -m rfc9534pure serialize 0 65535` → valid JSON output, rc=0
- [x] `python -m rfc9534pure parse 0b000b00040000ffff` → valid JSON output, rc=0
- [x] `import rfc9534pure` → silent, rc=0
- [x] No files committed outside project scope
- [x] README install instructions functional

## Secret Scan
```
git grep -E "(ghp_|pypi-AgEI|npm_|sk-|AKIA|Bearer ey|BEGIN PRIVATE KEY)" . --no-ignore
→ CLEAN (no secrets found)
```

## F-1 Regression Confirm
The original F-1 bug was: `python -m rfc9534pure` (no args) would import the module and
silently exit rc=0 without calling `main()` because the `__main__.py` had no guard.
Post-fix behavior:
```
$ python -m rfc9534pure
usage: rfc9534pure <parse|serialize> ...
  parse <hex|JSON> [--compact]
  serialize <sender_id> <reflector_id> [--flags N] [--compact]
EXIT_CODE=2
```
This is correct — rc=2 (usage error) with the expected help text. F-1 is confirmed
remediated.

## Risk Callouts
- None. The fix is a minimal 2-line defensive guard that only fires when the module
  is executed as `__main__`, with zero impact on import behavior.

---

VERDICT: SHIP
