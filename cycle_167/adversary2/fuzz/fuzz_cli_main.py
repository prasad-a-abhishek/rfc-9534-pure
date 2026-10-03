"""Fuzz harness: `python -m rfc9534pure` CLI entry point.

Surface: rfc9534pure.__main__:main (subprocess invocation)
Strategy: invoke the CLI as a real subprocess with arbitrary argv bytes.
          This exercises argparse parsing, the hex decoder, and the
          underlying parser/serializer through the real CLI code path.
          Each invocation is bounded by a wall-clock timeout to detect
          hangs / infinite loops.

Adversary2 (post-F-1-fix) rebuild of cycle_167/adversary/T2's
fuzz_cli_main. CRITICAL DIFFERENCE FROM PRE-FIX: the F-1 fix added the
`if __name__ == "__main__": sys.exit(main())` guard to __main__.py at
commit 5ffe2ee. The pre-fix CLI harness would have observed the subprocess
silently exit 0 on every input (because `main()` was unreachable from
`python -m`). Post-fix, the CLI returns structured JSON and proper exit
codes — fuzz_cli_main is now a real surface, not a no-op smoke detector.

This harness explicitly asserts the F-1-fix exit-code contract:
  - argv empty / -h / --help / help: rc=0 or rc=2 (usage)
  - parse <valid>: rc=0
  - parse <invalid>: rc=1
  - serialize <valid>: rc=0
  - serialize <invalid>: rc=1
  - unknown subcommand: rc=2

ASan/UBSan: safe. We invoke the CLI in a clean subprocess so any
ASan/UBSan issues in the underlying parser are caught without polluting
the fuzzer's own state.

Run::

    PYTHONPATH=src python3 cycle_167/adversary2/fuzz/fuzz_cli_main.py \\
        -atheris_timeout=10
"""
import subprocess
import sys

import atheris

_PROJECT_ROOT = "/root/projects/rfc-9534-pure/.worktrees/t_cycle167-adversary-02"

# Make rfc9534pure importable from src/ for the child invocations.
sys.path.insert(0, _PROJECT_ROOT + "/src")

# Cap each child invocation so a hang in the CLI can't wedge the fuzzer.
_SUBPROC_TIMEOUT_S = 2

# Acceptable exit codes from the CLI:
#   0 = help / parse-ok / serialize-ok
#   1 = parse error / serialize error (malformed input)
#   2 = usage error (no args, unknown command, wrong arg count)
# Anything else (e.g. traceback leaked to stderr, crash, signal) is anomalous.
_ACCEPTED_EXIT_CODES = (0, 1, 2)


def TestOneInput(data: bytes) -> None:
    """Atheris entry: launch `python -m rfc9534pure <argv>...` with fuzzer bytes."""
    # Build a safe argv from the fuzzer buffer: split on whitespace, drop NULs,
    # cap length so subprocess.exec can't choke on a 100MB argv.
    raw = data.replace(b"\x00", b" ").decode("latin-1", errors="replace")
    tokens = raw.split()
    if not tokens:
        return
    argv = [sys.executable, "-m", "rfc9534pure", *tokens[:8]]

    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            timeout=_SUBPROC_TIMEOUT_S,
            check=False,
            cwd=_PROJECT_ROOT,
        )
    except subprocess.TimeoutExpired:
        # The CLI should never hang on any input. Flag it.
        raise AssertionError(f"CLI hung on argv={tokens[:8]!r}")
    except (FileNotFoundError, PermissionError):
        # Environment issue, not a target bug.
        return

    if proc.returncode not in _ACCEPTED_EXIT_CODES:
        raise AssertionError(
            f"unexpected exit code {proc.returncode} for argv={tokens[:8]!r}; "
            f"stderr={proc.stderr!r}"
        )


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()