#!/usr/bin/env bash
# pre-push gate — runs before every git push
set -e

echo "=== Pre-push gate: rfc9534-pure ==="

cd "$(dirname "$0")/.."

echo "--- pytest (113 tests) ---"
python3 -m pytest tests/ -v --tb=short

echo "--- CLI smoke: parse ---"
python3 -m rfc9534pure parse 000b000400010002 > /dev/null

echo "--- CLI smoke: serialize ---"
python3 -m rfc9534pure serialize 1 2 > /dev/null

echo "--- LOC budget check (≤250 LOC) ---"
LOC=$(python3 -c "
import pathlib, tokenize, io
total = 0
for f in pathlib.Path('src/rfc9534pure').glob('*.py'):
    with io.open(f, 'rb') as fh:
        total += sum(1 for _ in tokenize.open(fh) if _.type not in (tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.ENCODING))
print(total)
")
echo "Source LOC: $LOC"
if [ "$LOC" -gt 250 ]; then
    echo "FAIL: Source LOC $LOC > 250 budget"
    exit 1
fi

echo "--- Import sanity check ---"
python3 -c "from rfc9534pure import parse_micro_session_tlv, serialize_micro_session_tlv, parse_tlv_list, serialize_tlv_list, MicroSessionIDTLV, MICRO_SESSION_TLV_TYPE, EXPECTED_VALUE_LENGTH, WIRE_LENGTH; print('OK')"

echo "--- secret scan ---"
! grep -rE "(ghp_|pypi-AgEI|npm_|sk-|AKIA|Bearer ey|BEGIN PRIVATE KEY)" src/ tests/ || exit 1

echo "=== ALL GATES PASSED ==="
