# rfc9534-pure

**RFC 9534 STAMP LAG Micro-session ID TLV parser and serializer** — pure Python stdlib, zero dependencies.

> Parse and serialize RFC 9534 Micro-session ID TLVs (Type=11) used in STAMP extensions for Link Aggregation Group (LAG) member-link performance measurement.

[![PyPI version](https://img.shields.io/pypi/v/rfc9534pure.svg)](https://pypi.org/project/rfc9534pure/)
[![Python](https://img.shields.io/pypi/pyversions/rfc9534pure.svg)](https://pypi.org/project/rfc9534pure/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Quick Start

```bash
pip install rfc9534pure
```

```python
from rfc9534pure import parse_micro_session_tlv, serialize_micro_session_tlv

# Parse a Micro-session ID TLV
data = bytes.fromhex("000b000400010002")
tlv = parse_micro_session_tlv(data)
print(tlv.sender_id)    # 1
print(tlv.reflector_id)  # 2

# Serialize a Micro-session ID TLV
data = serialize_micro_session_tlv(sender_id=1, reflector_id=2)
print(data.hex())  # "000b000400010002"
```

CLI:

```bash
rfc9534pure parse 000b000400010002
rfc9534pure serialize 1 2
```

## Why rfc9534-pure?

Network engineers and DevOps practitioners debugging LAG member-link performance in serverless or edge Python environments need a zero-dependency parser and serializer they can vendor or install without pulling in transitive libraries. Existing RFC-parser repos are missing or niche in this specific RFC 9534 TLV space. This package does exactly one thing — the Micro-session ID TLV — with no external imports beyond the Python standard library.

## Key Features

- **Pure stdlib** — `dependencies = []` in `pyproject.toml`; no third-party imports
- **RFC 9534 compliant** — Micro-session ID TLV (Type=11), big-endian byte order
- **Total functions** — all public APIs handle `None`, empty bytes, malformed input, out-of-range IDs without raising uncaught exceptions
- **CLI + library** — both `parse` and `serialize` subcommands via `python -m rfc9534pure`
- **Comprehensive tests** — 113 tests covering happy path, edge cases, error paths, and RFC compliance

## CLI Reference

```
rfc9534pure <command> ...

Commands:
  parse <hex|JSON> [--compact]
    Parse a Micro-session ID TLV from hex string or JSON byte array.
    Output: JSON with ok, data (tlv_type, flags, sender_id, reflector_id, parsed_length), wire_hex

  serialize <sender_id> <reflector_id> [--flags N] [--compact]
    Serialize sender_id and reflector_id to a Micro-session ID TLV.
    Output: JSON with ok, wire_hex, wire_bytes, sender_id, reflector_id, flags

Global flags:
  --compact  Output compact JSON (no indentation)
```

## Library API Reference

### `parse_micro_session_tlv(data: bytes) -> MicroSessionIDTLV`

Parse an RFC 9534 Micro-session ID TLV from raw bytes.

| Parameter | Type | Description |
|-----------|------|-------------|
| `data` | `bytes` | Raw TLV bytes (at least 8 bytes) |

**Returns:** `MicroSessionIDTLV` with `.flags`, `.sender_id`, `.reflector_id`, `.parsed_length`

**Raises:** `ValueError` (wrong type, length≠4, short data, reserved flags set), `TypeError` (not bytes)

### `serialize_micro_session_tlv(sender_id: int, reflector_id: int, flags: int = 0) -> bytes`

Serialize sender and reflector IDs to an RFC 9534 Micro-session ID TLV.

| Parameter | Type | Description |
|-----------|------|-------------|
| `sender_id` | `int` | LAG member link ID at sender side (0-65535) |
| `reflector_id` | `int` | LAG member link ID at reflector side (0-65535) |
| `flags` | `int` | STAMP TLV flags byte (default 0) |

**Returns:** 8-byte serialized TLV

**Raises:** `ValueError` (out-of-range ID, reserved flags set), `TypeError` (non-integer argument)

### `parse_tlv_list(data: bytes) -> list[MicroSessionIDTLV]`

Parse a concatenated series of Micro-session ID TLVs from a buffer.

### `serialize_tlv_list(tlvs: list) -> bytes`

Serialize a list of `MicroSessionIDTLV` objects to concatenated bytes.

### `MicroSessionIDTLV`

Parsed TLV container with `__slots__`:

| Attribute | Type | Description |
|-----------|------|-------------|
| `.flags` | `int` | STAMP TLV flags byte |
| `.sender_id` | `int` | Sender LAG member link ID (0-65535) |
| `.reflector_id` | `int` | Reflector LAG member link ID (0-65535) |
| `.parsed_length` | `int` | Total wire length (always 8) |
| `.to_dict()` | `dict` | Dict representation |

## Limitations

- Only the Micro-session ID TLV (Type=11) is supported; other STAMP TLVs (e.g., HMAC, Follow-Up Telemetry) are not parsed
- No sub-TLV nesting support (not used in the Micro-session ID TLV per RFC 9534)
- No network I/O or full STAMP packet parsing — only the 8-byte Micro-session ID TLV
- CLI requires Python 3.8+

## Non-Goals

- Full STAMP packet construction or validation
- HMAC or authentication TLV handling
- Network socket communication
- Integration with other RFC 8972 TLV types beyond Micro-session ID

## Performance & Benchmarks

See [`benchmarks/BENCHMARK.md`](benchmarks/BENCHMARK.md) for 50-iteration head-to-head benchmarks.

## License

MIT License. See [LICENSE](LICENSE).
