# RFC 9534 — STAMP LAG Micro-session ID TLV

## RFC 9534 Summary

**Title:** Simple Two-Way Active Measurement Protocol Extensions for Performance Measurement on a Link Aggregation Group

**What it does:** Extends STAMP (RFC 8762) with a Micro-session ID TLV (Type=11) to identify individual LAG member links in STAMP test packets.

**TLV Format (8 octets total):**
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|STAMP TLV Flags|  Type = 11    |           Length = 4        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Sender Micro-session ID   |   Reflector Micro-session ID  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **STAMP TLV Flags:** 1 octet (U=M=R=0 for this TLV, per RFC 8972)
- **Type:** 1 octet, value 11 (IANA assigned)
- **Length:** 2 octets, big-endian, MUST be 4
- **Sender Micro-session ID:** 2 octets, big-endian, LAG member link ID at sender side
- **Reflector Micro-session ID:** 2 octets, big-endian, LAG member link ID at reflector side

**STAMP TLV Flags (per RFC 8972 §4):**
- U (Unrecognized): 1 bit — MUST be 0 for recognized TLVs
- M (More): 1 bit — more TLVs follow
- I (Integrity): 1 bit — Integrity check applied
- R (Reserved): 5 bits — MUST be 0

**Total TLV wire length:** 4 (header) + Length (4) = 8 octets

## 8 Acceptance Criteria

1. `parse_micro_session_tlv(data)` — given a byte string, returns dict with sender_id, reflector_id, flags, parsed_length. Raises `ValueError` for invalid TLV (wrong type, length ≠ 4, short data).
2. `serialize_micro_session_tlv(sender_id, reflector_id, flags=0)` — returns 8-byte serialized TLV. Raises `ValueError` for out-of-range IDs (>65535) or invalid flags.
3. Round-trip: `parse(serialize(s, r)) == {sender_id: s, reflector_id: r, ...}`.
4. CLI `parse` subcommand: accepts hex string or JSON bytes input, outputs JSON.
5. CLI `serialize` subcommand: accepts sender_id and reflector_id, outputs hex.
6. Total function (no uncaught exceptions): handles None, empty bytes, short buffer, type≠11, length≠4, out-of-range IDs.
7. LOC budget: parser.py + serializer.py + __main__.py ≤ 250 LOC combined.
8. 100+ tests covering all ACs and edge cases.

## Out of Scope

- Full STAMP packet parsing (only the Micro-session ID TLV)
- Authentication/HMAC TLVs
- Sub-TLV nesting (not used in Micro-session ID TLV)
- Network I/O
- Any non-stdlib imports
