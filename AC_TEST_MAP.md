# RFC 9534 Pure — Acceptance Criterion Test Coverage Map

| # | Acceptance Criterion | Test(s) |
|---|---|---|
| 1 | Parse valid Type=11 TLV | `test_parse_minimal_tlv`, `test_parse_basic`, `test_parse_roundtrip`, `test_parse_tlv_list_single`, `test_parse_tlv_list_multiple` |
| 2 | Serialize Type=11 TLV | `test_serialize_basic`, `test_serialize_roundtrip`, `test_serialize_zeros`, `test_serialize_max_ids`, `test_serialize_flags` |
| 3 | Parse wrong TLV type → error | `test_cli_parse_wrong_type`, `test_parse_tlv_list_invalid_second_tlv` |
| 4 | Parse truncated data → error | `test_parse_short_data`, `test_parse_truncated_tlv`, `test_parse_empty_bytes`, `test_parse_too_short` |
| 5 | Serialize out-of-range ID → error | `test_serialize_sender_id_negative`, `test_serialize_sender_id_too_large`, `test_serialize_reflector_id_negative`, `test_serialize_reflector_id_too_large`, `test_serialize_invalid_sender_negative`, `test_serialize_invalid_sender_too_large` |
| 6 | Round-trip parse → serialize | `test_roundtrip_many_values`, `test_serialize_roundtrip`, `test_roundtrip_reflector_id_zero`, `test_roundtrip_single_value_all_zeros` |
| 7 | Parse list of TLVs | `test_parse_tlv_list_single`, `test_parse_tlv_list_multiple`, `test_parse_tlv_list_empty`, `test_parse_tlv_list_stops_on_short`, `test_parse_tlv_list_three_tlvs`, `test_serialize_tlv_list_basic`, `test_serialize_tlv_list_empty`, `test_serialize_tlv_list_single` |
| 8 | CLI parse + serialize subcommands | `test_cli_parse_hex_basic`, `test_cli_parse_hex_with_spaces`, `test_cli_parse_hex_0x_prefix`, `test_cli_parse_json_bytes`, `test_cli_parse_invalid_hex`, `test_cli_parse_compact`, `test_cli_serialize_basic`, `test_cli_serialize_flags`, `test_cli_serialize_large_ids`, `test_cli_serialize_invalid_sender_negative`, `test_cli_serialize_invalid_sender_too_large`, `test_cli_serialize_compact`, `test_cli_no_subcommand`, `test_cli_invalid_subcommand`, `test_cli_parse_help` |
| 9 | Big-endian byte order | `test_serialize_big_endian_sender_high`, `test_serialize_big_endian_reflector_high`, `test_parse_big_endian_sender_high`, `test_parse_big_endian_reflector_high`, `test_wire_length_field_is_4`, `test_wire_type_field_is_11` |
| 10 | Wire length exactly 8 bytes | `test_wire_length_exactly_8`, `test_parse_minimal_tlv`, `test_serialize_basic` |
| 11 | Error handling — malformed JSON | `test_cli_parse_malformed_json`, `test_cli_parse_json_not_byte_list`, `test_cli_parse_json_negative_byte`, `test_cli_parse_json_overflow_byte` |
| 12 | Error handling — reserved flags non-zero | `test_parse_flags_reserved_non_zero`, `test_serialize_reserved_bit_5`, `test_serialize_reserved_bit_6`, `test_serialize_reserved_bit_7` |
| 13 | Type/reflector boundary values | `test_parse_id_boundary_zero`, `test_parse_id_boundary_max`, `test_parse_reflector_zero`, `test_reflector_id_zero_is_valid`, `test_roundtrip_reflector_id_zero`, `test_parse_max_ids`, `test_serialize_max_ids` |
| 14 | No external dependencies | `test_init_exports_all_public_symbols`, `test_version_available` |
| 15 | `__slots__` on MicroSessionIDTLV | `test_tlv_has_slots`, `test_tlv_no_extra_attributes` |
| 16 | Constant exports | `test_micro_session_tlv_type_constant`, `test_expected_value_length_constant`, `test_wire_length_constant` |
| 17 | CLI parse wire_hex round-trip | `test_cli_parse_wire_hex_is_valid`, `test_cli_serialize_wire_bytes_field` |

**Total spec criteria covered: 17 / 17**
**Total tests: 113**
