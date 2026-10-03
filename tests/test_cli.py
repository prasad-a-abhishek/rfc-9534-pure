"""Tests for RFC 9534 CLI — parse and serialize subcommands.

Tests call main() directly to avoid subprocess capture issues in constrained envs.
"""

import io
import json
import sys

import pytest

from rfc9534pure import __main__


def _capture_main(args):
    """Run main() with args, capture stdout as a string."""
    old_stdout = sys.stdout
    sys.stdout = captured = io.StringIO()
    try:
        exit_code = __main__.main(args)
    finally:
        sys.stdout = old_stdout
    return exit_code, captured.getvalue()


# ─── CLI: parse ───────────────────────────────────────────────────────────────

def test_cli_parse_hex_basic():
    rc, out = _capture_main(["parse", "000b000400010002"])
    assert rc == 0, out
    data = json.loads(out)
    assert data["ok"] is True
    assert data["data"]["sender_id"] == 1
    assert data["data"]["reflector_id"] == 2


def test_cli_parse_hex_with_spaces():
    rc, out = _capture_main(["parse", "00 0b 00 04 00 01 00 02"])
    assert rc == 0, out
    data = json.loads(out)
    assert data["ok"] is True
    assert data["data"]["sender_id"] == 1


def test_cli_parse_hex_0x_prefix():
    rc, out = _capture_main(["parse", "0x000b000400010002"])
    assert rc == 0, out
    data = json.loads(out)
    assert data["ok"] is True


def test_cli_parse_json_bytes():
    rc, out = _capture_main(["parse", "[0,11,0,4,0,1,0,2]"])
    assert rc == 0, out
    data = json.loads(out)
    assert data["ok"] is True


def test_cli_parse_invalid_hex():
    rc, out = _capture_main(["parse", "xyz"])
    assert rc == 1, out
    data = json.loads(out)
    assert data["ok"] is False
    assert "error" in data


def test_cli_parse_wrong_type():
    rc, out = _capture_main(["parse", "000a000400010002"])
    assert rc == 1, out
    data = json.loads(out)
    assert data["ok"] is False


def test_cli_parse_compact():
    rc, out = _capture_main(["parse", "000b000400010002", "--compact"])
    assert rc == 0, out
    assert " " not in out.strip()


# ─── CLI: serialize ───────────────────────────────────────────────────────────

def test_cli_serialize_basic():
    rc, out = _capture_main(["serialize", "1", "2"])
    assert rc == 0, out
    data = json.loads(out)
    assert data["ok"] is True
    assert data["wire_hex"] == "000b000400010002"
    assert data["sender_id"] == 1
    assert data["reflector_id"] == 2


def test_cli_serialize_flags():
    rc, out = _capture_main(["serialize", "1", "2", "--flags", "7"])
    assert rc == 0, out
    data = json.loads(out)
    assert data["flags"] == 7


def test_cli_serialize_large_ids():
    rc, out = _capture_main(["serialize", "65535", "65535"])
    assert rc == 0, out
    data = json.loads(out)
    assert data["sender_id"] == 65535
    assert data["reflector_id"] == 65535


def test_cli_serialize_invalid_sender_negative():
    rc, out = _capture_main(["serialize", "-1", "2"])
    assert rc == 1, out
    data = json.loads(out)
    assert data["ok"] is False


def test_cli_serialize_invalid_sender_too_large():
    rc, out = _capture_main(["serialize", "65536", "2"])
    assert rc == 1, out
    data = json.loads(out)
    assert data["ok"] is False


def test_cli_serialize_invalid_reflector():
    rc, out = _capture_main(["serialize", "1", "abc"])
    assert rc == 1, out


def test_cli_serialize_compact():
    rc, out = _capture_main(["serialize", "1", "2", "--compact"])
    assert rc == 0, out
    assert " " not in out.strip()


# ─── CLI: error paths ───────────────────────────────────────────────────────

def test_cli_no_subcommand():
    rc, out = _capture_main([])
    assert rc == 2


def test_cli_invalid_subcommand():
    rc, out = _capture_main(["invalid"])
    assert rc == 2


def test_cli_parse_help():
    rc, out = _capture_main(["parse", "--help"])
    # argparse exits with 0 for --help
    assert rc == 0
