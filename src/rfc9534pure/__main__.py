"""RFC 9534 STAMP LAG Micro-session ID TLV — CLI entrypoint."""

import argparse
import json
import sys

from .parser import parse_micro_session_tlv
from .serializer import serialize_micro_session_tlv


def _hex_to_bytes(data: str) -> bytes:
    data = data.strip()
    if data.startswith("0x") or data.startswith("0X"):
        data = data[2:]
    data = data.replace(" ", "").replace(":", "").replace("-", "")
    if not all(c in "0123456789abcdefABCDEF" for c in data):
        raise ValueError(f"invalid hex character: {data!r}")
    if len(data) % 2:
        raise ValueError(f"odd-length hex: {data!r}")
    return bytes.fromhex(data)


def cmd_parse(args: argparse.Namespace) -> int:
    try:
        raw = args.input.strip()
        data = bytes(json.loads(raw)) if raw.startswith("[") else _hex_to_bytes(raw)
        tlv = parse_micro_session_tlv(data)
        result = {
            "ok": True,
            "data": tlv.to_dict(),
            "wire_hex": serialize_micro_session_tlv(tlv.sender_id, tlv.reflector_id, tlv.flags).hex(),
        }
        _emit(result, args.compact)
        return 0
    except (ValueError, TypeError, json.JSONDecodeError) as e:
        _emit({"ok": False, "error": str(e)}, indent=2)
        return 1


def cmd_serialize(args: argparse.Namespace) -> int:
    try:
        sender_id = int(args.sender_id)
        reflector_id = int(args.reflector_id)
        flags = int(args.flags) if args.flags else 0
        data = serialize_micro_session_tlv(sender_id, reflector_id, flags)
        _emit({"ok": True, "wire_hex": data.hex(), "wire_bytes": list(data),
               "sender_id": sender_id, "reflector_id": reflector_id, "flags": flags},
              args.compact)
        return 0
    except (ValueError, TypeError) as e:
        _emit({"ok": False, "error": str(e)}, indent=2)
        return 1


def _emit(d: dict, compact: bool = False, indent: int = None) -> None:
    kwargs = {"separators": (",", ":")} if compact else {"indent": indent or 2}
    sys.stdout.write(json.dumps(d, **kwargs) + "\n")
    sys.stdout.flush()


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if not argv or argv[0] in ("-h", "--help", "help"):
        sys.stdout.write(
            "usage: rfc9534pure <parse|serialize> ...\n"
            "  parse <hex|JSON> [--compact]\n"
            "  serialize <sender_id> <reflector_id> [--flags N] [--compact]\n"
        )
        sys.stdout.flush()
        return 0 if argv else 2

    cmd, args = argv[0], argv[1:]

    if cmd == "parse":
        compact = "--compact" in args
        if "-h" in args or "--help" in args:
            sys.stdout.write("usage: rfc9534pure parse <hex|JSON> [--compact]\n")
            sys.stdout.flush()
            return 0
        inputs = [a for a in args if a != "--compact"]
        if len(inputs) != 1:
            sys.stdout.write("usage: rfc9534pure parse <hex|JSON> [--compact]\n")
            sys.stdout.flush()
            return 2
        return cmd_parse(argparse.Namespace(input=inputs[0], compact=compact))

    if cmd == "serialize":
        compact = "--compact" in args
        if "-h" in args or "--help" in args:
            sys.stdout.write("usage: rfc9534pure serialize <sender_id> <reflector_id> [--flags N] [--compact]\n")
            sys.stdout.flush()
            return 0
        inputs = [a for a in args if a != "--compact"]
        if len(inputs) < 2:
            sys.stdout.write("usage: rfc9534pure serialize <sender_id> <reflector_id> [--flags N] [--compact]\n")
            sys.stdout.flush()
            return 2
        sender_id, reflector_id = inputs[0], inputs[1]
        flags = None
        for i, a in enumerate(inputs):
            if a == "--flags" and i + 1 < len(inputs):
                flags = inputs[i + 1]
        return cmd_serialize(argparse.Namespace(sender_id=sender_id, reflector_id=reflector_id,
                                               flags=flags, compact=compact))

    sys.stdout.write(f"rfc9534pure: unknown command {cmd!r}\n"
                      f"usage: rfc9534pure <parse|serialize> ...\n")
    sys.stdout.flush()
    return 2
