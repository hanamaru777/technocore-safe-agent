"""R1098: source-pinned/offline assessment of candidate Ed25519 AWS KMS signer.

No cloud SDK/API calls, network, environment secrets, sign, import, or host writes.
This tests protocol coverage only; NOT authorization to export/import signer seed.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
SIGNER = ROOT / "scripts" / "sign.py"
EXPECTED_GIT_BLOB = "81202baa03bff62204fa9ac34ce1f9fd969ddf67"
# Official AWS KMS Sign API Message upper bound (bytes), not Unicode characters.
AWS_KMS_SIGN_RAW_BYTES_MAX = 4096
# Ed25519ph is a distinct signature scheme; it cannot substitute for Ed25519.
REQUIRED_SIGN_ALGORITHM = "ED25519_SHA_512"
REQUIRED_MESSAGE_TYPE = "RAW"


class Stop(Exception):
    pass


def need(value: bool, reason: str):
    if not value:
        raise Stop(reason)


def original_signer_shape() -> dict[str, int]:
    data = SIGNER.read_bytes()
    gitblob = hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + b"\x00" + data
    ).hexdigest()
    need(gitblob == EXPECTED_GIT_BLOB, "SIGNER_SOURCE_BLOB_STOP")
    text = data.decode("utf-8")
    tree = ast.parse(text)
    constants = {}
    for row in tree.body:
        if isinstance(row, ast.Assign) and len(row.targets) == 1:
            target = row.targets[0]
            if isinstance(target, ast.Name) and target.id in (
                "MAX_TEXT_CHARS", "MAX_VALUE_CHARS"
            ):
                need(isinstance(row.value, ast.Constant)
                     and type(row.value.value) is int, "SIGNER_CONSTANT_STOP")
                constants[target.id] = row.value.value
    need(constants == {"MAX_TEXT_CHARS": 4096, "MAX_VALUE_CHARS": 8192},
         "SIGNER_MAXIMUM_STOP")
    # Confirm original canonical Ed25519 format, but NEVER call load_key().
    expected_fragments = (
        'canonical = f"{args.room}|{args.nonce}|{swept(args.text, MAX_TEXT_CHARS)}"',
        'canonical = f"{args.ns}|{args.key}|{args.nonce}|{swept(args.value, MAX_VALUE_CHARS)}"',
        'raw = key.sign(message.encode("utf-8"))',
        'return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(given)), given',
    )
    need(all(fragment in text for fragment in expected_fragments),
         "SIGNER_CANONICAL_STOP")
    return constants


def assess() -> dict:
    c = original_signer_shape()
    # Room/ns/key names and required "|" delimiters add nonzero bytes.
    # We use minimal one-letter identifiers and a one-character nonce, which
    # UNDERstates real production messages. Even these exceed 4096 bytes.
    longest_say_ascii = f"r|1|{'a' * c['MAX_TEXT_CHARS']}"
    longest_set_ascii = f"n|k|1|{'a' * c['MAX_VALUE_CHARS']}"
    # A legal single Unicode character may encode to four UTF-8 bytes.
    longest_say_utf8 = f"r|1|{'😀' * c['MAX_TEXT_CHARS']}"
    sizes = {
        "say_ascii_max_bytes_lower_bound": len(longest_say_ascii.encode("utf-8")),
        "say_unicode_max_bytes_example": len(longest_say_utf8.encode("utf-8")),
        "set_ascii_max_bytes_lower_bound": len(longest_set_ascii.encode("utf-8")),
    }
    need(all(value > AWS_KMS_SIGN_RAW_BYTES_MAX for value in sizes.values()),
         "CAPABILITY_ASSUMPTION_STOP")
    return {
        "phase": "R1098",
        "result": "OFFLINE_COMPATIBILITY_LIMIT_CONFIRMED",
        "action": "READ_ONLY_SOURCE_ONLY",
        "source_git_blob": "MATCH",
        "original_did_algorithm": "Ed25519",
        "aws_kms_candidate": "IMPORTED_ORIGINAL_ED25519_KEY_THEORETICAL",
        "required_algorithm": REQUIRED_SIGN_ALGORITHM,
        "required_message_type": REQUIRED_MESSAGE_TYPE,
        "raw_request_limit_bytes": AWS_KMS_SIGN_RAW_BYTES_MAX,
        "original_canonical_byte_lengths": sizes,
        "ed25519ph_is_not_standard_ed25519": True,
        "protocol_full_coverage": "NO_GO",
        "key_export_and_import": "NOT_AUTHORIZED",
        "recurring_cost": "REQUIRES_SEPARATE_APPROVAL",
        "cloud_calls": 0,
        "cutover": "NO_GO",
        "oci_retirement": "STRICT_NO_GO",
    }


def main() -> int:
    try:
        print(json.dumps(assess(), sort_keys=True, separators=(",", ":")))
        return 0
    except (Stop, OSError, UnicodeError, SyntaxError):
        print('{"phase":"R1098","result":"STOP","code":"PIN_OR_SCHEMA_STOP"}')
        return 42


if __name__ == "__main__":
    sys.exit(main())
