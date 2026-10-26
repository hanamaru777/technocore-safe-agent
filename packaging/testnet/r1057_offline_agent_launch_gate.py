#!/usr/bin/env python3
"""R1057: offline-only FLOP Testnet agent launch-preflight contract.

No network requests, faucet, registration, signing, money, account creation,
cloud changes, or activation. Official testnet API/network specs unavailable
as of 2026-10-25. This deliberately CANNOT return LIVE_GO.
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit

OFFICIAL_REFS = (
    "https://flop.finance/official/",
    "https://flop.finance/testnet/",
    "https://flop.finance/airdrop/",
    "https://docs.flop.network/networks/testnet",
    "https://docs.flop.network/docs/testnet-and-timeline",
    "https://github.com/flop-labs/yellowpaper",
)
TARGET_DATE_ISO = "2026-11-03"
TARGET_CONFIRMED = False
NETWORK_RELEASE_VERIFIED = False
# URLs here are authoritative SOURCE PAGES, not protocol endpoints.
OFFICIAL_DISCOVERY_HOSTS = frozenset((
    "flop.finance", "docs.flop.network", "flop.network",
    "github.com", "ask.flop.finance"
))
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
IDENT = re.compile(r"[A-Za-z0-9._-]{1,96}\Z")
MAX_FACT_BYTES = 8192
FIELDS = frozenset(("network_state", "chain_id", "genesis_sha256",
                    "rpc_url", "faucet_url", "inference_url",
                    "signed_request_spec_sha256", "settled_receipt_spec_sha256",
                    "rate_rules_sha256", "original_did_continuity_attested",
                    "operator_reviewed_domains", "formal_operator_source_sha256"))


class Stop(Exception):
    """A fixed reason code; never include submitted packet data."""


def check(ok, reason):
    if not ok:
        raise Stop(reason)


def no_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        check(key not in obj, "DUPLICATE_FIELD_STOP")
        obj[key] = value
    return obj


def private_manifest(data: bytes) -> dict:
    """Parse externally captured OFFLINE launch-spec copy; no trust claimed."""
    check(type(data) is bytes and 2 <= len(data) <= MAX_FACT_BYTES,
          "MANIFEST_BYTES_STOP")
    try:
        obj = json.loads(data.decode("utf-8", "strict"),
                         object_pairs_hook=no_duplicate_keys)
    except (UnicodeError, TypeError, ValueError):
        raise Stop("MANIFEST_JSON_STOP") from None
    check(type(obj) is dict and set(obj) == FIELDS, "MANIFEST_EXACT_FIELDS_STOP")
    check(obj["network_state"] in ("NOT_PUBLISHED", "PLANNED", "OPEN"),
          "NETWORK_STATE_STOP")
    check(type(obj["original_did_continuity_attested"]) is bool,
          "DID_FLAG_STOP")
    check(type(obj["operator_reviewed_domains"]) is list and
          len(obj["operator_reviewed_domains"]) <= 8,
          "DOMAINS_BOUND_STOP")
    check(all(type(x) is str and IDENT.fullmatch(x)
              for x in obj["operator_reviewed_domains"]),
          "DOMAIN_SHAPE_STOP")
    check(len(set(obj["operator_reviewed_domains"])) ==
          len(obj["operator_reviewed_domains"]), "DUPLICATE_DOMAIN_STOP")
    for name in ("genesis_sha256", "signed_request_spec_sha256",
                 "settled_receipt_spec_sha256", "rate_rules_sha256",
                 "formal_operator_source_sha256"):
        value = obj[name]
        check(value is None or type(value) is str and SHA256.fullmatch(value),
              "INVALID_DIGEST_STOP")
    check(obj["chain_id"] is None or
          type(obj["chain_id"]) is str and IDENT.fullmatch(obj["chain_id"]),
          "CHAIN_ID_STOP")
    for name in ("rpc_url", "faucet_url", "inference_url"):
        value = obj[name]
        check(value is None or type(value) is str and len(value) <= 512,
              "ENDPOINT_SHAPE_STOP")
        if value is not None:
            validate_endpoint(value, obj["operator_reviewed_domains"])
    return obj


def validate_endpoint(url: str, allowed_domains: list[str]) -> None:
    """Allow only explicitly externally reviewed HTTPS hostnames; no fetch."""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        check(parsed.scheme == "https" and parsed.username is None and
              parsed.password is None and parsed.port in (None, 443) and
              host in allowed_domains and host is not None and
              parsed.fragment == "" and parsed.query == "" and
              parsed.path.startswith("/") and
              "\\" not in url and any(ord(c) < 32 for c in url) is False,
              "ENDPOINT_NOT_REVIEWED_STOP")
    except ValueError:
        raise Stop("ENDPOINT_PARSE_STOP") from None


def assess_offline(data: bytes) -> dict:
    """Perform synthetic completeness check, not verify URLs or allow actions.

    The manifest author can self-assert evidence; HTTPS trust, source freshness,
    availability, DID custody, sender permissions and limits require independent
    original-authority proof at a future LIVE release gate.
    """
    packet = private_manifest(data)
    full = (packet["network_state"] == "OPEN" and
            packet["original_did_continuity_attested"] and
            all(packet[k] is not None for k in (
                "chain_id", "genesis_sha256", "rpc_url", "faucet_url",
                "inference_url", "signed_request_spec_sha256",
                "settled_receipt_spec_sha256", "rate_rules_sha256",
                "formal_operator_source_sha256")))
    return {
        "schema_version": 1,
        "official_reference_count": len(OFFICIAL_REFS),
        "target_2026_11_03": "PROVISIONAL",
        "offline_manifest_complete": "YES" if full else "NO",
        "official_public_release_cryptographically_verified": "NO",
        "same_original_did_externally_attested": "NOT_PROVEN",
        "official_faucet_and_inference_currently_active": "NOT_PROVEN",
        "request_schema_reconciled_with_signed_settlement": "NOT_PROVEN",
        "original_oci_signer_ported": "NOT_PROVEN",
        "faucet_action_authorized": "NO",
        "inference_post_authorized": "NO",
        "testnet_live_go": "NO",
        "migration_or_retirement_authorized": "NO",
    }


def launch_report(data: bytes) -> str:
    """Return aggregate fixed labels; never echo DID, host, URL or payload."""
    return json.dumps(assess_offline(data), sort_keys=True, separators=(",", ":"))


# There is intentionally NO main(), transport, signing or server entrypoint.
