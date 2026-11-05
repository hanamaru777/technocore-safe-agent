"""R1105: fixed-origin, read-only agent testnet preparation.

A public GET can check availability, NOT an authenticated launch or a
chain/genesis/faucet/receipt proof. Never signs, creates a wallet, claims,
posts, pays, registers, reads local identity, or invokes third-party SDKs.

All HTTP is expressly opt-in (--live). In CI/default mode: NO network.
"""
from __future__ import annotations

import hashlib
import json
import re
import ssl
import sys
import urllib.error
import urllib.request

DOCS_URL = "https://ask.flop.finance/networks/testnet"
MODELS_URL = "https://api.flop.network/v1/models"
MAX_BYTES = 131072
TIMEOUT = 8
UA = "flop-agent-r1105-readonly/1"
# Sources: https://ask.flop.finance/docs/sdk-references (2026-10-30)
PUBLISHED_DEVNET_PACKAGES = {
    "npm_client": "@flop-labs/client@0.2.1",
    "npm_contracts": "@flop-labs/contracts@0.1.1",
    "npm_sdk": "@flop-labs/sdk@0.4.0",
    "npm_cli": "@flop-labs/cli@0.4.0",
    "python_sdk": "flop-sdk==0.2.0",
}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _get(url):
    if url not in (DOCS_URL, MODELS_URL):
        raise ValueError("SOURCE_NOT_ALLOWLISTED")
    request = urllib.request.Request(
        url, method="GET",
        headers={"User-Agent": UA, "Accept": "application/json" if url == MODELS_URL else "text/html"},
    )
    # Ignore proxy settings injected by parent host; only HTTPS with default CA.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        NoRedirect(),
    )
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            if response.status != 200:
                return None, "HTTP_NOT_OK"
            raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES or len(raw) == 0:
                return None, "BODY_BOUND_STOP"
            return raw, "OK"
    except (OSError, urllib.error.URLError, ValueError):
        return None, "FETCH_UNAVAILABLE"


def _doc_status(data):
    try:
        text = data.decode("utf-8", "strict").lower()
    except UnicodeError:
        return "INVALID_DOCUMENT"
    if "testnet (planned)" in text and "no verified public value" in text:
        return "PLANNED_UNVERIFIED"
    return "DOCUMENT_CHANGED_REVIEW_REQUIRED"


def _model_status(data):
    try:
        value = json.loads(data)
    except (ValueError, UnicodeError):
        return "INVALID_MODEL_REPLY"
    if (type(value) is not dict or type(value.get("data")) is not list or
            len(value["data"]) > 2048):
        return "INVALID_MODEL_REPLY"
    for model in value["data"]:
        if (type(model) is not dict or type(model.get("id")) is not str or
                not re.fullmatch(r"[a-zA-Z0-9._/:+-]{1,128}", model["id"])):
            return "INVALID_MODEL_REPLY"
    return "PUBLIC_DISCOVERY_ONLY"


def audit(*, live=False, getter=None):
    """Never returns READY, never prints private endpoint responses."""
    result = {
        "phase": "R1105",
        "mode": "READ_ONLY_PUBLIC_GET" if live else "OFFLINE",
        "official_target_date": "2026-11-03",
        "target_date_confirmed": False,
        "network": "TESTNET_NOT_VERIFIED",
        "published_devnet_sdk": PUBLISHED_DEVNET_PACKAGES,
        "model_discovery": "NOT_CHECKED",
        "testnet_profile": "NOT_CHECKED",
        "chain_genesis": "UNVERIFIED",
        "faucet": "NOT_AUTHORIZED",
        "agent_wallet_custody": "NOT_TOUCHED",
        "inference_spend": "DISABLED",
        "signing": "DISABLED",
        "external_write": "NONE",
        "production_migration": "NO_GO",
        "testnet_transactions": "NO_GO",
        "oci_retirement": "STRICT_NO_GO",
    }
    if live:
        get = getter if getter is not None else _get
        for key, url, evaluate in (
            ("testnet_profile", DOCS_URL, _doc_status),
            ("model_discovery", MODELS_URL, _model_status),
        ):
            try:
                raw, status = get(url)
                if status != "OK" or type(raw) is not bytes or not (0 < len(raw) <= MAX_BYTES):
                    result[key] = "FETCH_NOT_VERIFIED"
                else:
                    result[key] = evaluate(raw)
            except (OSError, ValueError, TypeError, RecursionError):
                result[key] = "FETCH_NOT_VERIFIED"
    return result


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args not in ([], ["--live"]):
        print('{"phase":"R1105","result":"INVALID_ARGUMENTS","testnet_transactions":"NO_GO"}')
        return 2
    print(json.dumps(audit(live=args == ["--live"]), sort_keys=True))
    return 0  # informational CLI exit only, NOT authorization


if __name__ == "__main__":
    raise SystemExit(main())
