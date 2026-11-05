"""T1150 local release-review contract, NOT a testnet wire protocol.

Only fixed public first-party source GETs are possible, explicitly requested.
An operator review signature authenticates an immutable offline capture; it is
not an official chain/launch signature or permission to transact.
"""
from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import ssl
import threading
import time
import urllib.request
from urllib.parse import urlsplit

from . import public_record, testnet_budget

SOURCES = (
    "https://docs.flop.network/docs/testnet-and-timeline",
    "https://ask.flop.finance/networks/testnet",
    "https://flop.finance/testnet/",
    "https://docs.flop.network/docs/official-links",
)
DOMAIN = b"FLOP-T1150-LOCAL-RELEASE-REVIEW-v1\0"
MAX_BYTES = 262144
READ_DEADLINE_SECONDS = 25
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z")
SHA = testnet_budget.HEX64


class Blocked(ValueError):
    """Fixed reason codes only; never include submitted values or exceptions."""


def need(ok, code):
    if not ok: raise Blocked(code)


def shape(value, fields):
    need(type(value) is dict and set(value) == set(fields.split()), "EXACT_SCHEMA_REQUIRED")


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()


def sha(value): return hashlib.sha256(canonical(value)).hexdigest()


def digest(value):
    need(type(value) is str and SHA.fullmatch(value), "DIGEST_REQUIRED")
    return value


def integer(value, lo=1, hi=10**12):
    need(type(value) is int and lo <= value <= hi, "INTEGER_BOUND_REQUIRED")
    return value


def parse(raw):
    need(type(raw) is bytes and 1 <= len(raw) <= MAX_BYTES, "PUBLIC_INPUT_BOUND")
    def pairs(rows):
        result = {}
        for k,v in rows:
            need(k not in result, "DUPLICATE_JSON_KEY")
            result[k] = v
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(Blocked("NONFINITE_JSON")))
    except (UnicodeError, ValueError, RecursionError):
        raise Blocked("INVALID_PUBLIC_JSON") from None


def timestamp(value):
    need(type(value) is str and len(value) <= 40, "UTC_TIMESTAMP_REQUIRED")
    try: dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError: raise Blocked("UTC_TIMESTAMP_REQUIRED") from None
    need(dt.utcoffset() is not None and dt.utcoffset().total_seconds() == 0, "UTC_TIMESTAMP_REQUIRED")
    return int(dt.timestamp())


def legacy(name):
    path = Path(__file__).resolve().parents[2] / "packaging/testnet" / name
    spec = importlib.util.spec_from_file_location("t1150_"+path.stem, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def endpoint(value):
    need(type(value) is str and 1 <= len(value) <= 256 and value.isascii() and
         not any(ord(c) <= 32 for c in value) and not any(c in value for c in "\\%?#"), "UNREVIEWED_ENDPOINT")
    try:
        p = urlsplit(value); host = p.hostname
        need(p.scheme == "https" and p.username is None and p.password is None and p.port in (None,443) and
             p.path.startswith("/") and host is not None and
             any(host == d or host.endswith("."+d) for d in ("flop.network","flop.finance")) and
             all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",label) for label in host.split(".")) and
             not any(x in value.lower() for x in ("devnet","mainnet","localhost")),
             "UNREVIEWED_ENDPOINT")
        try: ipaddress.ip_address(host)
        except ValueError: pass
        else: raise Blocked("UNREVIEWED_ENDPOINT")
    except ValueError: raise Blocked("UNREVIEWED_ENDPOINT") from None
    return value


def admit(bundle, trust, *, now):
    """Immutable offline first-party capture + independently pinned review key.

    trust is separately supplied by the operator, NEVER taken from bundle.
    There is no shipped release manifest, reviewer enrollment or real adapter.
    """
    shape(trust, "reviewer_public_hex manifest_sha256 genesis_sha256 original_did reference_sha256")
    shape(bundle, "manifest observations review identity")
    manifest = bundle["manifest"]
    shape(manifest, "version network release_id state published_at expires_at chain_id genesis_sha256 rpc gateway signature_schema_sha256 registration faucet inference settlement limits")
    need(type(manifest["version"]) is int and manifest["version"] == 1, "MANIFEST_VERSION")
    need(manifest["network"] == "testnet" and manifest["state"] == "LIVE", "WAIT_OFFICIAL_RELEASE")
    for k in ("release_id","chain_id"):
        need(type(manifest[k]) is str and IDENT.fullmatch(manifest[k]) and
             not any(t in manifest[k].lower() for t in ("devnet","mainnet","unreleased","planned")), "TESTNET_IDENTITY_REQUIRED")
    start, end = timestamp(manifest["published_at"]), timestamp(manifest["expires_at"])
    need(start <= now < end <= start + 86400, "RELEASE_STALE_OR_FUTURE")
    digest(manifest["genesis_sha256"]); digest(manifest["signature_schema_sha256"])
    need(manifest["genesis_sha256"] == digest(trust["genesis_sha256"]) and sha(manifest) == digest(trust["manifest_sha256"]), "IMMUTABLE_RELEASE_BINDING_MISMATCH")
    endpoint(manifest["rpc"]); endpoint(manifest["gateway"])
    shape(manifest["registration"], "required url schema_sha256")
    need(type(manifest["registration"]["required"]) is bool, "REGISTRATION_SPEC_REQUIRED")
    if manifest["registration"]["required"]:
        endpoint(manifest["registration"]["url"]); digest(manifest["registration"]["schema_sha256"])
    else:
        need(manifest["registration"]["url"] is None and manifest["registration"]["schema_sha256"] is None, "REGISTRATION_SPEC_REQUIRED")
    for action in ("faucet","inference","settlement"):
        shape(manifest[action], "url schema_sha256 terms_sha256")
        endpoint(manifest[action]["url"])
        digest(manifest[action]["schema_sha256"]); digest(manifest[action]["terms_sha256"])
    shape(manifest["limits"], "asset_kind unit max_request_units max_day_units max_total_units faucet_claims_per_day ttl_seconds")
    lim = manifest["limits"]
    need(lim["asset_kind"] == "TEST_ONLY" and type(lim["unit"]) is str and IDENT.fullmatch(lim["unit"]), "TEST_TOKEN_ONLY")
    testnet_budget.caps({k:lim[k] for k in testnet_budget.CAP_FIELDS})
    integer(lim["faucet_claims_per_day"],1,100); integer(lim["ttl_seconds"],1,900)
    obs = bundle["observations"]
    need(type(obs) is list and len(obs) == len(SOURCES), "ALL_FIXED_SOURCES_REQUIRED")
    seen = set()
    for row in obs:
        shape(row, "url body_sha256 observed_at status")
        need(row["url"] in SOURCES and row["url"] not in seen and row["status"] == "LIVE_RELEASE_REVIEWED", "SOURCE_NOT_REVIEWED_OR_CONFLICTING")
        digest(row["body_sha256"])
        need(start <= timestamp(row["observed_at"]) <= now and now-timestamp(row["observed_at"]) <= 86400, "SOURCE_EVIDENCE_STALE")
        seen.add(row["url"])
    review = bundle["review"]
    shape(review, "manifest_sha256 observations_sha256 reference_sha256 reviewed_at signature")
    need(review["manifest_sha256"] == trust["manifest_sha256"] and review["observations_sha256"] == sha(obs) and
         review["reference_sha256"] == digest(trust["reference_sha256"]) and
         start <= timestamp(review["reviewed_at"]) <= now and
         now-timestamp(review["reviewed_at"]) <= 86400, "INDEPENDENT_REVIEW_REQUIRED")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pub = bytes.fromhex(digest(trust["reviewer_public_hex"]))
        need(type(review["signature"]) is str and re.fullmatch(r"[0-9a-f]{128}",review["signature"]), "REVIEW_SIGNATURE_INVALID")
        Ed25519PublicKey.from_public_bytes(pub).verify(bytes.fromhex(review["signature"]),
            DOMAIN+canonical({k:v for k,v in review.items() if k!="signature"}))
    except Exception: raise Blocked("REVIEW_SIGNATURE_INVALID") from None
    identity = bundle["identity"]
    shape(identity, "room record")
    need(sha(identity) == trust["reference_sha256"] and identity["record"].get("from") == trust["original_did"], "ORIGINAL_DID_REBIND_REFUSED")
    try:
        public_record.verify_signed_record(identity["room"],identity["record"])
        integer(identity["record"]["seq"],1); timestamp(identity["record"]["ts"])
    except (ValueError,KeyError,TypeError): raise Blocked("ORIGINAL_PUBLIC_PROOF_INVALID") from None
    # Reuse old structural preflight. Its output is explicitly NEVER LIVE_GO.
    r1057 = legacy("r1057_offline_agent_launch_gate.py")
    old = dict(network_state="OPEN",chain_id=manifest["chain_id"],genesis_sha256=manifest["genesis_sha256"],
        rpc_url=manifest["rpc"],faucet_url=manifest["faucet"]["url"],inference_url=manifest["inference"]["url"],
        signed_request_spec_sha256=manifest["signature_schema_sha256"],settled_receipt_spec_sha256=manifest["settlement"]["schema_sha256"],
        rate_rules_sha256=sha(lim),original_did_continuity_attested=True,
        operator_reviewed_domains=sorted({urlsplit(manifest[k]["url"]).hostname for k in ("faucet","inference")} | {urlsplit(manifest["rpc"]).hostname}),
        formal_operator_source_sha256=sha(obs))
    try:
        need(r1057.assess_offline(canonical(old))["offline_manifest_complete"] == "YES", "LEGACY_STRUCTURAL_PREFLIGHT_FAILED")
    except r1057.Stop:raise Blocked("LEGACY_STRUCTURAL_PREFLIGHT_FAILED") from None
    return json.loads(canonical(manifest))


def inspect_official(*, getter=None):
    """Opt-in bounded read-only availability evidence; NEVER launch admission.

    A deadline detaches at most one daemon reader and stops further work. Even
    a stalled peer cannot block the CLI or spawn an unbounded set of workers.
    """
    r1105 = legacy("r1105_agent_public_readiness.py")
    rows = []; deadline = time.monotonic()+READ_DEADLINE_SECONDS
    def get(url):
        need(url in SOURCES,"SOURCE_URI_NOT_ALLOWLISTED")
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),r1105.NoRedirect())
        request=urllib.request.Request(url,method="GET",headers={"Accept":"text/html","User-Agent":"flop-t1150-readonly/1"})
        with opener.open(request,timeout=5) as response:
            need(response.status==200 and response.geturl()==url,"SOURCE_REDIRECT_OR_HTTP")
            raw=response.read(MAX_BYTES+1)
            need(0<len(raw)<=MAX_BYTES,"SOURCE_BODY_BOUND")
            return raw
    for url in SOURCES:
        result=[]
        def worker(source=url):
            try: result.append((getter or get)(source))
            except Exception: result.append(None)
        thread=threading.Thread(target=worker,daemon=True);thread.start()
        thread.join(max(0,deadline-time.monotonic()))
        if thread.is_alive():
            rows.append({"url":url,"state":"UNKNOWN","reason":"READ_ONLY_DEADLINE"});break
        raw=result[0] if result else None
        if type(raw) is not bytes or not 0<len(raw)<=MAX_BYTES:
            rows.append({"url":url,"state":"UNKNOWN","reason":"PUBLIC_SOURCE_UNAVAILABLE"});continue
        classification=r1105._doc_status(raw) if url==r1105.DOCS_URL else "CAPTURE_REQUIRES_REVIEW"
        rows.append({"url":url,"state":"UNKNOWN","reason":classification,"body_sha256":hashlib.sha256(raw).hexdigest()})
    return {"mode":"PUBLIC_GET_ONLY","launch_admitted":False,"observations":rows}
