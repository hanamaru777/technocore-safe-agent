"""R1110: bounded public FLOP operator-profile change review, never launch approval.

This independent read-only official source is intentionally NOT a signer or
testnet client. A profile drift can only create a human review issue; it
cannot mark a faucet, chain, session, airdrop or production adapter READY.
"""
from __future__ import annotations

import hashlib
import json
import re
import ssl
import urllib.error
import urllib.request
from html.parser import HTMLParser

URL = "https://ask.flop.finance/networks/testnet"
MAX_BODY = 131072
TIMEOUT = 8
_STATUS = re.compile(r"\bNetwork\s*:\s*testnet\s*\(\s*([a-z_-]{2,24})\s*\)", re.I)
_RELEASE = re.compile(r"\bRelease\s*:\s*[a-zA-Z0-9._-]{1,40}\s*\(\s*([a-z_-]{2,24})\s*\)", re.I)
_SECTION = ("Chain spec", "Expected genesis", "RPC", "Gateway", "Admission", "Model catalog")


class _Visible(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.blocks = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript"):
            self.hidden += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript") and self.hidden:
            self.hidden -= 1

    def handle_data(self, text):
        if not self.hidden:
            self.blocks.append(text)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _public_get():
    req = urllib.request.Request(URL, method="GET",
         headers={"Accept": "text/html", "User-Agent": "flop-r1110-operator-readonly/1"})
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _NoRedirect(),
    )
    with opener.open(req, timeout=TIMEOUT) as response:
        if response.status != 200:
            raise ValueError("HTTP_STATUS_STOP")
        body = response.read(MAX_BODY + 1)
        if not 0 < len(body) <= MAX_BODY:
            raise ValueError("SOURCE_BODY_STOP")
        return body


def inspect_public_profile(body):
    """Only enums and a fixed reason leave the source; NEVER raw HTML / endpoints."""
    if type(body) is not bytes or not 0 < len(body) <= MAX_BODY:
        return "unavailable", None
    try:
        text = body.decode("utf-8", "strict")
        parser = _Visible()
        parser.feed(text)
        parser.close()
        visible = re.sub(r"\s+", " ", " ".join(parser.blocks))
    except (UnicodeError, ValueError):
        return "unavailable", None

    net = _STATUS.search(visible)
    release = _RELEASE.search(visible)
    if not net or not release or not all(re.search(r"\b" + re.escape(x) + r"\b", visible) for x in _SECTION):
        return "unavailable", None

    net_value, release_value = net.group(1).lower(), release.group(1).lower()
    if net_value == "planned" and release_value == "unreleased":
        # Do not infer that all chain fields remain unpublished: if the
        # operator updates its detailed artifacts while planned, surface a
        # REVIEW only, not a verified new network.
        old = re.search(r"\bChain spec\s+Unavailable\s*[—-]\s*no verified public value\b", visible, re.I)
        genesis = re.search(r"\bExpected genesis\s+Unavailable\s*[—-]\s*no verified public value\b", visible, re.I)
        if old and genesis:
            return "planned_unreleased", None
        reason = "chain_artifacts_changed_review"
    else:
        reason = "network_or_release_changed_review"

    identity = {"kind": "official_operator_profile_review", "key": "testnet_network", "reason": reason}
    fingerprint = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
    return "changed_review_only", {**identity, "source": "flop_operator", "url": URL,
                                   "fingerprint": fingerprint}


def check(fetcher=None):
    """Optional public GET, no credentials; request failure is not launch evidence."""
    try:
        getter = _public_get if fetcher is None else fetcher
        return inspect_public_profile(getter())
    except (OSError, urllib.error.URLError, ValueError, TypeError, TimeoutError):
        return "unavailable", None
