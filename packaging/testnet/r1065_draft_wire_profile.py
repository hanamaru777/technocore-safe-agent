"""R1065: offline FLOP Yellow Paper v0.5.0 DRAFT wire-profile examples.

NON-OPERATIONAL REFERENCE ONLY; these formats are not proof of a released
testnet or its admitted RPC/inference transport. Uses no network, disk, keys,
crypto signing, faucet, wallet, settlement or production application hooks.

Public normative-draft source, PINNED:
  https://github.com/flop-labs/yellowpaper/tree/5730f4b6cf56fa88bb93bbda272dc449b2f77b17
  evidence/compute-channel.py and evidence/wire-format-v1.json
  Official vector Git blob: e0a47dd5f4582d1fbc6d0af535d91d045bfc9fc4

The receipt signature in the source is SR25519/Substrate context, NOT Ed25519
and NOT a self-verified settlement receipt. NO LIVE permissions result here.
"""
from __future__ import annotations

from hashlib import blake2b

DRAFT_SOURCE_COMMIT = "5730f4b6cf56fa88bb93bbda272dc449b2f77b17"
DRAFT_WIRE_VECTOR_GIT_BLOB = "e0a47dd5f4582d1fbc6d0af535d91d045bfc9fc4"
CHANNEL_DOMAIN = b"FLOP/COMPUTE_CHANNEL/ID"
RECEIPT_DOMAIN = b"FLOP/COMPUTE_CHANNEL/RECEIPT"


class Stop(Exception):
    """Only safe invariant codes; never encode a secret or untrusted value."""


def _fixed32(value: bytes) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise Stop("DRAFT_WIRE_32_BYTE_FIELD_STOP")
    return value


def _uint(value: int, bits: int) -> bytes:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise Stop("DRAFT_WIRE_UNSIGNED_RANGE_STOP")
    return value.to_bytes(bits // 8, "little")


def channel_id_v1(genesis_hash: bytes, agent: bytes, miner: bytes, nonce: int) -> bytes:
    """DRAFT channel identifier; same bytes as published Appendix F vector."""
    message = (CHANNEL_DOMAIN + b"\x01" + _fixed32(genesis_hash) +
               _fixed32(agent) + _fixed32(miner) + _uint(nonce, 64))
    return blake2b(message, digest_size=32).digest()


def receipt_signable_v1(
    channel_id: bytes, final_root: bytes, aggregate_gn: int, payable: int,
) -> bytes:
    """DRAFT raw sr25519 signable preimage; does NOT verify a signature.

    The true live receipt requires independently authenticated chain, actual
    signer identity + sr25519 verification, accepted settlement finality,
    and published testnet runtime/contract versions.
    """
    return (RECEIPT_DOMAIN + b"\x01" + _fixed32(channel_id) +
            _fixed32(final_root) + _uint(aggregate_gn, 128) +
            _uint(payable, 128))


def draft_safety_status() -> dict:
    """Fixed redacted NO_GO flags, even when all public vectors match."""
    return {
        "schema": "R1065_OFFLINE_DRAFT_V1",
        "reference_corpus_verified_as_deployed_testnet": "NO",
        "sr25519_signature_verified": "NO",
        "original_did_and_wallet_binding_verified": "NO",
        "official_testnet_chain_and_gateway": "UNRELEASED",
        "settled_receipt_finality_verified": "NO",
        "faucet_or_inference_post_authorized": "NO",
        "airdrop_score_established": "NO",
        "oci_retirement": "STRICT_NO_GO",
    }
