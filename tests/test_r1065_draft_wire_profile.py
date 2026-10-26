"""R1065: public FLOP Yellow Paper DRAFT Appendix F offline vectors."""
import ast
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "packaging/testnet/r1065_draft_wire_profile.py"
spec = importlib.util.spec_from_file_location("r1065_wire", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

# Identical to published source vector in FLOP Yellow Paper v0.5
VECTOR_CHANNEL = ("3655fa5a95712c31f0bd2380aa8193b3" +
                  "0c78bd955e4e966abb0d9f49d66e8d28")
VECTOR_RECEIPT = (
    "464c4f502f434f4d505554455f4348414e4e454c2f5245434549505401"
    + "11" * 32 + "22" * 32 +
    "2a000000000000000000000000000000"
    "e8030000000000000000000000000000"
)


def test_official_draft_channel_id_positive_vector():
    genesis = bytes(range(32))
    agent = bytes([0x11]) * 32
    miner = bytes([0x22]) * 32
    assert m.channel_id_v1(genesis, agent, miner, 42).hex() == VECTOR_CHANNEL


def test_official_draft_receipt_signable_preimage_exact_bytes():
    message = m.receipt_signable_v1(b"\x11"*32, b"\x22"*32, 42, 1000)
    assert message.hex() == VECTOR_RECEIPT
    assert len(message) == 125
    assert message.startswith(b"FLOP/COMPUTE_CHANNEL/RECEIPT\x01")


@pytest.mark.parametrize(("which","value"), (
    ("genesis_hash", b""),
    ("genesis_hash", b"a" * 31),
    ("genesis_hash", b"a" * 33),
    ("agent", b"a" * 31),
    ("miner", None),
    ("miner", bytearray(32)),
))
def test_wrong_length_or_untrusted_type_rejected_for_channel(which, value):
    params = {"genesis_hash": b"a"*32, "agent": b"b"*32,
              "miner": b"c"*32, "nonce": 1}
    params[which] = value
    with pytest.raises(m.Stop, match="DRAFT_WIRE_32_BYTE_FIELD_STOP"):
        m.channel_id_v1(**params)


@pytest.mark.parametrize("bad", (-1, 1 << 64, False, True, "42", 1.5, None))
def test_nonce_negative_overflow_bool_and_noninteger_rejected(bad):
    with pytest.raises(m.Stop, match="DRAFT_WIRE_UNSIGNED_RANGE_STOP"):
        m.channel_id_v1(b"a"*32, b"b"*32, b"c"*32, bad)


@pytest.mark.parametrize(("gn","fee"), (
    (-1, 0), (0, -1), (1 << 128, 0), (0, 1 << 128),
    (True, 0), (0, True), (None, 1), (1, 1.0)
))
def test_receipt_amount_range_overflow_and_bool_rejected(gn, fee):
    with pytest.raises(m.Stop, match="DRAFT_WIRE_UNSIGNED_RANGE_STOP"):
        m.receipt_signable_v1(b"a"*32, b"b"*32, gn, fee)


def test_receipt_requires_exact_channel_and_root_lengths():
    for ch,root in [(b"a"*31, b"b"*32), (b"a"*32, b"b"*33),
                    (b"a"*32, "private-root")]:
        with pytest.raises(m.Stop, match="DRAFT_WIRE_32_BYTE_FIELD_STOP"):
            m.receipt_signable_v1(ch, root, 1, 1)


def test_domain_genesis_agent_miner_nonce_and_payment_are_bound():
    genesis = bytes(range(32))
    a,miner = b"a"*32,b"b"*32
    original = m.channel_id_v1(genesis, a, miner, 1)
    assert original != m.channel_id_v1(b"z"*32, a, miner, 1)
    assert original != m.channel_id_v1(genesis, b"z"*32, miner, 1)
    assert original != m.channel_id_v1(genesis, a, b"z"*32, 1)
    assert original != m.channel_id_v1(genesis, a, miner, 2)

    root = b"d"*32
    receipt = m.receipt_signable_v1(original, root, 100, 200)
    assert receipt != m.receipt_signable_v1(original, root, 100, 201)
    assert receipt != m.receipt_signable_v1(original, root, 101, 200)
    assert receipt != m.receipt_signable_v1(original, b"z"*32, 100, 200)
    assert receipt != m.receipt_signable_v1(b"z"*32, root, 100, 200)


def test_even_perfect_vectors_never_claim_settled_score_or_live_authority():
    assert m.channel_id_v1(bytes(range(32)), b"\x11"*32,b"\x22"*32,42).hex() == VECTOR_CHANNEL
    result = m.draft_safety_status()
    assert result["sr25519_signature_verified"] == "NO"
    assert result["settled_receipt_finality_verified"] == "NO"
    assert result["original_did_and_wallet_binding_verified"] == "NO"
    assert result["official_testnet_chain_and_gateway"] == "UNRELEASED"
    assert result["faucet_or_inference_post_authorized"] == "NO"
    assert result["airdrop_score_established"] == "NO"
    assert result["oci_retirement"] == "STRICT_NO_GO"


def test_explicit_public_provenance_pinned_and_no_real_io_or_signature_verification():
    assert m.DRAFT_SOURCE_COMMIT == "5730f4b6cf56fa88bb93bbda272dc449b2f77b17"
    assert m.DRAFT_WIRE_VECTOR_GIT_BLOB == "e0a47dd5f4582d1fbc6d0af535d91d045bfc9fc4"
    source = SOURCE.read_text(encoding="utf8")
    tree = ast.parse(source)
    deny = {"open", "urlopen", "get", "post", "put", "request", "connect",
            "sign", "verify", "unlink", "remove", "rmtree", "system",
            "Popen", "run", "write_bytes", "write_text"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            name = n.func.id if isinstance(n.func, ast.Name) else (
                n.func.attr if isinstance(n.func, ast.Attribute) else "")
            assert name not in deny
    assert "SR25519" in source
    assert "NOT Ed25519" in source
    assert "PRIVATE KEY" not in source
