"""R1098 static, zero-cost/zero-seed AWS KMS algorithm coverage audit."""
from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "packaging/migration/r1098_ed25519_kms_portability.py"
spec = importlib.util.spec_from_file_location("r1098_portability", FILE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def test_pinned_real_canonical_algorithm_and_byte_size():
    report = m.assess()
    assert report["result"] == "OFFLINE_COMPATIBILITY_LIMIT_CONFIRMED"
    assert report["source_git_blob"] == "MATCH"
    assert report["original_did_algorithm"] == "Ed25519"
    assert report["required_message_type"] == "RAW"
    assert report["original_canonical_byte_lengths"]["say_ascii_max_bytes_lower_bound"] == 4100
    assert report["original_canonical_byte_lengths"]["set_ascii_max_bytes_lower_bound"] == 8198
    assert report["original_canonical_byte_lengths"]["say_unicode_max_bytes_example"] == 16388
    assert report["protocol_full_coverage"] == "NO_GO"
    assert report["cloud_calls"] == 0 and report["cutover"] == "NO_GO"


def test_source_check_fails_closed_on_untrusted_shape(monkeypatch, tmp_path):
    original = m.SIGNER.read_bytes()
    altered = tmp_path / "sign.py"
    altered.write_bytes(original.replace(b"MAX_VALUE_CHARS = 8192", b"MAX_VALUE_CHARS = 4000"))
    monkeypatch.setattr(m, "SIGNER", altered)
    try:
        m.assess()
    except m.Stop as ex:
        assert str(ex) == "SIGNER_SOURCE_BLOB_STOP"
    else:
        raise AssertionError("source drift was silently admitted")


def test_never_invents_signer_or_secret():
    source = FILE.read_text(encoding="utf-8")
    assert "boto3" not in source and "import oci" not in source
    assert "SIGN_SEED" not in source
    assert "kms.sign(" not in source
    assert m.REQUIRED_SIGN_ALGORITHM == "ED25519_SHA_512"
    assert m.AWS_KMS_SIGN_RAW_BYTES_MAX == 4096
