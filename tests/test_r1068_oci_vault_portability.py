"""R1068 candidate: synthetic OCI API-key secret reader, zero live network."""
import base64
import importlib.util
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import pytest

FILE = Path(__file__).resolve().parents[1] / "packaging/migration/r1068_oci_vault_portability.py"
spec=importlib.util.spec_from_file_location("r1068_oci_vault_portability", FILE)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
SECRET="ocid1.vaultsecret.oc1.ap-tokyo-1.example"
DID="did:key:z6Mk"+"a"*44

@pytest.fixture(autouse=True)
def signer_stub(monkeypatch):
    core=SimpleNamespace(signer_matches_pinned=lambda:True,current_did=lambda:DID)
    monkeypatch.setitem(sys.modules,"flop_agent",SimpleNamespace(core=core))
    return core


@pytest.fixture
def custody(monkeypatch,tmp_path):
    root=tmp_path/"candidate"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    monkeypatch.setattr(m,"AUTH_ROOT",root)
    key=root/"api_key"
    key.write_text("-----BEGIN RSA PRIVATE KEY-----\nSYNTHETIC-KEY-NOT-REAL\n-----END RSA PRIVATE KEY-----\n")
    key.chmod(0o600)
    cfg=root/"oci_config"
    cfg.write_text(
        "[DEFAULT]\n"+
        "user = ocid1.user.oc1..synthetic\n"+
        "tenancy = ocid1.tenancy.oc1..synthetic\n"+
        "fingerprint = "+":".join(["ab"]*16)+"\n"+
        "key_file = "+str(key)+"\n"+
        "region = ap-tokyo-1\n",encoding="ascii")
    cfg.chmod(0o600)
    return cfg,key,root


def mock_oci(monkeypatch, hexbytes=None, *, failure=None):
    seen=[]
    seed=hexbytes if hexbytes is not None else (b"b"*64)
    class Client:
        def __init__(self, config):
            seen.append(("new",dict(config)))
        def get_secret_bundle(self,**kwargs):
            seen.append(("read",kwargs))
            if failure is not None:
                raise RuntimeError("sensitive backend error PRIVATE_CANARY")
            return SimpleNamespace(data=SimpleNamespace(
                secret_bundle_content=SimpleNamespace(
                    content=base64.b64encode(seed).decode("ascii"))))
    monkeypatch.setitem(sys.modules,"oci",
                        SimpleNamespace(secrets=SimpleNamespace(SecretsClient=Client)))
    return seen


def test_existing_did_candidate_uses_vault_without_printing_seed(custody,monkeypatch,signer_stub):
    cfg,_,_=custody
    seen=mock_oci(monkeypatch)
    observed=[]
    monkeypatch.delenv("SIGN_SEED",raising=False)
    def derive():
        observed.append(os.environ["SIGN_SEED"]=="b"*64)
        return DID
    signer_stub.current_did=derive
    report=m.verify_existing_did(cfg,SECRET,DID)
    assert observed==[True]
    assert report=={
        "original_did":"MATCH", "oci_vault_fetch":"PASS",
        "proof_kind":"LOCAL_DERIVATION_ONLY","external_post":"NOT_PERFORMED",
        "live_signer":"NOT_ACTIVATED","cutover":"NO_GO",
        "oci_retirement":"STRICT_NO_GO"}
    assert seen[1]==("read",{"secret_id":SECRET,"stage":"CURRENT"})
    assert seen[0][1]["key_file"]==str(cfg.parent/"api_key")
    assert "SIGN_SEED" not in os.environ


def test_wrong_original_did_fails_closed_and_cleans_seed(custody,monkeypatch,signer_stub):
    cfg,_,_=custody
    mock_oci(monkeypatch)
    monkeypatch.delenv("SIGN_SEED",raising=False)
    signer_stub.current_did=lambda:"did:key:z6Mk"+"c"*44
    with pytest.raises(m.Stop,match="ORIGINAL_DID_MISMATCH"):
        m.verify_existing_did(cfg,SECRET,DID)
    assert "SIGN_SEED" not in os.environ


def test_invalid_seed_never_calls_derive(custody,monkeypatch):
    cfg,_,_=custody
    mock_oci(monkeypatch,b"invalid")
    monkeypatch.delenv("SIGN_SEED",raising=False)
    with pytest.raises(m.Stop,match="SEED_SHAPE_STOP"):
        m.verify_existing_did(cfg,SECRET,DID)
    assert "SIGN_SEED" not in os.environ


def test_untrusted_backend_failure_is_redacted(custody,monkeypatch):
    cfg,_,_=custody
    mock_oci(monkeypatch,failure=True)
    monkeypatch.delenv("SIGN_SEED",raising=False)
    with pytest.raises(m.Stop,match=r"^OCI_VAULT_FETCH_STOP$") as e:
        m.verify_existing_did(cfg,SECRET,DID)
    assert "PRIVATE_CANARY" not in str(e.value)
    assert "SIGN_SEED" not in os.environ


@pytest.mark.parametrize("mutate",["symlink","world_readable","hardlink","outside","root_exposed"])
def test_private_material_custody_is_enforced(custody,monkeypatch,tmp_path,mutate):
    cfg,key,root=custody
    mock_oci(monkeypatch)
    monkeypatch.delenv("SIGN_SEED",raising=False)
    if mutate=="symlink":
        cfg.unlink()
        cfg.symlink_to(key)
    if mutate=="world_readable":
        cfg.chmod(0o644)
    if mutate=="hardlink":
        other=root/"another"
        os.link(cfg,other)
    if mutate=="outside":
        cfg=tmp_path/"outside";cfg.write_text("test");cfg.chmod(0o600)
    if mutate=="root_exposed":
        root.chmod(0o755)
    with pytest.raises(m.Stop):
        m.verify_existing_did(cfg,SECRET,DID)
    assert "SIGN_SEED" not in os.environ


def test_no_seed_or_auth_in_nonopted_context(custody,monkeypatch):
    cfg,_,_=custody
    calls=mock_oci(monkeypatch)
    monkeypatch.setenv("SIGN_SEED","do-not-overwrite")
    with pytest.raises(m.Stop,match="SEED_ENV_SCOPE_STOP"):
        m.verify_existing_did(cfg,SECRET,DID)
    assert os.environ["SIGN_SEED"]=="do-not-overwrite"
    assert calls==[]


def test_no_production_mutations_or_cli():
    source=FILE.read_text()
    assert "if __name__" not in source
    for forbidden in ("os.system(", "subprocess.run(", "systemctl",
                      "delete_secret", "CreateKey", "create_user", "oci.auth.signers.InstancePrincipals",
                      "ssh-keyscan", "chmod 777", "requests.post("):
        assert forbidden not in source


def test_local_derivation_exception_is_redacted_and_seed_cleared(custody,monkeypatch,signer_stub):
    cfg,_,_=custody
    mock_oci(monkeypatch)
    monkeypatch.delenv("SIGN_SEED",raising=False)
    def broken():
        raise RuntimeError("private seed canary should never reach logs")
    signer_stub.current_did=broken
    with pytest.raises(m.Stop,match=r"^LOCAL_DERIVATION_STOP$") as error:
        m.verify_existing_did(cfg,SECRET,DID)
    assert error.value.__suppress_context__ is True
    assert "private seed canary" not in str(error.value)
    assert "SIGN_SEED" not in os.environ


def test_wrong_official_signer_pin_never_reaches_oci(custody,monkeypatch,signer_stub):
    cfg,_,_=custody
    calls=mock_oci(monkeypatch)
    signer_stub.signer_matches_pinned=lambda:False
    monkeypatch.delenv("SIGN_SEED",raising=False)
    with pytest.raises(m.Stop,match="SIGNER_PIN_STOP"):
        m.verify_existing_did(cfg,SECRET,DID)
    assert calls==[]


def test_callsite_rejects_arbitrary_user_supplied_derivation(custody,monkeypatch):
    cfg,_,_=custody
    calls=mock_oci(monkeypatch)
    with pytest.raises(TypeError):
        m.verify_existing_did(cfg,SECRET,DID,lambda:pytest.fail("unsafe callback"))
    assert calls==[]
