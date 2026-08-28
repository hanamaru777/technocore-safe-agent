import base64
import sys
from types import SimpleNamespace

import pytest

from flop_agent import oracle_signer


def test_vault_seed_accepts_general_oci_ocid_charset(monkeypatch):
    secret_id = "ocid1.vaultsecret.oc1.ap-tokyo-1.Example_ABC123"
    monkeypatch.setenv("OCI_VAULT_SECRET_OCID", f"  {secret_id}  ")
    calls = []

    class Client:
        def __init__(self, config, signer):
            calls.append((config, signer))

        def get_secret_bundle(self, **kwargs):
            calls.append(kwargs)
            content = base64.b64encode(b"a" * 64).decode()
            return SimpleNamespace(
                data=SimpleNamespace(
                    secret_bundle_content=SimpleNamespace(content=content)
                )
            )

    fake = SimpleNamespace(
        auth=SimpleNamespace(
            signers=SimpleNamespace(
                InstancePrincipalsSecurityTokenSigner=lambda: "instance-principal"
            )
        ),
        secrets=SimpleNamespace(SecretsClient=Client),
    )
    monkeypatch.setitem(sys.modules, "oci", fake)

    seed = oracle_signer.vault_seed()
    assert seed == bytearray(b"a" * 64)
    assert calls[1] == {"secret_id": secret_id, "stage": "CURRENT"}
    seed[:] = b"\0" * len(seed)


def test_vault_seed_rejects_shell_metacharacters_before_oci(monkeypatch):
    monkeypatch.setenv(
        "OCI_VAULT_SECRET_OCID",
        "ocid1.vaultsecret.oc1.ap-tokyo-1.example;rm",
    )
    with pytest.raises(RuntimeError, match="identifier is invalid"):
        oracle_signer.vault_seed()
