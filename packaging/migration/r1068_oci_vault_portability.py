"""R1068 candidate: prove existing DID using OCI Vault WITHOUT an OCI VM.

AWS/OCI API-key auth candidate only, NOT default signer wiring or production
approval. Keep the original seed inside OCI Vault, fetch it into process memory
for a single local DID derivation, and never log/return its bytes.

Requires an ALREADY provisioned least-privilege OCI IAM user API key whose
sole necessary permission is read the pinned existing Vault secret. This code
never creates credentials, grants IAM policies, or launches a service.
"""
import base64
import configparser
import hmac
import os
from pathlib import Path
import re
import stat

AUTH_ROOT = Path("/etc/flop-migration-signer")
OCID = re.compile(r"ocid1\.vaultsecret\.oc[1-9][0-9]?\.[0-9A-Za-z_-]*\.[0-9A-Za-z_-]+")
DID = re.compile(r"did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{20,128}")
FP = re.compile(r"(?:[a-f0-9]{2}:){15}[a-f0-9]{2}")
USER = re.compile(r"ocid1\.user\.oc1\.[A-Za-z0-9._-]+")
TENANCY = re.compile(r"ocid1\.tenancy\.oc1\.[A-Za-z0-9._-]+")
REGION = re.compile(r"[a-z]{2}-[a-z-]+-[1-9][0-9]?")
SEED = re.compile(rb"[a-f0-9]{64}\Z")
CONFIG_FIELDS = {"user", "tenancy", "fingerprint", "key_file", "region"}


class Stop(ValueError):
    pass


def need(ok, code):
    if not ok:
        raise Stop(code)


def owner_file(path, *, max_size):
    p = Path(path)
    root = AUTH_ROOT
    need(p.is_absolute() and p.parent == root and p.name not in ("", ".", ".."),
         "AUTH_SCOPE_STOP")
    for candidate in (root, *root.parents):
        need(not candidate.is_symlink(), "AUTH_LINK_STOP")
    rs = root.lstat()
    need(stat.S_ISDIR(rs.st_mode) and rs.st_uid in (0, os.geteuid())
         and stat.S_IMODE(rs.st_mode) == 0o700, "AUTH_ROOT_STOP")
    s = p.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1
         and s.st_uid == os.geteuid() and stat.S_IMODE(s.st_mode) == 0o600
         and 0 < s.st_size <= max_size, "AUTH_FILE_STOP")
    return p


def authenticated_config(path):
    cfgfile = owner_file(path, max_size=4096)
    parser = configparser.RawConfigParser(interpolation=None, strict=True)
    try:
        with cfgfile.open("r", encoding="ascii") as f:
            parser.read_file(f)
        need(not parser.sections(), "AUTH_CONFIG_STOP")
        values = dict(parser.defaults())
        need(set(values) == CONFIG_FIELDS
             and USER.fullmatch(values["user"])
             and TENANCY.fullmatch(values["tenancy"])
             and FP.fullmatch(values["fingerprint"])
             and REGION.fullmatch(values["region"]), "AUTH_CONFIG_STOP")
        key = owner_file(values["key_file"], max_size=16384)
        need(key != cfgfile, "AUTH_CONFIG_STOP")
        need(key.read_bytes().startswith((b"-----BEGIN ",)), "AUTH_KEY_HEADER_STOP")
    except (OSError, UnicodeError, configparser.Error, KeyError, TypeError) as error:
        raise Stop("AUTH_CONFIG_STOP") from error
    return values


def verify_existing_did(config_path, pinned_secret_id, pinned_did, derive_did):
    """Remote Vault READ + one local public DID derivation, never POST or persist.

    derive_did must be an independently reviewed local deterministic DID
    derivation (e.g. core.current_did); no network/external signing is authorized.
    """
    need(type(pinned_secret_id) is str and OCID.fullmatch(pinned_secret_id),
         "VAULT_SCOPE_STOP")
    need(type(pinned_did) is str and DID.fullmatch(pinned_did), "DID_PIN_STOP")
    need(callable(derive_did) and "SIGN_SEED" not in os.environ,
         "SEED_ENV_SCOPE_STOP")
    config = authenticated_config(config_path)
    try:
        import oci
        client = oci.secrets.SecretsClient(config=config)
        bundle = client.get_secret_bundle(
            secret_id=pinned_secret_id, stage="CURRENT").data
        content = bundle.secret_bundle_content.content
        raw = bytearray(base64.b64decode(content, validate=True))
    except Exception:
        # Never chain vendor errors: their repr can contain identifiers,
        # credential URLs or secret response details in systemd logs.
        raise Stop("OCI_VAULT_FETCH_STOP") from None
    seed = raw
    try:
        need(SEED.fullmatch(seed), "SEED_SHAPE_STOP")
        os.environ["SIGN_SEED"] = seed.decode("ascii")
        try:
            actual = derive_did()
        except Exception:
            raise Stop("LOCAL_DERIVATION_STOP") from None
        need(type(actual) is str and hmac.compare_digest(actual, pinned_did),
             "ORIGINAL_DID_MISMATCH")
        return {"original_did": "MATCH", "oci_vault_fetch": "PASS",
                "proof_kind": "LOCAL_DERIVATION_ONLY",
                "external_post": "NOT_PERFORMED", "live_signer": "NOT_ACTIVATED",
                "cutover": "NO_GO", "oci_retirement": "STRICT_NO_GO"}
    finally:
        os.environ.pop("SIGN_SEED", None)
        seed[:] = b"\x00" * len(seed)
