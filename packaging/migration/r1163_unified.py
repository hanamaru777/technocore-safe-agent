"""One public operator entrypoint. Default is offline; never a migration launcher."""
import argparse
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import sys
import time

spec = importlib.util.spec_from_file_location("r1163_contract", Path(__file__).with_name("r1163_contract.py"))
K = importlib.util.module_from_spec(spec); spec.loader.exec_module(K)

PREREQUISITES = (
    ("M2_K137", "UNKNOWN", "FRESH_PROVIDER_ONE_SHOT_GUEST_REPORT_AND_OWNER_REVIEW"),
    ("M2_ORACLE", "NO_GO", "INDEPENDENT_ORIGINAL_GUEST_SSHD_ANCHOR_AND_FRESH_BOOT_SCOPE"),
    ("R1160", "UNKNOWN", "EXISTING_NEW_PC_PUBLIC_BINDING_AND_ACL_ONLY_NO_REIMPORT"),
    ("G3", "NO_GO", "ORIGINAL_DID_VAULT_NONPORTABLE_CUSTODY_OR_ISOLATED_REMOTE_SIGNER_PROOF"),
    ("G4", "NO_GO", "ENFORCEABLE_GLOBAL_FIVE_ROUTE_DENY_INCLUDING_FUTURE_LAUNCHES"),
    ("G5", "NO_GO", "COMPLETE_AUTHENTICATED_HISTORY_FINALITY_UNKNOWN_NEVER_REPLAY"),
    ("G6_G7", "NO_GO", "TRUE_FULL_STATE_EPOCH_OFFHOST_READBACK_AND_INDEPENDENT_DISARMED_RESTORE"),
    ("M6", "NO_GO", "CONCURRENT_CAPACITY_AND_SEPARATE_NEW_ONLY_ACTIVATION"),
    ("M7", "NO_GO", "OBSERVED_STABILITY_AND_SEPARATE_ROLLBACK_CONSENT_KEEP_VM_AND_VOLUMES"),
    ("TESTNET", "UNKNOWN", "OFFICIAL_RELEASE_GENESIS_RPC_ATTRIBUTION_AND_SETTLEMENT_UNAVAILABLE"),
)


def testnet():
    # Reuse the exact T1150 implementation from pinned main. No watch, wallet,
    # faucet, registration, inference adapter, signature or network call.
    K.source_map()
    sys.path.insert(0, str(K.ROOT/"src"))
    from flop_agent import testnet_day1
    status = testnet_day1.status()
    return dict(state="UNKNOWN", official_release="NOT_RELEASED_AT_LAST_PUBLIC_CHECK", checked_on="2026-11-06",
                attribution="UNKNOWN",
                live_ready=status["live_ready"], code_evidence=status["code_evidence"],
                code_fingerprint=status["code_fingerprint"], plan=testnet_day1.plan(),
                faucet_previous_outcome="UNKNOWN_NO_RETRY", spend=0, network_access="NONE")


def custody_metadata(*, capsule=None):
    """Explicit local PUBLIC proof/ACL check, never private-file content access.

    This is not credential availability/signing authority. The capsule location
    is an exact optional owner path, never discovered by a recursive search.
    Nothing here calls local_key(), unseal(), import or any owner operation.
    """
    M = K.legacy("r1157_operator.py")
    C = K.legacy("r1160_owner_continuity.py")
    folder = M.store_path()
    M.secure_path(folder, directory=True)
    M.secure_path(folder/"public.json")
    public = M.read_public(folder/"public.json")
    M.validate_descriptor(public)
    C.verify_local(folder, public, M, control=M.control_identity())
    M.secure_path(folder/"approval.pem.enc")  # metadata/ACL only
    capsule_state = "PATH_NOT_SUPPLIED"
    if capsule is not None:
        p = Path(capsule)
        K.need(p.is_absolute() and p.name == "credentials.sealed.json", "CAPSULE_EXACT_PATH_REQUIRED")
        M.secure_path(p)  # no read, hash, parse, unseal or re-import
        capsule_state = "ACL_CHECKED_CONTENT_NOT_ACCESSED"
    return dict(state="PASS", scope="PUBLIC_SAME_OWNER_BINDING_AND_ACL_ONLY",
                capsule=capsule_state, private_material="NOT_ACCESSED",
                approval_key="EXISTING_SAME_KEY_NOT_ORIGINAL_DID", credential_use="NO_GO",
                aws_path="EPHEMERAL_R1162_NO_OLD_PEM", reimport="PROHIBITED")


def public_input(path):
    K.source_map()
    sys.path.insert(0, str(K.ROOT/"src"))
    from flop_agent.testnet_day1 import read_public
    return read_public(path)


def admission_operation():
    """Explicit future owner operation only. Not invoked during implementation.

    The unchanged runner owns its sole interactive approval and durable marker
    BEFORE AWS access. Its fixed source prints only a redacted result. A failure
    leaves its consumed marker; this wrapper neither clears it nor retries.
    There is no automatic Oracle, M3 or custody operation after this operation.
    """
    p = K.legacy("r1162_k137_provider_admission.py")
    original = sys.argv
    output = io.StringIO()
    try:
        sys.argv = [str(K.ROOT/"packaging/migration/r1162_k137_provider_admission.py"), "--execute"]
        with contextlib.redirect_stdout(output):
            code = p.main()
    finally:
        sys.argv = original
    raw = output.getvalue().encode("ascii")
    K.need(0 < len(raw) <= 32768, "ADMISSION_PUBLIC_OUTPUT_STOP")
    packet = p.strict(raw)
    if code != 0:
        # No forwarding of arbitrary exception text, child diagnostics or files.
        return dict(state="NO_GO", operation="R1162", outcome="STOP_NO_AUTOMATIC_RETRY", marker="RETAIN_IF_CREATED")
    checked = K.k137_receipt(packet, packet["body"]["challenge"], now=int(time.time()))
    return dict(**checked, public_receipt=packet, next_action="INDEPENDENT_REVIEW_ONLY")


def report():
    pins = K.source_map()
    return dict(task="R1163", mode="OFFLINE_NO_PROD", state="NO_GO",
                source_base=K.BASE, imported_t1150=K.T1150,
                source_files_checked=len(pins["files"]), prerequisites=[dict(component=c, state=s, evidence=e) for c,s,e in PREREQUISITES],
                capacity=K.resource_plan(), testnet=testnet(),
                historic_consumed=["R1160_RECIPIENT_SEAL_IMPORT", "R1071_BOUNDED_PROBE", "OWNER_SOURCE_INVENTORY",
                    "R1126_R1138_R1143_R1144", "R1095_CLEANUP", "INITIAL_FAUCET_POST", "OLD_PC_SCANS"],
                source_migration="NO_GO", activation="NO_GO", post="DISABLED",
                oracle_vm_stop="NO_GO", volume_delete="NO_GO", tradebot="PRESERVE",
                next_action="INDEPENDENT_CHATGPT_SOURCE_AUDIT_THEN_EXPLICIT_OWNER_K137_ONLY_APPROVAL")


class PublicParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default diagnostics reflect unknown values to stderr.
        # This public-only entrypoint never echoes even an accidental secret.
        raise K.Stop("PUBLIC_CLI_SCHEMA_STOP")


def main(argv=None):
    parser = PublicParser(description="R1163 public offline readiness / separately approved K137-only admission")
    parser.add_argument("operation", nargs="?", default="status", choices=("status", "custody-check", "oracle-import", "k137-review", "admit-k137"))
    parser.add_argument("--public-file")
    parser.add_argument("--challenge")
    parser.add_argument("--capsule-path")
    parser.add_argument("--execute", action="store_true")
    try:
        a = parser.parse_args(argv)
        K.need(not a.execute or a.operation == "admit-k137", "EXECUTION_NOT_AUTHORIZED")
        K.need(not (a.public_file or a.challenge) or a.operation in ("oracle-import", "k137-review"), "UNUSED_PUBLIC_INPUT_STOP")
        K.need(not a.capsule_path or a.operation == "custody-check", "UNUSED_CAPSULE_PATH_STOP")
        result = report()  # all prerequisites upfront in every public bundle
        if a.operation == "custody-check":
            result["custody"] = custody_metadata(capsule=a.capsule_path)
        elif a.operation in ("oracle-import", "k137-review"):
            K.need(a.public_file is not None and a.challenge is not None, "PUBLIC_PACKET_AND_FRESH_CHALLENGE_REQUIRED")
            fn = K.original_anchor if a.operation == "oracle-import" else K.k137_receipt
            result["public_review"] = fn(public_input(a.public_file), a.challenge, now=int(time.time()))
        elif a.operation == "admit-k137":
            K.need(a.execute, "SEPARATE_EXPLICIT_OWNER_EXECUTION_REQUIRED")
            result["admission"] = admission_operation()
        print(K.canonical(dict(body=result, sha256=K.sha(K.canonical(result)))).decode("ascii"))
        return 42  # local code/evidence consistency never implies production GO
    except Exception:
        # Never reflect exception text, input fields, paths, secrets or a
        # partly validated packet. Detailed redacted blocker lives in runbook.
        print(K.canonical(dict(task="R1163", state="NO_GO", code="UNVERIFIED_STOP_NO_AUTOMATIC_RETRY",
                               migration="NO_GO", post="DISABLED", oracle_vm_stop="NO_GO")).decode("ascii"))
        return 42


if __name__ == "__main__":
    raise SystemExit(main())
