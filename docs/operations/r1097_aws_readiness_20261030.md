# FLOP OCI → AWS K137: actual host status at 2026-10-30 JST

This is a short current operational checkpoint. **Production state and operator evidence override historical code/CI.** Detailed original chronology lives in Issue #765, operational R1095/R1097 results in Issue #905.

## Completed and accepted — DO NOT REPEAT

- Original Oracle `technocore-resident`, target OCI app HEAD `ec4bc4892d40cdd2a03e102faa44d72c89e01b99`: R1095 owner executed **one** pinned R987 Windows SSH cleanup; result `APPLIED`; 2,443 old atomic JSON temps deleted, **19,405,111,296 allocated bytes freed**, disk free rose from **11,826,589,696 to 31,231,700,992 bytes**, equal delta. Three files deliberately skipped for safety. No rerun. Original 5,166,563,328-byte `autopilot-audit.preperf-20260904T023321Z.jsonl` and source SQLite/WAL/DID/signer preserved by R1095 scope. The R1095 receipt is not an independent G4/G5 proof.
- Original historical R1072/R1080 all-root census (30,682 entries; 25,983,618,920 regular logical bytes, two DB/two WAL, 28 symlinks) was accepted **BEFORE R1095**. Never reuse its source byte count as the post-cleanup encrypted archive/restore pin; never rerun its consumed one-shot.
- AWS Lightsail existing **`tradebot-k137`** in Tokyo `ap-northeast-1`. Owner ran R1097 from AWS CloudShell which authenticated via short-lived AWS Lightsail keys/certificate to K137 Ubuntu; only R1096 metadata-only guest executed. **Success on K137**, `disk_total_bytes=61,285,326,848`, `disk_free_bytes=47,270,965,248`. Pre-restoration 20GiB reserve = 21,474,836,480 bytes, giving **25,796,128,768 bytes** possible restoration budget at that observation, *before* fresh proof of actual source bytes and payload/runtime overhead. At restore time repeat capacity check as integrated R1089 normal admission, not another broad discovery probe.
- K137 FLOP shadow `/opt/flop-shadow`: **5,488,640 allocated bytes**, 393 files (420 objects, no symlinks), all `OTHER_PROTECTED`; existing pinned staged release. K137 FLOP landing `/var/lib/flop-migration-r1066`: **4,096 allocated bytes**, 0 files. **No proven disposable AWS FLOP files**. Do not delete on AWS just to satisfy cleanup demand; no FLOP-only significant reclaim possible by evidence.
- TradeBot (its service, timers, processes, ledgers, current bot code, credentials and allocated reserve) never visited by R1096 and MUST remain untouched. R1096 is only storage observation, not a health or execution guarantee.
- First attempt R1096 in `~ $` shell failed K137_USER_STOP (AWS CloudShell vs K137 Ubuntu context). This was corrected by R1097 authenticated AWS CloudShell→Lightsail short-lived SSH. Do not rerun direct R1096 on CloudShell; **R1097 is also now accepted/consumed**.
- Oracle **Cloud Shell** monthly quota exhausted, not usable; AWS CloudShell is a distinct service. Remote Desktop Commander quota exhausted. Do not suggest either for the Oracle path.

## Proven implementation, not yet a real migration

- PR [#906](https://github.com/hanamaru777/technocore-safe-agent/pull/906) stays **DRAFT**, stacked over PR #899. Branch `codex/r1066-real-oci-to-k137-transfer-v1`. R1089 package already integrates controlled Windows→OCI encrypted R1001 AEAD archival into protected offhost NTFS and a disarmed K137 restoration. Prior synthetic CI PASS, **not live original source backup or AWS restore**. Do not reimplement passed components.
- A full encrypted backup of **both original app/state roots** is required with coherent two-SQLite/WAL and all POST/DID/nonce/ledger authority epoch. No backup yet. Windows private NTFS offhost admission, owner signed plan/trust enrollment, fresh exact source census during one fenced acquisition remain unproven.
- Gate **G4** original all-writer/launcher admission and independently signed continuous renewal is still missing. This must cover Capture, Resident, Discord, signer, TCLK, Close1, cron/systemd/manual transient restarts, writable FD and generation fencing.
- Gate **G5** requires **five authoritative POST route finality checks**: `oracle_signer`, `tclk_pilot_accept`, `tclk_pilot_reveal_publish`, `close1_approved_trade`, `close1_batch_trade`. Local prepared/quarantined records or no outbox entries are not upstream proof. Never replay attempts.
- Gate **G3** same-original-DID signer portability: OCI Vault original uses `InstancePrincipalsSecurityTokenSigner`. AWS Lightsail cannot simply impersonate OCI instance principal; no enrolled zero-extra-cost no-seed-export identity bridge, permission, disarmed original-DID proof. Cannot retire original until actual supported source-backed approach established.
- Gates G0/G1/G2/G6/G7/G8 need fresh signed authority epoch, evidence and distinct cutover/retirement approvals. Historical known AWS free alone does not make them PASS.

## New 2026-10-30 signer portability finding (source and Oracle/AWS official docs)

OCI **announced JWT→RPST external workload identity federation on 2026-08-26** (Oracle official release note:
https://docs.oracle.com/en-us/iaas/releasenotes/identity/jwt_to_rpst_token_exchange_for_workload_identity_federation.htm).
OCI officially documents validation of external issuer JWT, identity propagation trust,
short-lived Resource Principal Session Token exchange, and authorized OAuth client or
service/instance-principal signed token-exchange requests:
https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/token_exchange_grant_type_workload_id-federation.htm

This is a promising **OCI control-plane authentication candidate**, NOT an approved,
implemented or tested Lightsail signer, and NOT a seed non-export scheme.
An external trustworthy OIDC JWT issuer, OCI propagation-trust mapping, audience, client
authorization and refresh route on the actual continuously running K137 are not
enrolled or verified. AWS documentation for **Lightsail**, unlike EC2 instance profiles,
says Lightsail does not support general service roles:
https://docs.aws.amazon.com/lightsail/latest/userguide/security_iam_service-with-iam.html
Do not apply EC2 `associate-iam-instance-profile` instructions to Lightsail.

More importantly, original source `src/flop_agent/oracle_signer.py` lines 126–153
uses `oci.auth.signers.InstancePrincipalsSecurityTokenSigner()` to obtain a
`SecretsClient.get_secret_bundle(..., stage="CURRENT")` result. That bundle
contains the original signing seed, which the process decodes into its own
temporary memory. **Replacing OCI credentials with a federated RPST only
authenticates this retrieval: it does not magically make seed signing remote
or prevent secret data from crossing into the K137 process.** If the
non-export seed-custody boundary is retained, simply running that code
on AWS—even with perfect WIF—violates it.

Therefore G3 stays **NO_GO** until the owner separately authorizes one verifiably
safe concrete design, with full nonce/DID/receipt continuity and no unnecessary
credential exposure:
- A source-backed remote signing primitive or isolated signing endpoint that
  can perform the existing DID algorithm without returning the signing seed
  to an AWS workload. Whether OCI Vault supports the exact algorithm and
  service model is **UNCONFIRMED**; do not assume OCI KMS can sign Ed25519 DID.
- If explicit approval ever permits a changed custody boundary, a least-privilege
  alternative with short-lived federated authentication, seed transient custody,
  auditable revocation, disarmed exact-DID verification and complete five-route
  continuity could be separately evaluated; this is a **new security decision**,
  not implicit permission from a migration request.
- Retain original OCI signer and K137 GET-only, if needed to avoid unsafe
  export, but acknowledge this cannot retire Oracle. This is an interim
  architecture, not completed migration.

**Ed25519 algorithm hard stop — verified against current official key specs**:
The original DID signing algorithm is Ed25519. OCI Vault's remote asymmetric
`SignData` API supports only RSA or ECDSA signatures (explicit documented
algorithms do NOT include Ed25519):
https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/usingkeys_topic-To_sign_data_by_using_your_Vault_master_encryption_key.htm
https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/kms/crypto/signed-data/sign.html
Therefore replacing the original OCI Vault **Secret Bundle** with a call to
the current OCI KMS remote signing API is NOT compatible with the existing
Ed25519 DID. Do not run an algorithm-changing key migration or claim that it
retains the DID. AWS KMS *does* document a new Ed25519 asymmetric signing key
type, but a newly created public key changes the DID and KMS introduces
unverified costs/permissions. It is not an authorized zero-extra-cost,
no-export route for the existing original private key:
https://docs.aws.amazon.com/kms/latest/developerguide/kms-cryptography.html
Any theoretical import of the old key into AWS custody also crosses the
currently forbidden seed-export boundary, and is not approved. **G3 remains
blocked** until a specifically reviewed original-key-preserving custody
architecture exists.

No OCI IAM policy, cloud role, instance profile, secret or runtime was changed
during this research. Fees and tenancy-specific token-exchange enablement are
unverified; do not promise zero cost for a new identity-domain deployment.

## Next authorized sequence

1. **No more deletions on either host.** Accept current AWS FLOP space as ready and safely isolated. Keep the existing 20GiB protected margin for TradeBot/OS; no new paid infrastructure.
2. First address G3 signer portability and independently owner-authorized G4+G5 fence/finality, not another disk probe. Audit 27 named templates and five routes from existing `r1063_release_gates.py`, `docs/operations/r1063_consolidated_migration_gates.md`; do not fake approvals or widen source scope.
3. With proper authority, use the already-implemented R1089 Windows offhost owner acquisition, a **fresh** dynamically computed post-R1095 source-byte manifest and AEAD final commit. Do not place the full ciphertext backup on the shared K137 disk in parallel with restored plaintext; preserve an independent validated offhost ciphertext copy.
4. Using that verified existing archive, run K137 **disarmed-only** isolated restore, independent file/SQLite/ledger/DID verification, natural TradeBot unaffected health and runtime envelope checks. Cold development can continue in GitHub meanwhile; production FLOP activation must wait for G0–G8 GO and separate approval.
5. At most one publisher after approved cutover; preserve the original Oracle backup/source throughout rollback hold. Later distinct OCI retirement approval requires zero remaining references and validated stable destination. **Never delete original OCI while either G3/G4/G5 or full offhost backup and verified destination is missing.**

## Current honest decisions

- `ORACLE_ORPHAN_CLEANUP=COMPLETE` (2,443 files / 19,405,111,296 bytes).
- `AWS_K137_CAPACITY_CHECK=PASS_READONLY` (47,270,965,248 bytes free at observation).
- `AWS_FLOP_CLEANUP=NOT_NEEDED` (no proven disposable file).
- `FULL_OFFHOST_ARCHIVE=NOT_CREATED`; `K137_RESTORE=NOT_EXECUTED`; `PORTABLE_ORIGINAL_DID=NOT_PROVEN`.
- `CUTOVER=NO_GO`; `OCI_RETIREMENT=STRICT_NO_GO`.

Do not declare completion from code-only CI, host capacity or dry-run. Do not request redundant operator action, Codex credits, or Remote Desktop Commander access.
