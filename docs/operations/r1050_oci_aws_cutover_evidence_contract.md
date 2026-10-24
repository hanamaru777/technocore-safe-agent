# R1050 — OCI→AWS preservation and cutover proof boundary

**2026-10-24 | SOURCE ONLY | DRAFT / DO NOT MERGE, DEPLOY OR RUN ON PRODUCTION**

Authoritative historical record: Flop Issues #765 (v229) and #842.
TradeBot K137Q public-history incident: separate TradeBot Issue #626.
No Production instruction, restart, code execution or credential transfer is
authorized by this specification.

## Source and observed facts (never rerun already consumed passes)

・Original Flop OCI source HEAD ec4bc4892d40cdd2a03e102faa44d72c89e01b99.
  R1034/R1039/R1041 real read-only witnesses passed and are CONSUMED.
・R1041 signer local ledger: prepared=2, quarantined=2, recognized controlled
  E2E=2, unaccounted prepared=0, unaccounted quarantined=0, active/ambiguous
  outbox=0, ACK hash and local nonce binding both consistent.
  However autopilot is enabled and NOT paused; ledger reads are sequential,
  signer is live, in-flight external POST has NOT been independently resolved.
・Capture uses TWO different WAL-mode SQLite files: lobby-capture.sqlite3 and
  lobby-capture-service.sqlite3. A successful SQLite online copy of either
  does not prove a common source writer epoch.
・Known TCLK workers/timers, unknown oneshot services, possible cron writers,
  signer, Resident and independent Capture must all be included in the global
  writer freeze. R1041 classifies two unexpected oneshot ExecStart targets as
  OTHER_UNVERIFIED. A missing ReadWritePaths declaration does NOT prove RO.
・AWS K137 already completed isolated Flop-only source, venv, pinned package
  stages Phase01/02/03C (ACTUAL PASS/CONSUMED). No Flop live process may be
  activated. K137 is a 2GB/no-swap shared host, mixed capacity unverified.
  K137Q public service failed naturally 2026-10-24 02:02 UTC from ONE
  missing historical result file, h1-20261020T090000Z. Its safe HOLD is
  separate TradeBot authority; do NOT edit/delete/fill/replay that hour.
・AWS IMDSv2 token and iam/info HTTP200 are only metadata endpoint evidence,
  not proof of GetWebIdentityToken permission, OCI token exchange or Vault.

## R1050 six-file OFFHOST verifier

New source-only tool: packaging/archive/r1050_offhost_sixfile_audit.py.
It is built on the existing PR #880 R1005 SQLite image validator.
It is for a FUTURE independently preserved, sealed bundle on a separate,
non-root, non-production Linux host. It refuses live K137 and original OCI.

Exactly six permitted flat regular filenames:
・lobby-capture.sqlite3
・lobby-capture-service.sqlite3
・oracle-signer-receipts.json
・autopilot-outbox.json
・nonces.json
・verified-did.json

These SIX files are a deliberately narrow audited subset, NOT a complete Flop
state archive. Observer/Resident cursor state, activity/health logs,
Close1/TCLK artifacts, and additional original metadata still need an
independent whole-state inventory and authenticated preservation.
Passing this subset NEVER establishes whole-state restore.

The independently supplied private pin-map JSON must contain schema_version=1
and pins with exactly these six lowercase SHA256 entries. The pin map itself
is NOT an independently authenticated original source claim. The verifier
refuses extra files, WAL/SHM sidecars, symlinks (including pin-map ancestor directories), hardlinks, non-private files,
wrong ownership and hashes; it runs both R1005 real SQLite schema/integrity
checks. It only hashes the four private JSON ledgers and does NOT claim their
schemas/cross-file provenance or print their contents. No file is modified.

Even after all six byte/pin checks pass the output is UNCONDITIONALLY:
・PIN_MAP_SOURCE_AUTHENTICITY=NOT_PROVEN
・PINNED_FILES_ORIGINAL_OCI_PROVENANCE=NOT_PROVEN
・PRIVATE_LEDGER_SCHEMA=NOT_VERIFIED
・COMMON_WRITER_EPOCH=NOT_PROVEN
・EXTERNAL_SIGNER_POST_AND_NONCE=NOT_PROVEN
・ALL_WRITERS_FENCED=NO
・OCI_RETIREMENT=STRICT_NO_GO

Passing R1050 does NOT replace independently authenticated original signer
identity, writer freeze, in-flight POST, common epoch or restored provenance.

## Architecture gates, in strict dependency order

### 1. Same DID / Vault custody — NOT PROVEN

Current AWS Phase03C installed only the ten core locked runtime wheels plus
a pinned pip wheel. The OCI Python SDK dependency for the signer was NOT
staged on AWS. Original pyproject.toml declares optional signer-only
oracle-signer extra (oci>=2.0,<3), and the original Oracle prepare-signer.sh
installs it via frozen uv sync. Thus core-dependencies PASS cannot be
misreported as AWS signer-runtime PASS. Do not install the signer SDK or
reuse Oracle signer install scripts on K137 without a separate safe gate.

Original signer retrieves OCI Vault secret using OCI VM-only
InstancePrincipalsSecurityTokenSigner in oracle_signer.py. This does not
work unchanged from AWS Lightsail. No copying seed to chat/GitHub/general K137
user/compromised Dell or creating permanent OCI API keys as a shortcut.

Candidate ONLY: AWS STS GetWebIdentityToken outbound JWT → OCI IAM
JWT-to-RPST identity-domain federation → grant narrowly scoped access
to existing Vault secret. This could avoid plaintext seed export and
preserve DID while retiring OCI compute, but Lightsail workload IAM
credentials, explicit AWS IAM sts:GetWebIdentityToken authorization, feature
enablement, exact issuer/subject/audience, OCI tenant/identity-domain
availability, trust, SDK RPST handling and cost are all UNCONFIRMED.
AWS IAM/OCI account setup must not be changed without separate authorization.

Official primary documentation:
https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound_getting_started.html
https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound_policies.html
https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/token_exchange_grant_type_workload_id-federation.htm

### 2. Genuine complete writer fence and signer drain — NOT PROVEN

Plan exact known/unknown service/timer/TCLK/cron/process/boot writer paths,
including resident→capture lifecycle. Future production fence must be a
separately owner-approved operation with rollback, before snapshot.
Paused autopilot alone does not prove no in-flight POST. Distinguish
zero local queue, verified process drain, external accepted/unknown POST,
nonce watermark and DID identity. Never resubmit the quarantined E2E entries.

### 3. ONE source writer epoch for all six files — NOT PROVEN

After a provable no-writer barrier, use SQLite backup API (not raw live-WAL
copy) on EACH of the two capture databases without releasing barrier.
Within the same barrier capture four signer/nonce/DID ledgers. A separately
authenticated original-OCI source attestation must bind source HEAD,
writer/timer/process fence witnesses, UTC + monotonic epoch, image digests,
custody, and rollback. A self-assertion inside the same untrusted bundle
cannot prove original source authenticity or no intervening writes.
Review restored offhost copies with PR #880 and the new R1050 only AFTER
these gates; PR #881 sealed transfer is also independently gated.

### 4. AWS mixed-resource test, continuity and retirement — NOT PROVEN

Require measured simultaneous K137 public timer + prospective Flop workload
RAM/cgroup/PSI/CPU/disk and safe strict disarmed separation.
Then prove only one publisher, no old nonce replay, same signer DID,
observable upstream continuity, and an independent offsite restore.
Retain old Oracle during rollback window; final OCI release is a
distinct irreversible owner-authorized production task. Never conflate
the separate Aerodrome/TradeBot-owned Oracle VM with Flop's OCI VM.

**Present mandatory outcome: OCI_RETIREMENT=STRICT_NO_GO.**
