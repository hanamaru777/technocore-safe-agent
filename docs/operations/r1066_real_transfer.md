# R1066 executable preservation components — PARTIAL, CUTOVER BLOCKED

Issue #905. Base `f2244967c6d0e0079ddd95eb38fd33baef3839f7`.
This package performs real encrypted file preservation, ciphertext copying and
independent disarmed restoration on an authorized **offhost Linux copy**.
V2 adds a runnable Windows PowerShell 5.1 two-host read-only preflight, the
fallback authorized by Issue #905's v2 comment when independent K137 enrollment
and restore authority are unavailable. It does not implement the complete
Windows-to-OCI-to-K137 migration run.
Do not describe its CI success as a completed migration or a live-host test.

## Capabilities that execute actual I/O

`r1066_transfer.py archive` recursively enumerates both supplied application and
state trees with no excluded roots. It records every regular file, directory,
symlink and hardlink in an encrypted manifest, hashes actual binary bytes,
streams file contents without a plaintext tar/temp file, then rechecks the
whole tree before writing the authenticated final commit. Source drift and
unsupported special objects stop the candidate. Original files are never
modified or deleted. Archives without a final commit are incomplete forever;
encryption is never resumed with an old key/nonce pair.

The original R1001 component is vendored **byte-for-byte** as
`r1066_sealed_dependency.py`, Git blob
`f52bcea342cd5a08e7a0e9383d587404416d4785`, from PR #879's audited branch.
Its structures, PBKDF2/600000, AES-256-GCM, per-chunk sequence/nonces, AAD,
compression, 128MiB parts, authenticated final commit and existing Writer are
reused. R1066 envelopes can be independently checked by the unchanged R1001
verifier. No unauthenticated CBC format or seed-derived archive key is used.
The archive recovery material is **independent of R987 and the DID seed** and
entered using a hidden prompt; no CLI/env key input exists. Python cannot
guarantee erasure of every immutable key copy; use a trusted offhost process.
No runtime signing material is accessed by these components.

`copy-ciphertext` performs a bounded real file copy between independently
authorized private local/mounted destinations. Completed parts are byte-hash
checked on repeat invocation. Partial parts are compared against source from
byte zero before appending; bad prefixes stop. Each part is flushed/fsynced and
renamed, and commit is copied last. It needs no decryption key. This is **not
an SSH transport** and is not proof of offhost custody by itself. Archives are
immutable after seal; concurrent hostile same-user mutation is outside this
private-directory custody model.

`restore` authenticates the entire archive before creating a destination, then
reconstructs actual files, internal hardlinks and narrowly safe relative links
in a new private directory. Existing destinations are never overwritten. Paths
cannot escape the root or traverse a manifest symlink. Absolute/upward links
require explicit review and stop **before** any destination is created; the
encrypted archive still preserves their complete original targets. No silently
omitted links are declared restored. Originals and failed candidates remain.

Restored files are deliberately 0600/directories 0700, not original executable
modes or original user IDs. Original metadata remains in the encrypted manifest.
Both named SQLite copies including copied sidecars are opened read-only, checked
with `PRAGMA integrity_check`, and their message count/max-seq are recorded in a
private completion receipt. Sidecar/SQLite processing occurs only in the new
offhost candidate. A valid provisional WAL copy is **not a continuously fenced
common epoch**, nor a comparison to independently witnessed source cursors.
No receipt is emitted on an incomplete restore. Restore interruption requires
a different new destination; resumability currently applies to ciphertext copy,
not partial plaintext restoration. No automatic cleanup or rollback deletion.

## Operator use on an already authorized offhost Linux copy

These are component invocations, **not production instructions**. Replace only
the local copy/destination placeholders; all parent directories must already
be private, owned by the invoking non-production operator, with adequate free
space. The archive and recovery material must have independent custody.

```text
uv run python packaging/migration/r1066_transfer.py archive --app /PRIVATE/app-copy --state /PRIVATE/state-copy --archive /PRIVATE/new-encrypted --source-head ec4bc4892d40cdd2a03e102faa44d72c89e01b99
uv run python packaging/migration/r1066_transfer.py copy-ciphertext --source /PRIVATE/new-encrypted --destination /OTHER_PRIVATE/received
uv run python packaging/migration/r1066_transfer.py restore --archive /OTHER_PRIVATE/received --target /OTHER_PRIVATE/new-disarmed-restore --quota-bytes APPROVED_INTEGER_LIMIT
```

`--source-head` checks the allowed revision identifier, **not provenance of an
arbitrary supplied copy**. Source authority remains unknown. No copied source
or command is run. No source git worktree is relabeled as authoritative.
Quota is a plaintext restored-byte limit, not a filesystem/cgroup reservation.
At least 1GiB physical headroom is additionally required for these isolated
component operations; this does not replace R1063's conservative full K137
capacity/rollback budget. Unknown original logical bytes must be measured by an
authorized acquisition, not inferred from historical 19.5GiB allocated counts.

## Windows v2: executable read-only two-host preflight

Without an independent owner enrollment this stops before escrow or network I/O:

```powershell
.\packaging\migration\r1066_owner_workflow.ps1
```

The single immediate blocker is `K137_INDEPENDENT_ENROLLMENT_REQUIRED`: an
independently verified owner enrollment for the existing K137 endpoint, host key,
credential and isolated user/scope. No such enrollment is supplied in this PR.
Do not infer an IP from an internal hostname or opportunistic keyscan. No new
server, key, user, landing directory or cgroup is created by this workflow.

After separate owner authorization and authentic enrollment, the runnable command is:

```powershell
.\packaging\migration\r1066_owner_workflow.ps1 -EnrollmentFile C:\PRIVATE\r1066-enrollment.json -EnrollmentSha256 INDEPENDENTLY_CONFIRMED_ENROLLMENT_SHA256
```

Neither command has been run against production. The supplied enrollment digest
is an out-of-band operator trust anchor, not a digest accepted from the host being
verified. The owner and local administrators remain trusted. Enrollment and K137
credential must have current-user-only ACLs accepted by the audited R987 helpers.

Strict enrollment schema (no extra/duplicate fields):

- Root: `schema_version: 1`, `purpose: R1066_READONLY_PREFLIGHT`, `oci`, `k137`.
- Each endpoint: `host` (canonical numeric IPv4), `user`, `host_key` (exact OpenSSH
  public key without comment), `host_key_sha256` (lowercase hex SHA256 of decoded
  public-key blob), `credential_sha256` (independently enrolled SHA256 of exact
  existing credential bytes), `identity_file`, `machine_sha256` (SHA256 of stripped
  `/etc/machine-id`), `uid`, `head`, `cgroup_sha256`, `minimum_free_bytes`.
- OCI host/user and original source HEAD are fixed by the carrier. `identity_file`
  must be `R987_V2_ESCROW`, uid=0, host-key algorithm=`ecdsa-sha2-nistp256`.
  Its unused cgroup digest must still be 64 lowercase hex characters; source
  resource isolation is explicitly `NOT_ASSESSED`.
- K137 requires a different endpoint, machine identity, host key and credential,
  an existing non-root SSH user and private local existing credential path.
  `head` binds the existing `/opt/flop-shadow` release. OCI escrow is never reused.
- K137 staged Git checkout is explicitly under
  `/opt/flop-shadow/releases/3fb667837a8f01d17e97dabfd1a1bfe5ddc09e1e`
  (owner-reported already staged source). The parent `/opt/flop-shadow` is
  the isolation container, **not proven to be a Git checkout**. We verify the
  versioned release HEAD at its own directory and STOP if that evidence has
  changed or this particular release has no valid Git provenance. Never
  synthesize a repository or re-run the earlier consumed installer to satisfy
  the check.
- Trusted K137 SSH host keys may be independently obtained from the
  authenticated **AWS Lightsail control plane** via its official
  `get-instance-access-details` API for the already existing
  `tradebot-k137` instance in `ap-northeast-1`. The official API reports
  `hostKeys` and `ipAddress`, but **also returns temporary SSH credentials**.
  Therefore such a call is NOT run by this read-only preflight, and no
  temporary private key may be logged, printed, saved to GitHub or sent to
  ChatGPT. It requires separate owner authorization and a controlled
  credential-handling path; an API response is no proof that an existing
  Windows K137 credential or private landing/cgroup is installed. Do not use
  TOFU (`ssh-keyscan` alone) or guess a host fingerprint.
  Reference: https://docs.aws.amazon.com/cli/latest/reference/lightsail/get-instance-access-details.html
- K137 `cgroup_sha256` binds the exact stripped `0::/...` line of this user's
  existing cgroup v2 membership. Finite memory <=256MiB, pids<=64 and CPU quota
  <=one core are required. An ordinary unbounded login fails; nothing configures
  these limits. They are conservative probe ceilings, not restore capacity proof.
- Existing landing root is fixed to `/var/lib/flop-migration-r1066`, non-symlink,
  owned by that user, mode0700. Protected TradeBot/shadow directories must have
  different ownership and deny directory write access. This is reported only as
  `DIRECTORY_WRITE_DENIED_ONLY`, not complete filesystem isolation/restore approval.

Both endpoint domains are checked before a hidden R987 V2 recovery prompt. Only
pinned decryption/custody functions are imported; no consumed witness or source
fetch executes. SecureString is disposed, plaintext bytes cleared, temporary
current-user-only custody removed on success/error. Cleanup failure invalidates
success. The existing K137 credential is not copied or deleted.

SSH ignores user config, forwarding, proxies, agents, passwords and TOFU. Private
temporary known-hosts contain only independently enrolled exact keys. The child
environment contains only SystemRoot; stdout/stderr are bounded, stderr discarded,
timeout kills/joins the child, and no retries occur. Pinned local guest source and
a validated hex-encoded request go over stdin. The only remote commands are fixed
Python `-I -B -` (OCI only adds `sudo -n`). No remote artifact is installed.

The guest reads identity, HEAD, directory metadata, statvfs and cgroup limits,
not SQLite, receipts, private configuration, Vault or application data. Responses
must match a fresh per-run challenge and exact safe schema. Exit0 means **only**
`operation=preflight_verified`; next authority is
`WRITER_ADMISSION_AUTHORIZATION_REQUIRED`. POST finality, common epoch, signer
portability and restore authority remain `NOT_PROVEN`, regardless of historical
counts or synthetic tests.

**Still not implemented:** remote archive acquisition/upload/resume, live epoch
acquisition, authorized K137 quarantine restore or cutover. The new bounded binary
carrier transports probe source/responses, not archives. Existing offhost encryption,
ciphertext resume and Linux restore remain unchanged, including live-host guards.
This is the runnable preflight fallback, not full v2 transfer/restore acceptance.
Consumed R1058–R1065 witnesses and existing production carriers remain unchanged.

## Exact missing live integrations and evidence

1. **Destination transport:** independently pinned K137 identity/host key and
   existing credential, plus an authenticated fixed-function binary transport.
   Those facts are unknown. This code does not guess them, read existing keys,
   decrypt R987 early or provide a generic remote command escape hatch.
2. **Source admission:** enforceable, separately approved continuous generation
   covering independent Resident/Capture restart, manual/transient/dynamic TCLK,
   cron including SPECIAL, timers and all five POST routes. Actual source
   ownership/HEAD/unit inventory and exact absent unit are unproven. No stop,
   kill, disable, restart or admission mechanism is invented or executed here.
3. **POST finality:** independent authenticated accepted/not-accepted verdicts
   for every attempt/leg, same DID and nonce, across oracle_signer, accept,
   reveal_publish, approved_trade and batch_trade. Unknown means no replay and
   no cutover. Local receipts/counts cannot close this gap.
4. **Epoch acquisition:** real SQLite online backups and complete source stream
   acquired under that continuously held fence. Existing R1055/R1005 remain
   unchanged; they must be connected to an approved live carrier, not applied
   to original production by this coding task. This package's source copies
   are always labeled PROVISIONAL_UNFENCED. A live known source path is refused.
5. **K137 isolation:** authenticated existing flop-shadow user and protected
   TradeBot cgroup/workload proof, current disk/CPU credits/RAM/PSI, and approved
   resource limits for incoming restore. Presence of known live deployment roots
   makes the restorer STOP. A local quota argument is not authorization to run
   on K137. Existing releases and TradeBot paths are never overwritten.
6. **Signer portability:** no verified AWS credential issuer, OCI exchange
   trust/client/policies or same-DID disarmed public equality proof exists.
   Reuse R1063's source-backed G3 assessment. No raw seed export, new DID or
   invented AWS-role/STS-to-RPST path is offered. A separately reviewed operator
   custody proposal remains required before implementation/activation.
7. **Release/rollback:** R1063 remains the consolidated evidence policy. Its
   current CLI has no enrolled production trust roots; no fake packet can
   authorize cutover. Independently reviewed key enrollment and fresh G0–G8,
   nonoverlap rollback lease, later sustained live destination proof and
   separately captured cutover/retirement approvals remain absent. No cutover
   executor or OCI deletion route exists in this partial package.

The real migration is therefore **NOT COMPLETE**. All actual operation reports
retain unknown authority/common epoch/protected TradeBot, blocked signer and
cutover, and `OCI_RETIREMENT=STRICT_NO_GO`. Windows only reports fresh host/scope
observations after actual authenticated reads, never historical liveness or approval.
No actual archive, original restore or host result is supplied in this PR.

## Verification

New synthetic integration tests create real binary data, over 3000 files,
SQLite WAL, symlinks and hardlinks; test independent R1001 verification,
interruption/partial-copy continuation, wrong key/hash/head, incomplete archive,
quota/space, link escape, missing DB and refusal to overwrite.
POSIX custody tests run in Linux CI. V2 adds synthetic host metadata tests, actual
PS5.1 binary/timeout/environment tests, strict response/enrollment checks and a
fully mocked two-host coordinator success/failure/cleanup test. Windows also tests
the no-argument pre-credential STOP. No production credentials or cloud endpoints are
contacted. Broad full-suite/security/history coverage is provided once by the
existing draft-PR workflow; the standard Windows job additionally runs the focused
v2 tests only. No paid resources, caches or artifact uploads are added.

## R1066 Phase B SSH ciphertext relay (2026-10-27) — code only, NOT run

New `packaging/migration/r1066_ciphertext_ssh_relay.py` now implements the actual
two-process SSH ciphertext data plane. It streams bounded encrypted bytes from
an ALREADY sealed root-private OCI archive into an ALREADY provisioned K137
quarantine, uses verified remote offsets for interrupted-file resume, transfers
header and consecutive parts before commit, and verifies the entire exact mirror.
The remote Python helper is the exact Git-blob-pinned r1066_ciphertext_pipe.py
executed in memory, not an installation or arbitrary shell deployment.
Two existing host credentials and independently pinned exact known-hosts lines
are required; agent/TOFU/proxy/forwarding/password fallbacks are disabled.
The controller rejects malformed inventories and remote offset discrepancies;
stdout is bounded, streaming subprocesses have kill-on-timeout guards, and
completion never authorizes plaintext restoration, DID signing or cutover.

THIS SCRIPT IS NOT YET AN APPROVED PRODUCTION INVOCATION: original sealed archive,
host enrollment, source writer-admission fence, full two-SQLite coherent epoch,
five POST final verdicts, target cgroup/private landing/TradeBot capacity,
and independent offhost recovery are still unverified. It is deliberately NOT
automatically called from the PowerShell read-only owner preflight, and it does
not acquire credentials from R987, open active SQLite, produce raw Vault keys,
restore K137 or terminate any Oracle resources. Do not guess host fingerprints
or archive IDs, or point it at active source directories. Do not run on live
hosts until a reviewed owner controller bridges actual authenticated preflight
and an approved immutable archive. Python availability on owner Windows also
remains unverified; the existing PS5.1 preflight path is unchanged.

CI subprocess tests prove the binary streaming controller's success/fail-closed
semantics with synthetic local child processes, NOT an actual cloud transfer.
Result always carries cutover=NO_GO and oci_retirement=STRICT_NO_GO.
Remaining deliverable: integrate single Windows owner flow with existing
R987 custody and approved durable original archive; then separate independent
restore, same-DID signer continuity, protected TradeBot and rollback approval.

## R1066 Phase A to ciphertext Phase B owner integration — source-only

The existing Windows PowerShell 5.1 `r1066_owner_workflow.ps1` now optionally
invokes the SSH ciphertext relay IN THE SAME ephemeral R987 V2 OCI custody
session after BOTH separately authenticated read-only host preflights succeed.
Default execution remains Phase A READ-ONLY. Opt-in Phase B requires all of:

- `-StageCiphertext` explicitly set; otherwise an archive path/ID is rejected
- independently authenticated unmodified two-host enrollment and known-hosts
- `-SealedArchiveRoot` identifying an ALREADY committed immutable R1001 archive
  on the authenticated OCI source (never live state/app roots)
- `-ArchiveId` exact 32 lowercase hex characters matching sealed header
- local Python 3.9+ availability in addition to Windows PowerShell 5.1
- existing K137 private SSH credential and private landing/cgroup identity
- K137 observed disk free at the preflight snapshot >= 2 x total sealed
  ciphertext bytes + 10 GiB for both ciphertext, planned restore and TradeBot

This only preserves ciphertext and never makes an original complete coherent
backup or restores/starts the K137 FLOP agent. No actual original OCI sealed
archive currently exists as verified evidence; do NOT execute Phase B on the
live host and DO NOT invent archive path/ID/host enrollment. The K137 statvfs
figure may change between preflight and transfer, so these reserve checks
cannot substitute for fresh disarmed restore capacity and rollback evidence.
Transfer failure leaves staged `.partial` ciphertext under K137 private root
and does not grant deletion rights. The stage command's Python process tree
is terminated on explicit timeout where Windows allows, with failure marked
STOP. Relay/process termination under abrupt OS crash is NOT guaranteed.
The preflight's original already-audited R987 key handling is preserved;
the extra on-disk transient controller Python copy is pinned, ACL-checked
and explicitly deleted before custody cleanup.

Oracle cleanup status: NO deletion or cache pruning performed. Without a
complete live file/owner/process census and independently restored full archive
there is no proven SAFE_TO_DELETE inventory. On K137 the live TradeBot and
the versioned FLOP shadow release are both protected and must not be pruned.
Only ephemeral files created for this invocation are eligible for automatic
owned-temp cleanup; state, logs, SQLite/WAL, encrypted manifests, keys,
rollback archives and unknown directories are never safe to infer as unused.

Current release authority: cutover=NO_GO, OCI_RETIREMENT=STRICT_NO_GO.

## R1068 candidate — existing-DID Oracle Vault continuity without original OCI Compute

Validated October 28, 2026 against public Oracle documentation:

- https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/token_exchange_grant_type_workload_id-federation.htm
- https://docs.oracle.com/en-us/iaas/releasenotes/identity/jwt_to_rpst_token_exchange_for_workload_identity_federation.htm
- https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdk_authentication_methods.htm

EXISTING signer `src/flop_agent/oracle_signer.py` calls
`InstancePrincipalsSecurityTokenSigner()`, which cannot authenticate on the
existing AWS Lightsail host without an OCI instance principal. Merely moving
the Python runtime would BREAK the original DID signer. OCI now supports
JWT-to-RPST cross-cloud workload federation, but it requires an actual
trusted independently issued external JWT, OCI Identity Propagation Trust,
matching claims, least-privilege policies and a compatible OCI SDK. No such
issuer or trust is verified on the user-owned Lightsail instance. Do NOT
pretend native Lightsail SSH certificates are automatically OCI JWTs.

Fallback candidate for retiring the original OCI COMPUTE while retaining
the existing Vault secret. The candidate `r1068_oci_vault_portability.py` implements a
NON-DEFAULT, non-CLI, narrow existing Vault secret GET using a separately
authorized least-privilege OCI API key held under private 0700 directory
with mode 0600 key/config files and exact pinned Vault secret identifier.
It derives ONLY the existing public DID locally, compares against the
original pinned DID and emits a fixed redacted match result. It does NOT
POST, send a transaction, start services, create credentials or alter OCI
policies. It intentionally does NOT modify the original oracle_signer.py
or make the AWS signer usable without separate release integration.

Security caveat: Vault seed is STILL retrieved over authenticated HTTPS into
the isolated AWS process memory for deterministic derivation; it is NEVER
persisted by this module or emitted to logs, but Python environment strings
are not guaranteed securely erasable. This does NOT avoid every risk of
handling private seed material. An approved least-privilege OCI IAM API key
would itself be a sensitive persistent K137 credential, requiring scoped IAM
policy, monitoring, access-control review and revocation/rotation.
Do not create an IAM user or copy any secret/key to AWS automatically.

Preferred if feasible: independent OIDC JWT issuer + OCI workload identity
federation, with periodic renewal and exact resource-level deny/allow rules.
Backup option: dedicated OCI API-key signer with only exact pinned secret
read permission, NOT tenancy-wide read or manage access. Whether the user's
OCI tenancy/policy/Identity Domain and AWS installation can support either
is UNCONFIRMED. The original Oracle instance can be retired ONLY after
original DID signing and all POST outcomes are independently proved on
AWS; retaining OCI Vault as a service may have separate charges and must
be reviewed before the final retirement scope is approved.

R1068 tests use only synthetic keys/mocked OCI and never call AWS/OCI.
Nothing here proves source writer admission, common SQLite epoch, actual
encrypted transfer, DISARMED restore, original DID continuity, TradeBot
isolation or rollback. No production action and no deletion authorized.
OCI_RETIREMENT=STRICT_NO_GO.

## R1069 — authenticated owner-created K137 private quarantine directory

R1067 authenticated existing K137 using AWS-issued short-lived SSH credentials
and pinned the AWS-reported host key. Owner-proven October 28 evidence:
free disk 48,603,582,464 bytes; total 61,285,326,848, UID1000 SSH
identity; staged Git HEAD MATCH; protected TradeBot paths have distinct
ownership; private quarantine directory ABSENT.

New packaging/migration/r1069_aws_cloudshell_k137_private_landing.sh
reuses the proven AWS credential/host-key verification and does not retain
persistent SSH credentials. It changes K137 only after the owner's explicit
--allow-one-private-landing-create opt-in. It calls sudo noninteractively
and creates exactly ONE missing /var/lib/flop-migration-r1066 directory as
mode 0700, owned by existing UID1000 ubuntu. Before mutation it checks
root-owned non-writable parent directories, protected TradeBot/shadow
ownership, the exact staged Git HEAD and at least 20 GiB free.
It does not touch TradeBot files/services, edit existing directories,
launch FLOP or copy confidential source. If the landing already has exact
expected owner/mode, it returns ALREADY_PREPARED with no mutation.
An unexpected preexisting object stops, preserving existing contents.
No automatic deletion of a partially created root on failure, since another
actor might have used it.

R1069 does NOT establish the dedicated bounded cgroup required by R1066
preflight. That identity must be separately enrolled and verified.
Successful synthetic CI does not prove sudo availability on the real host.
Nothing here establishes the original Oracle writer stop, complete archive,
encrypted transfer, isolated restoration, original DID, rollback or cleanup.
Never issue actual sudo commands or send AWS keys to ChatGPT/GitHub.
Default R1067 remains READ ONLY; OCI_RETIREMENT=STRICT_NO_GO.


## R1082–R1083 release-gate corrections (source-only; NO live migration)

R1082 aligns offline G7 evidence entry cardinality with the R1081 archive and
restore hard limit of 100,000. Synthetic 30,682-entry signed evidence can now
pass G7; oversized or unequal source/restored entry counts still stop. This
neither constructs an archive nor establishes source authority.

R1083 corrects a distinct physical impossibility: the original G2 all-on-K137
capacity formula implicitly requires ciphertext, plaintext and rollback copies
on the 60GB shared disk. The original one-filesystem contract is preserved.
An optional explicit separate-existing-disk topology now requires a fresh,
independently signed owner-offhost receipt, exact owner approval, private
existing offhost custody and zero incremental cost. The offhost filesystem
must independently have encrypted archive peak plus at least 1GiB reserve.
K137 itself must retain free room for restored source + SQLite allowance +
20GiB TradeBot/OS reserve. No compression credit or K137 ciphertext co-location
is assumed. Memory, CPU/PSI and TradeBot checks remain unchanged. These are
STRICT offline evidence requirements; no existing owner offhost measurement,
approval, OCI fenced backup, K137 restored bytes or signing credentials are
implied or manufactured. Both split and legacy assessments continue to output
CUTOVER NO_GO and OCI_RETIREMENT STRICT_NO_GO. No live SSH, disk writes, IAM,
production service change, or permission to restore on protected host is added.


## R1084 bounded ciphertext stream (OFFLINE implementation, no live authorization)

The new source-only \`r1084_offhost_ciphertext_stream.py\` reuses R1066's exact
offline census, deterministic manifest, source drift detection and R1001
AES-GCM/PBKDF2 framing, but emits ciphertext header, parts and final commit
over a binary length-and-hash-framed stream. It DOES NOT make a 26GB plaintext
or ciphertext duplicate on the source host. Its receiver writes the ciphertext
to a new private POSIX offhost directory after checking pre-existing free
capacity and an explicit bounded quota. It fsyncs each completed file, rejects
truncation, trailing data, bad hashes, wrong order and reuse of a destination,
and never asserts common SQLite epoch or live authority. The unchanged R1066
decrypt/restore independently verifies the received encrypted archive.

This is an actual integration-tested binary stream over synthetic OFFLINE files,
not the production two-host coordinator. The original OCI roots remain blocked
by \`offline_source\` until a separately approved and proven complete writer
admission/fence; no remote SSH or recovery-material handoff is enabled.
Offhost Windows NTFS custody is not enrolled, and a Windows binary receiver,
source epoch attestation and real production operator integration remain OPEN.
The existing direct OCI→K137 ciphertext relay retains its protective
dual-copy disk gate: it is NOT a substitute for independent offhost custody.
CUTOVER NO_GO; OCI_RETIREMENT STRICT_NO_GO.
