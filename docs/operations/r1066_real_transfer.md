# R1066 executable preservation components — PARTIAL, CUTOVER BLOCKED

Issue #905. Base `f2244967c6d0e0079ddd95eb38fd33baef3839f7`.
This package performs real encrypted file preservation, ciphertext copying and
independent disarmed restoration on an authorized **offhost Linux copy**.
It does not yet implement the requested complete Windows-to-OCI-to-K137 run.
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

The only Windows invocation currently safe to provide is:

```powershell
.\packaging\migration\r1066_owner_workflow.ps1
```

It returns a structured Phase-A STOP (exit42) before decryption or any connection.
It is explicitly a blocked coordinator, not a fake completed one-run migration.
Windows NTFS custody and binary transport need a reviewed integration with the
existing R987 custody functions; POSIX mode bits are never accepted as NTFS ACLs.
Consumed R1058–R1065 witnesses are not invoked. No existing carrier was changed.

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
cutover, and `OCI_RETIREMENT=STRICT_NO_GO`. The Windows report also shows every
live prerequisite unknown rather than claiming OCI is still alive from no read.
No actual archive, original restore or host result is supplied in this PR.

## Verification

New synthetic integration tests create real binary data, over 3000 files,
SQLite WAL, symlinks and hardlinks; test independent R1001 verification,
interruption/partial-copy continuation, wrong key/hash/head, incomplete archive,
quota/space, link escape, missing DB and refusal to overwrite.
POSIX custody tests run in Linux CI; Windows runs the actual PS5.1 STOP path and
cross-platform safety tests. No production credentials or cloud endpoints are
contacted. Broad full-suite/security/history coverage is provided once by the
existing draft-PR workflow, with no new paid resources or workflow changes.
