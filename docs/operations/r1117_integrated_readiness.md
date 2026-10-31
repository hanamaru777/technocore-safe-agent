# R1117 integrated engineering — DISARMED / NO_GO

Canonical scope: [#909 comment 6539752633](https://github.com/hanamaru777/technocore-safe-agent/issues/909#issuecomment-6539752633).
Start: `b18ee1dbb53f403626aefc5418f966e73ba84316`, parent draft #913.
Original source stays `ec4bc4892d40cdd2a03e102faa44d72c89e01b99`.
No production, SSH, Vault, billing, service, POST or deletion operation is part
of this implementation. Never run old R1112 or consumed R1095/R1097/R1102.

## Four code paths versus four real-evidence gaps

| Domain | Code added / reused | Not established by code or CI |
| --- | --- | --- |
| G3 | `r1117_signer.py`: independent owner/recipient public admission, exact original DID/host/recipient/challenge binding, original 4096/8192-character canonical Ed25519 verification and canonical 86-character signature encoding. Synthetic encrypted recipient + password custody reuses **unchanged** R1100 and R1099, including their synthetic domains. New isolated unit is a **public-proof verifier only**, not a live unseal/signing service. | Real key export/import is **not implemented or authorized**. No live key provider, generic signing RPC, unattended unseal, KMS, or proof of real K137 possession/custody. A source-produced signature alone does not prove destination custody. |
| G4 | `r1117_boundary.py`: bounded v249 text lists, observed-only show, mixed service/timer properties, template disk-only digest, exact private identity review using R1104; existing R1107 inode/namespace observation and Controller leases. New private append-once, fsynced undo journal precedes driver changes; owner+independent operation admission, boot binding, fault/rollback recovery. | No real root-wide future-launch/POST deny driver or independent lease issuer is supplied. systemd/cron/manual/transient/namespace unknowns still give **G4_NOT_PROVABLE**. No production stop/mount/firewall/kill implementation is hidden in the adapter. |
| G5 | Reuses original five route-specific R1107 sidecar/signature/nonce/fence checks. `RetainedHistory` explicitly returns UNKNOWN, including all-known-positive results. New exact per-attempt/leg finality interface cannot be released by a renamed test adapter or signed GO flag. | No official authenticated complete historical index/negative finality or claim-CAS authority is enrolled. **Production complete-history release is hard-disabled.** A future real protocol adapter needs separate source review, not a config flag. |
| G6/G7 | `OneShot.acquire`: G3 admission, held G4, complete G5, exact owner action, fresh capacity and distinct fixed host pins before SQLite/full-state reads. Reuses common-epoch census and unchanged R1089 AES-GCM stream. Guards every output write, journals attempting/interruption, forbids blind re-export. Independent restore/rollback receipt binding. Offline binary/SQLite/WAL → ciphertext → independent AEAD → inert restore/resume integration is executable in tests. | Default CLI/PS entrypoint cannot export, transfer or activate. Actual common epoch, full offhost backup, protected K137 restore, same-DID continuity, current resources and rollback evidence remain unproven. No source cleanup or cutover. |

All old R987/R1089/R1107/R1112 files and their pins remain unchanged. The new
map additionally pins canonical LF forms of reused and new dependencies; CRLF
normalization never permits a substantive signer/source change.

## G4 lifecycle and limits

`Controller` subclasses R1107 only to require backend operation admission;
its short-lease signature, hash-chain, issuer continuity and rollback semantics
are unchanged. A driver must supply the exact capability set: future launches,
all five POST paths, all namespaces, inode aliases, directory/deleted FDs,
writable mappings, root/manual/transient authority and durable undo. These are
independently admitted requirements, **not assertions the Linux metadata reader
can prove**. Missing capability means no original state read/export.

`UndoJournal` is a POSIX owner-private 0700-directory / 0600-record sequence.
It appends with exclusive no-follow creation and fsyncs the record and directory
before any driver mutation. It retains earlier undo through crash, partial
apply, reboot or failed restoration. Corrupt/truncated/orphan/concurrent records
STOP rather than being erased or guessed. Sequence hashes detect inconsistency;
they are not protection against a malicious privileged owner.

On interruption, restart performs **no** automatic deny, unfence or writer
restart. Fresh independent enrollment/admission for the current boot and exact
owner+independent recovery approval must bind journal, plan, undo, destination
writers fenced and five-route POST finality. A failed undo remains
`RESTORE_FAILED_REVIEW_REQUIRED`; original recovery evidence is retained.
The operator must not mistake systemctl stop or a private RO view for denial.

The v249 adapter never queries an expected-but-unobserved missing unit. It
collects optional properties without inventing absent service properties on
timers. `systemctl cat` for `@.service` is labelled
`DISK_ONLY_NOT_LIVE_EQUIVALENCE`, and cannot satisfy live/global closure. Exact
27 expected / 8 absent / 11+ extra identities are private; historical counts do
not invent their names. Unknown indirect cron, generators, user managers, manual
root, future activation, aliases or races remain blockers, not keyword matches.

## G5 finality and G6 ordering

The separate original paths are Oracle receipt/outbox, TCLK accept, TCLK reveal
plus claim, permanent Close1 single-attempt fence, and each Close1 batch leg.
Sidecar acquisition is guarded before and after the private provider read and
bound to the full state hash index. Missing sidecars, duplicate nonces, changing
epochs, forged/malformed receipts and source/upstream mismatch do not produce
terminal acceptance or negative finality.

The ordinary room read can show only a newest tail (up to 200 records), while the official export streams the entire currently retained on-disk ring. Neither proves that an older, evicted attempt was never accepted. Timeout, HTTP 409, ring miss, compaction, unknown
generation, claim-CAS or incomplete batch evidence stays UNKNOWN. The concrete
retained verifier has no release implementation. Only explicitly synthetic
complete-authority adapters can exercise the offline pipeline, and only against
roots rejected as production by the old offline-source guard. A test adapter's
profile cannot be renamed into production authority.

After all trial admissions pass, common-epoch verification checks both distinct
SQLite/WAL/SHM images and all other state. Source cap, original DID, manifest,
ledger, journal, run and host-pin bindings are retained. The 20 GiB reserve plus
SQLite allowance and OS/TradeBot/RAM/CPU safety are unchanged. Partial ciphertext
is not an archive; attempting/interrupted state cannot automatically export
again. Independently authenticated existing ciphertext may be restored/resumed
with the **existing R1089** verifier/restorer after separately reviewed authority;
do not discard the journal, regenerate recovery material or reset a nonce.

The offline test restores only into a synthetic quarantine. Real target remains
the existing `/var/lib/flop-migration-r1066/disarmed`, never flop-shadow or
TradeBot. No real transport backend is activated by these library hooks.

## One owner action contract — public dry-run only, after independent review

The new PowerShell 5.1 entrypoint is `r1117_owner_onepass.ps1 -DryRun`.
It accepts optional **public** proof/enrollment files and independently verified
SHA-256 digests, using the unchanged owner/SYSTEM-only ACL/hash reader and native
R1089 binary pipe. It never prompts for R987/unlock material or inherits SSH
configuration. A correctly signed full-length public proof can be checked;
output remains DISARMED, NO_SOURCE_EXPORT, NO_GO / STRICT_NO_GO (exit 42).
No proof files means the concise fixed missing-prerequisites report.

This is an invocation **contract**, not permission to run production. The new
isolated service reads only root-enrolled public admission, has no install/start
path, no TCP/metadata access and no credentials. It is not a portable real signer.
No production command or request for secret evidence is issued by this runbook.

Next grouped operator decision after ChatGPT's independent audit: enroll real
original/K137 host/recipient identities, separately authorize any real key-custody
ceremony, and provide reviewed global-denial backend/issuer plus genuine complete
five-route upstream authority. Until these exist, do not request another old
probe or execute acquisition/restore. Future actual transfer/start/cutover and
retirement each need exact independent evidence and separate explicit approval.

Permanent current result: **G3 real custody NO_GO; G4 NOT_PROVABLE; G5 UNKNOWN;
G6 NO_SOURCE_EXPORT; G7 NOT_PERFORMED; CUTOVER NO_GO;
OCI_RETIREMENT STRICT_NO_GO.** Synthetic success is code evidence only.


## R1118 safety correction — 2026-10-31 (source-only, not a migration)

The example `r1117-k137-signer-disarmed.service` in R1117 had an
`ExecStart` path under `/opt/technocore-safe-agent`, which is NOT
the independently observed K137 versioned Flop staging arrangement. It also
listed generic TradeBot paths instead of the historically observed protected
K137 roots. It must **never** be copied and started as a deployed service.

R1118 makes this unit deliberately non-startable even if copied:
`RefuseManualStart=yes`, unconditional `ExecCondition=/usr/bin/false`,
and `ExecStart=/usr/bin/false`. This is an INERT reference, not a real
service installer and not proof of AWS continuity. It adds the historically
observed protected TradeBot directories
`/opt/tradebot-k137`, `/var/lib/tradebot-k137-public`,
`/home/ubuntu/k137-canonical-source`, `/home/ubuntu/k137q-public-only`,
`/home/ubuntu/k137-public-state`. These are historical names; current
systemd/cgroup mounts, ownership, available memory and free disk must be
freshly verified before any actual K137 application installation. Do not
guess a replacement Flop release path or install/enable/start this unit.

Additional G5 first-party source and upstream issue review:
- `flop-labs/technocore-chat` `src/app.py:room_post` issues a write then
  responds with a room-view; the current `GET /r/{room}/export` reads only
  retained JSONL from `store.export_room` with acknowledged generation race.
  A source-side HTTP 200, current room tail, exported ring miss or duplicate
  nonce rejection is NOT historical acceptance or definitive nonacceptance.
- https://github.com/flop-labs/technocore-chat/issues/141 documents a
  timed-out signed claim that had actually committed and consumed its nonce.
- https://github.com/flop-labs/technocore-chat/issues/775 documents a moving
  retention floor lacking a dedicated window bound.
- https://github.com/flop-labs/technocore-chat/issues/919 is an OPEN,
  unverified caller report of HTTP 200 but absent stored writes. It is a risk
  to investigate, NOT confirmed proof the service drops data.
- https://github.com/flop-labs/technocore-chat/issues/711 documents why
  JavaScript number parsing can lose 19-digit nonce precision; source
  verification must preserve exact decimal digits and signed bytes.

Concrete G5 missing authority is an authenticated append/finality index for
ALL original five route/nonce/leg attempts, including historically evicted
room records, NOTE compare-and-set claims, original DID, exact text/hash,
server-assigned seq or a durable proven negative outcome, and a consistent
G4-held epoch. Unless such independently attested authority is available,
retain UNKNOWN and prohibit replay, live POST, cutover and OCI retirement.
Do not misreport these external blockers as locally code-fixable.
