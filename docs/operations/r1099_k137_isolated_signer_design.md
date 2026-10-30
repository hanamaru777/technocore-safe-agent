# R1099 — existing original DID signer: owner-approved custody DESIGN, NOT live key transfer

Date: 2026-10-30 JST. User explicitly approved proceeding with design of a securely
isolated signer on the **already paid** Lightsail `tradebot-k137` preserving the
original Ed25519 DID. This is **approval to develop and independently verify
the architecture**, not to extract a real Vault signing seed, move it to AWS,
activate POST, modify OCI Vault, or delete the original OCI. Those actions need
an exact reviewed recovery-ready production plan and final separate operator
approval after attestation G0–G7 is complete.

## Immutable original protocol — do not optimize away

Original OCI `ec4bc4892d40cdd2a03e102faa44d72c89e01b99`
`scripts/sign.py` Git blob `81202baa03bff62204fa9ac34ce1f9fd969ddf67`:
Ed25519 did:key, canonical signed message `room|nonce|swept(text)` or
`ns|key|nonce|swept(value)`, UTF-8 original bytes, maximum 4,096 text
characters or 8,192 note characters. Nonces, receipts, pending attempts,
DID, sidecars, and all five POST routes retain their exact source status
and rollback obligations. **Neither Ed25519ph, text truncation, a freshly
generated key/DID, nor a signing library shortcut are equivalent.**
R1098 proved why paid AWS KMS is not transparently compatible.

## Proposed K137 production trust architecture (DESIGN ONLY)

- Only dedicated nonlogin `flop-signer` identity can decrypt/use key. This
  identity must be different from `ubuntu`, `flop-shadow`, TradeBot user,
  and service accounts. Tight service-to-service allowlist; background
  Observer/TradeBot receive **no** signer capabilities. Review all local
  group memberships and sudo privileges before deployment.
- No public signing endpoint, no TCP listener, no metadata service access,
  no inherited cloud credential or ambient AWS/OCI token. **AF_UNIX** only
  (private runtime directory), socket `0600`, filesystem DAC and Linux
  `SO_PEERCRED` checked on **every** connection. The caller must be an
  independently pinned authorized POST client. A socket mode or UID check
  by itself does NOT protect against root: trusted root remains a risk.
- The signer signs only complete original canonical payloads, after
  independent policy+nonce/receipt checks and one-publisher lease have
  been verified for the exact original DID/generation. It must NEVER
  initiate HTTP POST, choose or regenerate a nonce, update receipts, read
  TradeBot files, or accept a generic 'sign arbitrary bytes' RPC.
  Client-side upstream ambiguity and all five route outcomes remain
  enforced by original R1063 G4/G5/G8, not by assertion.
- Only authenticated, versioned AES-256-GCM ciphertext for the original
  32-byte Ed25519 seed may be stored at rest. Dedicated storage owned by
  signer with no access granted to Observer/TradeBot or broad project
  users; no environment variable, command-line argument, plaintext
  script/file, backup log, Git object, CloudShell clipboard, history
  or crash dump. Owner private off-host encrypted recovery copy is
  mandatory, independently tested before any original-custody action.
- Use independent owner high-entropy passphrase plus per-custody scrypt
  salt as a *proposed* zero-extra-cloud-fee unlock. Since there is no
  verified hardware root or paid key management on Lightsail, this
  requires **manual authorized unseal after reboot** (and careful
  clipboard/passphrase protection). Automatic unattended decryption
  would require a locally retained usable unlock key or independent
  attested secret provider. It cannot simultaneously promise zero
  extra cost, no manual action, and verified no-local-key exposure
  without proving such infrastructure. This is a deliberate limitation.
- Memory isn't an HSM: Python and cryptography can retain copies of
  private material even after best-effort buffer wipe. Use short-lived
  signing sessions, strict environment isolation, swap/core dump policy
  and process termination, with an independent hostile-code and crash
  audit. Do not claim a proof of no memory leakage.
- If future production development proceeds, use a **distinct** signer
  service under a reviewed systemd sandbox, `NoNewPrivileges`,
  `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
  `PrivateDevices=yes`, `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`,
  unprivileged identity, exact `ReadWritePaths`/runtime directory,
  limits compatible with protected K137 TradeBot peaks. These are
  target design controls, **not installed systemd settings**.

## What R1099 actually proves (safe synthetic-only)

`packaging/migration/r1099_k137_synthetic_signer_envelope.py` is an
**offline-only** program: it generates a random nonproduction key within a
test invocation; never opens files other than the pinned signer source,
never accepts secret/owner key from the terminal, never contacts OCI/AWS,
never persists an envelope. It uses exact original source functions
to derive DID and validate complete 4,096-character Unicode `say` and
8,192-character `set` signed canonical payloads; AES-256-GCM scrypt
rehearsal binds synthetic DID and synthetic machine digest with
authentication. Wrong passphrase/host/DID/modified ciphertext/duplicate
keys are rejected; no alternate signing algorithm.

`SYNTHETIC_ROUNDTRIP_ONLY` **does not** establish that the real original
seed, private identity, Windows/OCI sealed transfer, locked signer
runtime, sockets, activation policy or fresh G4/G5 are safe on K137.
R1099 is not a runnable production import procedure.

## Next state transitions and hard STOP rules

1. Independently acquire a no-replay complete source and signer inventory,
   all five upstream finality verdicts and approved continuous original
   writer/POST admission G4/G5. The old R1072/R1080 one-shot is consumed.
   No synthetic approvals; zero unresolved writable/unknown FDs.
2. Independently verify actual existing owner Windows offhost private
   capacity/custody and R1089 AEAD + inert K137 restore before releasing
   original signer. Source never deleted as preparation.
3. Design/review a **new narrow one-time** seed rewrap protocol from the
   OCI Vault isolated signer into protected Windows/offhost custody and
   the new K137 identity, with exact authenticated recipient, host
   key and original public DID proof. NEVER export seed to GitHub, logs,
   external plugin or ChatGPT. Require independent signed owner approval
   of immutable source/destination and explicit allowed action when
   preconditions are met. No such operation is implemented or run.
4. Stage source and runtime under separate **disarmed** signer user;
   prove full-length Ed25519 signed fixture compatibility, public DID
   equality from actual one-time verification and G3 all-route custody;
   keep POST disabled and original OCI signer/rollback intact.
5. G0–G8 full independent signatures, TradeBot natural-cycle and
   20GiB disk reserve, CPU/PSI, runtime isolation, security tests and
   authorized single-writer cutover. No duplicate posts.
6. OCI retirement is a **second separate later decision** after successful
   AWS natural operation, independently verified original backup,
   rollback hold completion, zero remaining references and scoped
   deletion plan. Never delete OCI instance/data from a code CI PASS.

Current:
`G3=NO_GO`; `G4=NO_GO`; `G5=NO_GO`;
`ORIGINAL_CUSTODY_TRANSFER=NOT_STARTED`;
`FULL_OFFHOST_ARCHIVE=NOT_CREATED`;
`K137_DISARMED_RESTORE=NOT_EXECUTED`;
`AWS_SIGNER_SERVICE=NOT_DEPLOYED`;
`CUTOVER=NO_GO`; `OCI_RETIREMENT=STRICT_NO_GO`.

The earlier Oracle R1095 19,405,111,296-byte cleanup and AWS R1097
47,270,965,248-byte K137 free capacity proof are accepted and MUST NOT
be repeated. No AWS FLOP cleanup was needed; TradeBot stays untouched.
