# FLOP R1001 — Off-host authenticated stream envelope (DRAFT ONLY)

**Date:** 2026-10-19 JST  
**Phase:** Source archival transport security primitive, offline-only  
**Status:** DRAFT / DO NOT MERGE / DO NOT OPERATE AGAINST LIVE OCI OR AWS.

## What this contributes

`packaging/archive/offhost-sealed-stream.py` is a self-contained **off-host-only** primitive which ingests an arbitrary piped byte stream and creates confidential, authenticated, independently decrypt-verifiable, compressed shards. It is not a source reader, SSH transport operator, backup source manifest, exporter for the two SQLite DBs, or application-restoration tool. Existing PR #876–#878 is a separate *source-census/shard-bytes verifier* and is unchanged. Any end-to-end integration must provide an authenticated, content-complete source stream and caller-verified `pipefail` before elevating this to backup acceptance.

・Uses `cryptography` AES-256-GCM authenticated encryption, 1MiB plaintext chunks, independent nonce per ordered frame, encrypted authenticated final commit.  
・Key derived from a **new independent** 64-character random-hex secret file by PBKDF2-HMAC-SHA256 with 600,000 iterations. *Never reuse R986/R987 SSH-key backup passcodes or signer/Vault seeds.*  
・Compresses each chunk with zlib level 1 before encryption, writes encrypted ~128MiB shard files. No raw plaintext is written to disk by this process. Chunk reassembly is verified by plaintext hash *inside the authenticated commit*. No plaintext is printed.  
・Offhost-only: Linux nonroot, rejects `/opt/technocore-safe-agent` and `/opt/tradebot-k137`; refuses world/group-accessible secret/archive files, symlinked archive parts and overwrites, tampered/unknown/truncated archive members. Secret is read from file, not from argv/environment.  
・`init-secret` produces new mode0600 file, never prints the secret. Separate, independent offline custody is a required later operator step.  
・`verify` authenticates every chunk and encrypted final commit, reconstructs the expected byte stream in volatile memory, computes the original SHA-256 but discards plaintext rather than writing any sensitive archive on disk.  
・No network, OCI/AWS API, signing, original data, service, filesystem cleanup or existing executable is called by this module.

## Strict limitations — must NOT misinterpret PASS

1. This does not read source file contents or bind payload to source SHA, source file paths, provenance, writer epoch or receipts. Authenticated encryption of an incomplete stream is still **incomplete**. The caller must enforce source SSH `pipefail`, source checksum and byte-count pin, pinned source HEAD and exact scope, and independently classify 4 unknown directories + 24 symlinks, including 2 lexical outside links.
2. No data is actually offsite until encrypted shards **and the separately stored recovery secret** have been retained outside original OCI/Cloud Shell and independently downloaded + verified. Cloud Shell's limited filesystem and quota remain unverified for this archive size. This prototype has no resume logic: partial archives deliberately lack a final `commit.bin` and fail verification.
3. This does not replace the required SQLite online-backup of both observed DBs nor the single-writer boundary (Resident/Capture/Signer, timers, TCLK/Radar, all outboxes). Read-only hot file scanning is not a coherent application snapshot.
4. This does not prove original DID/nonce/receipt continuity, AWS K137 2GiB memory and hourly `:02` cgroup isolation, OCI Vault identity authorization, testnet endpoint readiness or OCI retirement.
5. `verify` deliberately does *not* write a live application restore or prove application startup. A separate sandboxed restore and replay-safe verification is mandatory.
6. Local fixture tests PASS are **not** Oracle production validation. This PR is DRAFT; no operator command should reference it until the source-producer, safe transport topology and storage/cost gates are accepted.
7. The 2026-10-19 actual owner R995/R996 observed ~19.436GB stale transient state files: 1312 resident-state; 1132 resident-heartbeat; 2 observer-state. This is not evidence they are safe to remove. No automatic `.tmp` skip/delete; no `autopilot` 5.169GB or symlink exclusions.

## Offline test contract

Run in an unprivileged local sandbox with `cryptography` installed, using synthetic payload only:

`pytest -q -p no:cacheprovider tests/test_r1001_offhost_sealed_stream.py`

Test matrix: actual AES-GCM encryption/decryption (including incompressible binaries and forced multipart boundaries), wrong passphrase, header/commit/part bit flip, truncation, unexpected member, part reordering, symlinked member, insecure permissions, duplicate destination, empty source; no production state touched.

## System-wide rollout gates

- Gate 0: GitHub Draft PR only, no deployment or merge.
- Gate 1: Original OCI source-scoped file manifest with no silent exclusions, reader permission and authenticated SSH origin; verify source SHA `ec4bc4892d40cdd2a03e102faa44d72c89e01b99` prior to any source action.
- Gate 2: Exact cross-writer checkpoint/fence, all money/nonce/signer/TCLK and two SQLite online backup images accepted, protected financial write path no duplicate.
- Gate 3: Bound stream volume, choose secure external storage and prove free headroom/charging; avoid Cloud Shell plaintext disk and AWS K137 live data/service paths, do not perturb hourly K137 `:02`.
- Gate 4: An independent ciphertext copy / secret custody plus verify; application restore with same DID and receipt-order comparison.
- Gate 5: Explicit production cutover and separate irreversible OCI retirement approval. Preserve original boot and its only matched FULL backup until every gate is independently evidenced.

**OCI_RETIREMENT: STRICT NO-GO.**
