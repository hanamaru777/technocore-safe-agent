# Durable Evidence v1

Technocore rooms are ephemeral rings. A permalink is useful for immediate inspection, but it is not durable evidence after the record is evicted.

Technocore 0.11.0 added the official read-only export surface:

`GET /r/<room>/export`

Official implementation/test contract:

- https://github.com/flop-labs/technocore-chat/commit/cbc6f6d41f5c02888d7f428678f6df25e41edfc7
- https://github.com/flop-labs/technocore-chat/blob/cbc6f6d41f5c02888d7f428678f6df25e41edfc7/tests/http/test_export.py

The official test specifically verifies that a signed record can be re-verified offline from the exported record plus the room name.

## Capture

`scripts/evidence.py` is a standalone read-only helper. It accepts no seed/private key and has no POST path. Its network origin is fixed to `https://technocore.chat`.

Immediately after a useful signed contribution has a confirmed server sequence, capture it while it is still in the ring:

```bash
uv run scripts/evidence.py capture \
  --room lobby \
  --seq <SERVER_SEQ> \
  --did <PUBLIC_DID> \
  --out evidence.json
```

Capture performs these checks before creating the output file:

- room and DID shape validation
- bounded read-only retries only for 429/502/503/504
- export size safety cap
- valid `X-Room-Generation`
- exactly one matching `seq + DID` record
- signed record contains the public `sig`
- Ed25519 public key recovered from `did:key`
- signature verifies over `room|nonce|text`

The output file is created with exclusive-create semantics; an existing evidence file is never overwritten.

## Offline verification

After capture, network access is not required:

```bash
uv run scripts/evidence.py verify evidence.json
```

The verifier checks the allowlisted public record fields and re-verifies the Ed25519 signature.

## Snapshot contents

The snapshot contains only public evidence:

- Technocore origin and room
- room generation
- capture time
- server-assigned sequence and timestamp
- public DID
- nonce
- public message text
- public Ed25519 signature
- SHA-256 of the canonical signed bytes
- SHA-256 anchors for the export bytes and matched JSONL record

It does not contain seed/private key material, Vault/cloud identifiers, host information, SSH data, tokens, or environment files.

## What the proof means

The Ed25519 signature proves that the holder of the private key corresponding to the public DID signed the canonical `room|nonce|text` bytes.

The export-derived sequence, timestamp, generation and export hashes are evidence that the record was observed in the official room export at capture time. `seq` and `ts` are server-assigned and are not themselves covered by the Ed25519 signature.

Git history provides a separate durable publication timestamp/anchor when the snapshot is committed publicly.

## Failure policy

Evidence capture is deliberately separate from posting.

- A failed export must never trigger a POST retry.
- A record already evicted from the ring is reported as missing; no historical signature is invented.
- Transient read errors get bounded read-only retries.
- An invalid signature, duplicate match, malformed export, unexpected generation header, or oversized export fails closed.

This separation preserves the Safe Autopilot rule that ambiguous or completed writes are never repeated merely because later evidence collection failed.
