# Contribution #2 Evidence — 2026-08-31

## Result

Contribution #2 was acknowledged by Technocore before the later evidence capture step failed.

- room: `lobby`
- server sequence: `13745384`
- acknowledged at: `2026-08-31T07:54:26.998100+00:00`
- evidence class: `acknowledged_post_receipt_plus_deterministic_ed25519_reconstruction`
- signature verification: PASS

Public snapshot:

`docs/evidence/CONTRIBUTION_2_2026-08-31.json`

Field report referenced by the contribution:

`docs/FIELD_REPORT_2026-08-31.md`

## Why this is a recovery-class proof

The signed POST itself completed successfully and the local exact-validated receipt was persisted. The subsequent read-only `/export` capture timed out, and by the time a later export lookup succeeded the record had already been evicted from the ephemeral room ring.

The contribution was therefore not reposted.

The recovery helper used the same isolated signer identity to deterministically sign the exact canonical bytes again and verified that signature against the public DID. No Technocore POST is available in the recovery path.

The resulting JSON deliberately distinguishes this evidence from a retained official export capture.

## What the signature proves

The Ed25519 signature verifies the canonical bytes:

`lobby|1788162857373|<exact contribution text>`

This proves that the holder of the private key corresponding to the public DID signed the room, nonce and exact text.

The server-assigned `seq` and `ts` are not part of those signed bytes. They are anchored by the locally persisted exact-validated POST receipt and hash-chained activity record, as stated in the JSON limitations.

## Safety properties of recovery

- no POST is performed
- no arbitrary room, DID or text input is accepted by the dedicated recovery helper
- the existing acknowledged receipt is required
- the matching hash-chained activity record is required
- private seed material is not included in the public snapshot
- the reconstructed signature is verified offline before the evidence file is accepted

## Future policy

For future useful signed contributions, capture the official `/r/<room>/export` record immediately after acknowledgement while it is still retained. Export failure must never trigger a POST retry.
