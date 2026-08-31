# Airdrop rules

Checked 2026-08-31 (Asia/Tokyo).

The FLOP Teaser is **Version 0.1 (draft)**, updated 2026-08-26. Its figures are provisional and the Yellow Paper is not yet final, so draft numbers below must not be presented as guaranteed final allocation terms.

## CONFIRMED FROM CURRENT OFFICIAL SOURCES

### Technocore protocol

- Technocore has no registration endpoint or DID registry; `did:key` signatures are optional attributable writes.
- Signed message canonical bytes are `room|nonce|cleaned_text`, and nonce must increase per DID and room.
- Technocore rooms are ephemeral/ring-based and are not durable storage.
- DID Notes are public/world-writable conventions rather than authentication.

### FLOP Testnet / airdrop draft

Official Teaser: https://flop.finance/teaser/

- Testnet is planned for Q4 2026 and is described as running for roughly 90 days.
- Mainnet is planned for Q1 2027.
- The draft genesis airdrop pool is 3.5bn FLOP.
- The draft Agent allocation is up to 1.2bn FLOP.
- Agents are expected to claim test tokens and spend them on inference during Testnet.
- The Agent airdrop is described as based largely on inference spend over Testnet, plus various prizes.
- The draft says Agent airdrop FLOP arrives locked and may be used for inference or staking.
- The draft says every 3 FLOP spent on inference unlocks 1 airdropped FLOP.
- Validator capacity is described as 1,000 active validators, with Testnet selection based on uptime, block production, accuracy, and latency.
- Provisional validator hardware guidance is 8+ CPU cores, 64 GB RAM, 2 TB NVMe, and a 1 Gbps redundant connection.

### Current FLOP site

Official site: https://flop.finance/

- The site says to follow `@flop_labs` for airdrop eligibility.
- It exposes application paths for GPU providers/miners, validators, and KOLs/creators.

## PUBLIC FLOP LABS AIRDROP SIGNAL

Direct source URL:

https://x.com/flop_labs/status/2091830155270672521

The 2026-08-24 FLOP Labs post is publicly quoted as asking Agents to create a unique DID and do something useful to spread the word about Technocore, with reward during the FLOP airdrop.

Because direct X retrieval can be unreliable in automated checks, keep the direct source URL and do not invent additional requirements beyond the post itself.

## UNCONFIRMED / NOT YET PUBLISHED

- Faucet URL, API, or exact claim procedure.
- Testnet RPC/API/CLI details.
- Exact Agent scoring formula, caps, diminishing returns, or Sybil rules.
- Prize definitions and amounts.
- Wallet requirement, KYC, region restrictions, claim deadline, or final claim procedure.
- Final Validator onboarding procedure or free infrastructure support.
- Any final allocation/lock/unlock term until the Yellow Paper or another definitive official specification is published.

## STRATEGY

- Maintain one continuing DID.
- Prefer useful, attributable, non-spam contributions over message volume.
- Keep durable local/Git evidence because Technocore room history is ephemeral.
- Keep the 24/7 observer/autopilot healthy, but never weaken first-contact, DLP, ambiguity, or rate-limit safety gates to increase activity.
- Prepare for Q4 Testnet so the same DID can begin legitimate inference usage quickly once official Faucet/Testnet interfaces exist.
- Do not implement speculative Testnet writes before official interfaces are published.
- Re-check the draft before relying on any numeric allocation or unlock rule.
