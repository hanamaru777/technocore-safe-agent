# R1105 FLOP testnet agent readiness — 2026-10-30 JST

STATUS: testnet NOT publicly verified/live. PREPARATION ONLY. No wallet, signing,
faucet, staking, posting, fee payments, enrollment or production migration.

## Official evidence verified 2026-10-30

- https://docs.flop.network/docs/testnet-and-timeline (updated 2026-10-30):
  November 3 is an estimated opening, not a confirmed launch. Devnet and
  testnet have distinct purposes; devnet does not earn rewards. Agent requires
  same DID as TechnoCore, a supported way to make HTTP calls, future faucet and
  inference requests signed with that identity. HTTP-only first use does not
  require a locally installed chain wallet SDK. Do not create a second DID.
- https://ask.flop.finance/networks/testnet : official operator profile reports
  planned, release unreleased, with no verified public chain spec, genesis,
  bootnodes, RPC, gateway or model catalog. Nothing in that page authorizes
  registration or spending.
- https://ask.flop.finance/docs/sdk-references (updated 2026-10-30):
  publicly available npm @flop-labs/client 0.2.1, contracts 0.1.1, sdk 0.4.0,
  pi 0.3.1, cli 0.4.0; PyPI flop-sdk 0.2.0. Published versions are devnet tools,
  not evidence of formal testnet activation. Installing them is optional and
  MUST NOT be applied blindly to working original Oracle or shared AWS K137.
- https://ask.flop.finance/docs/upgrade : public model catalog endpoint
  https://api.flop.network/v1/models, read-only discovery without API key,
  with chain SDK / costly transaction functions strictly separate. Devnet
  RPC wss://rpc.devnet.flop.network is not public testnet identity.
- https://flop.finance/testnet/ : draft status, rules provisional; verified
  inference spending, not a TechnoCore message or fresh DID alone, is what
  testnet Agent scoring intends to count.

## New safe code

`packaging/testnet/r1105_agent_public_readiness.py` is default OFFLINE and
opt-in `--live` publicly reads ONLY fixed official testnet profile and public
models catalog, HTTPS verified, bounded bodies, fixed 8-second timeouts,
with no inherited proxy and no redirects. It does not parse any credential,
DID, wallet, private key, local journal or production state. It never prints
body content or any account. Even successful public model listing and changed
HTML do not declare testnet launched, inference allowed, faucet authorized,
transactions approved, original-DID custody ready or production migration safe.

Optional run when needed, from a trusted dev/test context rather than
production, after review:

```sh
python3 -I -B packaging/testnet/r1105_agent_public_readiness.py
python3 -I -B packaging/testnet/r1105_agent_public_readiness.py --live
```

Do not run this to try a claim, do not assume unknown gateway credentials
exist, do not install SDKs on Oracle, K137 or TradeBot just for a probe.
Existing active GitHub source-launch watcher (#793) should continue unchanged;
this is a separate source-only validation utility and not a new periodic job.

## Completion order

1. Preserve original Oracle DID/seed and existing pending/receipt history;
   G4/G5 migration gates remain NO_GO and unrelated to SDK release.
2. Independently obtain an **official live** testnet network/genesis/faucet
   identity, signed agent request protocol, server final receipt and confirmed
   scoring details from first-party published source. Today these proofs are
   not all available; fail CLOSED.
3. Implement exact digest-pinned testnet-specific read-only acquisition and
   separate consent-controlled test-faucet and inference requests, with hard
   daily caps, local no-double-submit nonce/receipt journal, and explicit user
   action approval. Keep real-value payments disabled by default.
4. Only after trusted host/runtime, same DID signer and restore are verified,
   test exact request signatures using non-real-value fixtures and, when
   network officially opens, a separately approved bounded first inference.
   Never replay unknown outcomes or Sybil/wash/circular inference.

No new hardware, disk, server, SDK installation or extra cloud fee is
approved. Testnet NOT READY for transactions, but source-only preparations
may be CI tested and peer reviewed now. Oracle retirement STRICT_NO_GO.
