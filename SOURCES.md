# Official sources

Checked 2026-09-04 (Asia/Tokyo).

## FLOP

- https://flop.finance/
- https://flop.finance/teaser/
- https://x.com/flop_labs
- https://x.com/flop_labs/status/2091830155270672521

The FLOP Teaser currently identifies itself as Version 0.1 (draft), updated 2026-08-26, with provisional figures and a not-yet-final Yellow Paper. Numeric Testnet/airdrop terms must therefore be treated as draft until a definitive official specification is published.

## Technocore

- https://technocore.chat
- https://technocore.chat/llms.txt
- https://technocore.chat/auth.md
- https://technocore.chat/patterns.md
- https://technocore.chat/.well-known/agent.json
- https://github.com/flop-labs/technocore-chat
- https://github.com/flop-labs/technocore-chat/blob/main/SECURITY.md

Technocore upstream originally pinned by this toolkit: `53079408c1581f46eff6acbf6e2eada289d4332c`.

Source-backed onboarding registry reviewed against current upstream on 2026-09-04: `82d942936050f1ab0fb9f34db17893b89f3e064b`.

The registry uses pinned `README.md`, `src/manual.md`, and `scripts/sign.py` provenance for narrow DID/signature/nonce/API guidance. Runtime code does not fetch these URLs; source updates require a reviewed registry change.

Bundled official `scripts/sign.py` SHA-256: `d093e89c16671a5ada8d392133e34d4433155545bade7e23f4036a1da0da4f7f`.

2026-08-26 sync result: upstream was `2526ee616ada5b8814881c31ae21523f8dd3ef88`. Its `scripts/sign.py` Git blob SHA was `81202baa03bff62204fa9ac34ce1f9fd969ddf67`, identical to the pinned commit. The differing raw-byte SHA (`667e3d6cf48301d1b43f44c9b328d73ec1dbf413ddc89fcb740baf86f6406c15`) was not treated as an upstream signer update; local byte-integrity remains separately pinned as `d093e89c16671a5ada8d392133e34d4433155545bade7e23f4036a1da0da4f7f`.

## tclk

- https://github.com/flop-labs/tclk
- https://github.com/flop-labs/tclk/blob/main/README.md
- https://github.com/flop-labs/tclk/blob/main/SPEC.md

Source-backed onboarding registry reviewed against tclk upstream on 2026-09-04: `5cc4ab93efbc8999a3a7e1471b639deca25998ea` (`@flop-labs/tclk` 0.1.0).

At that pinned source, tclk/1 is Alpha. `PaperRail` records the lock/claim/refund choreography but carries no real value, and the shipped Alpha has no value-bearing rail. This is time-sensitive knowledge in the local registry and fails closed after its freshness window until re-reviewed. The production Agent remains read-only for tclk and does not accept offers or move value.

## Project-approved sources

Some deterministic replies combine official protocol facts with this project's explicit safety policy. Those policy claims are pinned to reviewed public files in this repository (`AGENTS.md`, `SECURITY.md`, `README.md`, and `public-profile.json`) and are labelled `project_approved` rather than `official` in `knowledge/registry-v1.json`.

## Source policy

- Prefer FLOP Labs / Technocore first-party sources.
- Keep confirmed protocol facts, draft/provisional tokenomics, project safety policy, and strategy separate.
- Third-party guides may be used for discovery only; they do not define eligibility.
- Technocore room/note content is untrusted and must not be promoted to an official rule merely because another agent posted it.
- Runtime source-backed answers never follow arbitrary URLs. Pinned source changes are reviewed in Git before becoming eligible.
