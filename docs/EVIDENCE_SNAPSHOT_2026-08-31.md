# Evidence Snapshot — controlled Oracle E2E

Date: 2026-08-31

Purpose: preserve the facts that remain independently inspectable after the original Technocore room record has been evicted from the live ring.

This is not an airdrop registry and does not prove any FLOP reward or eligibility.

## Public project anchor

Repository:

https://github.com/hanamaru777/technocore-safe-agent

Production code commit used for the successful controlled E2E:

`c04569c8641aac571314169d53318b989f050e34`

## Controlled E2E result

Room:

`lobby`

Server-assigned sequence:

`13484079`

Local terminal state after POST:

- Autopilot outbox: `acknowledged`
- Autopilot receipt present: `true`
- isolated signer receipt: `acknowledged`
- ambiguous state: absent
- signer `last_error_code`: `None`
- signer attempts field: `0` after the acknowledged direct-success path

Recorded POST/ACK time in local state:

`2026-08-31T05:08:51Z` (UTC, rounded from the recorded timestamps)

## Later ring-eviction proof

A later read succeeded, but the target record was no longer inside the retained room ring.

Observed at verification time:

- `TARGET_SEQ=13484079`
- `FIRST_SEQ=13546666`
- `RETURNED_COUNT=20`
- `LOWEST_RETURNED_SEQ=13546666`
- `HIGHEST_RETURNED_SEQ=13546685`
- `TARGET_PRESENT=false`
- result: `TARGET_EVICTED_FROM_RING`

Difference between the first retained sequence and target:

`62,587`

Because `FIRST_SEQ > TARGET_SEQ`, the later absence is explained by eviction rather than by a claim that the POST never existed.

Technocore explicitly documents room storage as ephemeral/ring-based:

https://github.com/flop-labs/technocore-chat

https://github.com/flop-labs/technocore-chat/blob/main/SECURITY.md

## Reboot persistence proof

After production activation, the Oracle VM was rebooted and the post-reboot checker recorded:

- boot ID changed: PASS
- metadata blocker active + enabled
- Resident active + enabled
- isolated signer active + enabled
- broad metadata rule absent
- scoped metadata rule present
- ordinary-user IMDS access blocked
- signer IMDS access allowed
- Autopilot enabled and unpaused after reboot
- Resident unpaused after reboot
- Technocore DNS pass
- GitHub DNS pass
- signer health `ok`

Final gate:

`POST_REBOOT_RESULT=PASS`

`PRODUCTION_24H_ACTIVE=true`

## What is intentionally not published here

This snapshot does not publish:

- any seed/private key
- Vault secret identifiers
- cloud instance identifiers
- host/IP information
- SSH material
- credentials/tokens
- private environment files

Those are not needed to demonstrate the operational result.

## Cryptographic-verification limitation

The original room message was evicted before a later independent read-back could capture the public signature again. The historical activity record is hash-chained and the signer receipt includes local integrity hashes, but the current public snapshot does not contain the exact public Ed25519 signature from that already-evicted record.

Therefore this file should be read as a durable operational evidence snapshot, not as a complete offline cryptographic proof of that historical message.

The next evidence-format improvement should preserve, at successful POST time, the public signature plus canonical public fields required for offline verification while continuing to exclude all secret material. That work remains tracked in Issue #4.
