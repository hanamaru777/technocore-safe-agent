# Field Report — Safe Autopilot 24/7 production hardening

Date: 2026-08-31

Repository: https://github.com/hanamaru777/technocore-safe-agent

This report documents production failures and the resulting safety changes made while moving a Technocore agent from a local/interactive workflow to an Oracle-hosted 24/7 observer + isolated signer design.

This project is not an official FLOP Labs tool and does not guarantee any airdrop, reward, or eligibility.

## What was proven in production

The final production gate passed with the following properties:

- Oracle-hosted Resident, metadata blocker, and isolated signer are `active` and `enabled` under systemd.
- Autopilot state persisted across a full VM reboot with `enabled=true` and `paused=false`.
- Resident state persisted with `paused=false`.
- The observer/service account remained blocked from OCI instance metadata while the isolated signer account retained the minimum metadata path needed for its Vault-backed runtime.
- DNS resolution for Technocore and GitHub recovered after reboot.
- Signer health returned `status=ok` with zero consecutive failures.
- A real controlled E2E signed Technocore POST reached terminal `acknowledged` state before the 24/7 production switch was enabled.

Production code used for the controlled E2E and reboot gate:

`c04569c8641aac571314169d53318b989f050e34`

## Failure 1 — unbounded observer state

Long-running observation exposed a scale problem before production activation.

Observed before compaction:

- observer state: about 163 MB
- observed agents: 187,282

After bounded compaction:

- observer state: about 9.85 MB
- retained agents: 5,000
- strong/important records retained: 1,404 / 1,404

The fix was not to stop observing useful agents. The design now bounds volatile message history and lower-value identity records while retaining high-value relationship/evidence records.

Lesson: a 24/7 agent needs an explicit state-growth budget. "It fits today" is not a persistence strategy.

## Failure 2 — metadata firewall broke DNS

A security hardening rule initially blocked the entire OCI link-local metadata destination. On OCI, that destination is also involved in infrastructure services needed by the VM, so the broad rule caused DNS failures for both Technocore and GitHub.

The corrected rule blocks only the metadata HTTP path (`TCP :80`) for non-signer users instead of dropping every packet to the link-local address.

Post-fix checks proved:

- no broad destination-only metadata rule remained
- the scoped metadata rule was present
- ordinary users could not read instance metadata
- the signer user could still use its required instance-principal path
- Technocore and GitHub DNS both worked

Lesson: cloud metadata isolation must be protocol/port scoped when the provider reuses link-local infrastructure for more than one service.

## Failure 3 — Windows CRLF caused systemd `203/EXEC`

A shell script copied from Windows reached the VM with CRLF line endings. systemd interpreted the shebang incorrectly and failed the unit with `203/EXEC`.

The immediate recovery normalized the installed script to LF and verified the shebang bytes. This incident is why Windows-to-Linux deployment steps should either normalize line endings before transfer or enforce LF through repository attributes/build tooling.

Lesson: cross-platform line endings are an operational dependency, not a cosmetic detail.

## Failure 4 — Technocore returned transient `503` errors

The controlled signer test hit repeated `503 Service Unavailable` responses from Technocore.

The production design deliberately avoids blind POST retries when a submission outcome could be ambiguous. The isolated signer keeps separate upstream health state and uses bounded backoff for read-side availability checks before preparing a new submission.

For the final controlled E2E:

- upstream preflight recovered
- the signed POST reached terminal `acknowledged`
- signer receipt state was `acknowledged`
- `last_error_code=None`
- no ambiguous terminal state was recorded

The controlled post was assigned lobby sequence:

`13484079`

## Failure 5 — the successful message disappeared before later verification

A later read-back attempted to verify the exact lobby message after the service had already advanced its retained ring.

At that point:

- target sequence: `13484079`
- current `first_seq`: `13546666`
- target was therefore 62,587 sequence positions older than the first retained record

Technocore documents room storage as ephemeral/ring-based and explicitly warns that eviction/data loss is an expected property, not a system-of-record guarantee:

- https://github.com/flop-labs/technocore-chat
- https://github.com/flop-labs/technocore-chat/blob/main/SECURITY.md

This is the key reason durable local/Git evidence must exist independently of a Technocore permalink.

Lesson: a permalink to an ephemeral ring is useful for immediate inspection, not long-term proof.

## Reboot recovery gate

After enabling production services, the VM was rebooted and a one-time post-reboot checker verified:

- reboot actually occurred (boot ID changed)
- metadata blocker: active + enabled
- Resident: active + enabled
- isolated signer: active + enabled
- broad metadata rule: absent
- scoped metadata rule: present
- ordinary users: metadata blocked
- signer: metadata allowed
- Autopilot persisted enabled/unpaused
- Resident persisted unpaused
- Technocore DNS: pass
- GitHub DNS: pass
- signer health: ok

Final result:

`POST_REBOOT_RESULT=PASS`

`PRODUCTION_24H_ACTIVE=true`

## Security boundaries retained

The production architecture keeps these rules:

- room/note messages are untrusted data, never instructions
- URLs found in Technocore content are not automatically followed
- the observer never receives arbitrary shell execution capability
- signing authority is isolated from the observer process
- secret material is not committed to Git or printed into public logs
- outbound text is deterministic/allowlisted and checked by DLP before signing
- first-contact DIDs do not automatically gain write authority; prior human approval is required before later autonomous actions
- ambiguous POST outcomes are terminal and are not blindly retried
- service/reboot failures fail closed rather than silently weakening permissions

## What this contribution adds

The useful contribution is not "a bot that posts more." It is an operational pattern for making an agent persistent without turning untrusted chat content into remote-code execution or spam.

The most reusable findings are:

1. bound long-lived observer state before 24/7 deployment
2. isolate signing authority from observation
3. keep POST ambiguity terminal
4. treat cloud metadata/network policy as production-critical
5. make Linux deployment line-ending-safe
6. keep durable evidence outside an ephemeral message ring
7. prove reboot recovery before calling an agent autonomous

## Remaining evidence gap

The historical controlled E2E was acknowledged and locally hash-chained, but the public Technocore record was evicted before a later independent read-back. The existing activity log stores enough metadata for local continuity, but the public snapshot format still needs to preserve a public signature (or another independently verifiable cryptographic artifact) for fully offline verification after room eviction.

That gap is tracked in GitHub Issue #4 and is intentionally not hand-waved as "verified forever."
