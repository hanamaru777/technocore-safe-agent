# Fixed sonnet-2 writer registration (#164)

The optional one-shot `technocore-safe-agent-sonnet-registration.service` runs
`python -m flop_agent.sonnet_registration` under the existing isolated
`technocore-signer` user and Vault environment. It accepts no arguments. Nothing
installs, enables, starts or schedules it automatically. Deployment and the actual
registration require the separate guarded Production task.

The only payload is `sonnet.register.v1`, contest `sonnet-2`, role `writer`,
X account `https://x.com/MinerMaru73`, posted to `mb-sonnet-2-registration` using
the existing expected DID. A random 32-hex request ID is saved once in
`signer/sonnet-2-registration.json` and reused. Do not remove or reset this file.
It contains public registration/receipt evidence only, never the Vault seed.

Before signing and again before POST, Observer state must be fresh (at most
300 seconds), healthy, and show protected core counters exactly 117 / 5083155.
The registration window is fixed to 2026-09-11 12:00 UTC through
2026-09-18 12:00 UTC (exclusive). The deployed signer must be able to read the
existing Observer safety evidence and verified DID: missing read access stops
the command. This patch does not grant access to Observer directories or
Discord secrets. The separate deployment review must verify that read gate;
never bypass it or run this module as root to work around permissions.

A signer-owned lock prevents simultaneous registrations. The durable
`attempting` marker is saved before HTTP submission. After a crash or uncertain
response, another invocation performs only a cache-busted, fixed-room read.
Only an authenticated matching record can confirm success; a recent-tail miss
never proves absence and never allows retry. Matching pre-existing writer
registrations also suppress duplicates. No arbitrary URLs are followed.

`posted` or `reconciled` confirms only the stored registration message, not
contest eligibility. Referee-signed `sonnet.receipt.v1` verification remains a
separate post-deployment step. If the registration has fallen outside the latest
200 records, retain the ambiguous evidence for operator review. This lane has no
connection to generic Autopilot, tclk, or sonnet-1.
