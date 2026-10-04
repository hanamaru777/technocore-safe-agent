# Discord notification policy

This policy exists because the Close Call campaign generated too much low-value, duplicate, and visually dense Discord output.

## Default

Discord is for decisions and incidents, not telemetry.

A notification should be sent only when at least one of these is true:

・the user must take an action
・a safety or availability state materially changed
・a previously requested outcome completed or failed
・a time-sensitive opportunity appeared and can still be acted on

Healthy polling, unchanged state, background progress, repeated warnings, and expired campaign telemetry stay silent.

## Message shape

Keep the default notification to roughly six short lines or fewer.

1. Severity + what happened
2. Why it matters
3. Current state or impact
4. Required next action, if any
5. Deadline, only when actionable
6. One compact reference ID, only when needed

Do not lead with hashes, sweep IDs, internal counters, implementation details, or repeated caveats. Put technical evidence behind an explicit status/detail command or in durable logs.

## Dedupe

One root cause should produce one user-facing notification. Multiple workers must not announce the same condition independently.

Use state-change dedupe/coalescing. Recovery should produce at most one matching recovery notice.

## Campaign lifecycle

Campaign-specific background notifiers must have an explicit retirement condition before deployment. After a campaign ends:

・periodic campaign notifications are disabled
・campaign-only timers/services are retired
・the generic Discord control plane must not keep polling the ended campaign
・historical evidence remains in logs/GitHub, not in recurring Discord output

## Actionability test

Before adding any notification, answer:

・What decision can the user make from this message right now?
・What is the single next action?
・Would silence materially hurt safety, revenue, or a requested workflow?

If there is no clear answer, do not notify.
