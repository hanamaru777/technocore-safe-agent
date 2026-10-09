# Flop archival handoff — 2026-10-09 JST

IMPORTANT: This is a historical snapshot, not a competing CURRENT/NOW/NEXT authority. Always read Issue #765 latest comment first, then this file for historical facts. All past GitHub links, 61 handoff comments, signed-off PASS and consumed STOP evidence remain linked at https://github.com/hanamaru777/technocore-safe-agent/issues/765 .

## Current at archive time

- GitHub main 11105d0209fdc0ae754f3e8d6feee8741b7d858f, merged PR #827, postmerge security-gate Actions 37883400882 SUCCESS, open PR0.
- Native ARM64 Actions 37883226433 SUCCESS, 116 existing offline tests PASS (Python3.12, Node22, locked npm/uv including optional OCI signer and Discord imports, Observer/Capture/TCLK/Signer offline). PR security Actions 37883226486 SUCCESS. This is not live OCI A1 or Production runtime compatibility.
- Last REAL production R822 single read-only sample at 2026-10-09T02:30:24Z: Flop Production still OLD source ec4bc4892d40cdd2a03e102faa44d72c89e01b99, main/clean. Four protected units Resident/Capture/Signer/Discord active with NRestarts0 and unchanged accepted PIDs. Rich Observer and Safety both degraded for known lobby protected backlog capacity. Memory PSI FULL avg10=12.22 > allowed5, IO PSI FULL avg10=39.86 > allowed10. Last verified resource gate NO-GO; no sustained >=60s safe window. No new Production mutation as part of ARM64 work.
- Rich cursor71155086 vs previous tiny bootstrap69155082, gap2,000,004 is a sequence-value distance NOT a SQLite row count. Core protected gap143 events/5,652,707 messages and startup bridge26/569,552 unchanged in R822; earlier losses not restored. Actual Capture persistent writes remain unproven.
- User Oracle Tokyo Instances screenshot confirms TWO running Always Free VM.Standard.E2.1.Micro 1GB VMs, one Flop technocore-resident, second an independent VM. Both AMD Micro slots exhausted. OCI A1.Flex is a separate Always Free compute allocation, but actual free shared boot/block storage (200GB total), A1 quota, home region and physical host stock are UNCONFIRMED. No permission to provision, resize, stop or delete any VM.

## Chronological historical successes and failures — NEVER RERUN

### October 6: Windows CI Bootstrap

Old dc629... invocation stopped before Production mutation due PowerShell 5.1 empty ssh-keygen password argv and missing public key. #766/PR767 noninteractive keygen fixed. Next 8553db... stopped in SSH preflight due Windows CRLF in Bash pipeline; #768/PR769 LF checkout fixed. Next 99a286... scp argv failed due PowerShell Args conflict; #770/PR771 switched to ArgumentList. The 403128... action failed locally on benign native stderr BUT remote git FF had already happened; follow-up read-only audit proved partial Production mutation and missing CI key. #772/PR773 separated stderr and exit status. Then 313081... STOP_REMOTE_SETUP_FAILED due direct execution of an installer tracked mode100644; #774/PR775 changed to fixed /bin/bash, #776/PR777 resolved CI dedicated account shadow. Every failed carrier is CONSUMED/DO_NOT_RERUN.

A NEW guarded Phase B targeting fcecfb8662ad01edc3896f125a0fbb90da879efe then SUCCEEDED: local dedicated CI key bootstrap, Github fixed read-only Actions proof 37437941347 SUCCESS, supervisor refresh PASS, Discord presentation refresh PASS, Resident/Lobby/Signer protected PIDs and NRestarts unchanged. An extra independent read-only post-audit initially STOPPED due root-only sudo redirection and was separately corrected to PASS. #759/#736 CLOSED completed. Never repeat Phase B, dedicated key installation, supervisor or Discord refresh. GitHub Actions proof is intentionally binding_capable=false and NOT an autonomous trade path.

### October 6-7: official readiness and cleanup

- #778/PR779 official FLOP Testnet/Airdrop page Radar; #780/PR781 current Yellow Paper parser; #782/PR783 trusted FLOP-hosted Github launch-link discovery without following/executing arbitrary links; #785/PR786 source-truth docs update.
- #311 real Testnet adapter WAIT official RPC/chain ID/faucet/registration/inference/receipt/settlement specs; no unsupported real Testnet action implementation.
- #787/PR788 expired Sonnet/Close Call Oracle cleanup: first SSH255 failure consumed, later exact-safe cleanup PASS and protected units unchanged. Do not rerun.
- #789/PR790 and #791/PR792 55 obsolete tracked files, 8935 lines retired without loss of durable history. #793/PR794 read-only official launch-artifact hourly Github watch.

### October 8: source optimization and Production phases

- #795/PR796 Capture import isolation; #797/PR798 lazy Airdrop Notifier; #799/PR800 ended Close Call Discord polling; #801/PR802 idle TCLK import reduction. #803/PR804 Signer refactor REJECTED/UNMERGED/NOT PLANNED, do not revive.
- PROD805 guarded source rollout + one restart each of Capture and Discord PASS/CONSUMED; Resident and Signer stayed unchanged.
- R806 natural Airdrop Monitor and Ledger50/50 PASS/CONSUMED. Do not induce fake natural evidence by manual scheduler.
- R807 source-only FF to ec4bc4892d40cdd2a03e102faa44d72c89e01b99 PASS/CONSUMED. Running processes NOT restarted.
- Flop and Aerodrome are DIFFERENT OCI VMs. Flop own Capture, Resident, Discord contribute I/O/swap; source of host-wide PSI not uniquely attributed.

### October 8-9: Capture P0, diagnostic failures and code hardening

- Capture heavy reads/no measured writes in previous windows, old ~700MB SQLite file/0 WAL, live DB FD matches current inode READ_WRITE. These do not prove exact root cause or DB corruption. Avoid opening active SQLite.
- Observer V2 size-guard STOP, V3 false PASS bad jq, V4 correct lobby degraded, V5/V6 shell EOF STOP; all consumed/DO_NOT_RERUN. V7 found startup_lobby_capture_protected_backlog_capacity. V8 proved tiny heartbeat missed lobby cursor while old bootstrap cursor stale by 2,000,004 sequence positions.
- PR #808 async tiny heartbeat cursor source fix; #811/PR812 safe prune capped to 5,000 already-consumed SQLite rows per transaction; #823/PR824 skip expensive 1s SQL count/OFFSET/meta COMMIT when blocked cursor truly unchanged. All source CI PASS, NOT imported into old live Production.
- R809 read-only Production resource audit PASS/CONSUMED, strict service restart gate FAIL. #813/PR814 offline readiness evaluator, #815/PR816 bounded 60s proof collector, #817/PR818 stale/future proof rejection, #820/PR821 allowlisted failure-stage codes, all source PASS.
- R819 one-shot read-only SSH ended ValueError/SSH exit2 with no proof, consumed STOP; exact failed stage never known, do NOT rerun. R822 separate instantaneous read-only preflight PASS/CONSUMED, but mem/IO PSI above thresholds and observer/safety degraded => Production still NO-GO. Never rerun R809/R819/R822.
- #810 staged Production recovery DESIGN ONLY: strict fresh memory and I/O sustained safety, protected counters/no unknown room, narrow independently approved health exception, then guarded source update, Capture FIRST with bounded-safe prune, stop and independently audit, Resident SECOND only if still safe. Old Capture + new Resident cursor could do huge unsafe DELETE; never reverse order. No auto two-stage restart.
- #825 resource/OCI maintenance design NO-GO, no unapproved cloud resource purchase, shape migration, hot SQLite copy or protected process control.
- #826/PR827 ARM64 source CI SUCCESS 116 tests, not proof of A1 stock or actual signer/SQLite migration. Source only.

## Current open authority and absolute no-repeat

- CURRENT/NOW/NEXT: Issue #765 latest comment, not issue body. Permanent #667 OPEN safety gates; #666 human-independent binding unresolved; #723 control-path redundancy NO-GO; #311 official Testnet WAIT. #805 Capture P0 OPEN; #810 phased repair design NO-GO; #825 OCI/resource research NO-GO.
- All previous failed/successful Production attempts, R806/R807/R809/R819/R822, old V2/V3/V5/V6, Phase B, PROD805, expired Oracle cleanup are consumed. Do NOT rerun even when a previous GitHub comment called them NEXT at the time.
- No Trade/POST/Signer/Vault/approval change, no active SQLite SELECT/PRAGMA/VACUUM/DELETE/backup, no manual cursor bump, no service restart, no source FF, no swapoff/drop caches, no whole-VM reboot; no change to the other VM/BOT.
- Desktop Commander monthly quota 10,001/10,000 is exhausted. Do not ask user to reconnect, upgrade or pay. User Windows SSH could be used ONLY for a new and individually audited read-only probe after a material new resource safety reason, not to repeat consumed scripts. ChatGPT handles GitHub and safety audit; Codex only if substantial actual local implementation needed.

## Current NEXT, not authorization

1. Do not create a third VM yet. Need ONE read-only evidence set showing combined OCI boot and block volume allocated sizes vs 200GB free storage pool, tenancy home region and A1 remaining capacity. Existing screenshot already verified TWO Micro shapes; do not ask again. If necessary ask for ONE OCI Storage Boot Volumes list screenshot of SIZE columns, mask IDs/IP, then validate any other block volumes.
2. A1 has distinct free compute pool but host stock/billing/volume headroom unknown. Even if available, fresh Arm-compatible OS and isolated OFFLINE test without keys or two simultaneous live Capture writers would precede any separately approved planned downtime/cutover.
3. Old Flop Production P0 remains NO-GO due R822 pressure and degraded Lobby. Never infer immediate safe restart from GitHub CI PASS. To consider a guarded restart needs genuinely changed conditions, fresh sustained >=60s resource proof with MemAvailable>=256MiB, memory PSI FULL avg10<=5 and IO PSI FULL avg10<=10 for all samples, four protected PIDs/NR0, unchanged core/bridge gaps and fresh Rich/Safety, plus separate approved narrow known-degraded exception. Existing R813 policy pins old target a1b3517; update to exact latest target before reuse.
4. Future full source manifest must be freshly compared: GitHub now includes PR827 inert CI file in addition to previous 8 changed paths, and production is still at ec4bc..., main/clean last observed. Capture FIRST, Resident SECOND only with separately approved step gates and stop-after-each-stage receipts.
5. Never close #805 until real durable Capture recovery/continuity proven.

## Links

- Latest authoritative freeze: https://github.com/hanamaru777/technocore-safe-agent/issues/765
- Permanent readiness: https://github.com/hanamaru777/technocore-safe-agent/issues/667
- Production P0: https://github.com/hanamaru777/technocore-safe-agent/issues/805
- Staged recovery: https://github.com/hanamaru777/technocore-safe-agent/issues/810
- OCI resource feasibility: https://github.com/hanamaru777/technocore-safe-agent/issues/825
- Arm64 result: https://github.com/hanamaru777/technocore-safe-agent/issues/826
- Historical #765 contains 61 dated comments prior to this archive, including all observed failures, exact historical SHAs and CI proofs. Do not claim this concise archive duplicates all low-level stdout; use original comment for that precision.

## Next-chat copy/paste

Flop開発の続きです。Repository: hanamaru777/technocore-safe-agent。唯一のCURRENT/NOW/NEXT正本はIssue #765の最新Handoff Freezeコメントです。必ず全文を読んでください。詳細史料は docs/CHATGPT_HANDOFF_ARCHIVE_2026-10-09.md と#765の過去コメント、関連#667/#666/#723/#311/#805/#810/#825にあります。成功/失敗/消費済み/DO_NOT_RERUNを再実行せず、私に説明させ直さないでください。PR#827 Arm64は116テストPASS、main11105d...、PR/main CI成功（数値はfresh確認）。ユーザーOCI画面で既存2台がE2.Micro/1GB/Always Free/Runningと確認済みで、3台目A1の実行可否は無料ストレージ/tenancy quota/host availability未確認。既存VM2台を削除/停止しないでください。旧Flop本番ec4bc...はR822でmemory PSI12.22、IO PSI39.86、Rich/Safety degraded、#805 P0、#810復旧設計NO-GO。GitHubの修正を本番適用済みと誤認せず、リソース証明なしにCapture/Resident/Signer/Discordを再起動しないでください。ChatGPT自身がGitHubの調査・監査・Issue更新を担当し、安全な次の確認から進めてください。
