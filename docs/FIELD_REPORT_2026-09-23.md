# FIELD REPORT — 1GB VMで24/7 AI Agentを安定運用するまで

Date: 2026-09-23 JST
Project: technocore-safe-agent
Repository: https://github.com/hanamaru777/technocore-safe-agent

## TL;DR

AI Agentを24/7で動かすと、最初に壊れるのは「モデルの賢さ」ではなく、状態管理・I/O・再起動設計・heartbeatの意味付けでした。

このProjectでは、FLOP / Technocore向けの独立Community Agentを小さなVMで常時運用しながら、Production障害を1つずつ潰しました。

最終的に効いたのは次の3つです。

・重いmaintenanceと生存heartbeatを分離する
・負荷が一瞬下がっただけでは重い処理を再開しない
・巨大stateを定期pollせず、tiny revisionで変更を検知する

特に3番目の変更後、60秒の同条件比較で以下まで改善しました。

・Discord process major faults: 21,341 → 2,152（約89.9%減）
・Discord disk read: 約167.9MiB → 約64.8MiB（約61.4%減）
・Host total major faults: 35,932 → 7,501（約79.1%減）
・Host swap-in: 約67.8%減
・Host swap-out: 約72.9%減

ただし、1GB VMに十分な余裕ができたという意味ではありません。pressure guardは今も重要な安全機構です。

## 1. heartbeatに複数の意味を持たせない

当初は、Residentのheartbeat更新が重いmaintenance処理の完了と実質的に結び付いていました。
そのためhost pressureでmaintenanceを安全に止めると、process自体は生きているのにheartbeatだけ古く見える状態になりました。

改善後は意味を分離しています。

・supervisor liveness: processが生きて監視できているか
・maintenance last refresh: 重いmaintenanceが最後に本当に成功した時刻

pressure中はsupervisor heartbeatだけを更新し、statusを pressure_paused とし、maintenanceの最終成功時刻は書き換えません。

重要なのは「生きている」と「仕事が完了した」を同じtimestampで表現しないことです。

## 2. Recoveryは速く、resumeは慎重にする

小さなVMではmemory / I/O pressureが大きく揺れます。一瞬だけ閾値を下回った時に重いchildを即再起動すると、page-in → pressure上昇 → stop → 再起動、というthrashingが起きます。

そこでmaintenance開始条件を「60秒間連続でpressure clear」に変更しました。

・停止は速く
・再開は慎重に

という非対称設計です。

## 3. 一番効いたのは巨大JSONの定期readをやめたこと

steady-state pressure attributionでは、optional maintenanceを止めた状態でもDiscordが最大のavoidable paging actorでした。

60秒間のmajor fault増加:

・Discord: +21,341
・Resident main: +7,351
・Capture: +563
・Signer: +0

原因は、Discord側のtclk review pollingが30秒ごとにrich Observer state JSONをfull loadしていたことでした。offerが変わっていなくても毎回parseしていました。

## 4. revision-gated cacheへ変更

Observerが元々書いていた小さいheartbeat JSONへ、tclk_revisionという小さな整数だけ追加しました。

新しいvalidated tclk offerがretained stateへ追加された時だけrevisionを増やします。

Discord側は:

1. tiny heartbeatだけ読む
2. revisionが同じならcacheを再利用
3. revisionが変わった時だけrich Observer stateをfull load
4. cacheには巨大state全体ではなく小さいtclk subtreeだけ保持

という構成に変更しました。

rolling upgrade中にheartbeat revisionが存在しない場合は、性能より正しさを優先し、従来のfull loadへfallbackします。
heartbeatとfull stateのrevisionが一致しないraceでも、そのpollはfail closedにして次回retryします。

## 5. Before / After

Discord:
・major faults: +21,341 → +2,152（約89.9%減）
・read: 約167.9MiB → 約64.8MiB（約61.4%減）

Host全体:
・major faults: +35,932 → +7,501（約79.1%減）
・swap-in: +57,453 pages → +18,496 pages（約67.8%減）
・swap-out: +49,127 pages → +13,322 pages（約72.9%減）

同時にprotected continuity counterが増えていないこと、Observer / Lobbyが前進していることも確認しています。

## 6. 24/7 Agent運用で学んだこと

・「生存」と「仕事完了」を別々に観測する
・Recoveryは速く、resumeにはhysteresisを入れる
・Full state pollingを最初に疑う
・tiny metadata → rich state の順で読む
・cacheは速さよりstale safetyを優先する
・optional workはcore continuityより弱くする
・推測ではなくmajor faults / RSS / swap / read_bytes / PSI / vmstatを同時に測る

## 7. v1の現在地

このProjectのv1 engineeringは完了しています。

実装済み:

・24/7 Observer / Resident
・isolated Signer
・bounded state / gap recovery
・Safe First Contact
・relationship / outcome visibility
・tclk opportunity / lifecycle safety
・Airdrop Radar
・Evidence Ledger
・Challenge Runner
・Action Inbox
・Staging Bridge
・Executor Gate
・Adapter Readiness Gate
・resource-pressure guard
・sustained-clear maintenance admission
・revision-gated Discord polling

今後の大きな機能は、未実装だから止まっているのではなく、FLOP Testnet / faucet / inference / claimの公式仕様、本物の外部Agentからのtclk opportunity、公式KOL / referral program開始などのexternal trigger待ちです。

## 8. FLOP / Technocore

このrepoはFLOP Labs公式ツールではなく、独立したCommunity implementationです。

Official tclk:
https://github.com/flop-labs/tclk

This project:
https://github.com/hanamaru777/technocore-safe-agent

## Final note

AI Agentの本番運用で難しかったのは、LLMを賢くすることよりも、

「壊れているのか、重いだけなのか、安全に止まっているのかを区別すること」

でした。

小さなVMほど、この違いがそのまま可用性になります。