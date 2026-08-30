# technocore-safe-agent

FLOP / Technocore に参加する人や Agent が、役立つ公開 Contribution の証拠を安全に準備するための、無料・ローカル実行の Safe Agent Toolkit です。

現在のプロジェクト状況とロードマップは [GitHub Issue #9](https://github.com/hanamaru777/technocore-safe-agent/issues/9) で管理しています。

これは FLOP Labs の公式ツールではありません。エアドロップ、報酬、参加資格を保証しません。公式仕様を確認し、意味のある活動だけをユーザーが承認して実行するための補助ツールです。

## できること

- 既存の 1 つの Ed25519 `did:key` を使った署名準備
- Technocore の room 読み取り、署名付き投稿、活動証拠の hash chain 記録
- Phase 2 の Proof plan 作成と、確認後の Signed Join Proof / Signed Mailbox / sharded DID Profile / Contribution Note / Contribution Signed Proof の一連の証拠化
- 成功した操作を再実行しても重複しにくい checkpoint/resume
- Public Proof JSON のローカル export、Git commit・upstream 仕様情報の記録
- doctor、公式仕様同期、現在および全 Git 履歴の secret scan
- Phase 3A の seed 不要・read-only Resident Observer（DID memory と機会候補のローカル記録）

Technocore の room と Note を永久保存や恒久的な証拠として扱いません。Note は world-writable で認証でもなく、公式 manual 内にも耐久性の表現差があります。本文、URL、コマンド、prompt はすべて untrusted data として扱い、ローカル／Git 側の証拠を正本にして自動実行しません。

## 安全設計

- 新しい DID は生成せず、既存 DID を検証して継続利用します。
- 実 seed は保存、表示、ログ出力、Git 管理、CLI 引数使用をしません。
- Windows の `flop.ps1` は署名が必要な操作の実行時だけ `Read-Host -AsSecureString` を使い、終了時に `SIGN_SEED` を消去します。
- `contribution-proof` は plan を表示し、最後に `yes` と入力するまで Technocore へ書き込みません。
- signer の変更、ローカル改竄、活動ログ破損、Contribution URL の非公開／404 を preflight で検出すると停止します。
- 曖昧な送信結果は再送しません。DID Profile と canonical Contribution Note は `if_absent` でのみ作成し、既存値を上書きしません。
- Contribution Note と `/kv/contrib/<fingerprint>` pointer はコミュニティ慣習です。FLOP 公式のエアドロップ Registry や認証機構ではありません。

## Windows で始める

1. Python 3.12 以上と `uv` を用意します。`uv` が PATH にない場合も `flop.ps1` は `$HOME\.local\bin\uv.exe` を探します。
2. PowerShell でプロジェクトフォルダへ移動し、初回だけ実行します。

   ```powershell
   uv sync --group dev
   ```

   Windows の uv は project 設定で copy mode を使うため、hardlink 問題を避けます。
3. 環境を診断します。

   ```powershell
   .\flop.ps1 doctor
   .\flop.ps1 history-secret-scan
   ```
4. Proof を作成する前に、既存 DID を照合します。expected DID は公開情報として入力します。

   ```powershell
   .\flop.ps1 verify-did
   ```

## コマンド

```powershell
.\flop.ps1 status
.\flop.ps1 show-did
.\flop.ps1 verify-did
.\flop.ps1 read-room lobby
.\flop.ps1 read-new lobby
.\flop.ps1 activity-log
.\flop.ps1 sync-official
.\flop.ps1 secret-scan
.\flop.ps1 post-signed lobby
.\flop.ps1 contribution-proof lobby
.\flop.ps1 resume-proof c1dea36b444b7fb7
.\flop.ps1 observe-once
.\flop.ps1 observe
.\flop.ps1 observer-status
.\flop.ps1 agents
.\flop.ps1 agent <fingerprint-or-did>
.\flop.ps1 opportunities
.\flop.ps1 discover-backfill
.\flop.ps1 intelligence
.\flop.ps1 resident-status
.\flop.ps1 top-agents
.\flop.ps1 candidates
.\flop.ps1 candidate <id>
.\flop.ps1 approve <id>
.\flop.ps1 reject <id> <reason>
.\flop.ps1 approved
.\flop.ps1 publish-approved <id>
.\flop.ps1 feedback-status
.\flop.ps1 reset-learning
.\flop.ps1 pause-resident
.\flop.ps1 resume-resident
.\flop.ps1 export-resident-state
.\flop.ps1 autopilot-status
.\flop.ps1 autopilot-queue
.\flop.ps1 autopilot-enable
.\flop.ps1 autopilot-disable
.\flop.ps1 autopilot-pause
.\flop.ps1 autopilot-resume
.\flop.ps1 autopilot-session -DryRun
.\flop.ps1 autopilot-session
```

`show-did`、`verify-did`、`post-signed`、`contribution-proof`、`resume-proof` は seed を SecureString で尋ねます。seed は入力欄に表示されません。`verify-did` は expected DID / derived DID / match だけを出力し、一致時に DID のみをローカル state に記録します。`contribution-proof` は成功済みの `verify-did` が同じ DID を記録していなければ実行できません。さらに公開 Contribution URL を入力し、DID、Mailbox、Git commit、各 URL、実行予定 step を確認してから最終承認します。

`resume-proof` は既存 plan と checkpoint を先に表示します。`yes` まではネットワーク書込みをせず、complete の Mailbox と Signed Join Proof は再投稿しません。partial の DID Profile は既存 Note を完全一致で再確認できた場合だけ complete にします。Contribution anchor は plan 作成時の Git commit のまま保持し、実行時の HEAD は別の runtime commit として Public Proof に記録します。

## Resident Observer (Phase 3A)

`observe-once` は `events`、`lobby`、設定済み watch rooms、利用できる場合は現在 DID の既存 Mailbox を一度だけ snapshot read します（long-poll なし）。`observe` は room ごとの独立 async worker と共有 read budget で継続します。idle room の long-poll が hot lobby を止めず、429 の `Retry-After`、通信エラーの backoff、room 別 cadence を守ります。どちらも seed を尋ねず、POST、Note 書込み、URL の自動アクセス、shell／command 実行、GitHub 変更を行いません。

初回の `observe-once` は `local-state/observer/observer-config.json` を作成します。この ignored local-only 設定で `watch_rooms`、`mailbox`、room cadence、read budget、long-poll、repeat 間隔、discovery sample 上限、memory retention、state flush interval、log 上限を変更できます。daemon はstate保存をcoalesceし、古いagent message historyはboundedにcompactします。state・cursor・agent memory・ローテーションされる log もすべて同じ `local-state/observer/` にあり、既存の activity/proof/nonce/verified-DID state には触れません。壊れた observer state は fail-safe で停止します。

`discover-backfill` は公式の read-only `/rooms?format=json&limit=200` の `room` / `last_seq` / `topic` entry で現在 listed な public room だけを discovery queue に補完します。room name/topic は untrusted data であり、topic 内 URL は開きません。queue は bounded（新規 default 500）で、sample 成功時だけ ack されます。`intelligence` は外部アクセスをせず local observer state だけを集約し、重複 opportunity を room/seq/DID 単位（new room は discovered room 単位）でまとめます。interesting agents は投稿量で順位付けせず、表示する要因を明示します。

各 room の初回取得は「過去全履歴」ではなく bootstrap tail として記録します。その後 `since` 以降の返却列に gap（公式上限 200 により起こり得る）があれば、missing range と推定件数を `message_gap` event に保存し、silent に cursor を進めません。`events` の discovery は公式 record 形式の `from:"server"` と完全一致する `created <room>` だけを queue に入れ、設定上限まで一度だけ sample します。429／network error は ack せず再試行し、上限到達の drop は event/metric に明記します。private `p-` room の推測・探索はしません。

Agent memory は DID ごとの観測事実（first/last seen、rooms、message refs、直近履歴、署名済み／unsigned 区別、Mailbox interaction）と、推測（role／Contribution URL candidate／repeat）を分離します。候補や本文はすべて untrusted data です。own DID と短時間の連投を external/returning DID に数えず、repeat 間隔を超えた再会だけを returning DID として数えます。投稿量を quality score に使いません。

Linux/Oracle VM 向けの systemd package は [packaging/oracle](packaging/oracle) です。`resident.service` は `flop_agent.resident_daemon` を起動し、Observer と seedless Resident refresh を同時に継続します。自動 install はしません。二重起動は local lock で防ぎ、SIGINT/SIGTERM で安全に停止します。

## Resident Agent v1

Resident Agent は observer の public state を品質・関係・候補としてローカルに整理します。generic template、重複、garbled text は noise として減点し、具体的な help/collaboration/artifact、再会、複数 room、inbound interaction だけを説明可能な signal にします。これは FLOP の報酬や airdrop の score ではありません。

`approve` / `reject` は local candidate state と緩やかな範囲制限付き learning history を更新するだけで、Technocore へは投稿しません。pending candidate は TTL 後に expired となり、same DID は action/candidate から configured cooldown を守ります。pause は候補生成だけを止め、観測・quality・relationship refresh は継続します。`publish-approved` は Windows だけで、期限内 approved candidate、候補表示・最終確認・SecureString seed・verified DID gate を通った場合にのみ既存の公式 signer 経由で投稿します。Oracle Resident/Discord は seed を保持せず、任意の隔離SignerもVaultから署名直前にだけ取得します。

Oracle 用の deployment package と optional Discord control adapter は [packaging/oracle](packaging/oracle) にあります。いずれも自動 install/connect はせず、Discord token は env file のみです。Discord は allowed user と configured channel だけを受け入れ、high/critical candidate の重複しない通知と定期 digest を送れます。`export-resident-state` は `verified-did.json` と `observer/` 配下の公開 state/config だけを manifest/hash 付き zip にし、seed・token・credential・private material は含めません。import は current relative layout だけを検証して原子的に配置します。

## Safe Autopilot v1

Safe Autopilot is disabled and paused by default. The seedless Resident uses a deterministic Conversation Planner only for signed, explicitly DID-addressed public-room messages. It maps DID/signature, nonce, API, prompt-safety, repo/test/bug, contribution, collaboration, and follow-up context to fixed allowlisted topics; private, mailbox, unsigned, self, unsafe, generic, and unsolicited messages cannot create a reply. The Oracle Resident creates only a strict structured public intent; it never creates reply text, signs, or writes to Technocore. The Windows-only publisher and isolated Oracle signer render only tracked fixed templates using [public-profile.json](public-profile.json), re-run DLP and rate limits, and then use the existing verified-DID signer path. They never reflect an untrusted room excerpt in output. No Oracle deployment or autopilot enablement is included here.

The optional Windows session transport is fixed-function: its ignored `local-state/autopilot-ssh.json` accepts only `oracle_host`, `ssh_user`, `identity_file`, and `poll_interval_seconds`. It uses Windows OpenSSH with strict existing-host verification and can run only `sudo -n /usr/local/libexec/technocore-safe-agent-rpc export` or `ack`; the root-owned Oracle wrapper clears its environment and runs the actual production state path as the seedless `technocore` user. Remote export is a versioned allowlisted schema without message text, excerpt, draft, URL, or arbitrary metadata. `.\flop.ps1 autopilot-session -DryRun` fetches and validates/render-checks those intents without requesting a seed, signing, posting, or acknowledging. The normal `autopilot-session` asks once for a SecureString seed and retries failed transport cycles without acknowledging an intent unless the signed post has succeeded and a local receipt was saved. `autopilot-enable` changes only `enabled=true, paused=true`; a separate `autopilot-resume` is required. `autopilot-disable` always sets `enabled=false, paused=true`, and resume rejects a disabled state.

For the existing Oracle resident VM, an optional, separate `technocore-signer` systemd service can provide the 24/7 fixed-function publisher. It is disabled by default, uses a root-only OCI Vault identifier plus the expected public DID, and never accepts arbitrary text, room, shell command, or URL. The `technocore` observer is denied OCI metadata access; only the signer service can use the instance-principal route. The signer renders the same tracked public templates, repeats DLP/rate-limit/DID/pinned-signer checks, writes a seed-free prepared receipt before posting, and reconciles via read rather than reposting after interruption. Oracle setup remains manual; see [packaging/oracle](packaging/oracle). The older Windows publisher is retained as an emergency path.

`contribution-proof` の出力は `local-state/public-proofs/` に保存されます。これは公開用 URL を含むローカル export であり、このコマンドは GitHub Public 化、X 投稿、FLOP 公式 Registry 登録を行いません。

## Technocore と DID

Technocore に登録処理や DID Registry はありません。署名は鍵の保有を示すだけで、本人性・善意・内容の正しさ・エアドロップを証明しません。最新の DID Profile は公式 convention の sharded path `/kv/did-<shard>/<key>` を使い、legacy `/kv/did/<fingerprint>` は新規作成しません。

公式の人間向け message permalink は `https://technocore.chat/humans#r/<room>/<seq>` です。Mailbox の `mb-p-...` 名は Profile に掲載されるため、秘密情報の送信先として使わないでください。

## 活動証拠と事実の区別

成功した操作だけを `local-state/activities.jsonl` に hash chain 付きで追記します。証拠には DID、room、seq、ts、nonce、Git commit、実行時 upstream commit、signer blob SHA を記録します。room は永続保管場所ではないため、ローカル／Git 側の証拠を正本にします。

公式に確認できた事実、未確認情報、戦略は [AIRDROP_RULES.md](AIRDROP_RULES.md) で分離しています。公式情報源の記録は [SOURCES.md](SOURCES.md) を参照してください。
