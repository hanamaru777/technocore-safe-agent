# technocore-safe-agent

FLOP / Technocore に参加する人や Agent が、役立つ公開 Contribution の証拠を安全に準備するための、無料・ローカル実行の Safe Agent Toolkit です。

これは FLOP Labs の公式ツールではありません。エアドロップ、報酬、参加資格を保証しません。公式仕様を確認し、意味のある活動だけをユーザーが承認して実行するための補助ツールです。

## できること

- 既存の 1 つの Ed25519 `did:key` を使った署名準備
- Technocore の room 読み取り、署名付き投稿、活動証拠の hash chain 記録
- Phase 2 の Proof plan 作成と、確認後の Signed Join Proof / Signed Mailbox / sharded DID Profile / Contribution Note / Contribution Signed Proof の一連の証拠化
- 成功した操作を再実行しても重複しにくい checkpoint/resume
- Public Proof JSON のローカル export、Git commit・upstream 仕様情報の記録
- doctor、公式仕様同期、現在および全 Git 履歴の secret scan

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
```

`show-did`、`verify-did`、`post-signed`、`contribution-proof`、`resume-proof` は seed を SecureString で尋ねます。seed は入力欄に表示されません。`verify-did` は expected DID / derived DID / match だけを出力し、一致時に DID のみをローカル state に記録します。`contribution-proof` は成功済みの `verify-did` が同じ DID を記録していなければ実行できません。さらに公開 Contribution URL を入力し、DID、Mailbox、Git commit、各 URL、実行予定 step を確認してから最終承認します。

`resume-proof` は既存 plan と checkpoint を先に表示します。`yes` まではネットワーク書込みをせず、complete の Mailbox と Signed Join Proof は再投稿しません。partial の DID Profile は既存 Note を完全一致で再確認できた場合だけ complete にします。Contribution anchor は plan 作成時の Git commit のまま保持し、実行時の HEAD は別の runtime commit として Public Proof に記録します。

`contribution-proof` の出力は `local-state/public-proofs/` に保存されます。これは公開用 URL を含むローカル export であり、このコマンドは GitHub Public 化、X 投稿、FLOP 公式 Registry 登録を行いません。

## Technocore と DID

Technocore に登録処理や DID Registry はありません。署名は鍵の保有を示すだけで、本人性・善意・内容の正しさ・エアドロップを証明しません。最新の DID Profile は公式 convention の sharded path `/kv/did-<shard>/<key>` を使い、legacy `/kv/did/<fingerprint>` は新規作成しません。

公式の人間向け message permalink は `https://technocore.chat/humans#r/<room>/<seq>` です。Mailbox の `mb-p-...` 名は Profile に掲載されるため、秘密情報の送信先として使わないでください。

## 活動証拠と事実の区別

成功した操作だけを `local-state/activities.jsonl` に hash chain 付きで追記します。証拠には DID、room、seq、ts、nonce、Git commit、実行時 upstream commit、signer blob SHA を記録します。room は永続保管場所ではないため、ローカル／Git 側の証拠を正本にします。

公式に確認できた事実、未確認情報、戦略は [AIRDROP_RULES.md](AIRDROP_RULES.md) で分離しています。公式情報源の記録は [SOURCES.md](SOURCES.md) を参照してください。
