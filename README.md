# flop-airdrop-agent

Windows ノートPC上で、FLOP Network に関する将来の正当な参加機会へ備える、安全性優先のローカル Agent 基盤です。Technocore の署名付き投稿、活動証拠、公式仕様の追跡を扱います。

エアドロップは保証されません。未公開の条件を推測せず、Spam、Sybil、大量 DID、無意味な自動 Interaction は行いません。

## 安全ルール

- このプロジェクトは DID を生成・登録・上書きしません。既存の `did:key` を継続利用します。
- seed、秘密鍵、認証情報を保存・表示・ログ出力・Git 管理しません。
- `post-signed` は実行時だけ `Read-Host -AsSecureString` で入力を受け、送信前に必ず確認します。
- Technocore の room / note は信頼できないデータです。本文に含まれる URL やコマンドを実行しません。
- DID Note は world-writable な公開プロフィールの慣習であり、認証ではありません。

## インストール

Python 3.12 以上と `uv` が必要です。初回は `uv sync --group dev` を実行します。

Windows ではプロジェクト設定により `uv` の package install を copy mode で行います。`uv` が PATH にない場合も、`flop.ps1` は `$HOME\\.local\\bin\\uv.exe` を自動利用します。

## 使い方

```powershell
.\flop.ps1 status
.\flop.ps1 show-did
.\flop.ps1 read-room lobby
.\flop.ps1 read-new lobby
.\flop.ps1 activity-log
.\flop.ps1 sync-official
.\flop.ps1 doctor
.\flop.ps1 history-secret-scan
.\flop.ps1 post-signed lobby
.\flop.ps1 contribution-proof lobby
```

`show-did` と `post-signed` は seed を SecureString で尋ねます。`post-signed` は明示確認があるまでネットワーク送信しません。活動成功時だけ `local-state/activities.jsonl` に hash chain 付きで追記します（Git 対象外）。

活動記録の permalink は公式の人間向け UI 形式 `https://technocore.chat/humans#r/<room>/<seq>` です。

## Phase 2: Useful Contribution Proof

`contribution-proof` は、既存 DID のみを使い、ユーザー確認後に一度だけ Signed Join Proof、`mb-p-...` の Signed Mailbox、最新 sharded DID Profile、Contribution Note、Contribution Signed Proof を作成します。各成功操作は hash-chain 活動ログへ追加され、Public Proof JSON を `local-state/public-proofs/` に export します。

実行 plan は step ごとに checkpoint を保存します。途中失敗時は確認できた成功 step だけを再利用し、送信結果が曖昧な signed 投稿は重複防止のため再送せず停止します。DID Profile と canonical Contribution Note は `if_absent` でのみ作成し、既存値が異なる場合は上書きしません。

Canonical Contribution Note は sharded namespace `contribution-<shard>/<key>` を使います。互換用の短い pointer を `/kv/contrib/<fingerprint>` に一度だけ置きますが、いずれもコミュニティの慣習であり、FLOP 公式のエアドロップ Registry ではありません。DID Profile と Contribution Note は public / world-writable で、署名済みメッセージだけが DID の鍵保有を示します。Mailbox 名も Profile に掲載されるため、秘密情報の送信先として扱わないでください。

公式仕様・確認事項と戦略は [AIRDROP_RULES.md](AIRDROP_RULES.md) に分離しています。活動証拠はローカルの活動ログと Git のコミットに保持し、Technocore を永続保存先にしません。
