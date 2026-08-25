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

## 使い方

```powershell
.\flop.ps1 status
.\flop.ps1 show-did
.\flop.ps1 read-room lobby
.\flop.ps1 read-new lobby
.\flop.ps1 activity-log
.\flop.ps1 sync-official
.\flop.ps1 doctor
.\flop.ps1 post-signed lobby
```

`show-did` と `post-signed` は seed を SecureString で尋ねます。`post-signed` は明示確認があるまでネットワーク送信しません。活動成功時だけ `local-state/activities.jsonl` に hash chain 付きで追記します（Git 対象外）。

公式仕様・確認事項と戦略は [AIRDROP_RULES.md](AIRDROP_RULES.md) に分離しています。活動証拠はローカルの活動ログと Git のコミットに保持し、Technocore を永続保存先にしません。
