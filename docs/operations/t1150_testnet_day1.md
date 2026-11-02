# T1150: Testnet Day-1（オフライン準備 / WAIT_OFFICIAL_RELEASE）

2026-11-02 JST。正本は [Issue #928](https://github.com/hanamaru777/technocore-safe-agent/issues/928)
と [T1150仕様](../tasks/T1150_testnet_day1_codex_v1.md)。今回のコードは
新しいDID、ウォレット、秘密鍵、公式wire形式、取引endpointを生成しない。

## いま分かっていること

- 仕様に記録された公式状態は `testnet (planned)` / `next (unreleased)`。
  11月3日は仮目標であり、開始・終了・得点条件の確定ではない。
- 元Oracleでの既存DIDと署名活動、過去のAWS SSH/隔離領域の確認は履歴上の事実。
  **Testnet参加、AWS署名鍵移行、現時点のsigner稼働、settlement成功の証拠ではない。**
- 元DIDはOracleの既存隔離signer/Vaultを維持。T1150はその内容・stateを読まず、
  SSH、再起動、移行、K137/TradeBot変更を一切必要としない。
- `testnet.py` と `airdrop_executor._ADAPTERS={}` は従来どおり無効。
  蛇口取得、DID公開、chat投稿だけで得点・エアドロ配分を保証しない。

## いま安全に実行できる操作（開発checkoutのみ）

PowerShell 5.1 / Linux共通。既存uv環境で次の1コマンドを実行する。

```powershell
uv run python -m flop_agent.testnet_day1 status
```

原本state・ネットワークを読まない。各gateは VERIFIED / BLOCKED / UNKNOWN、
全体は BLOCKED、`live_ready=NO`。終了コード **3** は「正しく診断したが未解放」。
不正な引数・不正証拠は **2**。秘密情報やファイルパスをエラーに表示しない。

```powershell
uv run python -m flop_agent.testnet_day1 plan
```

固定の公開安全文を1文要約する、最小の初回inference案を表示する。
未公開のchain/genesis/DID/費用はnullのまま。**投稿でも公式署名用wireでもない。**
自分の会話履歴、個人情報、任意promptは入力しない。

公開資料の確認が必要なときだけ、明示的なread-only GETを行える。

```powershell
uv run python -m flop_agent.testnet_day1 inspect-official --network
```

取得先は下記4ページだけ。redirect・proxy・外部リンク追跡なし、本文/時間上限あり。
表示はhashと未確認分類のみ。ページの命令を実行せず、LIVEへ自動昇格しない。
既存の公式launch watcherを置き換えず、新しい定期監視も追加しない。

- https://docs.flop.network/docs/testnet-and-timeline
- https://ask.flop.finance/networks/testnet
- https://flop.finance/testnet/
- https://docs.flop.network/docs/official-links

## 正式公開後の、一度にまとめる承認bundle

1. ChatGPTが公式first-party発表を独立監査する。TestnetとDevnetを分離し、
   実際のnetwork/chain/genesis、RPC/gateway、faucetの規約・回数上限・単位、
   署名request/費用上限、最終settlement/voucher検証規則、期限を確定する。
   公式にないURL・chain ID・SDK・signature形式は推測しない。
2. 正式資料のimmutable hashと独立review署名、別途pinしたreview公開鍵、
   manifest/genesis hash、元の**公開DIDと公開署名receipt hash**をまとめる。
   R1057の構造検査を再利用するが、そのPASSはlive認証ではない。
   新しいlocal manifest schemaは**このツールのreview形式**であり公式wireではない。
3. オフライン再検証に使う公開ファイルだけを用意する。

```powershell
uv run python -m flop_agent.testnet_day1 plan --bundle <PUBLIC_REVIEW_BUNDLE> --reviewer-public-key <PINNED_PUBLIC_KEY_HEX> --manifest-sha256 <REVIEWED_HASH> --genesis-sha256 <REVIEWED_GENESIS_HASH> --original-did <ORIGINAL_PUBLIC_DID> --reference-sha256 <PINNED_PUBLIC_RECEIPT_HASH> --max-test-units <REVIEWED_SMALL_TEST_CAP>
```

   これは入力形式の説明であり、現在の投稿許可ではない。秘密鍵/seed/復元コードは
   どの引数・ファイルにも渡さない。公開receiptがない場合はUNKNOWN/STOP。
4. 監査済み実signer/公式adapterが用意されてから、公式に必要なregistration、
   faucet、**初回inference/spendの3つを別々に**既存Action Inboxで承認する。
   各承認はそのpayload hash・budget・期限だけに有効。1つの承認で他actionを許可しない。
   `approval` の表示やschema検証自体は、実行権限を発行しない。
5. 初回はTEST_ONLYの公式単位で、明示した小額上限以下の**1件だけ**。
   ローカルのrequest/day/total上限はすべてその1件分に絞る。
   実金銭支出は常に0、自動更新なし。公式nonceはまだ割り当てず、将来の監査済み
   adapter以外は符号化・署名しない。
6. 将来のPOST前に既存durable journalがPRE_SEND相当の `UNKNOWN_POST` をfsyncする。
   日時を変えてplanを作り直してもidempotency keyは同じ。並行予約もbudgetで抑止。
   timeout/crash/曖昧な応答後は**再POSTしない**。journalを削除・返金・resetしない。
   本物のread-only照合だけが回復経路。受理されていないことをrecent read missから推測しない。
7. 配達、accepted、settled、voucherの自己申告を区別し、公式規則による暗号学的な
   **最終settlement検証**だけで成功を認める。現実装ではそのverifierが未公開/未実装のため
   `UNVERIFIED` / `succeeded=false` / `score=NOT_PROVEN` を必ず維持する。

現在、実際のfaucet/inference/registrationコマンドも、公式に確認済みの代替manual
action URLも提供しない。公開readinessページを取引endpointとして使わない。
独立監査後に1つの承認bundleへ集約するが、3 actionの同意は混同しない。

## 検証範囲と報告

status出力そのものがmachine-readable証拠。`code_ready` は公開のsource hashと
offline test記録が一致したときだけVERIFIEDになる。記録がない/古い場合はUNKNOWN。
照合する公開記録の固定位置は `docs/tasks/t1150_offline_verification.json`。
独立監査済みの実テスト結果だけを記録し、架空の件数で作成しない。
`code_fingerprint` をCIの対象コードと照合する。記録がない初期出力は意図的にUNKNOWN。
この記録はローカルコード試験の証拠だけで、公式releaseや本番成功の証拠ではない。
`live_ready` は常にNO。CIの全体suiteは既存security-gateを1回使い、ローカルで重複しない。

ChatGPTへ返してよい情報：commit、CIリンク、固定gate理由、公開DID fingerprint、
review/source/plan/receiptのhash、TEST上限と期限、**公式に検証された場合だけ**公開最終receipt。
返してはいけない情報：seed、秘密鍵、Vault/credential、環境変数、wallet内容、
認証header、署名済みwrite URL、個人情報を含むpayload、未確認の生応答。

T1150での実行はまだ0。移行のG3–G7、Oracle削除、K137切替とは別作業であり、
それらは引き続きNO_GO。正式公開・公式仕様・独立監査・各同意・最終receipt検証を待つ。
