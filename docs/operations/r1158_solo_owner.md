# R1158: SOLO_OWNER v2（未実行・独立監査待ち）

一人の所有者が **SOLO_OWNER** を明示選択する方式。独立した人間の審査があったとは主張しない。既存v1のowner/independent/destination署名は残す。同じ署名をwitness欄へコピーすることは禁止。v2のwitnessは常に`null`。

本実装・テストでは実機接続、鍵移送、転送、サービス操作、POSTを一切実行しない。本書も実行承認ではない。Oracle VM、SSH、二つの既存起動バックアップ、元データを残し、Oracle削除は常に`STRICT_NO_GO`。

## 承認と事実を分離

Windowsの既存R1157暗号化owner承認鍵だけを使う。未作成時のみ`Init`でowner一個を作る。DID鍵、SSH鍵とは異なる鍵で、DIDや第三者の署名を代行しない。承認鍵を二つのサーバーへ送らない。承認のデフォルト1800秒、上限3600秒。期限切れ後は新しい明示承認が必要。

二ホストのroot専用**技術検査鍵**は固定の機械検査結果だけを別ドメインで署名する。人間の独立署名・所有者の承認・DID署名には使えない。既存ホストのローカルファイル以外に新しいクラウド資源・Vault・端末・承認者を作らない。初期設定は別の`ISOLATED_LOCAL_SETUP`承認が必要。鍵・bootの変更は再enrollmentが必要で、黙って信用しない。

機械証拠は30秒以下、再確認は10秒間隔。承認を自動再署名しない。Sourceでは既存R1154の実UID、systemd、起動経路、プロセス、FD/mmap/namespace、SSH保持、永続egress denyを再検査。確認不能は停止。Targetでは実ディスク・PSI・MemAvailable・publisherプロセスと復元DIDを検査する。保存済みJSONの`true`だけではHOLD・転送・起動を許可しない。

G5は過去の5経路を**永久再送禁止**にする。外部でUNKNOWNが受理されなかったとは断言しない。技術証拠の固定値は`UNKNOWN_REMAINS_UNKNOWN`。未確定履歴、元nonce、receipt、原本を保存し、新しい承認で過去IDを復活させない。TCLK accept/revealとClose1単発/batchは引き続きDISARMED。

## Windows PS5.1入口

入口は`packaging/windows/r1158_solo_owner.ps1`。全コードをcanonical LF Git blob mapで検査してから、既存R987/R1089の**関数定義だけ**を再利用する。消費済みbootstrapは呼ばない。既存V2 escrowはOCI専用、K137は独立してピン済みの既存認証。承認鍵のパスフレーズ、SSH復元コード、アーカイブ復元コードは別のSecureString入力。DID seedの入力は要求しない。

公開requestは現在ユーザー限定ACLのJSONとSHA256で指定する。戻り値も同ACLの公開artifactとそのSHA256。consoleには固定code/hashだけ。出力の上書きは拒否するので各段階の出力ディレクトリは分ける。既存の実鍵・復元コードを公開requestへ入れない。

```powershell
# REQUEST.jsonは公開データのみ。下記はローカル審査であり接続しない。
$request = 'C:\path\private-public-input\REQUEST.json'
$digest = (Get-FileHash -LiteralPath $request -Algorithm SHA256).Hash.ToLowerInvariant()
.\packaging\windows\r1158_solo_owner.ps1 -Operation Audit -RequestFile $request -RequestSha256 $digest
# Build / Assemble / Enrollも明示-Executeと固定確認文が必要。
# 接続操作だけ、別途確認済みのEndpointsFileとSHA256を指定する。
```

各公開データの厳密なschemaは`r1158_owner.py`の`profile_from_public`、`validate_binding`、`build`、`assemble`が正本。許可しないフィールド、偽witness、期限延長、boolの文字列化は拒否する。任意の遠隔コマンド・Python・パスは設定できない。

## 所有者が独立監査後に行う順序

1. 既存の正しいOCI/K137公開SSH identity・machine digest・known-host pin・元DIDを確認する。秘密鍵内容は表示しない。旧R1157 read-only metadataで実bootを取得し、`Collect`/固定`host-info`でboot bindingを確認する（OCIは既存raw boot、K137 runtimeは既存strip boot規約）。`Enroll`は一人のdescriptor、二つのboot、公開endpointsだけを取り込む。最初はmachine_keysが`null`の暫定profileで**設定だけ**を承認し、両ホストの`machine-init`で返る公開鍵を固定した最終profileを作る。最終profileが変われば後続承認は全部取り直す。`protected_tradebot.unit`は実物を所有者が特定し、変更しない。
2. `prepare-identities`は既存R1156の隔離user/recipient設定を再利用する（root所有、owner v2署名、no_start）。既存recipient生成/解除は従来通りK137隔離signerのローカルTTYで行う。R1158は受信者秘密鍵もそのパスフレーズもWindowsへ取り出さない。`recipient-proof`は隔離signer所有の公開鍵ファイルからだけ証明を作る。旧recipientに公開ファイルが無ければSTOPし、所有者の安全な公開鍵導出手順が必要。勝手に再生成しない。
3. `Build custody`はその本物のrecipient証拠から固定の同一DID継続要求を作る。`Consent`に`-DIDTransferApproved`と`ORIGINAL_DID_ENCRYPTED_EXPORT`が必要。`Assemble`で署名をexact bindingに取り付ける。固定`source-custody-once`も別の確認と同switchが必要。既存R1155 public installer/R1154隔離oneshotを一回だけ使い、root/Windowsは暗号文のみ受け取る。起動マーカー・既存custody・失敗があれば再実行禁止。成功済み暗号文の取得だけは`source-custody-read`。不明結果を再取得/再署名で解決しない。
4. custody unit設置後にSource metadataを再取得する。所有者が既存ホストのみ・追加課金なしを確認し、`r1158-capacity`の`EXISTING_HOST_ZERO_NEW_BILLING`承認を出した後、`initial-capacity`でK137実容量と現在のinactive状態を取得する。技術検査はクラウド契約を知っているとは主張しない。legacy容量schemaのzero_cost項目はこの明示policy承認を検証した結果であり、将来の請求予測ではない。`Build scope`→HOLD承認→`Assemble`。pre-HOLD inventory/ledgerは`null`の**未取得**であり架空のhashではない。既知追加unitも全て実scopeへ含める。旧UIDがK137の既存account/processと衝突すればSTOPし、TradeBot等を改変しない。
5. `prepare-quarantine`は別の`PERMANENT_FIVE_ROUTE_NO_REPLAY`承認で、Targetの旧UIDだけへ永続IPv4/IPv6 denyを適用。`Build monitor`→ownerのbounded monitor承認を取得。`probe`→`publish-target-evidence`で両ホストの現状を確認した後だけ固定`hold`が可能。HOLDは**FLOPアプリだけ**を既存Controllerで停止し、VM/SSHとegress denyを残す。途中失敗はdurable journalを残し、無断修復・再HOLDはしない。
6. HOLD後の固定`inventory`は実際の両SQLite/WALと状態原本を共通epochで検証し、安全なhashだけを返す。`Build preserve`/`Build policy`の別承認、`Build plan`→転送承認→`Assemble`。上限は最初の実容量計画と同一。成長・hash差・epoch差ならSTOPして計画を審査し直す。ledgerの64MiB/各16MiB上限やWALの2GiB scratch上限を超えても制限を外さない。
7. `Transfer -Execute -DIDTransferApproved`は既存R1155のNTFS暗号文custody、R1089 AES-GCM、独立AEAD検証、K137 sandbox restoreをそのまま呼ぶ。Watchが現状確認を継続し、通信断・boot差・30秒切れ・owner期限切れは子転送を停止。既存ciphertext/restoreの再開規約を維持し、SOURCE_ATTEMPTINGの不明結果は新規exportしない。K137を起動しない。
8. 既存R1156のverified restore baseline/generation/activationを元データから作る。`stage-runtime`はownerの`NEW_ONLY_ACTIVATION`（config、capability、stage文書それぞれexact binding）と本物のSource HOLD/凍結証拠を既存installerへ渡す。v2のinitialは`{"mode":"SOLO_OWNER_AWAIT_FRESH_MACHINE_CHECK"}`だけ。これはGOでもadmitted packetでもなく、無効状態のまま配置するための待ち印。配置後の実unit/cgroup/DID検査を`runtime-check`が通るまで起動不可。
9. `Monitor`は同じownerの有効なmonitor承認とautonomy承認を使い、Source機械証拠→Target root `runtime-check`を10秒ごとに運ぶ。owner鍵は開かない。実TradeBotのMemoryMax/MemoryCurrentと5 FLOP unitの残余capに256MiBを加えたheadroom、ディスク20GiB+必要量+1GiB、CPU/IO PSI、同一DID、単独publisherを実測検査。MemoryMaxが無制限/不明、unit不明、2GB VMで余裕が成立しない場合は停止し、TradeBotのcapを下げない。常駐分のcap合計は実RSSと混同しない。
10. 新しいsigner/reader/publisherの実起動は既存R1156 `--start-*`の明示操作だけ。R1158は自動start/enableしない。隔離signerの受信者unlockも既存ローカルTTYのまま。期限内の新規Resident処理だけを許可し、UNKNOWNは永久拒否。Monitor停止/期限切れならruntime gateは新規送信を止める。長時間継続には新しいownerの明示セッション承認が必要で、無期限GOとはしない。

途中で異常ならOracleの元データ、暗号文、inert restore、journalを残す。`rollback`は明示したownerの`DISARMED_ROLLBACK_NO_OLD_POST_RELEASE`署名と、AWS publisher非稼働/元egress denyの実検査が揃ったときだけ旧unit-fileを戻す。自動startや過去POSTの解放は一切しない。

## 実機移行の残条件

コード検査と実機GOは別。実ホストpin/boot、既存SSH権限、隔離recipient準備、全起動経路検査、完全HOLD、凍結inventory、5経路永久隔離、独立した復元hash/SQLite/DID一致、TradeBotを変えない実容量とmemory headroom、実runtime pin、現在のゼロ追加課金確認が必要。ひとつでも不足なら具体的なSTOP/NO_GOで止める。第二の人間が居ないこと自体はv2のSTOP理由ではない。

新機械鍵はrootが偽造できない第三者証拠ではない。root/adminとWindows所有者はtrusted operator境界。全root/外部未知writerの不存在まで主張しない。長い走査やネットワーク遅延で30秒が切れた場合も、安全側に停止する。クラウドSKU・IAM・billing・元backup・TradeBot・消費済みR1095/R1097/R1102には触れない。

履歴スキャンで既知の公開digestヒットが残る場合はファイル/commitとともに報告し、除外追加や履歴改変で隠さない。

## K137実サービス名と物理メモリによる起動制約（2026-11-04）

実機で確認されたTradeBotの保護サービスは `k137q-public-k58.service`（毎時自然実行、MemoryHigh=1,000MiB、MemoryMax=1,200MiB）。旧 `tradebot*.service` 形式だけを許可していたR1158は実機名と不一致だったため、この実機名だけを追加し、`ssh.service` など無関係なサービス名は拒否する。TradeBotを停止・改名・再設定しない。

R1158同時起動判定は、TradeBot上限1,200MiB、FLOP 5ユニット上限128+128+96+384+128=864MiB、安全余裕256MiB、合計2,320MiBを求める。K137物理メモリ約1,906MiBでは現行の保守的な最大上限予約を満たせない。実際のRSSと制限上限を混同しない。停止状態でのDISARMED復元と同時稼働判定を別フェーズに分け、資源予算/配置の独立検証ができるまではTradeBot上限を下げずAWS増額もしない。
