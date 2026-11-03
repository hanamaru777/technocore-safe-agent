# R1153 — cold migration admission / 永久再送禁止

## 実装と実機の区別

本Taskは新しいcold-source経路のコードと合成テストだけです。
Oracle停止、Vault取得、SSH、実転送、サービス操作、課金変更は行っていません。
本番既定値は `source_archive=NO_GO / cutover=NO_GO / OCI_RETIREMENT=STRICT_NO_GO`。
原本Oracle、二つの既存backup、元DID、K137 TradeBotはそのまま維持します。
R1144の実機metadata PASSは消費済みです。R1095/R1097/R1102/R1126/R1132/
R1138/R1143/R1144を再実行する手順ではありません。

## 新しい公開admission契約

`packaging/migration/r1153_cold_migration.py` の `Authority` は、独立したlocal
enrollmentと**別経路で確認したdigest**から作ります。evidence bundleやSSH応答から
公開鍵を自己登録しません。元DID鍵・source鍵を承認者にできない既存R1107契約を再利用。
owner、independent、destination、identityの役割は別鍵です。実鍵は未登録です。

`admit()` は副作用なしで以下を検証します。

1. 独立署名付きOCI **STOPPED**、元instance/boot/全attached volumeの固定ID digest、
   元HEAD、元DID、全root scope、同一epochのimmutable冷却copy、restart禁止と他host writer不在。
   これは**稼働中Oracleのglobal G4を証明するものではありません**。
2. rootごとの元volume対応、取得hostのpath/device/inode/capture、mount table、full manifest。
   両SQLiteのDB/WAL/SHMを別々にhashし、同一epoch・count/seqを束縛します。
   sidecarが無いclean-checkpoint形式は現在未対応なのでSTOP。単独boot backupはoffhost archiveではありません。
3. 原本5経路の既存parserによるattempt/leg、DID、nonce、room・record digest。
   欠落route、重複attempt/nonce、全state hashとledgerの不一致はSTOP。
4. ownerの別署名による永久NO-REPLAYと、未確定分の業務上の損失承認。
   **UNKNOWNを未受理・確定済みに書き換えません**。保持済みGETは過去の否定証拠になりません。
5. source/destination双方の恒久deny設置証拠。全5経路・全bootでdeny、policy消失時もdeny。
   この署名は実際の設置・復旧試験を独立確認した担当者だけが発行するものです。
   本コードを置いただけで既存publisherがこのpolicyを参照するとは主張しません。
6. K137既知machine/host-key、UID、既存DISARMED root、20GiB保護容量に加えarchiveと
   restoreの二重保持・余裕2GiB、現在のmemory/PSIと固定された低いresource上限。
   quotaの設定やTradeBotの変更を行うコードではありません。未適用なら署名してはいけません。
7. 既存R1117のcanonical全文長DID署名検証に加え、実recipient custodyの独立identity署名。
   デモ署名だけでは不足。実Vault鍵の取得・転送・unseal機能は追加していません。
8. 明示owner承認：停止時間、cold capture、rollback、ZERO_NEW_BILLING、最大4時間の操作期限。
   「今日移行したい」という指示はこの署名の代わりになりません。

初期証拠は30秒以内。取得中は同一tupleを束縛したfresh STOPPED leaseを更新し、
期限・再起動・volume/epoch変更時は停止します。権限を自動延長しません。

## 永久denyと一回限りのarchive adapter

`PermanentPolicy` は既存R1117のprivate POSIX append-only/fsync journalを使います。
installには独立enrollmentとownerのquarantine署名が必要です。期待policy digestを
別途保管し、再起動後も再読取検証。壊れた／消えたstateを空のallowlistに戻しません。
`can_send()` は常にfalse。このTaskに送信機能はありません。

`source_peer()` は署名全検証と双方policy証拠、local永久deny、実durable journalの後だけ
承認済みcold copyを読みます。保護されたlive/TradeBot rootは禁止。
取得hostのkernel read-only mountとidentityを確認し、全manifest再census、元sidecarの
再parse、元DIDと両SQLite整合性を検証。既存R1089/R1084のAES-GCMをそのまま使います。
raw recoveryは既存の承認済みmemory-only呼出元からだけ受け、CLI/env/file経路はありません。
`ATTEMPTING` をfsyncしてから出力。中断は `UNKNOWN_NO_RETRY` として保持します。
journal削除・新nonce・同じgrantの再実行で復旧させません。

`restore_peer()` はR1089 `LockedArchive` による完全AEAD first passを要求します。
manifest一致後、second passをboundedにR1086の固定K137 DISARMED childへ渡し、
全file/link、SQLite integrity/count/seq、復元DIDを確認します。新規childのみ、上書きなし。
失敗時は `RESTORE_UNKNOWN_NO_RETRY`、元backup・失敗copy・journalを自動削除しません。
起動、切替、source再起動、秘密鍵importはしません。

## ownerの一括順序（実機操作はまだ承認されていない）

独立監査 → enrollment/digest確認 → 正確な停止・費用0・rollback承認 → 独立した
STOPPED/restart-deny証明と全volume cold epoch → 5経路inventory/quarantineと双方の
永久deny設置証明 → 実same-DID custody証明 → fresh K137 capacity → owner署名付き一回の
encrypted acquisition → 独立offhost完全AEAD検証 → DISARMED復元 → 独立restore/rollback監査。

G3実custody・source永久deny・G5処分承認が不成立なら実peerは呼び出しません。
boot snapshotだけを転送・復元完了としません。課金するvolume/VMを作って迂回しません。
source停止中の可逆的rollbackと、将来のG8一writer起動／Oracle retirementは別承認です。

Windows 5.1の新入口は `packaging/windows/r1153_cold_owner_preflight.ps1`。
owner/SYSTEMのみの保護ACL・SHA確認済み公開enrollment/bundleをローカルで検証するだけです。
4MiBを超えるcontrolはSTOP。R987鍵を要求せず、SSHや秘密入力は起動しません。
正しい合成署名でも `COLD_CONTRACT_CHECKED_NOT_EXECUTION_AUTHORITY` / exit42。
監査後に使うpreflight形は次のとおりです（値は独立確認した公開ファイルだけ）。

```powershell
powershell.exe -NoProfile -File .\packaging\windows\r1153_cold_owner_preflight.ps1 `
  -EnrollmentFile <ABSOLUTE_PUBLIC_ENROLLMENT_PATH> -EnrollmentSha256 <INDEPENDENT_SHA256> `
  -BundleFile <ABSOLUTE_PUBLIC_BUNDLE_PATH> -BundleSha256 <INDEPENDENT_SHA256>
```

**本番の2-host自動SSH carrierやOCI停止APIは追加していません。** 必要な独立証拠を発行・
renewするoperator/runtimeと、承認済みsecret custody・host transportは外部の実行前提です。
不足はコード開始の阻害にせず、runtime NO_GOとして維持します。
チャットへ出すのは固定結果codeだけ。DID全文、nonce、grant、raw stdout/stderr、鍵、
file bodyを表示しません。既知のcross-branch公開digest履歴scanは改変・免除しません。
