# R1151: 3ファイル仮preseed・owner承認境界

## 現在の結論

**READINESS_STOP / ready_for_owner_call=false。実転送0 bytes。**
これは仕様E/Hによる安全側フォールバックであり、本番転送コマンドではありません。
OCI SSH、K137の既存鍵・host pin・receiverは過去にPASSしていますが、
R1144の実owner出力は未受領です。元Oracleの現在の3ファイルmetadataとmachine SHA、
独立owner公開鍵・署名export grantは未登録です。合成テストはこれらの実機証明になりません。

新Windows入口 `packaging/windows/r1151_preseed_owner_onepass.ps1` は公開証拠の
ローカル検証だけを行います。identity未指定ならPython起動・秘密入力より前に
`SOURCE_IDENTITY_STOP`。署名一式が正しくても `INDEPENDENT_SOURCE_RUNTIME_NOT_ENROLLED`。
SSH、R987復号、PEM検索、sourceファイル読取り、receiver起動には進みません。
監査前のowner実行コマンドはリリースしていません。

## 再利用した境界と追加した契約

- R1128のroot/mount/元HEAD、独立R1063 owner署名、厳密な3ファイル選択、
  R1084 AES-GCMは変更なし。元の `provisional_preseed_offhost` 承認も必須。
- 追加承認 `r1151_preseed_once` は一意のarchive ID、source grant、独立metadata署名、
  enrollment digest、32MiB/180秒、K137新規child名をまとめて束縛します。
  全署名は最大300秒。source自身の鍵・ownerと同じwitness鍵は不可。
- metadataはR1139の厳密な正規形を独立登録したdigestと比較。
  source peerは元ホストguardを先に行い、取得直前にmetadataを再比較します。
  読取り中の変更は既存R1128再censusで停止。common epochの証明ではありません。
- source stdinは `R1151S01` + big-endian公開JSON長/JSON + recovery長/bytes。
  独立Trustはこのstdinから採用しません。R1128 recoveryはR987復元コードやDID seedとは別物。
  C# SecureString→BSTR→mutable UTF-8、binary pipe、可能な範囲のzeroizationを合成検証。
  Python/OS内部のimmutable copyを完全消去できるとは主張しません。
- R1140/R1142 native bridge（no BOM、上限・global timeout・child終了）と
  R1141 strict receipt gateを再利用し、二つの偽SSH peerをローカルで試験。
  本番SSH引数やhost authenticationが実行された証拠ではありません。
- 専用C# journal primitiveはowner/SYSTEMのみの保護ACLとCreateNew/Flush(true)で
  attempt前に `UNKNOWN_POST` を固定。再利用・上書き・自動再試行なし。
  **現在のreadiness入口はこのprimitiveも起動せず、まだ本番carrierに接続していません。**
- R1129の実UID/machine/0700/20GiB保護容量、fresh child、暗号文だけの保存は変更なし。
  receiptはbyte数とfalse authorityを確認しても、AEAD・完全性・DID復元のPASSではありません。

対象は `verified-did.json`（16KiB）、`nonces.json`（1MiB）、
`signer/oracle-signer-receipts.json`（8MiB）のみ。source合計16MiB、wire32MiB。
SQLite/WAL、環境設定、Vault、DID seed、SSH鍵、その他stateは対象外です。
sourceとK137の既存host pins/custodyは変更せず、古いR1079の16KiB制限も維持します。
新helper・既存依存をGit blobでpinし、Windows入口がmap自体を固定します。

## 監査後に一度だけ行う登録・承認手順（まだ実行しない）

1. ChatGPTがこのbranchのコード・pins・CIを独立監査する。
2. ownerが保有する**実R1144結果**を独立確認し、元machine SHA、正しいsource SSH
   fingerprint、source HEAD、K137既知machine/host pinを公開enrollmentへ結び付ける。
   未受領をPASSで埋めない。鍵や復元コードをChatGPT/Codex/Gitへ送らない。
3. 既存独立owner承認者とmetadata witnessの公開鍵を別経路でenrollし、profile SHAを
   別経路でpinする。source/SSH応答/approval packetから自己登録しない。
   このTaskはowner鍵を発行・保管するツールを追加しない。
4. 独立source Trustを安全に届ける**新immutable source bootstrap/runtime**を別途監査する。
   現在このinterfaceの承認・配置証明がありません。request内の公開鍵からTrustを作る、
   `python -` にコードと秘密binaryを混在させる、旧read-only carrierを拡大する方法は禁止。
   従って現在は正しい署名だけを渡しても転送可能になりません。
5. 上記が成立した後だけ、一意archive IDと厳密3ファイルに対するfresh metadata proof、
   既存source grant、追加transfer grantをownerが承認する。独立R1128 recoveryを
   R987 recoveryとは分離してローカル非表示入力するcarrierは、まだ解放しない。

R1126/R1132/R1138/R1143やOracle cleanupを再実行しません。失敗・timeout・応答不明は
UNKNOWN_POSTで停止。journalの削除・同一ID再試行で成功に見せません。
チャットに出してよいのは固定STOP codeと非秘密の集計だけです。
raw SSH stdout/stderr、grant全文、file body、DID全文、recovery、鍵を出しません。

## 完全移行とは別

G3 signer custody、G4全writer遮断、G5外部finality、G6二つのSQLite/WAL同一epoch、
G7真正復元、G8切替承認は未成立。cutover=NO_GO / OCI retirement=STRICT_NO_GO。
source変更0、TradeBot変更0、新規費用0。Testnet T1150や本番構成の変更はありません。

## 継承済みscan検出

開始コミットの `docs/tasks/R1151_oci_k137_provisional_preseed_v1.md:6` には、
仕様として公開済みのK137 machine SHAがそのまま記載されています。既存scannerの
bare-64-hex規則がtracked/history両方で検出します。秘密鍵の検出ではありませんが、
scannerを緩めたり元仕様・履歴を改変して消したりしません。
この既存検出が残る限り、全体securityテスト2件はPASSにならず、独立監査での扱いが必要です。
