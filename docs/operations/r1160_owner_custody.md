# R1160: 元owner承認identityの保管先変更（source-only）

本実装は移転コードと合成試験のみ。実機保管・転送・鍵生成を実行済みという証拠ではない。M2、移行、HOLD、Oracle廃止の許可ではない。Initは消費済みのため再実行禁止。

## 独立監査で先に確認する条件

- Issue #948の元`public.json`（377 bytes、SHA256は`r1160_owner_continuity.py`の`ROOT_PINS.public_sha`とIssue #948の公開記録に固定）をimmutable rootとする。公開鍵・署名・元controlは書き換えない。
- 元`approval.pem.enc`（302 bytes）と既存K137 PEMの正確なハッシュは本作業では未取得。別途承認された、安全なローカル確認から取得し、公開planを独立レビューする。推測値・テスト値で代用不可。
- OLDには侵害履歴がある。OLDで実行するコード・端末の安全性について別途クリアランスが必要。planの`source_clearance_ref`とSHAはレビュー参照であり、プログラムが端末の無感染や参照内容を認証したという意味ではない。URLへの自動アクセスはしない。
- 同じ鍵の移転では、OLDや攻撃者の既存コピーを失効できない。過去の流出可能性は解消されない。疑義があれば実行STOP、identity維持と別途明示承認によるrotationを人間が判断する。本ツールはrotationしない。
- NEWの信頼できるローカルWindowsアカウントとMicrosoft Software KSP、正しいPS5.1・Python環境、owner-only ACL、未使用の出力先が必要。管理者/カーネル侵害への防御や、メモリの完全な法科学的消去は保証しない。
- NEWのrecipient request SHA256をOLDへ渡す経路は、クラウド上の同じファイルだけを信用せず、独立した認証済み経路で比較する。plan SHA、暗号化capsule SHAも同様。間違ったrecipientを承認すると別人へ暗号化することになる。
- 実行は個別のowner承認後に限る。承認パスワードはNEWの非表示入力のみ。DID seed、R987復元コード、SSH認証は不要。通常console、`-NoProfile`、transcript/debug/画面録画なしで実行する。

## 暗号・継続証明

NEWだけに非exportableなuser CNG RSA3072受取鍵を作る。これは新しいowner承認鍵ではない。recipient packetはそのRSA鍵によるPSS/SHA256 possession証明、SID hash、MachineGuid hash、24h期限、transfer IDを持つ。

OLDは承認鍵を復号も署名もしない。元公開descriptor、暗号化PKCS8、R987 V2暗号文、K137 PEMの**4個だけ**を固定順のバイナリframeにし、AES256-GCMとrecipient RSA-OAEP/SHA256で包む。AADはplan、recipient、transfer IDに結合。平文鍵を一時ファイル、引数、環境、クラウド、ログへ出さない。既存ファイルACLを修復して読み進めることもしない。

NEWはrecipient秘密鍵でunwrap後、元ownerパスワードでPKCS8をメモリ内復号し、元公開鍵と完全一致を要求する。その**同一Ed25519鍵**で別domainの`host-binding.json`に署名する。元`public.json`と暗号化PKCS8はバイト一致で保存する。承認のrole・既存署名形式は変更しない。

R1157の鍵読込とR1159の公開preflightは、元SIDか、正しい元root・同一鍵署名・NEW SID/machine・plan/receiptの全てが一致する場合だけ許可する。R1159は公開証拠だけを読み、承認鍵を開かない。

K137 PEMはNEWに平文ファイルとして展開せず、`credentials.sealed.json`内で保持する。R987暗号文もcapsule内で保全する。この作業だけでNEWのSSH利用準備が完了したとは扱わない。後日の用途別安全解放には別監査・承認が必要。

## 後日、別途承認後の操作

本リポジトリを両PCに同じレビュー済みcommitで用意する。旧PIN対象・R987・R1089を変更しない。外部ソフトのダウンロードやネットワーク操作は本entrypointにない。

1. NEWで`Recipient`。既存owner storeがある場合はSTOP。`%LOCALAPPDATA%/FLOP-R1160-recipient/`に公開requestとSHAだけが出る。CNG受取秘密鍵はNEW userに残りexportされない。setup途中失敗を自動再試行しない。

```powershell
powershell.exe -NoProfile -File .\packaging\windows\r1160_owner_custody.ps1 -Operation Recipient -Execute
```

2. 独立レビュー済みplanを作る。以下は**schema説明**であり実行可能なGO証拠ではない。各hashは64桁lowercase、transfer_idはrequestの32桁、期限はrequest以内かつ実行時から24h以内。`recipient_sha256`はcanonical requestのSHA。未知hashを本書から補完しない。

```text
version: 1
transfer_id: recipient.body.transfer_id
recipient_sha256: 認証済みNEW request SHA256
original_public_sha256: 上記immutable root
encrypted_approval_sha256: 実物の独立確認済みSHA256（未取得）
oracle_cipher_sha256: ROOT_PINS.oracle_shaの固定R987 V2公開hash
k137_sha256: 既存PEMの独立確認済みSHA256（未取得）
source_control: 元descriptorの不変control
source_clearance_ref: https://github.com/hanamaru777/technocore-safe-agent/issues/<番号>#issuecomment-<番号>
source_clearance_sha256: 承認したsource実行クリアランスのhash
consent: PRESERVE_SAME_OWNER_NO_INIT_NO_ROTATION
expires_at: UTC Unix整数秒
```

3. OLDに公開plan/requestのみを、owner-only protected ACLのローカル入力として用意する。NEWからのrequest SHAとplan SHAを別途比較する。安全性が未確認のOLDで実行しない。固定元SIDと元public rootが一致した後だけ、既存4個を固定保存場所から読む。既存ファイルの属性変更・削除はしない。

```powershell
powershell.exe -NoProfile -File .\packaging\windows\r1160_owner_custody.ps1 -Operation Seal -Execute -PlanFile <local-plan.json> -PlanSha256 <reviewed-sha256> -RecipientFile <local-recipient.json> -RecipientSha256 <independently-verified-sha256>
```

4. `%LOCALAPPDATA%/FLOP-R1160-export/credentials.sealed.json`の**暗号文だけ**をownerが別途承認した経路でNEWへ移す。本スクリプトは転送しない。NEWのローカルowner-only入力に置き、OLD側の出力SHAを独立比較する。クラウドに置けるのは暗号化capsuleと公開証拠のみ。元PEMやパスワードは置かない。

```powershell
powershell.exe -NoProfile -File .\packaging\windows\r1160_owner_custody.ps1 -Operation Import -Execute -PlanFile <local-plan.json> -PlanSha256 <reviewed-sha256> -RecipientFile <local-recipient.json> -RecipientSha256 <independently-verified-sha256> -EnvelopeFile <local-credentials.sealed.json> -EnvelopeSha256 <independently-verified-sha256>
```

NEWの既存owner storeを上書きしない。暗号化/公開ファイルだけを同一filesystemのstageにfsync後、directory renameでcommitする。保存先は元R1157 store、capsuleとattempt markerは`%LOCALAPPDATA%/FLOP-R1160-import/`。正しい元ownerパスワードを非表示入力する。成功コードは`R1160_SAME_OWNER_IMPORTED`であり移行承認ではない。

## STOP・後片付け・残件

不正SID/machine、原本hash、recipient possession、期限、AEAD、同一公開鍵、ACL、partial write、既存出力、cleanup不確実性はSTOP。秘密を含む例外本文やパスは表示しない。処理途中の結果不明はattemptを残して自動再試行しない。中間stageの削除は自分が作った固定ファイルだけ。OLDデータ、recipient CNG鍵、commit済みstoreは自動削除しない。

可変secretバッファとBSTRは可能な限り消去するが、Python/暗号provider内部の一時immutableコピーの完全消去は証明できない。端末のswap/管理者境界はownerの前提。プロセス強制終了時は復元状態を人間が監査し、出力を消して無条件に再実行しない。

独立監査必須: 元rootの正当性、OLD実行クリアランス、2個の未知原本hash、NEW recipientの別経路認証、同一鍵binding、両端末ACL/cleanup、失敗後の残存状態。M2ホスト鍵・cgroup・メモリ制限、G3–G7移行条件は本作業で解消しない。`cutover=NO_GO`、`OCI_RETIREMENT=STRICT_NO_GO`を維持する。

既知の継承CI: reachable-history scanはR1151 task文書の公開machine digestで失敗する既存問題がある。例外追加・scanner変更・履歴書換えで隠さない。
