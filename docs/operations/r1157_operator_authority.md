# R1157: 独立承認の発行から既存Windows移行入口まで

本番操作は未実行。今回のコードは**承認鍵と公開artifactの作成・検証**、
明示指定時の固定2ホストread-only取得、既存R1154/R1155入口への接続を実装する。
署名が有効でも、それだけでG3/G4/G5や本番移行がPASSになるわけではない。
最終表示は常にNO_GO。既存UNKNOWN、TCLK/Close1 DISARMED、Oracle SSH、
2つの保護backup、K137 TradeBot、同一DIDのcustody境界は変更しない。

## 最初の必須条件

* owner、**別管理の人間の独立承認者**、destination確認者を用意する。
  各roleは1つの暗号化承認鍵、別の保護されたOS identity/custodyを持つ。
  ownerの鍵をコピーしてwitnessにしない。DID鍵/SSH鍵を承認鍵に使わない。
* 独立承認者の公開key IDを別経路で本人と照合する。OS identity digestや
  self-signatureだけでは人間の独立性を証明できない。この照合は自動化できない。
  不在なら`OPERATOR_WITNESS_NOT_ENROLLED`で終了。代理の仮鍵を作らない。
* 既存の独立pin済みR1066 endpoint enrollment（OCIとK137）、元の公開DID、
  正しいR987 V2 escrow、K137専用credential、既存known host-keyを使用する。
  新規credentialを要求しない。秘密情報をJSON・引数・環境変数に入れない。
* 実行前のGitHub reviewが必要。本書はHOLD、鍵移送、POST、AWS起動の承認ではない。

## 一つの入口

review済みcheckoutのWindows PowerShell **5.1**で実行する。
下の`$Entry`と公開file hash以外を秘密情報で置き換えない。

```powershell
$Entry = '.\packaging\windows\r1157_operator.ps1'
# 各担当者の別管理Windowsで、それぞれ一度だけ。owner側で他roleを作らない。
& $Entry -Operation Init -InitRole owner -Execute
# 独立承認者側: -InitRole independent / destination確認者側: -InitRole destination
```

非表示入力は**承認鍵用の新しい32byte以上のpassphrase**。DID seedではない。
承認鍵は`LocalApplicationData/FLOP-R1157-approval`に暗号化PKCS8で保存し、
directory/fileとも現ユーザーだけのACLにする。既存鍵は置換しない。
同じstoreで別roleを初期化できない。入力と一時bufferはfinallyで消去し、
秘密鍵objectは署名後解放する（Python/暗号library内部の全copyのzero化までは保証しない）。
公開descriptorだけを交換し、private PEM/passphraseは交換しない。

公開requestはSHA256でpinする。公開JSONにも現ユーザーだけのACLが必要。
生成物は`LocalApplicationData/FLOP-R1157-public`、fileごとに`.sha256`付き。
同名artifactを上書きしない。更新版は別の保護output directoryへ出す。

```powershell
$Request = 'C:\operator-public\enroll-input.json' # 保護ACLの公開document
$Sha = (Get-FileHash -LiteralPath $Request -Algorithm SHA256).Hash.ToLowerInvariant()
& $Entry -Operation Enroll -RequestFile $Request -RequestSha256 $Sha -Execute
```

`enroll-input.json`は`endpoints,source_did,source_key_ids,descriptors,independent_key_id`。
endpointsは既存pin済みdocument、descriptorsは3担当者の公開出力、最後は別経路で照合したID。
source_key_idsは既存enrollmentの除外対象を保持する。省略して信頼を広げない。
host/source HEAD/DID contextはこの入力から作成する。架空host/bootやtest fixtureは使わない。
canonicalなendpoints.jsonとそのSHA256も出力する（既存の独立pinとの値照合は維持）。

## 固定ホストの情報を一度取得して計画を束縛する

公開collect requestは`enrollment,enrollment_sha`だけ。`enrollment_sha`はcanonical JSON hash。
生成artifactのhash出力と`.sha256`を使い、endpoint hashも既存の独立pinを使う。

```powershell
& $Entry -Operation Collect -RequestFile $Request -RequestSha256 $Sha `
  -AuthoritySha256 $AuthoritySha -EndpointsFile $EndpointFile `
  -EndpointsSha256 $EndpointSha -Execute
```

この**別途承認された操作だけ**がSSHを使う。Codex実装中には実行しない。
R987 V2をOCIだけに復号し、一時鍵/ACL/cleanupを既存helperで管理する。
K137は別鍵。StrictHostKeyChecking、固定host-key algorithm、非対話publickey、
config/proxy/agent/forwarding無効を既存`ssh_base`から継承する。
任意command/hostは受け付けない。新challengeを応答に照合し、raw SSH出力は表示しない。
boot/UID/cgroup、元HEAD、service scope、launcher hash、現在のlogical source size、
K137空き/メモリ/pressureだけを取得する。DID seed、鍵、環境、SQLite内容は読まない。
sizeはstatだけで計測し、linkはfollowしない。source metadataは最大900秒、
destination情報とdestination承認は既存どおり30秒。期限を延ばさない。
live sizeはfrozen archiveではない。成長すると既存captureのquota検査でSTOPする。
HOLD後は既存Controllerのread-only verifyを使い、masked unitを元のfragmentとして再解釈しない。

## 公開sessionと独立review

以後のrequestは`kind,session`、assemble時のみ`packets`（role→公開署名）を追加。
sessionの固定項目は次の出所を持つ。自由文や任意shellを署名するAPIではない。

| 項目 | 出所 |
|---|---|
| enrollment / enrollment_sha / endpoints / snapshots | 上記の実際の公開artifact |
| settings | run_id、既存known_hosts hash、NTFS親、実測以上のquota、既存5経路inventory/ledger hash、実K137 recipient公開鍵とcontinuity challenge |
| review_data | 両snapshot/endpoint/bootへの束縛。cron/user units/generators/manual/transient/namespaces/external writers/processes/FD aliases/全5経路の独立証拠hash、complete/unknown、zero-cost、DISARMED確認 |
| review / destination | 独立承認者とdestination確認者がそれぞれ発行した公開署名 |

`review_data`は取得成功から自動でcompleteにしない。未知項目や全writer/5経路の証拠不足は
`G4_NOT_PROVABLE`/`G5_NOT_PROVABLE`。過去200件GETは完全なPOST履歴ではない。
UNKNOWNは永久quarantineのまま。証拠hashを推測したり、仮署名で穴埋めしない。
この外部証拠を用意できない現状では、ここでSTOPするのが正しい。

```powershell
# defaultはAudit: 鍵unlock、SSH、artifact作成、HOLD、転送なし
& $Entry -RequestFile $Request -RequestSha256 $Sha
& $Entry -Operation Draft -RequestFile $Request -RequestSha256 $Sha -Execute
# 各担当者が同じpin済みrequestをreviewし、自分の保護storeだけで署名
& $Entry -Operation Issue -RequestFile $Request -RequestSha256 $Sha -Execute
& $Entry -Operation Assemble -RequestFile $Combined -RequestSha256 $CombinedSha -Execute
```

順序は`review`→`destination`→`scope`→`recipient`/`custody`。
scopeをassembleすると旧R1154用の`hold-request.json`も生成する。
custodyは承認だけ。元DIDの暗号化取得・recipient-local準備は既存の独立承認済みR1155経路で実施する。
requestのkind/役割/TTL/size/reserve/束縛hashをAuditで確認し、別roleの秘密鍵を同じprocessに渡さない。
署名時刻には共通の実測観測時刻を用いる。後から署名しても900秒/30秒は伸びない。

## HOLDと暗号化transferは別の不可逆承認

```powershell
& $Entry -Operation Hold -RequestFile $HoldFile -RequestSha256 $HoldSha -AuthoritySha256 $AuthoritySha
# 明示承認後だけ同じ引数に -Execute（FLOPのみ停止、VM/SSHは維持）
```

HOLD後の独立証拠（実scope/journal/manifest/nonce/epoch/ledger/両deny）を`held_data`へ。
`held`は独立承認者の30秒attestation。元のR1154 verifier/Controllerで実際に検証した事実だけを署名する。
R1157 metadataはmanifestやprivate ledgerを読まず、これらを捏造・自動発行しない。
`preserve_binding`はこの実証とsource quotaに束縛し、`preserve`をowner/witness、
`policy`をdestinationが署名する。`custody.envelope`は既存の実暗号化出力だけ。
`transfer` draft/assembleはこれらからR1155 PlanFileを作り、既存`T.admit()`で検証する。

`renewal`は既存anchor/実metrics/previous（初回null）を使用し、毎回2人が新署名。
assembleした初回packetを`renewal.initial`へ追加してからouter transferを署名する。
更新packetは別directoryへ出し、R1156 relayの公開current fileへ承認済みatomic replaceする。
旧署名の延長、欠番、期限切れ後の再開は不可。自動発行サービスの権限は未検証なので無人運転を主張しない。

```powershell
& $Entry -Operation Transfer -RequestFile $Plan -RequestSha256 $PlanSha `
  -AuthoritySha256 $AuthoritySha -EndpointsFile $EndpointFile -EndpointsSha256 $EndpointSha
# 別途DID移送承認後だけ -Execute -DIDTransferApproved を追加
```

既存R1155のsecret-safe入口へ委譲するだけ。NTFS暗号化archive→K137 DISARMED restoreまで。
AWS起動、Oracle削除、TradeBot変更、POST、費用変更はこの入口に存在しない。
失敗は自動再試行しない。cleanup失敗でも成功を返さない。
