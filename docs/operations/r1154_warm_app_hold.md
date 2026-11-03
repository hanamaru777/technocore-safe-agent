# R1154 — VMを動かしたままFLOPだけHOLDするowner package

## 到達範囲

**本番未実行。完全移行・AWS publisher起動は未完成、cutover=NO_GO。**
Oracle VM停止API、ディスクdetach、削除、課金・IAM変更、Technocore POSTはありません。
これはR1153 cold-VM-firstの代替です。R1153を呼び出しません。
元Oracle SSHとCloud Agent、metadata-block、既存二つのboot backup、K137 TradeBotを維持します。
過去R1095/R1097/R1102/R1126/R1132/R1138/R1143/R1144のowner操作を繰り返しません。

今回追加した**実行コード**は次の範囲です。

| 機能 | 実際の動作 | 未証明／未接続 |
|---|---|---|
| `Controller.hold` | owner+independent署名、固定元host/HEAD、現effective unit/alias一覧、27 source template対応、全launcher digest、dedicated UID、fresh K137 capacityを検証後、exact unitを永続mask・stop。IPv4/6 UID POST denyとboot unitを先に永続化。Capture/Resident/Discord/Signer/TCLK/Close1を別々に扱う。 | 実scope・unknown launcher・11 extras/8 missingは独立確認が必要。古い件数を今の完全性証拠にしない。root/shared UID writerは拒否。 |
| `verify/status/rollback` | mask・egress・全writer FD/mmap/UID・launcher drift検証。statusはhashだけでhealthyを主張しない。rollbackは元unitを厳密復元し、失敗証拠を保持。 | rollbackは**POST denyを解除せず、何もstartしない**。AWS停止証拠とowner/witness別承認が必要。 |
| `capture_checkpointed` | 実HOLD後の別owner/witness承認、exact 5-route attempt/nonce parser、AWS永久no-replay設置署名を要求。DBのpositive integrityが成立するcheckpoint済みSQLiteはWAL/SHMなしでも可。全app/state manifestを再censusし、既存R1089/R1084で暗号化。 | 非空WAL/hot journalは未対応RO validation workerを要求してSTOP。新Windows coordinatorからこのAPIへのfull streaming接続は未完成。 |
| `r1154_custody` | 明示owner/witness承認とsingle-use journal後、元isolated signerの既存InstancePrincipals/Vault CURRENT getterを利用するone-shot。元DID一致、公式canonical全文長署名、recipient-pinned X25519/HKDF/AES-GCMで包み、ciphertextだけを保存。 | 実recipient enrollment・独立offhost recovery・AWS private-key provider／再起動後unseal・実機custodyは未成立。 |
| Windows PS5.1 | no-Executeは公開証拠だけのpreflight。`-Execute`はR987 V2既存custodyで固定元OCIへHOLD/verify/status/rollbackの一回のSSHだけを行う。固定code bundleと両承認を検証。 | K137接続・full archiveのowner NTFS sink/readback・AWS activationはこの入口にまだ接続していない。 |

R1089のglobal live G4やG5確定済みpacketを偽造・差し替えません。
既存R1089 owner coordinatorを無条件に起動するfallbackもありません。

## 必要な承認とscope

enrollmentは独立確認した公開authorityだけ。元DID鍵を承認者にせず、ownerとindependentは別鍵。
RequestFileはowner/SYSTEM保護ACLと独立SHA、さらにenrollmentの別SHAを要求します。
source machineの完全digestはownerの既存R1144 receiptで保持し、Git/チャットへ転載しません。
元source HEAD、known_hosts SHA、tool blob、exact unit properties/file SHA、専用UID、全launcher
digest、全5経路inventory/ledger、永久holdの業務上の損失承認をscopeへ束縛します。
effective stop/失敗時action、reverse stop依存もhashへ含め、停止伝播先は全てscope内に限定します。
root権限へ逸脱するExec prefix、非noneのhost action、未対応propertyは停止前に拒否します。
SSH/Cloud Agent/metadata guardの既存state・PIDとboot hashをjournalへ保存し、同一bootでは
全く変わらないことをHOLD/verify/rollbackで確認します。内容やPID自体はowner出力へ出しません。
明示downtime、VM RUNNING/SSH維持、費用0、永久old POST denyの二者署名が必須。
K137 current capacity/PSI・DISARMED・publisher停止・費用0証拠は30秒、操作承認は最大15分。
期限切れなら秘密入力／SSH前、またはsourceの最初のmutation前にSTOPします。

実scope作成には `Linux.discovered/unit/launchers` の固定readメソッドを独立担当者が確認します。
前二者はprivateなeffective systemd identity、後者はcron/at等のhashであり、本文をログにしません。
未知unitやshared/root writer、未確認cron/manual/transient経路をprefixだけで安全扱いしません。
旧8 missingの名前を推測したり、source templateをinstalled unitと同一扱いしたりしません。
HOLD中もtrusted root operatorが勝手にwriterを作らないという境界が必要です。
**無関係rootに対するglobal denyとは主張しません。** Controller自身のPRIVATE/COW library
mappingだけをfile writerから区別し、shared mappingや他processのwriterは拒否します。

## owner入口（独立監査後のみ。本Taskでは実行しない）

`packaging/windows/r1154_warm_owner.ps1` が唯一のWindows入口です。
公開RequestFileは `enrollment/enrollment_sha/operation/scope/owner/witness` の厳密なJSON。
operationは `hold/verify/status/rollback` のみ。任意command・host・room・textは不可。

```powershell
# ローカル公開証拠だけ。秘密入力・SSHなし。正常でもexit42 / NO_GO。
powershell.exe -NoProfile -File .\packaging\windows\r1154_warm_owner.ps1 `
  -RequestFile <ABSOLUTE_REVIEWED_PUBLIC_REQUEST> -RequestSha256 <INDEPENDENT_SHA> `
  -EnrollmentSha256 <INDEPENDENT_ENROLLMENT_SHA>
```

実行承認後のみ同じ入口に `-Execute` を付けます。現在はlive scope未登録なので実行不可です。
R987 V2 recoveryはローカルSecureString一回入力、既存backup SHA/復号/helper ACLを再利用。
鍵の一時fileは最小時間だけ。known_hostsは既存の独立pinに一致するECDSA exact rowのみ、
host-key autoaccept・old Windows key・agent/proxy/config fallbackはありません。
cleanup失敗で成功を返しません。grant/seed/鍵/SSH stderrは出力しません。

owner local journalは既存R1151 native exclusive primitiveを再利用します。marker名の
`UNKNOWN_POST` はここでは**remote maintenance actionの成否不明**で、Technocore送信ではありません。
切断後に同じHOLD/rollbackを再実行しません。status/verifyでscope/journal digestを確認し、
別署名のrollbackへ進みます。statusだけではsnapshotやAWS起動を許可しません。
rollback失敗も証拠を消さず、auto repair／auto restartしません。

## 同一DID custody順序

UID egress denyがVaultアクセスも止めるので、custodyを明示承認した場合は**HOLD前**です。
新source one-shot unit `packaging/oracle/r1154-custody.service` はinstall/startされていません。
root-owned reviewed public packageを固定libexecへ配置、private public-configをroot管理し、
既存signer.envだけを使います。Userはtechnocore-signer、補助groupはautopilotのみ。
Observer/Discord envを読ませません。timer/Install/Restartはありません。
新STATEに暗号化envelopeしか残しません。SIGN_SEEDを設定せず、鍵はargv/env/logに出しません。
mutable bufferをzero化しますが、Python/native crypto内部のcopy完全消去は保証しません。
recipient unsealはLinux K137の専用signer user限定。Windows/root/Observerへplaintextを渡しません。
テストのprivate memory helperは毎回fresh dummy key専用で、実鍵custodyの証拠ではありません。

## 未完成の本番critical path

- 独立scope/authority、現在のsource actor・launcher完全性、K137実capacityと費用0の証明。
- 実recipient key custodyとoffhost recovery、AWSの継続的な安全なunseal provider。
- 非空WALのRO validatorとfull encrypted owner NTFS archive→独立AEAD→K137 DISARMED restoreの
  一括Windows coordinator。既存R1089 primitivesは保持しているがwarm adapterとの接続は未完。
- AWS全5経路のin-process旧attempt遮断と新requestだけの許可、実際のG8 one-writer activation・health。
  既存publisherをそのままstartすると旧pending再送の危険があるため、起動コードを解放していません。
- AWS安定稼働後の別owner承認による元VM SOFTSTOP／retirement。**本packageにVM停止APIはありません。**

したがって完全移行100%・AWS稼働済みとは報告しません。実転送0、実seed取得0、
サービス操作0、TradeBot変更0、新規費用0。既知の別branch公開digestのhistory scanは免除しません。
