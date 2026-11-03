# R1156: Resident再接続と独立署名付き承認更新

この文書は**未実行のoperator手順**。本番移行済み・同一DID実機検証済みという証拠ではない。
Oracle VMとSSHを残す。旧writerのHOLD、旧UNKNOWNの永久再送禁止、K137 TradeBot、
Windowsの独立暗号化archiveを維持する。Oracle削除は引き続きSTRICT_NO_GO。

## 今回接続した機能とDISARMED境界

* 元のCapture/Resident daemon、分類、queue生成を専用の派生stateで動かす。
  Observerには鍵、Vault、署名socketへの接続権限を与えない。
* publisherは新世代のintent IDだけを渡す。独立signerが元のeligibility、
  source-backed knowledge、固定render、DLP、trust/first-contact policy、rateを再検査する。
  first-contactの元の設定と独立承認の両方が必要。設定を自動でON/unpauseにしない。
* 署名側の永続nonce/id予約と投稿側のattempt記録を維持。POST結果不明はterminal。
  ACK転送失敗時は保存済み署名recordのACKだけを再処理し、再POSTしない。
* `tclk_pilot_accept`、`tclk_pilot_reveal_publish`、`close1_approved_trade`、
  `close1_batch_trade`の新規処理は**DISARMED**。
  移行後のexact typed approvalとlive protocol/account照合を安全に結ぶadapterがないため。
  元のTCLK/Close1 writerやtimerを起動する代替手段は使わない。

## 実行前に必要な実証と承認

R1154/R1155の既存scope、独立enrollment、HOLD、5経路の禁止ledger、
元DIDに束縛された暗号化custody、独立復元receipt、固定host/bootを再利用する。
UNKNOWNを「未投稿」と読み替えない。署名者は同じDIDだけであり、新鍵を発行しない。
既存のR987入力経路以外に秘密情報を入力・保存しない。

K137のroot管理runtime `/opt/flop-r1155-runtime` はreview済みのこのcommit、clean、
既存依存込みの環境であることが必要。`runtime_head`はその実際のHEADに一致させる。
新しいbridge/hookを含む同じsourceをインストールする。復元archiveの実行コードは起動しない。
新規クラウドresource、課金、依存APIは作らない。ZERO_COSTと資源余力を独立確認する。

### 承認document

コードのstrict shapeが契約。任意field・任意command・私有鍵は含めない。
`r1156_setup.identities()` のdocumentはenrollment/pin、target boot、専用3 UID、
元のrecipient承認とowner/witness署名。`r1156-identities`の署名dataは
`document_sha`、`no_start=true`、`zero_cost=true`。

`parity.json`は既存runtime config、scope、run_id、独立source-held packet、
capability、initial renewal、owner/witness。`r1156-stage`署名も同じdocument hash束縛。
capabilityの`r1156-autonomy`署名は`anchor_sha`と`generation_sha`。
generationはepoch、start時刻、Resident UID、選択JSONのraw SHA256、
DB/WAL/SHM raw SHA256、凍結cursor、room generation、旧candidate一覧、
元first-contact flag、既存topic allowlistを正確に束縛する。

選択JSONは合計64MiB以下（個別も64MiB以下）。runtimeのResident/outbox各JSONは16MiB以下。
巨大なObserver stateを黙って切り捨てたり、古いevidenceを消して通したりしない。
上限を超える実機stateでは`SETUP_ACTIVE_STATE_BOUND_STOP`となる。
その場合は独立review済みの保存証拠付き派生projectionが別途必要で、本実装は自動生成しない。
元Oracle scratch上限2GiB、K137保護空き20GiBを維持する。

## 900秒超のarchive継続

既存Windows PowerShell 5.1入口 `packaging/windows/r1155_warm_transfer.ps1` を再利用。
既存署名済みplanへstrictな`renewal={anchor,initial}`を追加し、その**全plan**を再承認する。
元のgrantを編集・延長しない。anchorはpurpose=archive、authority、両host/boot、
source HEAD、scope/HOLD、manifest、epoch、DID、ledger、raw nonces、capture hashに固定。
archiveではruntime_sha/generation_shaはnull。

各更新は別々のowner/independent issuerによる`r1156-renewal`署名。
dataは`anchor_sha,seq,previous,metrics`。初回seq=0/previous=null、以後seq+1と直前packet hash。
署名は各900秒以内、前の承認が失効する前に次の承認を発行する。
metricsは署名前30秒以内の実測、source_running/ssh_retained、両deny、残容量、
メモリ余力、CPU/IO PSI、zero_costを含む。合成値・歴史的PASSを使わない。

既存owner sessionが作るoffhost親directory内の
`r1156-renewal-<run_id>.json`を、新しい**公開署名packetのみ**でatomic replaceする。
sessionは5秒ごとに検証し、同じpinned SSH/R987 custodyで固定`renew-source` RPCへ渡す。
発行鍵はこのsessionに渡さない。再接続で新しいarchiveを開始しない。
更新欠落/期限切れ/順序不正/relay失敗は子streamを停止してUNKNOWNにする。
新しい暗号化・nonce・自動再試行は行わない。ciphertext-onlyの既存resume条件は維持する。

## K137の明示setup（承認後のみ、今回未実行）

root管理の公開documentを`/etc/flop-r1155-admission/{identities,parity}.json`へ配置する。
既存state/鍵を上書きしない。以下は**順序を示す手順**で、一括実行の承認ではない。

```sh
# review済みcheckoutと既存venv内で、root operatorが個別に実行
python -I -B packaging/migration/r1156_setup.py --identities
# R1155の既存recipient-local初期化を専用signer userで実施
# 暗号化recipient/custodyと元DID照合後にのみ次へ
python -I -B packaging/migration/r1156_setup.py --stage
```

`--identities`は専用user/groupと必要最小限のdirectoryだけを準備する。
`--stage`は復元全体/ledger/nonce/DID/source HOLDを元のinstallerで検証する。
選択JSONを派生stateへコピーし、2つのDBと既存WAL/SHMは同一filesystem上で
raw hash照合してrenameする（二重DBコピーは作らない）。先にdurable promotion記録を置く。
途中失敗はUNKNOWN、再実行や元writer自動復帰は禁止。独立archiveは保持する。
完了してもserviceはdisabled、daemon-reloadのみ。元pause/enable設定を維持する。

runtime用anchorはpurpose=runtimeで、実際のconfig/generation hashを追加束縛する。
各新しい公開packetをroot operatorが次の固定CLIへ標準入力で渡す。

```sh
python -I -B /usr/local/libexec/flop-r1155/packaging/migration/r1156_renewal.py --install-runtime < reviewed-public-renewal.json
```

root-owned CASを進めてcurrent/admittedを一致させる。期限のgapは再開できない。
runtime用の更新を自動発行・自動署名する常駐サービスは追加しない。
継続運転には独立issuer/承認済みroot installerの運用が必要。

その後の`--start-reader`、`--start-signer`、元の`--unlock-local`、
`--start-publisher`はそれぞれ**別途明示承認**が必要。
signerの非表示ローカルunlockと元DID照合はR1155経路のまま。
開始markerはone-shot、失敗時に消して再試行しない。timer/enable/reboot自動起動はない。
承認失効で署名・POSTは止まり、optional Resident maintenanceはskip、観測だけ継続する。
再起動/boot変更では新しい独立admissionが必要。

## 検証・切り戻し境界

確認するのは新世代queue、固定reply、exact signed receipt、ACK、永続rate/nonce、
root guard freshness、更新seq、実際の資源余力。検証目的の本番POSTを自動追加しない。
原文/鍵/署名URL/環境dumpを出力しない。healthは固定codeのみ。
旧5経路のID/UNKNOWNは常に禁止ledgerに残す。

失敗時はAWS新publisher/署名をDISARMEDとして保持し、Oracle HOLDを自動解除しない。
Oracle再開にはAWS側停止・書込遮断・新規POST finalityとnonceの独立照合、
同一DIDの単独稼働を証明する新しい承認が必要。本Taskは切り戻しを自動実行しない。
DB promotion途中、更新失効、未照合POST、容量不足、鍵custody未成立のどれもNO_GO。
4つの金融経路と実機証拠は残件であり、完全移行完了と表現しない。
