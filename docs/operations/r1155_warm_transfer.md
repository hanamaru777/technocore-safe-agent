# R1155: warm full-state transfer and isolated new-only runtime

本番未実行。元VM/SSHを維持し、R1154のFLOP専用HOLDをそのまま使う。
VM停止/削除、TradeBot操作、旧writerの再開、課金変更、実鍵取得を本Taskでは行わない。
コードが動くことと、独立した本番証拠・承認が成立したことを区別する。

## 接続した実行経路

1. K137を先にoffline準備し、独立したhost/SSH鍵pin、費用0、20GiB reserve、CPU/IO/
   512MiB headroomを確認する。既存 `/opt/flop-shadow` / TradeBotへ配置・書込みしない。
2. K137 isolated signerのrecipient X25519 private keyを**K137内だけ**で生成し、
   ownerの32byte以上passphraseでPKCS8暗号化して0600/0700に置く。
   `r1155_custody_setup.recipient_init` が実I/Oを行う。DID鍵を新規生成する処理ではない。
   recipient公開鍵を独立確認後、既存R1154のowner/witness custody承認を行う。
3. Oracleのrootが `install_source_public` で**公開**custody configをroot:
   technocore-signer 0640、親0750へ配置する。Observer groupは追加しない。
   R1154 one-shotを別途明示承認して実行する。Vault CURRENTは元signer内のみで取得、
   同一DID検証後ciphertext envelopeしか保存しない。これはHOLD前（UID denyはVaultも遮断）。
   package自体はサービスをinstall/startせず、旧envや旧PINを書換えない。
4. R1154 PS5.1 HOLD入口を別承認で実行する。27 template、実unit/alias/extras/missing、
   cron/manual/transient/external actor、旧5経路inventory/ledger、専用UIDの独立レビューが必要。
   maskと永続IPv4/6 UID denyの後、APPのみstop。SSH/Cloud Agent/metadata guardは維持。
5. HOLD成功後、実journal hash・共通epoch・全5経路ledger・K137 permanent no-replay設置を
   束縛したfresh preserve二者署名、transfer二者署名を作成する。UNKNOWNを受理済みと
   推定せず、別署名の永久quarantine/loss consentを要求する。
6. 新 `packaging/windows/r1155_warm_transfer.ps1` のno-Executeで公開planだけ検証。
   `-Execute` は独立archive recoveryと既存R987 V2のみ非表示入力し、既存R1085 NTFS sink /
   R1088 custody / R1089 LockedArchiveを実際に呼ぶ。旧Windows鍵へのfallbackはない。
7. Oracleでは二つのDB/WAL/SHMをbounded private copyへREADする。SQLiteは私有copyだけを
   `mode=ro`（**immutableを使わない**）で開き、integrity/cursorを検証。非空WALにはSHM必須。
   [SQLite公式WAL format](https://www.sqlite.org/fileformat2.html#walformat)のheader/frame/salt/
   累積checksumを検査し、壊れた/未commit tailやhot journalはSTOPする。元のbyte列は
   一切checkpoint/truncate/chmodしない。hash/identity/全manifestを再検証し、共通epochで
   既存R1089/R1084 AEAD streamを出す。scratch最大2GiB、RAMはpage/chunk単位。
8. WindowsではciphertextだけをNTFSへ保存。**全AEAD first pass後**だけplaintextを
   pinned SSH内でK137 R1086 DISARMED restorerへstreamする。Windows plaintext fileなし。
   K137にciphertext二重copyを作らない。実disk/PSI/memoryを再測定してから復元し、
   完全manifest/hash/cursorを比較。ciphertext-only DID custody companionも同じ承認planで運ぶ。
9. K137 rootの `r1155_activation.prepare` が実復元ledgerから全5経路baselineを再計算し、
   独立したfresh source HOLD証拠と別activation二者署名に一致する時だけ新packageを設置。
   root-owned code/config、専用2 UID、source旧unit maskとboot UID denyを永続化する。
   旧unitが既に存在／UIDが共有／actorが動いている場合は勝手に停止・置換せずSTOP。
   root monitorは実mask・kernel IPv4/6 rulesを5秒ごとにREADし、root-owned healthへ保存。
   20秒以上古い結果・異なるboot/config/scopeなら署名／POSTを拒否する。監視で修復はしない。
10. 明示 `start(...publisher=False)` で新AF_UNIX signerのみstartする。ownerが**K137 local
    root TTY**で `r1155_signer.py --unlock-local` を実行する。passwordはSO_PEERCRED root限定
    Unix socketからメモリだけで渡す。seedはsealed envelopeから同一DID/signatureを再検証して
    isolated signer内だけに置く。DID seedは各署名の直前だけ復号し、直後にmutable bufferを
    zero化する。待機中に保持するのはrecipient keyでありDID seedではない。
    brokerはAF_UNIXのみ、network/Vault/ENV鍵/RPC任意bytesなし。
11. 別のfresh new-request二者承認をroot-owned `/etc/flop-r1155/new-request.json` に配置。
    明示 `start(...publisher=True)` はunlock済みsocket/UID/leaseを確認して**新publisherだけ**を
    one-shot起動する。署名前とPOST直前にlease検証。署名reservation・POST前fenceは永続化し、
    結果不明は永久UNKNOWN。成功はexact `posted` recordと署名・時刻を検証しdurable ACK。
12. 独立した継続稼働・TradeBot影響・機能確認後に限り、**全く別の後日承認**で元VM停止を検討。
    本実装にVM stop/delete APIはない。元HOLD rollbackも旧POST denyを解除しない。

## Windows owner入口

```powershell
# 公開planのみ。秘密入力もSSHも行わない。正常でもNO_GO。
powershell.exe -NoProfile -File .\packaging\windows\r1155_warm_transfer.ps1 `
  -PlanFile <PRIVATE_ABSOLUTE_PUBLIC_PLAN> -PlanSha256 <INDEPENDENT_FILE_SHA> `
  -AuthoritySha256 <INDEPENDENT_AUTHORITY_SHA>
# 独立監査・owner承認後だけ上記に -Execute と以下を追加:
# -EndpointsFile <EXISTING_PRIVATE_ENROLLMENT> -EndpointsSha256 <INDEPENDENT_ENDPOINT_SHA>
```

planは `r1155_transfer.admit` のstrict schema。`custody` はbinding/owner/witness/envelopeの
**暗号文**だけ。source/recipient trustをauto-enrollしない。新source code全体はGit blob map、
remote invocationはbundle SHA + enrollment SHA + exact machine digestでpinする。
stdinはbinary framing、unknown disconnectはdurable UNKNOWNでsource再取得禁止。
完結したciphertextのみ再AEAD検証でき、K137 inert restoreは既存byte-prefix比較でresumeできる。
不完全ciphertextを同じnonce-domainで継続せず、元データ・失敗記録を消さない。

K137側の固定CLIは `r1155_activation.py --prepare` / `--start-signer` /
`--start-publisher`。公開承認はroot-owned
`/etc/flop-r1155-admission/activation.json` のstrict config/scope/run_id/source_packet。
監査済みsource checkoutのコードから実行し、prepared code以外の任意pathを許可しない。
`r1155_custody_setup.py --recipient-init` は専用signer + local TTY + root-owned
recipient.jsonの二者承認が必要。`--source-public-install` は元Oracle root + 固定公開request /
独立authority.jsonを使い、公開code/config/unitだけ配置してdaemon-reloadする。startはしない。
これらのCLIをCodexは実行していない。既存同名package/unitは無条件上書きしない。

## runtime境界・残る本番条件

- 新規runtimeの `/opt/flop-r1155-runtime` は監査済みpublic HEADとlocked dependencyを別途
  offline provisionする。旧/復元appのunit・env・秘密を無条件に実行しない。
  Unix clientsは専用publisher UIDだけ。seed/passphrase/署名URLをログにしない。
- 全旧5経路をUID・unit・元nonce・request ID・receipt baselineで永久隔離。
  **新規投稿を実装したのは、別二者承認のOracle固定reply one-shotだけ**。
  既存Autopilot renderer/DLP/rateを使う。6/day、2/room/day、1/DID/6hは維持。
  自律的なResident queue取り込みは未接続。新TCLK/Close1送信は明示NO_GOであり、
  migrationを理由に既存pilot/trade承認を迂回しない。UNKNOWNの外部不受理を推測しない。
- recipient PKCS8/custody.jsonの専用UID 0600、socket group、root config 0640が必要。
  reboot後はboot-bound lease再発行とlocal手動unsealが必須。自動可用性は保証しない。
- source HOLD証拠30秒、preserve/transfer/runtime二者grant最大900秒。期限切れなら停止。
  900秒を超えるsource encryptionに必要な独立grant更新workerは未接続。新nonceでの
  自動再取得や長期grant偽装で回避しない。scratch2GiB超のDBも明示STOP。
- 所有者・独立authorityの実enrollment、実unit census、永久quarantine consent、両host pin、
  K137資源/費用0、recipient/offhost recovery、全量restore、same-DID実証、継続healthは未成立。
  原本VM停止・retirementはSTRICT_NO_GO。コード完成部分を本番移行完了と扱わない。
