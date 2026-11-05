# R1163 v1.0 — 統合ローカル実装・単一運用入口

対象 Issue: https://github.com/hanamaru777/technocore-safe-agent/issues/953

開始点は R1162 の 2033ec2159717d473fed2f0031d441ec105b504a。
指定 R1163 ブランチへ clean worktree から切り替え、HEAD 一致を確認した。
R1162 ブランチ、既存ファイル、既存ソース pin、スキャナ、sign.py は変更しない。
この成果物の運用状態は **OFFLINE_NO_PROD / NO_GO**。

## 最初に必要な外部証拠

|段階|不足する実証 / 所有者の判断|現時点|
|---|---|---|
|M2 K137|別途明示承認した R1162 の新 challenge・boot・cgroup・provider provenance・現行権限の単発実測。既存 R1071 は再実行しない|UNKNOWN|
|M2 original Oracle|元ゲスト sshd Ed25519 公開鍵と machine/boot/scope を独立した認証済み権威が結び付ける証拠。保存 Console history NONE のため現状は未入手|NO_GO|
|R1160|既に NEW へ import 済みの同一 owner 公開 binding と NTFS ACL の確認。秘密ファイルを開かない。必要なら暗号化 capsule の正確な保存パスだけを指定|UNKNOWN / 過去の実施は PASS|
|G3|元 DID を保持する非移植 OCI Vault Instance Principals signer の custody / 独立 remote signer 境界。owner 承認鍵を DID 鍵として扱わない|NO_GO|
|G4|元 Oracle 全 namespace・inode alias・timer・cron・manual・将来再起動を含む GLOBAL writer / 全 5 POST route deny の実効証明|NO_GO|
|G5|5 route の完全な認証済み accepted / never-accepted 証拠。retained room ring、空応答、timeout、409、CAS 主張だけでは負の確定にならない|NO_GO|
|G6/G7|実際の同一 epoch 全状態、両 DB と WAL/SHM、完全 AEAD offhost readback、独立 DISARMED restore receipt、undo / rollback 実証|NO_GO|
|M6|TradeBot を維持した fresh concurrent RSS / 全 cap / PSI / disk 証拠と別途 activation 承認|NO_GO|
|M7|観測安定期間、同一 DID・single publisher・backup readback・rollback drill・不明 POST 解消を示す独立証拠と別個の判断|NO_GO|
|Testnet|公式 release / genesis / RPC / admission / attribution / settlement 仕様。公開ページは 2026-11-06 確認時点で planned / unreleased|UNKNOWN|

これらの証拠は owner の署名・自己 SHA・Issue URL・手入力した PASS で代替できない。
現行 5 unit の上限は 128 + 128 + 96 + 384 + 128 = **864 MiB**。
TradeBot Max 1200 + 最小 reserve 256 を足すと **2320 MiB**、物理 1906 MiB に対し **414 MiB 超過**。
現在 RSS が低くても上限と実効 concurrent 判定を免除しない。TradeBot cap / schedule は変更しない。
移行元容量に加え SQLite allowance と 20 GiB reserve が必要。source size / free space は未実測。

## 固定再利用マップ / 証拠行列

各正確な Git blob と origin commit は r1163_source_pins.json の 122 path に固定。
公開 API の引数形も 16 個固定し、ロード前に全 map の SHA と各 blob を検証する。
T1150 のみ immutable main 8a46d43de6e7474941cd241278c00d3352c8a2b6 から欠けていた 8 ファイルをそのまま取得。
main 全体の merge、watcher の再作成、既存 pin の更新はしない。

|既存成分 / interface|統合での役割|証拠区分|
|---|---|---|
|R1151 preseed / source map|3 ファイル preseed は履歴のまま保持。全 backup として数えない|HISTORIC REAL PASS（限定 scope）|
|R1152/R1153 の既存評価・安全境界|既存診断と hold 前提を保持。対象 blob は開始点で固定|COMPLETE CODE / NEW REAL EVIDENCE REQUIRED|
|R1154 Controller.hold / rollback / capture_checkpointed|APP のみの exact consent・undo・permanent deny 維持。新入口から hold を実行しない|COMPLETE CODE / SYNTHETIC PASS / BLOCKED live|
|R1155 wal.validate / transfer.admit / LockedArchive|元 DB は書込 open せず private copy で WAL checksum・両 DB integrity/cursor。既存 wire / AEAD / 独立読戻し|COMPLETE CODE / SYNTHETIC PASS|
|R1155 signer.baseline / approved / activation|元 DID、nonce、rate history、5 route の old IDs / UNKNOWN を引継ぐ。新 DID は作らない|COMPLETE CODE / SYNTHETIC PASS / BLOCKED live|
|R1156 origin / publish_cycle / renewal|新規起源だけ、単一 publisher、署名前 durable reservation、曖昧 POST は再送禁止、fresh lease|COMPLETE CODE / SYNTHETIC PASS|
|R1157 public owner descriptor / secure_path|既存 NEW store の owner / ACL 検証だけ。local_key は呼ばない|COMPLETE CODE|
|R1158 solo / machine.target_activation|架空の第二人を設けず、同一 owner の別 consent と独立 machine evidence。実効 single writer / concurrent cap 判定を維持|COMPLETE CODE / SYNTHETIC PASS / NEW REAL EVIDENCE REQUIRED|
|R1159 fixed bootstrap|公開 host/key decoder だけ再利用。旧 OCI-first 実行入口は呼ばない|COMPLETE CODE / BLOCKED live|
|R1160 verify_local / verify_binding|NEW SID + MachineGuid と元公開 descriptor の同一 owner continuity。暗号化ファイル内容は開かない|HISTORIC REAL PASS / CONSUMED|
|R1161 original anchor STOP|既存鍵 digest と元インスタンスの関係を独立証拠無しで承認しない。古い boot/scope の流用無し|COMPLETE CODE / BLOCKED|
|R1162 sources / main / owner_run|唯一の将来 K137 provider admission。別承認、単発 marker、固定 guest / systemd / cleanup|COMPLETE CODE / SYNTHETIC PASS / NEW REAL EVIDENCE REQUIRED|
|G3 R1117 signer proof|元 upstream say / note 形式の公開 continuity 検証。synthetic portability は実 custody ではない|SYNTHETIC PASS / BLOCKED real custody|
|G4 R1117 JournalBackend / UndoJournal|undo fsync 後のみ side effect、boot 変更は再審査。GLOBAL driver は未認証|COMPLETE CODE / SYNTHETIC PASS / BLOCKED live|
|G5 R1117 verify_complete_authority|現行 retained history から production を解放しない。synthetic authority の改名も拒否|COMPLETE CODE / SYNTHETIC PASS / BLOCKED live|
|G6 R1117 OneShot.acquire + R1155 WAL + R1084 stream|全 app / state census、両 DB、links / permissions / receipts / DID / nonce、一 epoch と持続 journal|COMPLETE CODE / SYNTHETIC PASS|
|G7 R1089 LockedArchive + R1086 restore_stream|全 part / FINAL / 全 file hash 認証後に同一 archive を復元。独立 receipt 無しなら UNKNOWN、DISARMED のまま|COMPLETE CODE / SYNTHETIC PASS / BLOCKED live|
|G8 R1155/R1156 NEW-ONLY / R1158 activation|新規原点・署名権限・single writer・既存 resource checks。現状 activation 不可|COMPLETE CODE / SYNTHETIC PASS / BLOCKED live|
|M7 r1163 stable_gate / R1154 rollback|24 時間以上の独立観測と別 consent の APP review。VM stop / volume delete は操作を実装しない|COMPLETE CODE / SYNTHETIC PASS / BLOCKED live|
|T1150 status / plan / journal / release gate|既存固定公開文の offline preview。偽 release、未確定 receipt、曖昧単発は拒否|COMPLETE CODE / SYNTHETIC PASS / NOT RELEASED|

R1160 Init / Recipient / Seal / Import、R1071、R1126/R1138/R1143/R1144、元 owner inventory、R1095 cleanup、初回 faucet POST、旧 PC scan はすべて **CONSUMED**。再試行の対象外。

## 単一入口（秘密を渡さない）

Windows PowerShell 5.1 / 既存 venv:

    .\.venv\Scripts\python.exe -I -B packaging/migration/r1163_unified.py status

終了 42 は正常な fail-closed NO_GO。全 prerequisites、resource 算術、T1150 preview を単一公開 JSON bundle と整合性 SHA にまとめる。
SHA は真正性証明ではない。入力値、内部例外、秘密ファイル内容、パスを出力しない。
status はローカル公開ソースだけを読む。署名・SSH・cloud・POST・新 wallet・watch を起動しない。

必要な場合だけ既存 NEW store の公開証拠 / ACL を確認:

    .\.venv\Scripts\python.exe -I -B packaging/migration/r1163_unified.py custody-check

任意の --capsule-path は owner が既に知っている credentials.sealed.json の絶対パスのみ。
探索、内容読取、hash、unseal、復号、再 import はしない。公開 binding が PASS でも credential_use は NO_GO。
R1160 store の approval.pem.enc も ACL / metadata だけ。元 DID signer custody と混同しない。

original Oracle の将来の公開証拠入力:

    .\.venv\Scripts\python.exe -I -B packaging/migration/r1163_unified.py oracle-import --public-file <公開packet.json> --challenge <今回challenge>

現行 ORIGINAL_AUTHORITIES は空であり必ず停止する。packet / CLI から trust root を指定できない。
将来 source review で pin された独立権威だけが対象。known_hosts、keyscan、authorized_keys、serial proxy fingerprint、AWS key、自己 digest は受け付けない。
packet は元 Oracle host / instance / Ed25519 wire key、独立証拠 digest、fresh challenge / machine / boot / scope と短い期限に署名する公開形式。
この署名形式自体は OCI が提供する attestation API という主張ではない。実在する独立権威が得られなければ STOP を維持する。

## 監査後に限る最初の owner 操作

**先に ChatGPT が commit / tests / 実行環境 / zero-cost 前提を独立監査すること。今この開発タスクでは実行しない。**
監査合格と owner の別途明示承認後、既存 AWS 認証済み Linux CloudShell 非 root セッションで、同じ検証済み checkout の次の **K137 のみ**を一回:

    python3 -I -B packaging/migration/r1163_unified.py admit-k137 --execute

既存 R1162 が一つの固定 approval phrase を一度だけ要求する。新しい包括承認は発行しない。
Lightsail GetInstanceAccessDetails の固定 instance / region / host / user、AWS TLS tool path、証明書 principal / expiry / private-public 整合、provider-witnessed host key、payload / report / boot / scope を既存コードで検証する。
資格情報は /tmp の private directory、3 つの列挙済み temporary file のみ。R1160 capsule / 旧 Downloads PEM は不要。
get-instance-access-details は既存 instance の一時 SSH credential 取得であり、instance / storage / paid SKU を新設しない。実際の account eligibility / permission は未実証のまま。
2026-11-06 に [GetInstanceAccessDetails schema](https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_GetInstanceAccessDetails.html) と
[InstanceAccessDetails](https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_InstanceAccessDetails.html) の temporary certKey / privateKey / expiresAt / hostKeys を照合した。
hostKeys.witnessedAt は host key の観測時刻であり現在の API 呼出時刻ではない。R1162 と同じ過去 witness を許し、未来 witness は拒否。今回 challenge / report / credential の freshness は別に検証する。
[CloudShell pricing](https://aws.amazon.com/cloudshell/pricing/) は shell 自体の追加料金無しだが、他 resource と data transfer の標準課金は別と明記している。
account の現行 free transfer / entitlement まで確認したという意味ではない。
現在の fee 影響を owner が ZERO_COST=PASS と確認できなければ実行しない。事前一般承認や過去の $0 を根拠にしない。

systemd-run --system --pipe --wait --collect --service-type=exec が guest Python より前に 256M / swap0 / Tasks64 / CPU50% を適用。
RuntimeMax45s / TimeoutStart15s / TimeoutStop5s / KillMode=control-group / Restart=no / collect を維持。
SSH authentication、PAM、login shell、sudo、systemd manager はこの unit の制限外。SSH login を bounded と表現しない。
guest に書込・service install 権限を渡さない。TradeBot は状態を読むだけ。
API schema / cert 異常、権限不足、sudo 不成立、cgroup 検証失敗、timeout、cleanup 不確実なら STOP。
~/.flop-r1162/ATTEMPTED.json は AWS 呼出前に durable 作成。失敗でも消さず、自動再試行しない。
timeout 後の guest unit 終了は既存期限による。追加の remote cleanup / retry SSH を勝手に行わない。
成功時も独立 authority は UNKNOWN、M2 / migration / cutover は NO_GO。Oracle への次操作へ連鎖しない。

## 統合試験 / 回復境界

r1163_pipeline.Trial は Linux の private な非本番 root に限定された library。CLI は公開しない。
新鮮 dummy key / dummy recovery で元と同じ proof / exact owner grant / G4 lease / synthetic 完全 history を使う。
元の full census → strict WAL copy 検査 → 既存 AEAD stream → ciphertext-only offhost receiver → 全 archive readback → 既存 DISARMED restore を接続する。
全 plaintext を一時ファイルやメモリ一括に置かず bounded stream で渡す。復元先は隔離した module instance の quarantine のみ。
元 metadata / symlink は manifest に保持し activation 前には inert。DISARMED 完了 receipt は両 DB / 全ファイル検証後にのみ確定する。
symlink / hardlink は private quarantine 内で実際の link として保存される。リンクを実行・運用経路として追跡せず、links_require_activation_review を維持する。元の ownership / mode は manifest に保存し運用権限として自動適用しない。
独立 restorer / rollback receipt の署名が別に無い場合はローカル復元が成功しても UNKNOWN。
暗号化 archive の完全再認証を毎回先行させ、同じ archive の明示 restore resume だけを許す。再 capture は不可。
capture 中断は INTERRUPTED_NO_BLIND_RETRY。session / capture の hash-chain journal を消さない。
APP rollback は R1154 の保存済み exact undo、destination publisher fence、old permanent POST deny 維持を再検証。自動再起動無し。
VM stop / volume deletion の backend は含めない。将来でも各々 fresh consent と独立 backup 検証が別途必要。
本番 G3/G4/G5 authority が欠けたまま production_migration は source 読取前に停止する。
HOLD、実 transfer、Vault seed export、DID 署名、外部 POST、TradeBot / Oracle 変更は実行していない。

## 公式 Testnet の確認と判定

2026-11-06 の公開 read-only 確認:

- https://docs.flop.network/networks/testnet — planned / next unreleased、検証済み genesis / RPC 等未提供。
- https://flop.finance/testnet/ — Draft Q4 2026、日程・ルールは暫定。
- https://docs.flop.network/docs/testnet-and-timeline — working target は確定 launch ではない。

T1150 の公式 release、network identity、元 DID、settlement、owner consent、重複防止 journal をそのまま利用。
ここに公式 adapter / 新 wallet / 独自 watcher を追加しない。local JSON manifest は公式 wire protocol ではない。
公開ページの後日の更新は新しい公式証拠として再審査が必要。源泉確認日を bundle に表示し、自動 GO にしない。
初回 devnet faucet POST は UNKNOWN_NO_RETRY。Day-1 の単発 request も別 approval と最終 settled receipt が必要。
token holding / draft attribution から score や airdrop を約束しない。有料 inference は禁止。

## 検証記録

新規公開 contract / PS5.1、および新規 integration の Windows 非 POSIX 部分を focused 実行。
Linux CI は新規 full path と WAL / APP rollback / durable undo / NEW-ONLY / T1150 の直接関連 node のみ。
変更の無い full suite、R1071 実 operation、過去 owner operation は再実行しない。
最終的な件数と CI は本タスク最終報告に記載する。未観測の実環境 PASS を書き込む検証 JSON は作らない。

継承 failure は別枠: reachable Git history の R1151 公開 machine digest
（6c6e4755e813:docs/tasks/R1151_oci_k137_provisional_preseed_v1.md:6）。
sign.py の Git LF blob と Windows CRLF byte hash の既存差異も維持する。
スキャナ例外追加、履歴改変、signer pin / 改行修正による隠蔽は行わない。

正確な変更 path（すべて追加、8 個は上記 T1150 commit と同一）:

|新規統合 / 証拠|変更 path|
|---|---|
|固定 contract|packaging/migration/r1163_contract.py|
|実 crypto / SQLite 統合|packaging/migration/r1163_pipeline.py|
|immutable reuse / interfaces|packaging/migration/r1163_source_pins.json|
|単一 operator 入口|packaging/migration/r1163_unified.py|
|新規試験|tests/test_r1163_pipeline.py、tests/test_r1163_unified.py|
|focused CI|.github/workflows/r1163-integration.yml|
|日本語 matrix / runbook|docs/tasks/R1163_unified_local_integration_v1.md|
|T1150 既存 source|src/flop_agent/testnet_budget.py、src/flop_agent/testnet_day1.py、src/flop_agent/testnet_day1_actions.py、src/flop_agent/testnet_day1_release.py、src/flop_agent/testnet_journal.py|
|T1150 既存 gate / test|packaging/testnet/r1057_offline_agent_launch_gate.py、packaging/testnet/r1105_agent_public_readiness.py、tests/test_testnet_day1.py|
