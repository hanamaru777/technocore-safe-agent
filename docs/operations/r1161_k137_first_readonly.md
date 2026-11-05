# R1161 v1.0: K137先行・原Oracleホスト鍵の相互確認

Issue #949の**実装のみ**。本作業ではSSH、秘密ファイル確認、復元、cloud変更を実行しない。R1158 Init、R1160 Recipient/Seal/Importは成功・消費済み。再実行禁止。旧source・保管状態は変更しない。

## 現在のSTOP条件

原Oracle guest sshdのEd25519 pinの独立した真正性は未確認。`PINNED_ORIGINAL_EVIDENCE_SHA256 = None`のため、任意のURL、自己申告digest、known_hostsの一致だけではOracle接続を許可しない。`ORIGINAL_ED25519_INDEPENDENT_TRUST_REQUIRED`で**復元コード入力・escrow探索・Oracle SSHの前に停止**する。K137成功もOracleの信頼を作らない。

必要な独立証拠: 過去に真正性を別経路で確認した原guest sshdの公開Ed25519鍵、固定原IPとの対応、取得日時・方法・原archiveのhashと保管元。公開SHA256はIssue #949の`13d1b2…f626`。別途ChatGPTが原記録と独立経路を監査する。現在はその証拠が無いため、operator入力で解除不可。将来の**別sourceレビュー**でのみ、認証済み証拠packetのcanonical SHA256をsourceに固定し、PS側helper blob pinも再レビューする。本書はその変更を承認しない。

証拠packetは厳密JSONの`kind`, `known_hosts`, `independent_archive_sha256`, `reference`。kindは`PREVIOUSLY_AUTHENTICATED_ORIGINAL_GUEST_SSHD_ARCHIVE`、known_hostsは固定原IPと`ssh-ed25519`の一行のみ。archive hashは独立監査済み原本を指す。JSONのhash一致は証拠内容の正当性を自動認証しない。URLを自動取得しない。

OctoberのECDSA `SHA256:SAoJ8SERYhfqcN/1wFCz6VHGmpC4BIbd34D0GBuprkg`は未証明として拒否された値。期待値に一致しても単独のtrust rootにしない。[Oracleのserial-console文書](https://docs.oracle.com/en-us/iaas/Content/Compute/References/serialconsole.htm)のconsole接続サーバfingerprintは別接続のもの。guest sshdのEd25519/ECDSA証拠に代用不可。新console・鍵生成・cloud変更を行わない。

## 後日、独立監査とowner個別承認後だけの一回操作

既存K137 PEMのある、実行安全性を別途確認済みのWindowsを使用する。現在のNEWにはPEMを平文展開しないR1160保管のみであり、本entrypointはcapsuleを開かず、NEWへPEMを複製しない。OLDの実行安全性が不明ならSTOP。本作業でmalware再scanもしない。

レビュー済みcheckoutと既存`.venv`、native Windows PowerShell 5.1、Microsoft署名済みWindows OpenSSHが必要。コードはlocal Gitの固定開始commit `75ce50b1071e543774ba7235e063beaf308c8bea`のtreeと凍結manifestを照合する。ダウンロードやfetchはしない。

監査者が独立した新challenge（64桁lowercase hex）を指定する。K137の期待boot hash、login scope hash、TradeBot cgroup hashを既存の真正な公開記録から確認した**公開plan**をowner-onlyローカルfileに用意する。不明値は推測・合成値で埋めない。boot/scopeが確認できなければSTOP。planの実際のfile SHA256を別経路で照合する。

```text
version: 1
challenge: 独立監査者が今回だけ発行した64桁hex
expires_at: 実行時より未来、600秒以内のUTC Unix整数
k137_boot_sha256: 改行を除いたboot_idのSHA256
k137_scope_sha256: /proc/self/cgroupの元バイト列（改行込み）のSHA256
tradebot_cgroup_sha256: systemctl ControlGroup値（改行なし）のSHA256
consent: READ_ONLY_R1161_NO_M2_NO_HOLD
```

上記はschema説明。実際のJSONは未知・重複field禁止。通常console、`-NoProfile`、transcript/debug/録画なし。**以下のcommandは未実行・現在の実行許可ではない**。パスとhashは監査済み実値のみ使う。

```powershell
powershell.exe -NoProfile -File .\packaging\windows\r1161_k137_first_readonly.ps1 -Execute -PlanFile 'C:\reviewed\r1161-plan.json' -PlanSha256 '<reviewed-file-sha256>'
```

確認文`READ_ONLY_R1161_NO_M2_NO_HOLD`の後、`%LOCALAPPDATA%\FLOP-R1161\ATTEMPTED.json`をCreateNewで記録。current-user mutexで並行実行禁止。失敗・timeout・途中終了も再試行しない。既存folder/markerは削除して再実行しない。

最初に既存の正確なTokyo PEMを一個だけ選ぶ。owner=current user、継承無効、canonical、他principal/deny無しのACLを要求し、修復・複製しない。秘密内容はhelperへ渡さず、固定OpenSSHだけが読み取る。固定Ed25519 host pin、固定IP/user、config/agent/proxy/forwarding/password認証なし。guest commandは`/usr/bin/python3 -I -B -`だけ、sourceはstdin、SSHは一回・58秒以内。read-onlyのmachine/UID/boot/HEAD/landing、scope membership、256MiB/64PIDs/1CPU以下、TradeBot active・1000/1200MiB caps、21GiB以上freeを確認する。不一致は設定を変更せずSTOP。TradeBotやサービスを停止しない。

K137 PASS後だけ、必要なら**同じ一回command**に`-CrossCertOriginal -OriginalEvidenceFile 'C:\reviewed\original-guest-anchor.json'`を付ける。後から同じattemptを再利用不可。現sourceでは独立trust STOPになる。将来sourceで真正なanchorが承認された場合のみ、local hidden SecureStringで既存R987 V2復元コードを入力し、既存R1027 crypto/ACL/cleanupで一時SSH鍵を扱う。コードはargv/env/log/ChatGPT/Codexへ渡さない。DID seedやowner承認鍵は使用しない。SSHは原Ed25519を要求し、sudo無しで原guestの`/etc/ssh/ssh_host_ecdsa_key.pub`だけを1024 bytes以内で読む。原ECDSAの正確なpinを照合し、秘密host keyは読まない。

## 結果・残件

一時known_hosts・復元鍵とhandleのcleanupが確認できた後だけ、公開`k137-admission.json`、任意の`original-crosscert.json`と各`.sha256`を新規出力する。receiptは独立challenge、plan/report/guest/source hash、原host pin、最大180秒TTLに結合し、machine/user/pathの観測平文を出さない。自己hashは改変検知用で署名・独立認証ではない。表示されたfile hashとbody hash、challenge、期限、sourceをChatGPTが別途検証する。K137 receiptが残ってもOracle STOPは解消しない。期限切れreceiptを後日のM2許可として使わない。

cleanup不明、重複・locked attempt、PEM不足/ACL、scope/caps不足、boot変化、host-key不一致、未確認archiveはSTOP。自動retry・source pin差替え・TOFU・unbounded shellなどの回避禁止。強制終了時の残存物はownerが独立監査する。R1159を自動実行しない。真正な結果の新GitHub commentと独立監査後にのみ、別途ownerレビュー済みM2を検討できる。HOLD/backup/cutover/Oracle廃止は全て未承認。

CIの`ZERO_COST=PASS`確認（2026-11-05）: repositoryはPublic、使用runnerはstandard GitHub-hosted `windows-latest`のみ。[GitHub公式料金条件](https://docs.github.com/en/billing/concepts/product-billing/github-actions)でPublicのstandard runnerは無料と確認。対象試験のみ、artifact/cache/Packages追加なし、cloud利用なし。既存tracked/history scannerを変更しない。継承の公開machine digestによるhistory FAILは別問題として報告し、例外や履歴変更で隠さない。

Windows実行policyがreview済みlocal scriptを許可しない場合はSTOP。自動bypassや永続policy変更は行わない。開発の合成試験はprocess限定`RemoteSigned`で検証し、実owner操作は実行しない。復元bufferは既存helperでbest-effort消去するが、OS/provider内部のコピーや強制終了後の消去は証明できないため、cleanup不明時に成功を出さない。
