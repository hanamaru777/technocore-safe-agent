# R1159: 最初のM2認証（SOURCE ONLY、実機未実行）

対象は固定の元Oracleと既存K137だけ。初回のread-only SSH認証と現在の公開ホスト情報から、R1158で不足していたendpointsを作る。新しいenrollment、承認署名、DID署名、HOLD、転送、サービス操作は行わない。既存owner承認鍵のInitはSUCCESS/CONSUMEDであり、再実行・再生成・解除をしない。

4種類のローカルファイルのPRESENT結果は認証結果ではない。本タスクの実装・テストで、実在するescrow/PEM/復元コードの読み取りや実機接続は行わない。今後のowner操作も、ソースとCIの独立監査および明示的な実行承認が前提。

## 信頼の入口

- OCI: R1126/R1144等で独立確認された**公開SSH ECDSA key blobのSHA256（小文字hex）**と、その公開証拠comment URLを所有者が指定する。ローカルknown_hostsからその場で計算した値を「独立確認済み」と扱ってはいけない。URLの形式確認は、その記事内容が正しいことの証明ではない。所有者／監査者が記録そのものを照合する。独立digestが不明なら`OCI_INDEPENDENT_TRUST_REQUIRED`で復号／SSHより前に停止する。推測値や架空の証拠URLを入力しない。
- K137: R1136で固定された既存ED25519公開鍵を固定する。新規取得・TOFU・ssh-keyscan・変更されたhost keyの自動受容は行わない。ローカルにK137の同algorithmレコードが存在して不一致なら停止する。
- known_hostsのOCIレコードは独立digestとの一致が必須。hashed-hostをHMACで照合し、重複・曖昧・revoked/cert形式の対象レコードは拒否する。接続には選択した固定公開鍵だけを入れた一時known_hostsを使う。
- 新しいホストのmachine/boot/cgroupを仮置きしない。固定公開鍵で認証した新guestの実測値だけを記録する。元Oracleの既定Git HEADとK137の既存stage SHA、K137 machine digestは既存R1066/R1151に一致しなければ停止する。

公開digestはSSH公開鍵blobのhashであり、秘密鍵、暗号化escrowファイル、known_hostsファイル全体のhashではない。未確認の値を端末のファイルやネットワークから補完しない。必要な独立公開証拠が欠ける場合、それが本番M2の具体的な残条件となる。

## 独立監査後に限る一回のowner呼出形

確認済みの公開値を置き換えて実行する。下記は実行承認ではない。

```powershell
.\packaging\windows\r1159_authenticated_m2_bootstrap.ps1 -Execute `
  -OracleHostKeySha256 '<independently-verified-public-ECDSA-blob-SHA256-lowercase-hex>' `
  -OracleTrustReference 'https://github.com/hanamaru777/technocore-safe-agent/issues/<issue>#issuecomment-<evidence>'
```

端末で`READ_ONLY_M2_NO_ENROLL_NO_HOLD`を確認し、**R987 V2の復元コードだけ**をSecureStringで非表示入力する。owner承認鍵パスフレーズやDID seedは入力しない。旧R986コード・旧Windows SSH鍵にはfallbackしない。引数なし、`-Execute`なし、独立公開pinなしでは、credentialを選択・復号・認証しない。

実行入口は、既定3か所のR987 V2暗号化ファイルとDownloadsの既存Tokyo Lightsail PEMを一意選択する。過去のpresence用スクリプトや消費済みR1136/R1138等を再実行しない。旧ソースからはピン済みの関数定義だけを使う。既存ファイルのowner、ACL、reparse、サイズを確認し、ACLが不適切でも自動修復しない。管理用SYSTEM/Administratorsの既存ACEはR1138と同じ境界で許可するが、それ以外のprincipal、非owner、非canonical／未保護ACLは拒否する。

正確なescrow SHA256を復号前に確認。K137 PEMは元の場所でread handleを保持し、コピーしない。OCI鍵だけをcurrent-user-onlyの一時directoryへ短時間復元し、全成否経路で消去する。復元コードはargv/env/file/logへ出さず、既存R987のSecureString変換・バッファ消去を再利用する。SSHは固定Windows OpenSSH、`-F NUL`、StrictHostKeyChecking、algorithm固定、agent/password/proxy/forwarding無効、各host一回、58秒上限。stdout/stderrやcredentialをconsoleへ流さない。

## 新guestが読むもの／止まる条件

stdinで送る新しい固定guestのみを実行する。OCIは承認済み`sudo -n /usr/bin/python3 -I -B -`、K137は既存UID1000の`/usr/bin/python3 -I -B -`。遠隔ファイルの配置・保存・サービス変更はしない。

- 現在のmachine-id、boot-id、正確なcgroup membership、自PIDのmembership、disk/cgroup limits、固定Git HEADを読む。challenge、時刻、全source blobを検証し、guest走査中のboot／cgroup変化も拒否する。内部PID、raw cgroup path、host identifiersはconsoleに表示しない。
- K137の現在のlogin cgroupは、既存R1066の`memory.max <=256MiB`、`pids.max <=64`、`cpu.max <=1 core`を満たす必要がある。`max`／不存在／membership不一致は`K137_LOGIN_CGROUP_UNBOUNDED`等で停止。cgroupを作らず、上限を変更しない。
- 元DIDは、元Oracleの固定`verified-did.json`の**公開did/verified_atだけ**から取得する。regular file・owner・サイズ・symlink・競合を検査し、Ed25519 multicodecを既存公開decoderで確認する。source_key_idsはその実測公開鍵のSHA256から導出し、根拠を明記する。新しいDIDや鍵を作らない。これは現在のVault秘密鍵の存在や移送成功の証明ではない。
- K137では既存landingと保護directoryのmetadata、固定`k137q-public-k58.service`の公開systemd/cgroup metadataだけを読む。MemoryHigh=1000MiB、MemoryMax=1200MiBとの相違は停止し、TradeBotを変更しない。SQLite、WAL、journal、signer receipts、Vault、environment file、TradeBot内部データは読まない。
- Oracleのfreeは最低1GiB、K137は最低21GiBであることを確認する。これはM2の観測に限り、全移行用容量・RSS・writer fence・同一epochが成立したとは判断しない。

## 成果物と次段階

一回目のSSHより前に、新規owner-only `%LOCALAPPDATA%\FLOP-R1159-M2\ATTEMPTED.json`を作る。既存directory／既存attemptがあれば停止し、上書き・自動再試行しない。失敗済みattemptを削除して再実行する手順は本実装の権限外。失敗理由を監査者へ報告する。

両hostの成功と**一時鍵cleanup成功の後だけ**、同directoryに以下を排他的に出力する（各SHA256 sidecar付き）。

- `endpoints.json`: R1066_READONLY_PREFLIGHT schema。実host-key／credential digest／machine／uid／HEAD／current cgroup digest。
- `host-evidence.json`: challenge付きの実観測、source pins、承認されていないgateのNO_GO表示。
- `enroll-input.json`: 既存ownerの**公開descriptorだけ**と実測DID/bootを使う、R1158 Enrollのレビュー用入力。machine keysは未設定を示す`null`であり、偽の値ではない。
- `M2-result.json`: 全成果物hashを束縛する最終receipt。これが欠ける部分出力は使用不可。helperへ手作りJSONを渡したものは実SSHの証明にならない。監査済みPS入口の完了結果とreceiptを確認する。

consoleの成功codeは`M2_AUTHENTICATED_PUBLIC_ARTIFACTS_ONLY`で、enrollmentは`NOT_DONE`、cutoverは`NO_GO`、OCI retirementは`STRICT_NO_GO`のまま。cleanup、timeout、認証、schema、source pinの失敗にPASSは出さない。

endpointsのcgroup hashはR1157/R1158が要求する**raw `/proc/self/cgroup` bytes**で、normalized hashも証拠に残す。旧R1066の単独`resources()`はstrip版を検査するため、新guest内ではstrip版を渡す。両規約を取り違えて旧entrypointを呼ばない。新SSH sessionでmembershipが変われば旧snapshotが一致するとは保証しない。boot／cgroup／credentialの再検証を省略しない。

所有者／監査者が成果物と信頼根拠を確認した後、R1158 Enrollを**別の明示操作**として行う。Initは絶対に繰り返さない。M3以降、HOLD、DID暗号化export、archive、restore、runtime start、5 POST経路、金融処理、Oracle停止／削除の承認にはならない。

## 検査と既知のCI制限

新guest／clientとnative PS5.1を合成鍵・合成host情報で検査する。R1066、R1157/R1158の直接依存部分を必要な範囲だけ回帰検査する。本番操作、実credentialの読み取り、過去の成功probeの再実行はしない。

既存のreachable-history検査は、旧commit/blob `6c6e4755e813` のR1151仕様書6行にある公開machine digestを検出している。これは未解決の継承CI failureとして別途報告する。scanner変更、除外追加、履歴改変、未変更full suiteの反復による隠蔽をしない。
