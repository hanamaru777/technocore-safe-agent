# R1162 v1.0 — K137 provider認証・payloadだけのbounded admission

Issue #951のSOURCE ONLY候補。今回の開発でAWS/SSH接続、credential取得、transient unit作成を実行しない。R1071は消費済みで再実行禁止。R1161 -Executeも使用禁止。R1160 encrypted custody、旧PEM、Oracle/R987、既存service/config/data、旧source/pin mapは変更しない。

## 保証範囲とSTOP

固定のsudo -n systemd-runが、一時的なsystem serviceにUser/Group=ubuntu、MemoryMax=256M、MemorySwapMax=0、TasksMax=64、CPUQuota=50%、NoNewPrivileges、ProtectSystem=strict、ProtectHome=yes、PrivateTmpを設定してからguest Pythonをexecする。scopeではない。45秒runtime、15秒startup、5秒stop上限、Restart=no、KillMode=control-group、collectを指定する。他のunitを停止・変更しない。

SSH client/sshd、認証・login shell、sudo、systemd-run制御process、system managerはこのchild制限の外。SSH_LOGIN_PREBOUNDEDは未対応で、reportのssh_login_preboundedは常にfalse。login時のrc等も本候補は隔離しない。PRE-LOGIN上限が必要ならSTOPし、本scopeでsshdやloginを変更しない。K137_PAYLOAD_BOUNDEDはM2移行許可ではない。

現在のsudo権限・systemd機能があるとは仮定しない。固定commandを非対話で実行できない場合、guestは開始せずSTOP。sudoers変更、別sudo probe、root login、bare Pythonや別commandへのfallbackは禁止。現在の許可・既存hostの安全性が独立確認できなければ、production使用自体をSTOPする。

## 認証と一回制限

実行先は既存のowner認証済み標準AWS CloudShell Linuxを想定する。NEW WindowsにAWS CLIがあるとは仮定せず、OLD PEMやR1160 capsuleを使わない。Python 3.9以上、root所有・group/other非書込の既存AWS CLI/OpenSSH、既存system CAが必要。追加install、credential作成、profile設定、resource作成はしない。別endpoint/CA/model/role/profile等のenvironment overrideはSTOP。環境全体や認証値を読んだり表示しない。

AWS CLIは固定のLightsail GetInstanceAccessDetailsだけを、tradebot-k137 / ap-northeast-1 / ssh、固定AWS HTTPS endpoint、system CA検証、retry一回で要求する。CLIは既存CloudShell session認証を使用する。永続config/credentials fileとCLI historyの使用を避けるため、そのprocess内でconfigとshared credentials参照を/dev/nullにする。認証が成立しなければSTOP。入力JSONや「信頼URL」を認証の代わりに渡す機能は無い。

providerの固定instance/IP/user、唯一のEd25519 hostKeys、SHA256 fingerprint、既存不変K137公開host pinを全て要求する。別algorithmへのfallback、TOFU/keyscanはない。witnessedAtを記録し、新API呼出とowner challengeの公開binding hashを作る。hostKeys自体は既存guestを全面監査した証拠ではない。

短期user certificateのprincipal=ubuntu、有効期間・残存時間、key種別、critical options、署名algorithmを限定する。metadata expiryが無くても実certificateの期限を検証する。許容期間は最大約1時間。想定外のprovider形式・期間はSTOPし、緩和して接続しない。既存OpenSSH parserでprivate/certificate一致とcertificate署名を確認する。CAの真正性はAWS HTTPS応答が根拠であり、certificate単独の自己署名を外部authorityと見なさない。SSHはcertificate algorithmのみ許可し、agent・proxy・forwarding・password・config・known-host-commandを無効化する。

ownerによる明示承認の後、OS乱数で新しい256-bit challengeを生成し、実Unix accountのHOME/.flop-r1162/ATTEMPTED.jsonを0600のCreateNewで作成する。directoryは0700。AWS呼出より前に記録し、R1161 markerは再利用しない。duplicate、error、timeout、interrupt、結果不明はterminal。markerを消して再実行しない。異なるCloudShell HOMEを使えば同じlocal guardを共有できないため、owner側でもtask単位の一回承認を管理する。

privateKeyと短期certificateは0700の新規/tmp directory内の0600 fileにだけ展開する。AWS access JSONをdisk/repo/stdout/logへ保存しない。AWS CLI diagnosticsも表示しない。SSHとkeygenにはAWS環境を継承しない。通常終了・例外・interruptでは自分の3個の一時fileだけを削除し、directory消失を確認するまでPASSを出さない。cleanup不明はSTOP。SIGKILL/端末喪失時の完全消去は保証せず、short-lived credentialとprivate modeが残存対策。Python/provider内部immutable copyの完全消去も証明できない。信頼済みsession、recording/debug無効、swap/host侵害境界はowner確認事項。

## Guest・report

guestは自分の実cgroup v2が固定新serviceであること、実memory/pids/cpu/swap上限、PID membership、UID/GIDを最初に読む。service sandbox properties、固定machine公開pin、fresh boot、既存release HEAD、protected directory、landingのowner=1000/0700かつmount経由で非書込、TradeBot unitのactive状態・1000/1200MiB caps・ControlGroup、21GiB以上free（20GiB保護+1GiB reserve）を確認する。cgroup/boot/machine/sandbox/TradeBotを再確認し、不一致・変更はSTOP。新しいexpected boot/scope digestを捏造しない。guestにwriter、financial/DID/Oracle処理はない。

stdoutはcompactな公開receipt一個。challenge、最大180秒期限、provider binding/host-key、固定開始commit、R1071参照commit、source/guest/report/cgroup/boot/TradeBotのhashを結合する。instance/IP/user/秘密path・credential・AWS JSON・完全logは公開しない。bodyの自己hashは改変検知用で、外部署名でも第三者proofでもない。真正なAWS session・固定SSH接続からの取得過程とhashを独立監査する必要がある。M2=NO_GO、cutover=NO_GO、OCI retirement=STRICT_NO_GOを維持する。

## 後日の別owner承認がある場合だけ

現時点の実行許可ではない。独立監査済みfinal commitを既存の安全なCloudShell local checkoutで確認する。code内のsource pinsは不変R1071/R1066/R1159 treeと新guestをオフライン検証し、R1071 shellを実行しない。公式sourceを追加downloadしたり未知URLを実行しない。

    python3 -I -B packaging/migration/r1162_k137_provider_admission.py --execute

通常TTYで確認文字列 CREATE_ONE_K137_TRANSIENT_SERVICE_R1162_NO_M2_NO_HOLD を入力する。これは将来の一時unit作成への一回承認であり、現在のCodex実行対象ではない。default/引数違いは接続前STOP。credentialやchallengeをargv/envへ貼らない。

残件: ownerによる安全な既存AWS session・料金・現在の限定sudo/systemd機能・login残余負荷の許容性確認、実hostの独立した観測、cleanup/receipt監査。元Oracle guest sshdのprovider anchor欠落は全く解消しない。Oracle操作、R987 unseal、R1160解放、HOLD/backup/cutoverは別scopeでも未承認。

## 検証・費用

新synthetic testsと直接関連R1071/R1161 regressionのみ。実AWS/SSH/systemdは実行しない。PS source変更がないためnative PS検証の追加はない。CIは既存Public repositoryのstandard ubuntu-latest、artifact/cacheなしでZERO_COST=PASS（2026-11-05確認済み[GitHub公式条件](https://docs.github.com/en/billing/concepts/product-billing/github-actions)）。productionの料金条件は今回検証もactivationもしない。

既存tracked/history scannerは変更しない。full-ref historyの既知R1151公開machine digest hitは独立のFAILとして表示し、例外追加や履歴変更で隠さない。

参照: [AWS temporary access details](https://docs.aws.amazon.com/cli/latest/reference/lightsail/get-instance-access-details.html)、[systemd-run公式manual](https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html)、[公式manual source](https://github.com/systemd/systemd/blob/main/man/systemd-run.xml)、[OpenSSH certificate parserの署名検証](https://github.com/openssh/openssh-portable/blob/master/sshkey.c)。OracleのRun Command/consoleを本実装では呼び出さない。
