# Oracle FLOP本番へ入る方法（固定運用手順）

最終確認：2026-10-29 JST（利用者が提示したOracle Cloudインスタンス画面を確認）
管理：FLOP Issue #765 / 移行作業 Issue #905 / Draft PR #906

## 1. どのサーバーか

| 項目 | 確認内容 |
| --- | --- |
| クラウド | Oracle Cloud Infrastructure（OCI、AWSではない） |
| 管理画面 | https://cloud.oracle.com/ |
| 画面 | Compute → Instances → `technocore-resident` |
| 状態 | Running（2026-10-29の画面上。将来の状態は必ず再確認） |
| リージョン | 東京 `ap-tokyo-1` |
| 表示された Public IP | `140.238.55.171` |
| 画面に表示された Username | `ubuntu` |
| マシン | `VM.Standard.E2.1.Micro`（1 OCPU／1GBメモリ） |
| 本番アプリ | `/opt/technocore-safe-agent` |
| 本番の状態・履歴 | `/var/lib/technocore-safe-agent` |
| 元の正本HEAD（過去確認） | `ec4bc4892d40cdd2a03e102faa44d72c89e01b99` |

**AWS Lightsail / `tradebot-k137` は別の機械。ブラウザーの「CloudShell | ap-northeast-1」はAWSのCloudShellであって、このOracle本番のターミナルではない。**

## 2. Oracle管理画面から本番を見つける

1. https://cloud.oracle.com/ にサインイン。
2. 左上のメニュー → **Compute（コンピュート）** → **Instances（インスタンス）**。
3. インスタンス名 **`technocore-resident`** をクリック。
4. **Details** タブ → **Instance access** にある `Public IP address` と `Username` を確認。
5. この画面自体は **Linuxのコマンド入力画面ではない**。サーバーに入るには、認証済みSSH（Secure Shell）接続が必要。

## 3. Oracleコンソール画面からブラウザでシリアル接続する場合

**Oracle公式案内で確認済み**：https://docs.oracle.com/ja-jp/iaas/Content/Compute/References/serialconsole.htm

2026-10-29利用者が提示した `technocore-resident` の画面では、上部に **OS Management** タブが表示されている。まずそのタブをクリックし、画面を下へスクロールして **Console connection（コンソール接続）** を探す。OCI画面のバージョンによっては左の **Resources → Console connection** にある。

**Launch Cloud Shell connection（Cloud Shell接続の起動）** をクリックすると、ブラウザ下部にシリアルコンソールのターミナルが開く。この接続ではOCIが一時的なコンソール接続・認証鍵を用意するため、WindowsのR987エスクローSSH鍵ファイルを直接指定する必要はない。

ただし**シリアルコンソールは通常のSSHログインとは違う**。Linuxのユーザー名・ログインパスワードが求められる場合、OS上にその資格情報が既に設定されていなければログインできない。一般的なOCI Ubuntu初期構築はSSH鍵を利用するため、パスワードログインが設定済みだと推測しない。**ユーザーにパスワード・鍵・シードをチャットへ送らせない。** 設定を変更・再発行して進めない。

利用者が「どこを押す？」と尋ねたら：**スクリーンショットの OS Management → Console connection → Launch Cloud Shell connection** と答える。OS Managementに見つからなければResources下のConsole connectionを確認する。進行途中のスクリーンショットに表示された実際のボタンを優先する。

接続が有効でもログイン自体は未検証。ブラウザにCloud Shellが現れただけでOracle本番内にログインしたとはみなさない。Linuxのプロンプトと対象ホスト・Git HEADを照合するまで、本番削除コマンドは実行しない。

## 4. WindowsからSSHで入る場合

Windowsのスタートメニューから **Windows PowerShell** を開く。
**既存の、Oracle側で登録済みのOpenSSH秘密鍵が安全に利用可能な場合だけ**、次の形式でログインする。

```powershell
ssh -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -i "C:\PATH\TO\EXISTING_OPENSSH_PRIVATE_KEY" ubuntu@140.238.55.171
```

**重要**：
- 上の `C:\PATH\TO\...` は実在するパスではなく説明用。実際の秘密鍵の場所を推測して指定しない。
- 2026-10-29のOracle画面だけでは秘密鍵を取得できない。**ログイン成功はまだこの手順では確認していない。**
- 過去の成功ルートは、Windows上で既存の暗号化 **R987 V2エスクロー**を復号し、一時的にSSH鍵を厳密なACL下で使用する専用ツール。暗号化ファイル自体は `ssh -i` に直接渡せない。既存の専用ツールは通常の対話型シェルを提供しない。
- 以前のR987/R1079/R1080は認証済み*読取り専用ゲスト処理*の実績があるが、**現在の対話ログイン可能性や本番削除権限を保証しない**。
- SSHホスト鍵を新規に無確認で受け入れない（`StrictHostKeyChecking=no` は禁止）。ホスト鍵確認で止まったらそれ以上進めず、既存の信頼済みピンとの整合性確認が必要。
- 鍵がないときに鍵を再発行・作り直す／サーバー設定を変更することはしない。
- パスワード、秘密鍵、R987復号コード、DID seed、OCI認証情報をチャットやGitHubに貼らない。
- OracleのシリアルConsole Connectionは別の管理機能で、事前の設定・認証条件があり、一般のSSHログイン代用として手順を断定しない。

ログインできると `ubuntu@...:~$` などが表示される。ホスト名は環境により異なる。必ず最初に **read-only** で同一機械・同一正本を確認し、予期しない相違があれば停止する。

```bash
hostname
id
git -C /opt/technocore-safe-agent rev-parse --verify HEAD
```

想定元HEAD `ec4bc4892d40cdd2a03e102faa44d72c89e01b99`。これは2026-10-29までの過去の実測・ソースに基づく値で、変化していたら無理に戻さず調査する。

## 5. 不要ファイル整理 R1091 との関係

2026-10-29に既存Draft PR #906へ追加した **`packaging/oracle/r1091_safe_cache_cleanup.py`** は、Oracleにログインした後の「容量内訳確認／再生成可能なアプリキャッシュのみ削除」のプログラム。GitHubでのソース作成・CI PASSと、本番での削除完了は**別**。

- 安全な初回はオプションなし（読み取り・容量分類のみ）。実際のキャッシュ削除は利用者の明示的な意思のもと `--delete-proven-cache` を付けた時だけ。
- 元の本番 `state`、SQLite/WAL、DID、nonce、POST履歴、`.venv`、`.git`、ログ、TradeBotは削除対象外。
- これは**26GB全体を消せるという意味ではない**。今回の元容量情報は合計値しかなく、内訳は未検証。
- プログラムは現在のPRコミットの固定Git blobをチェックしてから実行する。権限を持たない、意図しない対象、原本HEAD違い、シンボリックリンク、特殊オブジェクト、開いたファイル検出などでは止まる。
- OCI本番へChatGPTのGitHub操作だけでSSH接続することはできない。環境側の認証済み実行主体が必要。

ソース（初回コミット固定）：
https://github.com/hanamaru777/technocore-safe-agent/blob/605328b2b5094ebc5fc41e2488d0e621ef30a57f/packaging/oracle/r1091_safe_cache_cleanup.py

## 6. 禁止事項と既存PASS

- Oracleの停止・再起動、インスタンス削除、ディスク初期化、未検証データの一括削除を「不要ファイル整理」と混同しない。
- 同じサーバーへのR1072/R1080容量一括調査を繰り返さない。以前に消費済みの一回限りの実測：30,682エントリ／25,983,618,920バイト、SQLite 2＋WAL 2、OCI空き11,852,025,856バイト。当時の数字であって現在の空き容量ではない。
- 本番移行完了、同一DID署名、5 POST整合、G4 writer fence、AWS移行、OCI削除の承認は一切意味しない。

**接続入口の説明を新チャットでユーザーに繰り返し要求しない。** このドキュメントの確認済み項目を再利用し、変動するIPや認証条件だけ新鮮な実データで検証する。
