# VulnNote Manager 基本設計

## 1. 文書情報

- 対象仕様: `docs/spec.md` 0.1.0
- 初回決定日: 2026-07-16
- 目的: 実装時に推測が入りやすい既定値、層構造、安全対策を固定する。

## 2. 技術調査と依存関係

### 2.1 OpenAI API

2026-07-16時点のOpenAI公式開発者文書を確認した。

- `gpt-5.6-terra` はGPT-5.6ファミリーの、性能とコストのバランスを取るモデルとして提供されている。このため仕様の初期モデルを維持する。
- 新規開発にはResponses APIが推奨されている。
- 通常の生成は `client.responses.create(...)` を使い、構造化応答はResponses APIの `text.format` にJSON Schemaを指定する。SDKが対応する箇所では型付きparse機能を利用してもよいが、返却値は業務層でも項目、長さ、未知キーを再検証する。
- 診断メモは機密性が高いため、API呼び出しでは `store=False` を明示し、会話状態をOpenAI側へ保存する前提にしない。
- 初回の依存関係検証にはOpenAI Python SDK 2.45.0を使用した。`pyproject.toml` では破壊的変更を避けるためメジャーバージョン2へ制限し、更新時はテストでResponses APIの呼び出し形状を再確認する。

参照:

- <https://developers.openai.com/api/docs/guides/latest-model.md>
- <https://developers.openai.com/api/docs/guides/migrate-to-responses>
- <https://developers.openai.com/api/docs/guides/structured-outputs>

### 2.2 CSRF

CSRF対策だけを目的とする外部依存は追加しない。`secrets.token_urlsafe()` でセッションごとのトークンを生成し、POST等の変更リクエストで `hmac.compare_digest()` により照合する。トークンはJinjaの共通関数からhidden項目へ埋め込む。将来JSON APIを追加する場合も同一トークンを専用ヘッダーで要求する。

### 2.3 画像検証

標準ライブラリはPNG、JPEG、WebPの完全なデコード検証を提供しない。先頭シグネチャの自前検査だけでは、途中で切れた画像や破損画像を確実に拒否できない。このためPillowを画像のデコード検証に限って追加する。

検証順序は、サイズ、空ファイル、拡張子、申告MIMEタイプ、ファイルシグネチャ、Pillowの `verify()`、再オープン後の `load()` とする。画像の再エンコードは行わず、原本のバイト列を保持する。

## 3. パッケージと責務

```text
src/vulnnote_manager/
├── presentation/   Flask Blueprint、フォーム変換、テンプレート
├── services/       業務規則、トランザクション単位、出力、AI連携
├── repositories/   sqlite3によるプレースホルダーSQL
├── migrations/     順序付きスキーマ変更
├── templates/      Jinjaテンプレート
├── static/         CSPで許可する自前CSS・JavaScript
├── config.py       環境変数と保存先
└── errors.py       利用者向け例外
```

表示層はSQLやOpenAI SDKを直接呼ばない。サービス層はFlaskのrequest/sessionへ依存しない。リポジトリ層は表示用文字列を作らない。OpenAI SDKは専用サービス内だけで使用し、テストではクライアントを差し替える。

## 4. URLと画面遷移

| 用途 | URLの基本形 |
| --- | --- |
| ホーム | `/` |
| 案件 | `/projects`, `/projects/new`, `/projects/<id>`, `/projects/<id>/edit` |
| 対象 | `/targets`, `/projects/<id>/targets/new`, `/targets/<id>`, `/targets/<id>/edit` |
| メモ | `/notes`, `/targets/<id>/notes/new`, `/notes/<id>`, `/notes/<id>/edit` |
| 画像 | `/screenshots/<id>/content` |
| 出力 | `/notes/<id>/exports/<format>`, `/projects/<id>/exports/<format>` |
| AI校正 | `/notes/<id>/ai-polish`, `/notes/<id>/ai-polish/send`, `/notes/<id>/ai-polish/apply` |
| AI報告書 | `/projects/<id>/ai-report`, `/projects/<id>/ai-report/download` |

変更成功後はPOST-Redirect-GETとし、成功通知はセッションのflashへ保存する。入力不備は同じフォームを422相当で再表示し、項目単位のエラーを関連付ける。競合は409、存在しないデータは404とする。

## 5. データモデルと日時

- 主キーはSQLite `INTEGER PRIMARY KEY` とする。
- Project、Target、VulnerabilityNote、Screenshotは仕様9.1の項目を持つ。
- 列挙値と真偽値にはCHECK制約、親子には外部キーを設定する。階層削除はサービス層でロック確認後に明示トランザクションで行い、外部キーのCASCADEは整合性の最後の防壁として用いる。
- 日時はUTCのISO 8601形式（マイクロ秒付き、末尾 `+00:00`）で保存する。
- 利用者入力の発見日時はブラウザが送るUTCオフセットと合わせてUTCへ変換する。表示はISO日時を持つ `time` 要素を静的JavaScriptでローカル化し、JavaScript無効時はUTCであることを明示する。
- 更新では画面表示時の `updated_at` をWHERE条件へ含め、更新件数0件なら再取得して削除済みまたは競合を判定する。同一時刻更新を避けるため更新値は直前値より必ず大きくする。

## 6. マイグレーション

`PRAGMA user_version` をスキーマバージョンとして使う。各マイグレーションは番号順に `BEGIN IMMEDIATE` からコミットまでを1トランザクションで実行する。失敗時はロールバックして起動を中止し、既存DBを自動削除しない。接続のたびに `PRAGMA foreign_keys = ON` を設定する。

## 7. ファイルとDBの一貫性

アップロードは全ファイルを先に検証し、同一保存先内の一時ファイルへ書き込みと `fsync` を行う。すべてを原子的に最終名へ移動した後、単一DBトランザクションで全行を登録する。移動またはDB処理の失敗時は、そのリクエストで作成した一時ファイルと最終ファイルを補償削除する。

削除は対象ファイルを同一ファイルシステム内の回復用領域へ原子的に移動してからDBを削除する。DB失敗時は元へ戻し、コミット成功後に回復用ファイルを削除する。コミット後の物理削除失敗はデータ参照不能な回復用領域に残し、次回起動時の清掃対象として安全に記録する。ログには元ファイル名やメモ内容を含めない。

## 8. 削除対象とトランザクション

- 単一削除は確認時にID、更新日時、配下件数を提示し、実行時に再取得する。
- 複数選択は画面に表示したIDの署名付き集合を送り、重複を除去して各ルート単位に削除可否を再判定する。削除可能なルートごとにトランザクションを分け、一部成功を許可する。
- 表示中全件削除は確認時の検索条件を許可リストで正規化して署名し、実行時に同条件を再検索する。ページ番号は対象条件に含めない。
- 自身または子孫にロックがあれば、そのルート全体を削除しない。

## 9. 一覧の確定値

- ページサイズは既定25件、許可値は25、50、100件とする。
- 対応状況の意味順は仕様7.4の記載順（未確認、確認済み、報告済み、対応中、修正済み、再診断済み、対象外）とする。
- 案件検索は案件名、顧客名、概要を対象とし、案件名、顧客名、開始日、終了日、更新日時で並べ替える。
- 対象検索は対象名、ベースURL、概要、案件名を対象とし、案件、対象名、ベースURL、更新日時で並べ替える。案件で絞り込める。
- SQLへ渡す並べ替え列と方向はサーバー側の固定辞書から選ぶ。利用者入力を識別子として連結しない。

## 10. 出力形式

Markdownは案件、対象、メモの順に固定見出しを使う。値はMarkdownの制御文字とHTMLをエスケープし、証跡のコードフェンスは本文中の最長バッククォート列より長くする。CSV列は仕様の入力順に階層項目、システム日時、画像識別子を並べる。ファイル名はASCII代替名とUTF-8の `filename*` を併記し、パス要素と制御文字を除く。

ZIPはルート直下にMarkdown、`images/` 以下に推測困難な内部名と安全化した拡張子の画像を置く。ZIPエントリは常にアプリが生成し、利用者入力をパスとして使わない。

## 11. AI確認データ

確認本文やAI結果はSQLite、ログ、セッションCookieへ保存しない。推測困難な一回限りトークンをブラウザへ渡し、本文、対象ID、表示時の更新日時、有効期限はプロセス内メモリだけに最大30分保持する。送信・採用・出力時にトークンを消費し、再利用を拒否する。アプリを終了すると未完了の確認データは破棄される。

## 12. HTTP安全方針

- Jinja自動エスケープを維持し、利用者入力へ `safe` を使わない。
- CSPは `default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'` を既定とする。
- `X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer`、`X-Frame-Options: DENY` を全レスポンスへ付ける。
- インラインCSSとJavaScript、外部CDNは使用しない。

## 13. 実装既定値

| 項目 | 既定値・環境変数 |
| --- | --- |
| ホスト | `VULNNOTE_HOST=127.0.0.1` |
| ポート | `VULNNOTE_PORT=5000` |
| データ領域 | `VULNNOTE_DATA_DIR`、未指定時はOS標準領域 |
| AIモデル | `OPENAI_MODEL=gpt-5.6-terra` |
| AIタイムアウト | `VULNNOTE_AI_TIMEOUT=60` 秒 |
| ページサイズ | `VULNNOTE_PAGE_SIZE=25` |
| 画像上限 | 1ファイル10MiB |
| リクエスト上限 | 50MiB |

OS標準の保存先は次の規則で解決する。

- Windows: `%LOCALAPPDATA%\VulnNote Manager`。未設定時は `%USERPROFILE%\AppData\Local\VulnNote Manager`
- macOS: `~/Library/Application Support/VulnNote Manager`
- Linux: `$XDG_DATA_HOME/vulnnote-manager`。未設定時は `~/.local/share/vulnnote-manager`

保存先配下に `vulnnote.sqlite3`、`uploads/`、`recovery/` を作る。起動時にディレクトリ作成と一時ファイルの作成・削除で書き込み可能性を確認する。
