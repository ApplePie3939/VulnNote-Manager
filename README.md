# VulnNote Manager

VulnNote Managerは、脆弱性診断中の断片的なメモを案件・対象・脆弱性ごとに整理し、診断記録や報告書の下書きへつなげるローカルWebアプリケーションです。

案件・対象・脆弱性メモの管理、検索・削除ロック・画像添付、安全なMarkdown／CSV出力、OpenAI APIを使う文章整理と報告書下書きを利用できます。

## 必要環境

- Python 3.12以上
- Windows、macOS、Linux

## 開発環境の準備

```shell
python -m venv .venv
```

Windows（PowerShell）:

```powershell
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

macOS / Linux:

```shell
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

Debian/Ubuntuで仮想環境を作成できない場合は、先にOSの `python3-venv` パッケージを導入してください。

## 起動

```shell
python -m vulnnote_manager
```

ブラウザで <http://127.0.0.1:5000> を開きます。通常起動ではデバッグモードと自動リローダーは無効です。終了するには起動したターミナルで `Ctrl+C` を押します。

このアプリケーションは1人でのローカル利用専用です。LANやインターネットへ公開しないでください。

## 設定

| 環境変数 | 既定値 | 用途 |
| --- | --- | --- |
| `VULNNOTE_HOST` | `127.0.0.1` | 待受ホスト |
| `VULNNOTE_PORT` | `5000` | 待受ポート |
| `VULNNOTE_DATA_DIR` | OS標準領域 | SQLiteと画像の保存先 |
| `OPENAI_MODEL` | `gpt-5.6-terra` | AI機能で使うモデル |
| `VULNNOTE_AI_TIMEOUT` | `60` | AI通信のタイムアウト秒数 |
| `VULNNOTE_PAGE_SIZE` | `25` | 一覧の表示件数（25、50、100） |

`OPENAI_API_KEY` はAI機能を使う場合だけ環境変数に設定します。APIキーを `.env`、設定ファイル、ソースコード、Gitへ保存しないでください。

AI機能は、送信確認画面に表示されたテキストを利用者が編集・マスキングし、明示的に同意した場合だけOpenAI Responses APIへ送信します。選択外の項目とスクリーンショット画像は送信しません。API呼び出しでは保存を無効化し、送信本文と生成結果をSQLite、ログ、セッションCookieへ保存しません。AI生成結果は自動採用されず、項目ごとの採用または確認後のMarkdown出力が必要です。

既定のデータ保存先は次のとおりです。

- Windows: `%LOCALAPPDATA%\VulnNote Manager`
- macOS: `~/Library/Application Support/VulnNote Manager`
- Linux: `$XDG_DATA_HOME/vulnnote-manager` または `~/.local/share/vulnnote-manager`

保存先を準備できない場合は、権限と空き容量を確認するか、`VULNNOTE_DATA_DIR` を書き込み可能な場所へ変更してください。

## 基本操作と削除時の注意

ホームから案件を登録し、案件詳細で対象、対象詳細で脆弱性メモを登録します。一覧では検索、絞り込み、並べ替え、複数選択削除、検索条件に一致する全件の削除ができます。

削除にゴミ箱や取り消し機能はありません。案件を削除すると配下の対象、メモ、画像も削除されます。残す必要がある案件・対象・メモは削除ロックを有効にしてください。自身または配下にロックがある項目は削除されません。

## バックアップと復元

初版にはアプリ内バックアップ・復元機能がありません。アプリを終了してから、上記データ保存先全体（`vulnnote.sqlite3`、`uploads/`、`recovery/`）を同時に別媒体へコピーしてください。復元時もアプリを終了し、同じ構成をデータ保存先へ戻します。SQLiteファイルだけ、または画像だけを個別にコピーすると不整合になるため避けてください。

## よくある問題

- 起動できない: Python 3.12以上か確認し、データ保存先のパス、書き込み権限、空き容量を確認してください。
- 画像を保存できない: PNG、JPEG、WebPのいずれかで、1ファイル10MB以下か確認してください。拡張子だけを変更した画像や破損画像は保存できません。
- AIを利用できない: `OPENAI_API_KEY` を現在のシェルへ設定してアプリを再起動してください。認証、利用上限、ネットワーク、タイムアウトは画面の案内に従って確認してください。
- 更新が競合した: 別画面で先に更新されています。詳細画面を再読み込みし、最新内容を確認してから編集し直してください。

## テスト

```shell
python -m pytest
```

テストは一時データ領域を使い、通常の利用データを変更しません。

1万件性能試験は次で実行できます。

```shell
python tools/measure_performance.py --count 10000 --runs 20
```

基本設計と依存関係の採用理由は [docs/design.md](docs/design.md) を参照してください。
