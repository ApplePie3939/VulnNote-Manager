# VulnNote Manager

VulnNote Managerは、脆弱性診断中の断片的なメモを案件・対象・脆弱性ごとに整理し、診断記録や報告書の下書きへつなげるローカルWebアプリケーションです。

現在は初版を開発中です。現時点ではアプリケーション基盤と基本画面まで利用できます。

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

`OPENAI_API_KEY` はAI機能を使う場合だけ環境変数に設定します。APIキーを `.env`、設定ファイル、ソースコード、Gitへ保存しないでください。AI機能は未実装のため、現在はAPIへデータを送信しません。

既定のデータ保存先は次のとおりです。

- Windows: `%LOCALAPPDATA%\VulnNote Manager`
- macOS: `~/Library/Application Support/VulnNote Manager`
- Linux: `$XDG_DATA_HOME/vulnnote-manager` または `~/.local/share/vulnnote-manager`

保存先を準備できない場合は、権限と空き容量を確認するか、`VULNNOTE_DATA_DIR` を書き込み可能な場所へ変更してください。

## テスト

```shell
python -m pytest
```

テストは一時データ領域を使い、通常の利用データを変更しません。

基本設計と依存関係の採用理由は [docs/design.md](docs/design.md) を参照してください。
