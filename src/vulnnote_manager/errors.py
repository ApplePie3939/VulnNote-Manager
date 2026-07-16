"""利用者向けHTTPエラー表示。"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass

from flask import Flask, render_template
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ErrorPresentation:
    title: str
    what_happened: str
    save_state: str
    next_action: str


ERROR_PRESENTATIONS = {
    400: ErrorPresentation(
        "リクエストを処理できません",
        "送信内容が正しくないか、必要な情報が不足しています。",
        "この操作による変更は保存されていません。",
        "入力内容を確認して、もう一度操作してください。",
    ),
    404: ErrorPresentation(
        "ページが見つかりません",
        "指定されたページまたはデータは存在しません。",
        "データは変更されていません。",
        "URLを確認するか、一覧画面へ戻って最新の状態を確認してください。",
    ),
    409: ErrorPresentation(
        "更新が競合しました",
        "表示後に同じデータが更新または削除されました。",
        "入力した変更は上書き保存されていません。",
        "最新の内容を開き直し、変更内容を確認してから再度編集してください。",
    ),
    413: ErrorPresentation(
        "送信サイズが上限を超えています",
        "アップロードを含むリクエスト全体が許可サイズを超えました。",
        "送信されたデータは保存されていません。",
        "ファイルの数またはサイズを減らして、もう一度送信してください。",
    ),
    500: ErrorPresentation(
        "予期しないエラーが発生しました",
        "アプリケーション内部で処理を続けられない問題が発生しました。",
        "この画面を表示した操作が保存されたとは判断しないでください。",
        "前の画面へ戻って状態を確認してください。繰り返す場合はアプリを再起動してください。",
    ),
}


def _render_error(status_code: int, *, incident_id: str | None = None) -> tuple[str, int]:
    presentation = ERROR_PRESENTATIONS.get(status_code, ERROR_PRESENTATIONS[500])
    return (
        render_template(
            "errors/error.html",
            status_code=status_code,
            error=presentation,
            incident_id=incident_id,
        ),
        status_code,
    )


def register_error_handlers(app: Flask) -> None:
    """秘密情報を表示・記録しない共通エラーハンドラーを登録する。"""

    for status_code in (400, 404, 409):
        app.register_error_handler(status_code, lambda _error, code=status_code: _render_error(code))

    @app.errorhandler(RequestEntityTooLarge)
    def handle_request_too_large(_error: RequestEntityTooLarge) -> tuple[str, int]:
        return _render_error(413)

    @app.errorhandler(Exception)
    def handle_unexpected_error(error: Exception) -> tuple[str, int]:
        if isinstance(error, HTTPException):
            return _render_error(error.code or 500)
        incident_id = secrets.token_hex(6)
        # 例外メッセージやリクエスト内容は診断メモ・秘密情報を含み得るため記録しない。
        logger.error(
            "未処理の例外を安全に捕捉しました incident_id=%s exception_type=%s",
            incident_id,
            type(error).__name__,
        )
        return _render_error(500, incident_id=incident_id)
