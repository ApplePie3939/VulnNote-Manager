"""共通HTTPレスポンスの安全化。"""

from __future__ import annotations

import hmac
import secrets

from flask import Flask, Response, abort, request, session

CSP_POLICY = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "style-src 'self'; "
    "script-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)


def apply_security_headers(response: Response) -> Response:
    """全レスポンスへブラウザ向け防御ヘッダーを付与する。"""

    response.headers["Content-Security-Policy"] = CSP_POLICY
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    return response


def get_csrf_token() -> str:
    """セッション単位で固定した推測困難なCSRFトークンを返す。"""

    token = session.get("csrf_token")
    if not isinstance(token, str) or len(token) < 32:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def validate_csrf_token() -> None:
    """状態変更リクエストのフォームまたは専用ヘッダーを検証する。"""

    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return
    expected = session.get("csrf_token")
    supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not isinstance(expected, str) or not isinstance(supplied, str):
        abort(400)
    if not hmac.compare_digest(expected, supplied):
        abort(400)


def init_security(app: Flask) -> None:
    """CSRF検証とテンプレート用トークン関数を登録する。"""

    app.before_request(validate_csrf_token)
    app.jinja_env.globals["csrf_token"] = get_csrf_token
