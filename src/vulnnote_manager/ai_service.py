"""OpenAI Responses APIを使う文章整理・報告書生成サービス。"""

from __future__ import annotations

import json
import re
import secrets
import time
from dataclasses import dataclass
from threading import Lock
from typing import Any, Callable, Literal

from openai import APIConnectionError, APIStatusError, APITimeoutError, AuthenticationError, OpenAI, RateLimitError

from .config import get_openai_api_key

NOTE_AI_FIELDS = ("summary", "reproduction_steps", "evidence", "impact", "remediation")
FIELD_LABELS = {
    "summary": "概要", "reproduction_steps": "再現手順", "evidence": "リクエスト・レスポンス",
    "impact": "影響", "remediation": "対策方法",
}


class AIServiceError(RuntimeError):
    """秘密情報やSDK内部情報を含まないAI利用者向けエラー。"""


@dataclass(frozen=True, slots=True)
class SecretWarning:
    field: str
    label: str
    kind: str


_SECRET_PATTERNS = (
    ("APIキーらしい文字列", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|(?:api[_-]?key)\s*[:=]\s*\S+)", re.I)),
    ("Authorizationヘッダー", re.compile(r"(?im)^\s*Authorization\s*:\s*\S+")),
    ("Cookieヘッダー", re.compile(r"(?im)^\s*(?:Cookie|Set-Cookie)\s*:\s*\S+")),
)


def detect_secret_warnings(fields: dict[str, str]) -> list[SecretWarning]:
    """断定せず、機密情報の可能性がある項目と種類を返す。"""

    warnings: list[SecretWarning] = []
    for field, value in fields.items():
        for kind, pattern in _SECRET_PATTERNS:
            if pattern.search(value):
                warnings.append(SecretWarning(field, FIELD_LABELS.get(field, field), kind))
    return warnings


class TemporaryAIState:
    """AI本文をCookieやDBへ保存しない短時間・一回限りの状態管理。"""

    def __init__(self, ttl_seconds: int = 1800) -> None:
        self.ttl_seconds = ttl_seconds
        self._items: dict[str, tuple[float, dict[str, Any]]] = {}
        self._lock = Lock()

    def put(self, value: dict[str, Any]) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._purge()
            self._items[token] = (time.monotonic() + self.ttl_seconds, value)
        return token

    def pop(self, token: str) -> dict[str, Any]:
        with self._lock:
            self._purge()
            item = self._items.pop(token, None)
        if item is None:
            raise AIServiceError("AI処理の確認期限が切れました。元の画面からやり直してください。")
        return item[1]

    def _purge(self) -> None:
        now = time.monotonic()
        for token, (expires, _value) in list(self._items.items()):
            if expires <= now:
                self._items.pop(token, None)


temporary_ai_state = TemporaryAIState()


def _client(api_key: str, timeout: float, factory: Callable[..., Any] | None) -> Any:
    return factory(api_key=api_key, timeout=timeout) if factory else OpenAI(api_key=api_key, timeout=timeout)


def _call(client: Any, **kwargs: Any) -> Any:
    try:
        return client.responses.create(**kwargs)
    except AuthenticationError as error:
        raise AIServiceError("OpenAI APIの認証に失敗しました。OPENAI_API_KEYを確認してください。") from error
    except RateLimitError as error:
        raise AIServiceError("OpenAI APIの利用上限に達しました。時間をおいて再実行してください。") from error
    except APITimeoutError as error:
        raise AIServiceError("OpenAI APIが時間内に応答しませんでした。通信状態を確認して再実行してください。") from error
    except APIConnectionError as error:
        raise AIServiceError("OpenAI APIへ接続できませんでした。通信状態を確認してください。") from error
    except APIStatusError as error:
        raise AIServiceError("OpenAI APIで処理に失敗しました。時間をおいて再実行してください。") from error


def polish_note(
    fields: dict[str, str], *, model: str, timeout: float,
    client_factory: Callable[..., Any] | None = None,
) -> dict[str, str]:
    """確認済みの項目だけを送信し、同じキーの校正結果を返す。"""

    api_key = get_openai_api_key()
    if not api_key:
        raise AIServiceError("AI機能を使うには、環境変数 OPENAI_API_KEY を設定してアプリを再起動してください。")
    properties = {key: {"type": "string", "maxLength": 100000} for key in fields}
    schema = {"type": "object", "properties": properties, "required": list(fields), "additionalProperties": False}
    response = _call(
        _client(api_key, timeout, client_factory), model=model, store=False, max_output_tokens=8000,
        input=[
            {"role": "system", "content": "脆弱性診断メモを日本語で整理・校正してください。原文にない事実を創作せず、不明点は『要確認』と明示し、技術的証跡の値を変更しないでください。指定された各項目だけをJSONで返してください。"},
            {"role": "user", "content": json.dumps(fields, ensure_ascii=False)},
        ],
        text={"format": {"type": "json_schema", "name": "polished_note", "strict": True, "schema": schema}},
    )
    try:
        parsed = json.loads(response.output_text)
    except (AttributeError, TypeError, json.JSONDecodeError) as error:
        raise AIServiceError("AIの応答を解釈できませんでした。元データは変更されていません。") from error
    if set(parsed) != set(fields) or any(not isinstance(value, str) or len(value) > 100000 for value in parsed.values()):
        raise AIServiceError("AIの応答形式が想定と異なります。元データは変更されていません。")
    return parsed


def draft_report(
    source: str, *, model: str, timeout: float,
    client_factory: Callable[..., Any] | None = None,
) -> str:
    """確認済みテキストだけから、保存しないMarkdown下書きを生成する。"""

    api_key = get_openai_api_key()
    if not api_key:
        raise AIServiceError("AI機能を使うには、環境変数 OPENAI_API_KEY を設定してアプリを再起動してください。")
    response = _call(
        _client(api_key, timeout, client_factory), model=model, store=False, max_output_tokens=16000,
        input=[
            {"role": "system", "content": "入力された確認済み情報だけから日本語の診断報告書下書きをMarkdownで作成してください。案件概要、対象、脆弱性一覧、各脆弱性の概要、再現手順、影響、対策、未確認事項を含めます。情報不足は『未記入』または『要確認』とし、事実を補完しないでください。画像は入力されていません。"},
            {"role": "user", "content": source},
        ],
    )
    text = getattr(response, "output_text", None)
    if not isinstance(text, str) or not text.strip() or len(text) > 500000:
        raise AIServiceError("AIの応答を解釈できませんでした。元データは変更されていません。")
    return text
