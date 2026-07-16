"""環境変数とユーザーデータ保存先の設定。"""

from __future__ import annotations

import os
import platform
import secrets
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000
DEFAULT_MODEL = "gpt-5.6-terra"
DEFAULT_AI_TIMEOUT_SECONDS = 60.0
DEFAULT_PAGE_SIZE = 25
DEFAULT_MAX_REQUEST_BYTES = 50 * 1024 * 1024
ALLOWED_PAGE_SIZES = frozenset({25, 50, 100})


class ConfigurationError(RuntimeError):
    """利用者が設定または保存先を修正できる起動エラー。"""


@dataclass(frozen=True, slots=True)
class Settings:
    """秘密情報をreprへ含めない、検証済みアプリケーション設定。"""

    host: str
    port: int
    data_dir: Path
    openai_model: str
    ai_timeout_seconds: float
    page_size: int
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES
    session_secret: str = field(default_factory=lambda: secrets.token_urlsafe(32), repr=False)

    @property
    def database_path(self) -> Path:
        return self.data_dir / "vulnnote.sqlite3"

    @property
    def upload_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def recovery_dir(self) -> Path:
        return self.data_dir / "recovery"


def _parse_int(name: str, raw_value: str, *, minimum: int, maximum: int) -> int:
    try:
        value = int(raw_value)
    except ValueError as error:
        raise ConfigurationError(
            f"設定 {name} は整数で指定してください。現在値を確認してください。"
        ) from error
    if not minimum <= value <= maximum:
        raise ConfigurationError(
            f"設定 {name} は {minimum} から {maximum} の範囲で指定してください。"
        )
    return value


def _parse_float(name: str, raw_value: str, *, minimum: float, maximum: float) -> float:
    try:
        value = float(raw_value)
    except ValueError as error:
        raise ConfigurationError(
            f"設定 {name} は数値で指定してください。現在値を確認してください。"
        ) from error
    if not minimum <= value <= maximum:
        raise ConfigurationError(
            f"設定 {name} は {minimum:g} から {maximum:g} の範囲で指定してください。"
        )
    return value


def resolve_default_data_dir(
    *,
    system: str | None = None,
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> Path:
    """OS標準規則に従ってユーザーデータ領域を返す。"""

    env = MappingProxyType(dict(os.environ if environ is None else environ))
    user_home = Path.home() if home is None else home
    current_system = platform.system() if system is None else system

    if current_system == "Windows":
        base = env.get("LOCALAPPDATA")
        if base:
            return Path(base) / "VulnNote Manager"
        profile = Path(env.get("USERPROFILE", str(user_home)))
        return profile / "AppData" / "Local" / "VulnNote Manager"
    if current_system == "Darwin":
        return user_home / "Library" / "Application Support" / "VulnNote Manager"

    xdg_data_home = env.get("XDG_DATA_HOME")
    if xdg_data_home:
        return Path(xdg_data_home) / "vulnnote-manager"
    return user_home / ".local" / "share" / "vulnnote-manager"


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    """すべての変更可能な設定を環境変数から一度だけ読み込む。"""

    env = os.environ if environ is None else environ
    host = env.get("VULNNOTE_HOST", DEFAULT_HOST).strip()
    if not host:
        raise ConfigurationError("設定 VULNNOTE_HOST が空です。待受ホストを指定してください。")

    port = _parse_int(
        "VULNNOTE_PORT", env.get("VULNNOTE_PORT", str(DEFAULT_PORT)), minimum=1, maximum=65535
    )
    timeout = _parse_float(
        "VULNNOTE_AI_TIMEOUT",
        env.get("VULNNOTE_AI_TIMEOUT", str(DEFAULT_AI_TIMEOUT_SECONDS)),
        minimum=1,
        maximum=600,
    )
    page_size = _parse_int(
        "VULNNOTE_PAGE_SIZE",
        env.get("VULNNOTE_PAGE_SIZE", str(DEFAULT_PAGE_SIZE)),
        minimum=min(ALLOWED_PAGE_SIZES),
        maximum=max(ALLOWED_PAGE_SIZES),
    )
    if page_size not in ALLOWED_PAGE_SIZES:
        allowed = "、".join(str(value) for value in sorted(ALLOWED_PAGE_SIZES))
        raise ConfigurationError(f"設定 VULNNOTE_PAGE_SIZE は {allowed} のいずれかを指定してください。")

    raw_data_dir = env.get("VULNNOTE_DATA_DIR", "").strip()
    data_dir = (
        Path(raw_data_dir).expanduser().resolve()
        if raw_data_dir
        else resolve_default_data_dir(environ=env)
    )
    model = env.get("OPENAI_MODEL", DEFAULT_MODEL).strip()
    if not model:
        raise ConfigurationError("設定 OPENAI_MODEL が空です。利用するモデル名を指定してください。")

    return Settings(
        host=host,
        port=port,
        data_dir=data_dir,
        openai_model=model,
        ai_timeout_seconds=timeout,
        page_size=page_size,
    )


def prepare_data_directories(settings: Settings) -> None:
    """保存先を作成し、実際のファイル作成で書き込み可能性を確認する。"""

    for directory in (settings.data_dir, settings.upload_dir, settings.recovery_dir):
        try:
            directory.mkdir(parents=True, exist_ok=True)
            if not directory.is_dir():
                raise NotADirectoryError(directory)
            with tempfile.NamedTemporaryFile(prefix=".write-check-", dir=directory):
                pass
        except OSError as error:
            raise ConfigurationError(
                f"データ保存先を準備できませんでした: {directory}。"
                "保存先のパス、権限、空き容量を確認するか、"
                "VULNNOTE_DATA_DIR を書き込み可能な場所へ変更してください。"
            ) from error


def get_openai_api_key(environ: Mapping[str, str] | None = None) -> str | None:
    """APIキーを永続的な設定オブジェクトへ格納せず環境変数から取得する。"""

    env = os.environ if environ is None else environ
    value = env.get("OPENAI_API_KEY", "").strip()
    return value or None
