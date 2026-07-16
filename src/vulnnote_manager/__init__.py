"""VulnNote ManagerのFlaskアプリケーション。"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from flask import Flask

from .config import Settings, load_settings, prepare_data_directories
from .database import init_database
from .errors import register_error_handlers
from .presentation.main import main_blueprint
from .presentation.catalog import catalog_blueprint
from .security import apply_security_headers, init_security


def create_app(
    config_overrides: Mapping[str, Any] | None = None,
    *,
    settings: Settings | None = None,
) -> Flask:
    """設定を注入可能なFlaskアプリケーションを作成する。"""

    resolved = settings or load_settings()
    prepare_data_directories(resolved)

    app = Flask(__name__, instance_path=str(resolved.data_dir), instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=resolved.session_secret,
        MAX_CONTENT_LENGTH=resolved.max_request_bytes,
        DATABASE=str(resolved.database_path),
        UPLOAD_DIR=str(resolved.upload_dir),
        RECOVERY_DIR=str(resolved.recovery_dir),
        OPENAI_MODEL=resolved.openai_model,
        AI_TIMEOUT_SECONDS=resolved.ai_timeout_seconds,
        PAGE_SIZE=resolved.page_size,
        HOST=resolved.host,
        PORT=resolved.port,
        DEBUG=False,
    )
    if config_overrides:
        app.config.from_mapping(config_overrides)

    init_database(app)
    init_security(app)
    app.register_blueprint(main_blueprint)
    app.register_blueprint(catalog_blueprint)
    register_error_handlers(app)
    app.after_request(apply_security_headers)
    return app


__all__ = ["create_app"]
