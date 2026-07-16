from __future__ import annotations

from pathlib import Path

import pytest
from flask import request

from vulnnote_manager import create_app
from vulnnote_manager.config import Settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        host="127.0.0.1",
        port=5000,
        data_dir=tmp_path / "data",
        openai_model="test-model",
        ai_timeout_seconds=2.0,
        page_size=25,
        session_secret="test-session-secret",
    )


@pytest.fixture
def app(settings: Settings):
    application = create_app({"TESTING": True}, settings=settings)

    @application.get("/_test/unexpected")
    def unexpected_error() -> str:
        raise RuntimeError("OPENAI_API_KEY=should-not-be-logged メモ本文")

    @application.post("/_test/read-body")
    def read_body() -> str:
        return request.get_data(as_text=True)

    return application


@pytest.fixture
def client(app):
    return app.test_client()
