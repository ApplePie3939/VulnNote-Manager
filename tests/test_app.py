from __future__ import annotations

import logging

from vulnnote_manager.database import connect_database
from vulnnote_manager.repositories import ProjectRepository, TargetRepository, VulnerabilityNoteRepository


def test_home_page_starts_with_safe_defaults(client) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "VulnNote Manager" in response.get_data(as_text=True)
    assert "ローカル専用" in response.get_data(as_text=True)


def test_security_headers_are_added_to_every_response(client) -> None:
    response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["X-Frame-Options"] == "DENY"
    csp = response.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp


def test_not_found_page_explains_state_and_next_action(client) -> None:
    response = client.get("/does-not-exist")
    body = response.get_data(as_text=True)
    assert response.status_code == 404
    assert "ページが見つかりません" in body
    assert "保存状態" in body
    assert "次の対処" in body


def test_request_too_large_is_safe(client, app) -> None:
    app.config["MAX_CONTENT_LENGTH"] = 8
    response = client.post("/_test/read-body", data="long request body")
    assert response.status_code == 413
    assert "送信サイズが上限を超えています" in response.get_data(as_text=True)


def test_unexpected_error_does_not_log_exception_message(client, caplog) -> None:
    with caplog.at_level(logging.ERROR):
        response = client.get("/_test/unexpected")
    combined_logs = "\n".join(record.getMessage() for record in caplog.records)
    assert response.status_code == 500
    assert "予期しないエラー" in response.get_data(as_text=True)
    assert "RuntimeError" in combined_logs
    assert "should-not-be-logged" not in combined_logs
    assert "メモ本文" not in combined_logs


def test_config_injection_uses_temporary_data_paths(app, settings) -> None:
    assert app.config["DATABASE"] == str(settings.database_path)
    assert app.config["UPLOAD_DIR"] == str(settings.upload_dir)
    assert app.config["TESTING"] is True
    assert app.config["DEBUG"] is False


def test_home_shows_recent_items_counts_and_empty_guidance(client, settings) -> None:
    empty = client.get("/").get_data(as_text=True)
    assert "最初の案件を登録" in empty
    db = connect_database(settings.database_path)
    project = ProjectRepository(db).create({"name": "最近の案件"})
    target = TargetRepository(db).create({"project_id": project["id"], "name": "対象"})
    VulnerabilityNoteRepository(db).create({
        "target_id": target["id"], "title": "最近のメモ", "severity": "Critical",
        "discovered_at": "2026-07-16T00:00:00+00:00", "status": "未確認",
    })
    db.close()
    body = client.get("/").get_data(as_text=True)
    assert "最近の案件" in body and "最近のメモ" in body
    assert "Critical" in body and "未確認" in body
