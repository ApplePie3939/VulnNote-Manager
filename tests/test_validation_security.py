from __future__ import annotations

import pytest
from flask import request

from vulnnote_manager.validation import (
    parse_local_datetime,
    validate_note,
    validate_project,
    validate_target,
    vulnerability_type_options,
)


def test_project_validation_trims_values_and_checks_date_order() -> None:
    result = validate_project(
        {"name": "  案件A  ", "client_name": "   ", "start_date": "2026-07-16", "end_date": "2026-07-15"}
    )
    assert result.values["name"] == "案件A"
    assert result.values["client_name"] is None
    assert "end_date" in result.errors


@pytest.mark.parametrize("name", [None, "", "   "])
def test_required_whitespace_is_rejected(name) -> None:
    assert "name" in validate_project({"name": name}).errors


def test_target_url_is_warning_not_error() -> None:
    result = validate_target({"project_id": "1", "name": "対象", "base_url": "example.test/path"})
    assert result.is_valid
    assert "base_url" in result.warnings
    assert result.values["base_url"] == "example.test/path"


def test_note_enums_datetime_and_default_status() -> None:
    result = validate_note(
        {
            "target_id": "2", "title": "XSS", "severity": "High",
            "discovered_at": "2026-07-16T12:30", "timezone_offset": "-540",
        }
    )
    assert result.is_valid
    assert result.values["status"] == "未確認"
    assert result.values["discovered_at"] == "2026-07-16T03:30:00.000000+00:00"

    invalid = validate_note(
        {
            "target_id": "2", "title": "XSS", "severity": "極高", "status": "完了",
            "discovered_at": "invalid", "timezone_offset": "0",
        }
    )
    assert {"severity", "status", "discovered_at"} <= invalid.errors.keys()


def test_datetime_accepts_timezone_aware_input() -> None:
    value, error = parse_local_datetime("2026-07-16T12:00:00+09:00", "ignored")
    assert error is None
    assert value == "2026-07-16T03:00:00.000000+00:00"


def test_vulnerability_options_remove_exact_trimmed_duplicates() -> None:
    options = vulnerability_type_options([" SQLインジェクション ", "独自分類", "独自分類", None])
    assert options.count("SQLインジェクション") == 1
    assert options.count("独自分類") == 1


def test_csrf_rejects_missing_and_mismatched_token(app, client) -> None:
    @app.post("/_test/change")
    def change() -> str:
        return request.form.get("value", "")

    assert client.post("/_test/change", data={"value": "x"}).status_code == 400
    with client.session_transaction() as state:
        state["csrf_token"] = "a" * 32
    assert client.post(
        "/_test/change", data={"value": "x", "csrf_token": "b" * 32}
    ).status_code == 400


def test_csrf_accepts_valid_reusable_session_token(app, client) -> None:
    @app.post("/_test/valid-change")
    def valid_change() -> str:
        return "保存しました"

    with client.session_transaction() as state:
        state["csrf_token"] = "token-value-that-is-long-enough-123"
    for _ in range(2):
        response = client.post(
            "/_test/valid-change", data={"csrf_token": "token-value-that-is-long-enough-123"}
        )
        assert response.status_code == 200
