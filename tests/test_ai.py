from __future__ import annotations

import json
import logging
import re
from types import SimpleNamespace

import pytest

from vulnnote_manager.ai_service import AIServiceError, detect_secret_warnings, draft_report, polish_note, temporary_ai_state
from vulnnote_manager.database import connect_database, migrate
from vulnnote_manager.repositories import ProjectRepository, TargetRepository, VulnerabilityNoteRepository


class FakeResponses:
    def __init__(self) -> None:
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if kwargs.get("text"):
            source = json.loads(kwargs["input"][1]["content"])
            return SimpleNamespace(output_text=json.dumps({key: value + "（整理済み）" for key, value in source.items()}, ensure_ascii=False))
        return SimpleNamespace(output_text="# 診断報告書\n\n## 未確認事項\n\n要確認")


class FakeClient:
    def __init__(self, responses: FakeResponses) -> None:
        self.responses = responses


def _records(settings):
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    db = connect_database(settings.database_path)
    migrate(db)
    project = ProjectRepository(db).create({"name": "AI案件"})
    target = TargetRepository(db).create({"project_id": project["id"], "name": "対象"})
    note = VulnerabilityNoteRepository(db).create({
        "target_id": target["id"], "title": "メモ", "severity": "High",
        "discovered_at": "2026-07-16T00:00:00+00:00", "status": "未確認",
        "summary": "原文",
    })
    return db, project, note


def _csrf(client) -> str:
    with client.session_transaction() as state:
        return state["csrf_token"]


def _state_token(html: str) -> str:
    match = re.search(r'name="state_token" value="([^"]+)"', html)
    assert match
    return match.group(1)


def test_secret_detection_is_a_possibility_warning() -> None:
    warnings = detect_secret_warnings({"evidence": "Authorization: Bearer secret\nCookie: sid=abc"})
    assert {item.kind for item in warnings} == {"Authorizationヘッダー", "Cookieヘッダー"}


def test_secret_detection_handles_case_multiline_and_empty_headers() -> None:
    warnings = detect_secret_warnings({
        "evidence": "authorization: bearer abc\nCOOKIE: sid=xyz\nAuthorization:\nCookie:",
        "summary": "api_key = value123",
    })
    assert {item.kind for item in warnings} == {"Authorizationヘッダー", "Cookieヘッダー", "APIキーらしい文字列"}


def test_ai_services_use_responses_store_false_and_validate(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    responses = FakeResponses()
    factory = lambda **_kwargs: FakeClient(responses)
    result = polish_note({"summary": "原文"}, model="test-model", timeout=2, client_factory=factory)
    report = draft_report("案件情報", model="test-model", timeout=2, client_factory=factory)
    assert result == {"summary": "原文（整理済み）"}
    assert report.startswith("# 診断報告書")
    assert all(call["store"] is False for call in responses.calls)
    assert responses.calls[0]["text"]["format"]["strict"] is True


def test_ai_service_rejects_unexpected_response_without_changing_data(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    broken = SimpleNamespace(responses=SimpleNamespace(create=lambda **_kwargs: SimpleNamespace(output_text="{}")))
    with pytest.raises(AIServiceError, match="応答形式"):
        polish_note({"summary": "原文"}, model="test-model", timeout=2, client_factory=lambda **_kwargs: broken)
    empty = SimpleNamespace(responses=SimpleNamespace(create=lambda **_kwargs: SimpleNamespace(output_text="")))
    with pytest.raises(AIServiceError, match="解釈"):
        draft_report("案件", model="test-model", timeout=2, client_factory=lambda **_kwargs: empty)


def test_note_ai_flow_applies_only_selected_field(client, settings, monkeypatch) -> None:
    db, _project, note = _records(settings)
    db.close()
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    responses = FakeResponses()
    client.application.config["OPENAI_CLIENT_FACTORY"] = lambda **_kwargs: FakeClient(responses)
    client.get(f"/notes/{note['id']}")
    confirm = client.post(
        f"/notes/{note['id']}/ai-polish",
        data={"csrf_token": _csrf(client), "field": "summary"},
    )
    token = _state_token(confirm.get_data(as_text=True))
    assert client.post(
        f"/notes/{note['id']}/ai-polish/send",
        data={"csrf_token": _csrf(client), "state_token": token, "summary": "編集した原文"},
    ).status_code == 400
    confirm = client.post(
        f"/notes/{note['id']}/ai-polish",
        data={"csrf_token": _csrf(client), "field": "summary"},
    )
    result = client.post(
        f"/notes/{note['id']}/ai-polish/send",
        data={"csrf_token": _csrf(client), "state_token": _state_token(confirm.get_data(as_text=True)), "summary": "編集した原文", "agreed": "1"},
    )
    result_token = _state_token(result.get_data(as_text=True))
    applied = client.post(
        f"/notes/{note['id']}/ai-polish/apply",
        data={"csrf_token": _csrf(client), "state_token": result_token, "field": "summary"},
    )
    assert applied.status_code == 302
    db = connect_database(settings.database_path)
    try:
        assert VulnerabilityNoteRepository(db).get(note["id"])["summary"] == "編集した原文（整理済み）"
    finally:
        db.close()


def test_report_flow_outputs_edited_markdown_without_changing_project(client, settings, monkeypatch) -> None:
    db, project, _note = _records(settings)
    before = dict(ProjectRepository(db).get(project["id"]))
    db.close()
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    responses = FakeResponses()
    client.application.config["OPENAI_CLIENT_FACTORY"] = lambda **_kwargs: FakeClient(responses)
    client.get(f"/projects/{project['id']}/ai-report")
    result = client.post(
        f"/projects/{project['id']}/ai-report",
        data={"csrf_token": _csrf(client), "agreed": "1", "source": "確認済み案件情報"},
    )
    token = _state_token(result.get_data(as_text=True))
    download = client.post(
        f"/projects/{project['id']}/ai-report/download",
        data={"csrf_token": _csrf(client), "state_token": token, "draft": "# 編集後\n\n要確認"},
    )
    assert download.status_code == 200
    assert download.get_data(as_text=True).startswith("# 編集後")
    db = connect_database(settings.database_path)
    try:
        assert dict(ProjectRepository(db).get(project["id"])) == before
    finally:
        db.close()


def test_report_can_start_from_selected_notes_only(client, settings) -> None:
    db, project, first = _records(settings)
    target_id = first["target_id"]
    second = VulnerabilityNoteRepository(db).create({
        "target_id": target_id, "title": "除外するメモ", "severity": "Low",
        "discovered_at": "2026-07-16T00:00:00+00:00", "status": "未確認",
    })
    db.close()
    client.get(f"/projects/{project['id']}/ai-report")
    confirmation = client.post(
        f"/projects/{project['id']}/ai-report",
        data={"csrf_token": _csrf(client), "stage": "confirm", "scope": "selected", "note_id": str(first["id"])},
    ).get_data(as_text=True)
    assert "メモ" in confirmation
    assert second["title"] not in confirmation


def test_empty_project_report_marks_missing_notes(client, settings) -> None:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    db = connect_database(settings.database_path)
    from vulnnote_manager.database import migrate
    migrate(db)
    project = ProjectRepository(db).create({"name": "空案件"})
    db.close()
    page = client.get(f"/projects/{project['id']}/ai-report").get_data(as_text=True)
    assert "脆弱性メモがありません" in page
    confirmation = client.post(
        f"/projects/{project['id']}/ai-report",
        data={"csrf_token": _csrf(client), "stage": "confirm", "scope": "all"},
    ).get_data(as_text=True)
    assert "脆弱性メモ: 未記入" in confirmation


def test_ai_all_rejected_and_conflict_leave_latest_note_unchanged(client, settings) -> None:
    db, _project, note = _records(settings)
    db.close()
    client.get(f"/notes/{note['id']}")
    rejected_token = temporary_ai_state.put({
        "kind": "note-result", "note_id": note["id"], "updated_at": note["updated_at"],
        "original": {"summary": "原文"}, "generated": {"summary": "生成結果"},
    })
    response = client.post(
        f"/notes/{note['id']}/ai-polish/apply",
        data={"csrf_token": _csrf(client), "state_token": rejected_token},
    )
    assert response.status_code == 302
    db = connect_database(settings.database_path)
    current = VulnerabilityNoteRepository(db).get(note["id"])
    assert current["summary"] == "原文"
    latest = VulnerabilityNoteRepository(db).update(
        note["id"], {"summary": "別画面の更新"}, expected_updated_at=current["updated_at"]
    )
    db.close()
    conflict_token = temporary_ai_state.put({
        "kind": "note-result", "note_id": note["id"], "updated_at": note["updated_at"],
        "original": {"summary": "原文"}, "generated": {"summary": "生成結果"},
    })
    conflict = client.post(
        f"/notes/{note['id']}/ai-polish/apply",
        data={"csrf_token": _csrf(client), "state_token": conflict_token, "field": "summary"},
    )
    assert conflict.status_code == 409
    db = connect_database(settings.database_path)
    try:
        assert VulnerabilityNoteRepository(db).get(note["id"])["summary"] == latest["summary"]
    finally:
        db.close()


def test_ai_failure_does_not_persist_or_log_sent_and_generated_text(client, settings, monkeypatch, caplog) -> None:
    db, _project, note = _records(settings)
    db.close()
    monkeypatch.setenv("OPENAI_API_KEY", "SECRET_API_KEY_X")
    broken = SimpleNamespace(responses=SimpleNamespace(create=lambda **_kwargs: SimpleNamespace(output_text="{}")))
    client.application.config["OPENAI_CLIENT_FACTORY"] = lambda **_kwargs: broken
    client.get(f"/notes/{note['id']}")
    confirm = client.post(
        f"/notes/{note['id']}/ai-polish",
        data={"csrf_token": _csrf(client), "field": "summary"},
    )
    with caplog.at_level(logging.ERROR):
        response = client.post(
            f"/notes/{note['id']}/ai-polish/send",
            data={
                "csrf_token": _csrf(client), "state_token": _state_token(confirm.get_data(as_text=True)),
                "summary": "SENSITIVE_SENT_BODY", "agreed": "1",
            },
            follow_redirects=True,
        )
    assert "応答形式" in response.get_data(as_text=True)
    logs = "\n".join(record.getMessage() for record in caplog.records)
    assert "SENSITIVE_SENT_BODY" not in logs
    assert "SECRET_API_KEY_X" not in logs
    db = connect_database(settings.database_path)
    try:
        assert VulnerabilityNoteRepository(db).get(note["id"])["summary"] == "原文"
        assert not db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'ai_%'").fetchall()
    finally:
        db.close()
    database_bytes = settings.database_path.read_bytes()
    assert b"SENSITIVE_SENT_BODY" not in database_bytes
    assert b"SECRET_API_KEY_X" not in database_bytes
