from __future__ import annotations

from vulnnote_manager.database import connect_database


def _csrf(client) -> str:
    with client.session_transaction() as state:
        return state["csrf_token"]


def _create_project(client, name: str = "診断案件") -> int:
    client.get("/projects/new")
    response = client.post(
        "/projects/new", data={"csrf_token": _csrf(client), "name": name}, follow_redirects=False
    )
    assert response.status_code == 302
    return int(response.headers["Location"].rstrip("/").split("/")[-1])


def _create_target(client, project_id: int) -> int:
    client.get(f"/projects/{project_id}/targets/new")
    response = client.post(
        f"/projects/{project_id}/targets/new",
        data={"csrf_token": _csrf(client), "name": "Webアプリ", "base_url": "https://example.test"},
    )
    assert response.status_code == 302
    return int(response.headers["Location"].rstrip("/").split("/")[-1])


def _create_note(client, target_id: int, *, title: str = "XSS") -> int:
    client.get(f"/targets/{target_id}/notes/new")
    response = client.post(
        f"/targets/{target_id}/notes/new",
        data={
            "csrf_token": _csrf(client), "title": title, "severity": "High", "status": "未確認",
            "discovered_at": "2026-07-16T12:00", "timezone_offset": "-540",
            "evidence": "GET /?q=<script>alert(1)</script>",
        },
    )
    assert response.status_code == 302
    return int(response.headers["Location"].rstrip("/").split("/")[-1])


def test_project_crud_validation_and_conflict(client, settings) -> None:
    client.get("/projects/new")
    invalid = client.post("/projects/new", data={"csrf_token": _csrf(client), "name": "   "})
    assert invalid.status_code == 422
    assert "空白以外の文字" in invalid.get_data(as_text=True)

    project_id = _create_project(client)
    detail = client.get(f"/projects/{project_id}")
    assert "診断案件" in detail.get_data(as_text=True)

    db = connect_database(settings.database_path)
    try:
        current = db.execute("SELECT updated_at FROM projects WHERE id=?", (project_id,)).fetchone()[0]
    finally:
        db.close()
    client.get(f"/projects/{project_id}/edit")
    updated = client.post(
        f"/projects/{project_id}/edit",
        data={"csrf_token": _csrf(client), "name": "更新案件", "updated_at": current},
    )
    assert updated.status_code == 302
    conflict = client.post(
        f"/projects/{project_id}/edit",
        data={"csrf_token": _csrf(client), "name": "古い更新", "updated_at": current},
    )
    assert conflict.status_code == 409
    assert "最新の内容" in conflict.get_data(as_text=True)


def test_three_level_crud_and_html_is_escaped(client) -> None:
    project_id = _create_project(client)
    target_id = _create_target(client, project_id)
    note_id = _create_note(client, target_id, title="<script>alert('title')</script>")

    target_detail = client.get(f"/targets/{target_id}").get_data(as_text=True)
    assert "Webアプリ" in target_detail
    note_detail = client.get(f"/notes/{note_id}").get_data(as_text=True)
    assert "<script>alert" not in note_detail
    assert "&lt;script&gt;alert" in note_detail
    assert "GET /?q=&lt;script&gt;alert(1)&lt;/script&gt;" in note_detail


def test_unknown_parent_ids_are_rejected(client) -> None:
    assert client.get("/projects/999/targets/new").status_code == 404
    assert client.get("/targets/999/notes/new").status_code == 404


def test_invalid_url_is_saved_with_visible_warning(client) -> None:
    project_id = _create_project(client)
    client.get(f"/projects/{project_id}/targets/new")
    response = client.post(
        f"/projects/{project_id}/targets/new",
        data={"csrf_token": _csrf(client), "name": "警告対象", "base_url": "not-a-url"},
        follow_redirects=True,
    )
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "完全なURLではありません" in body
    assert "not-a-url" in body


def test_new_note_defaults_to_unconfirmed(client) -> None:
    target_id = _create_target(client, _create_project(client))
    page = client.get(f"/targets/{target_id}/notes/new").get_data(as_text=True)
    assert '<option value="未確認" selected>' in page
