from __future__ import annotations

import io

from PIL import Image

from vulnnote_manager.database import connect_database, migrate
from vulnnote_manager.repositories import ProjectRepository, TargetRepository, VulnerabilityNoteRepository
from vulnnote_manager.services import assess_delete, make_csv, make_markdown


def _csrf(client) -> str:
    with client.session_transaction() as state:
        return state["csrf_token"]


def _records(settings):
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    db = connect_database(settings.database_path)
    migrate(db)
    project = ProjectRepository(db).create({"name": "=危険案件"})
    target = TargetRepository(db).create({"project_id": project["id"], "name": "対象"})
    note = VulnerabilityNoteRepository(db).create({
        "target_id": target["id"], "title": "# 見出し", "severity": "High",
        "discovered_at": "2026-07-16T00:00:00+00:00", "status": "未確認",
        "evidence": "```\n<script>alert(1)</script>\n```",
    })
    return db, project, target, note


def test_delete_assessment_respects_descendant_lock(settings) -> None:
    db, project, _target, note = _records(settings)
    try:
        VulnerabilityNoteRepository(db).update(note["id"], {"deletion_locked": 1}, expected_updated_at=note["updated_at"])
        result = assess_delete(db, "project", project["id"])
        assert not result.allowed
        assert result.notes == 1
        assert "配下" in (result.reason or "")
    finally:
        db.close()


def test_delete_assessment_covers_self_child_and_unlocked(settings) -> None:
    db, project, target, note = _records(settings)
    try:
        assert assess_delete(db, "project", project["id"]).allowed
        ProjectRepository(db).update(project["id"], {"deletion_locked": 1}, expected_updated_at=project["updated_at"])
        own = assess_delete(db, "project", project["id"])
        assert not own.allowed and "自身" in (own.reason or "")
        current_project = ProjectRepository(db).get(project["id"])
        ProjectRepository(db).update(project["id"], {"deletion_locked": 0}, expected_updated_at=current_project["updated_at"])
        TargetRepository(db).update(target["id"], {"deletion_locked": 1}, expected_updated_at=target["updated_at"])
        child = assess_delete(db, "project", project["id"])
        assert not child.allowed and "配下" in (child.reason or "")
        current_target = TargetRepository(db).get(target["id"])
        TargetRepository(db).update(target["id"], {"deletion_locked": 0}, expected_updated_at=current_target["updated_at"])
        VulnerabilityNoteRepository(db).update(note["id"], {"deletion_locked": 1}, expected_updated_at=note["updated_at"])
        assert not assess_delete(db, "target", target["id"]).allowed
    finally:
        db.close()


def test_exports_escape_injection_and_code_fences(settings) -> None:
    db, _project, _target, note = _records(settings)
    try:
        from vulnnote_manager.services import export_rows
        rows = export_rows(db, note_id=note["id"])
        csv_data = make_csv(rows)
        markdown = make_markdown(rows)
        assert csv_data.startswith(b"\xef\xbb\xbf")
        assert "'=危険案件" in csv_data.decode("utf-8-sig")
        assert "\\# 見出し" in markdown
        assert "````text" in markdown
    finally:
        db.close()


def test_image_upload_delivery_and_delete(client, settings) -> None:
    db, _project, _target, note = _records(settings)
    db.close()
    image = io.BytesIO()
    Image.new("RGB", (2, 2), "red").save(image, "PNG")
    image.seek(0)
    client.get(f"/notes/{note['id']}")
    response = client.post(
        f"/notes/{note['id']}/screenshots",
        data={"csrf_token": _csrf(client), "images": (image, "../../proof.png", "image/png")},
        content_type="multipart/form-data", follow_redirects=True,
    )
    assert response.status_code == 200
    db = connect_database(settings.database_path)
    try:
        shot = db.execute("SELECT * FROM screenshots").fetchone()
        assert shot["original_filename"] == "proof.png"
        shot_id = shot["id"]
    finally:
        db.close()
    delivered = client.get(f"/screenshots/{shot_id}/content")
    assert delivered.status_code == 200
    assert delivered.content_type == "image/png"
    assert delivered.headers["Cache-Control"] == "private, no-store"
    deleted = client.post(f"/screenshots/{shot_id}/delete", data={"csrf_token": _csrf(client)})
    assert deleted.status_code == 302


def test_fake_image_is_rejected(client, settings) -> None:
    db, _project, _target, note = _records(settings)
    db.close()
    client.get(f"/notes/{note['id']}")
    response = client.post(
        f"/notes/{note['id']}/screenshots",
        data={"csrf_token": _csrf(client), "images": (io.BytesIO(b"not png"), "fake.png", "image/png")},
        content_type="multipart/form-data", follow_redirects=True,
    )
    assert "破損" in response.get_data(as_text=True)


def test_note_delete_requires_csrf_and_honors_lock(client, settings) -> None:
    db, _project, _target, note = _records(settings)
    db.close()
    assert client.post(f"/note/{note['id']}/delete").status_code == 400
    client.get(f"/notes/{note['id']}")
    client.post(f"/note/{note['id']}/lock", data={"csrf_token": _csrf(client), "locked": "1"})
    blocked = client.get(f"/note/{note['id']}/delete").get_data(as_text=True)
    assert "自身が削除ロック中" in blocked
