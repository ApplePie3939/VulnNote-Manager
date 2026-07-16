from __future__ import annotations

import io
import errno
import re
import zipfile
from pathlib import Path

import pytest
from PIL import Image
from werkzeug.datastructures import FileStorage

from vulnnote_manager.database import connect_database, migrate
from vulnnote_manager.repositories import ProjectRepository, TargetRepository, VulnerabilityNoteRepository
from vulnnote_manager.services import delete_entities, delete_entity, delete_screenshot, export_rows, make_csv, make_markdown_zip, reorder_screenshots, save_screenshots, update_screenshot


def _records(settings, *, count=2):
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    db = connect_database(settings.database_path)
    migrate(db)
    project = ProjectRepository(db).create({"name": "案件"})
    target = TargetRepository(db).create({"project_id": project["id"], "name": "対象"})
    notes = [VulnerabilityNoteRepository(db).create({
        "target_id": target["id"], "title": f"メモ{index}", "severity": "High",
        "discovered_at": "2026-07-16T00:00:00+00:00", "status": "未確認",
    }) for index in range(count)]
    return db, project, target, notes


def _csrf(client) -> str:
    with client.session_transaction() as state:
        return state["csrf_token"]


def _hidden(html: str, name: str) -> str:
    match = re.search(rf'name="{name}" value="([^"]+)"', html)
    assert match
    return match.group(1)


def _png_upload(filename: str = "proof.png") -> FileStorage:
    data = io.BytesIO()
    Image.new("RGB", (2, 2), "red").save(data, "PNG")
    data.seek(0)
    return FileStorage(stream=data, filename=filename, content_type="image/png")


def test_bulk_delete_deletes_unlocked_and_retains_locked(client, settings) -> None:
    db, _project, _target, notes = _records(settings)
    VulnerabilityNoteRepository(db).update(notes[1]["id"], {"deletion_locked": 1}, expected_updated_at=notes[1]["updated_at"])
    db.close()
    listing = client.get("/notes")
    scope = _hidden(listing.get_data(as_text=True), "selection_scope")
    data = {"csrf_token": _csrf(client), "selection_scope": scope, "selected_id": [str(note["id"]) for note in notes]}
    confirmation = client.post("/note/bulk-delete", data=data)
    assert "削除可能" in confirmation.get_data(as_text=True)
    data["confirmed"] = "1"
    client.post("/note/bulk-delete", data=data)
    db = connect_database(settings.database_path)
    try:
        assert VulnerabilityNoteRepository(db).get(notes[0]["id"]) is None
        assert VulnerabilityNoteRepository(db).get(notes[1]["id"]) is not None
    finally:
        db.close()


def test_filtered_delete_reextracts_matching_rows(client, settings) -> None:
    db, _project, _target, notes = _records(settings)
    db.close()
    listing = client.get("/notes?q=%E3%83%A1%E3%83%A20")
    scope = _hidden(listing.get_data(as_text=True), "filter_scope")
    data = {"csrf_token": _csrf(client), "filter_scope": scope}
    confirmation = client.post("/note/filtered-delete", data=data)
    assert "全1件" in confirmation.get_data(as_text=True)
    data["confirmed"] = "1"
    client.post("/note/filtered-delete", data=data)
    db = connect_database(settings.database_path)
    try:
        assert VulnerabilityNoteRepository(db).get(notes[0]["id"]) is None
        assert VulnerabilityNoteRepository(db).get(notes[1]["id"]) is not None
    finally:
        db.close()


@pytest.mark.parametrize("entity", ["project", "target", "note"])
def test_filtered_delete_all_hierarchies_crosses_pages_and_keeps_locked(client, settings, entity) -> None:
    client.application.config["PAGE_SIZE"] = 1
    db, project, target, notes = _records(settings, count=2)
    if entity == "project":
        second = ProjectRepository(db).create({"name": "案件"})
        ProjectRepository(db).update(second["id"], {"deletion_locked": 1}, expected_updated_at=second["updated_at"])
        list_url = "/projects?q=案件"
        endpoint = "/project/filtered-delete"
        expected_remaining = ("projects", second["id"])
    elif entity == "target":
        second = TargetRepository(db).create({"project_id": project["id"], "name": "対象"})
        TargetRepository(db).update(second["id"], {"deletion_locked": 1}, expected_updated_at=second["updated_at"])
        list_url = "/targets?q=対象"
        endpoint = "/target/filtered-delete"
        expected_remaining = ("targets", second["id"])
    else:
        VulnerabilityNoteRepository(db).update(notes[1]["id"], {"deletion_locked": 1}, expected_updated_at=notes[1]["updated_at"])
        list_url = "/notes?q=メモ"
        endpoint = "/note/filtered-delete"
        expected_remaining = ("vulnerability_notes", notes[1]["id"])
    db.close()
    listing = client.get(list_url).get_data(as_text=True)
    scope = _hidden(listing, "filter_scope")
    data = {"csrf_token": _csrf(client), "filter_scope": scope}
    confirmation = client.post(endpoint, data=data).get_data(as_text=True)
    assert "全2件" in confirmation
    data["confirmed"] = "1"
    result = client.post(endpoint, data=data, follow_redirects=True).get_data(as_text=True)
    assert "1件を削除" in result and "1件を残" in result
    db = connect_database(settings.database_path)
    try:
        assert db.execute(f"SELECT COUNT(*) FROM {expected_remaining[0]} WHERE id=?", (expected_remaining[1],)).fetchone()[0] == 1
    finally:
        db.close()


def test_multi_upload_is_all_or_nothing(client, settings) -> None:
    db, _project, _target, notes = _records(settings, count=1)
    db.close()
    valid = io.BytesIO()
    Image.new("RGB", (2, 2), "red").save(valid, "PNG")
    valid.seek(0)
    client.get(f"/notes/{notes[0]['id']}")
    client.post(
        f"/notes/{notes[0]['id']}/screenshots",
        data={"csrf_token": _csrf(client), "images": [(valid, "valid.png", "image/png"), (io.BytesIO(b"bad"), "bad.png", "image/png")]},
        content_type="multipart/form-data",
    )
    db = connect_database(settings.database_path)
    try:
        assert db.execute("SELECT COUNT(*) FROM screenshots").fetchone()[0] == 0
        assert not list(settings.upload_dir.glob("*"))
    finally:
        db.close()


def test_markdown_zip_has_only_safe_relative_entries(settings) -> None:
    db, _project, _target, notes = _records(settings, count=1)
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    (settings.upload_dir / "stored.png").write_bytes(b"png")
    now = notes[0]["created_at"]
    db.execute("INSERT INTO screenshots(note_id,original_filename,stored_filename,mime_type,byte_size,display_order,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", (notes[0]["id"], "../../proof.png", "stored.png", "image/png", 3, 0, now, now))
    try:
        archive_data = make_markdown_zip(export_rows(db, note_id=notes[0]["id"]), settings.upload_dir, "../report.md")
    finally:
        db.close()
    with zipfile.ZipFile(io.BytesIO(archive_data)) as archive:
        assert all(not name.startswith(("/", "\\")) and ".." not in name.split("/") for name in archive.namelist())
        assert "report.md" in archive.namelist()


def test_hierarchy_delete_db_failure_restores_staged_image(settings) -> None:
    db, project, _target, notes = _records(settings, count=1)
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    settings.recovery_dir.mkdir(parents=True, exist_ok=True)
    (settings.upload_dir / "stored.png").write_bytes(b"png")
    now = notes[0]["created_at"]
    db.execute("INSERT INTO screenshots(note_id,original_filename,stored_filename,mime_type,byte_size,display_order,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", (notes[0]["id"], "proof.png", "stored.png", "image/png", 3, 0, now, now))
    db.execute("CREATE TRIGGER block_project_delete BEFORE DELETE ON projects BEGIN SELECT RAISE(ABORT, 'test failure'); END")
    try:
        with pytest.raises(Exception):
            delete_entity(db, "project", project["id"], settings.upload_dir, settings.recovery_dir)
        assert ProjectRepository(db).get(project["id"]) is not None
        assert (settings.upload_dir / "stored.png").is_file()
        assert not list(settings.recovery_dir.iterdir())
    finally:
        db.close()


def test_bulk_delete_reports_partial_database_failure(settings) -> None:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    settings.recovery_dir.mkdir(parents=True, exist_ok=True)
    db = connect_database(settings.database_path)
    migrate(db)
    first = ProjectRepository(db).create({"name": "削除成功"})
    second = ProjectRepository(db).create({"name": "削除失敗"})
    db.execute(f"CREATE TRIGGER block_one_project BEFORE DELETE ON projects WHEN OLD.id={second['id']} BEGIN SELECT RAISE(ABORT, 'test failure'); END")
    try:
        deleted, retained = delete_entities(
            db, "project", [first["id"], second["id"]], settings.upload_dir, settings.recovery_dir
        )
        assert [item.record_id for item in deleted] == [first["id"]]
        assert [item.record_id for item in retained] == [second["id"]]
        assert ProjectRepository(db).get(first["id"]) is None
        assert ProjectRepository(db).get(second["id"]) is not None
    finally:
        db.close()


def test_csv_quotes_unicode_newlines_and_all_formula_prefixes() -> None:
    row = {key: "" for key in (
        "project_name", "client_name", "project_summary", "project_start_date", "project_end_date",
        "target_name", "base_url", "target_summary", "title", "target_url", "vulnerability_type",
        "severity", "discovered_at", "summary", "reproduction_steps", "evidence", "impact",
        "remediation", "status", "deletion_locked", "created_at", "updated_at", "screenshots",
    )}
    row.update({"project_name": "日本語,\n案件", "client_name": '=式', "summary": "+加算", "impact": "-減算", "remediation": "@参照", "evidence": "\tタブ", "title": "\r復帰", "target_summary": '引用"符'})
    text = make_csv([row]).decode("utf-8-sig")
    for dangerous in ("'=式", "'+加算", "'-減算", "'@参照", "'\tタブ", "'\r復帰"):
        assert dangerous in text
    assert '"日本語,\n案件"' in text
    assert '"引用""符"' in text


def test_upload_failures_leave_neither_database_rows_nor_files(settings, monkeypatch) -> None:
    db, _project, _target, notes = _records(settings, count=1)
    note_id = notes[0]["id"]
    original_mkstemp = __import__("vulnnote_manager.services", fromlist=["tempfile"]).tempfile.mkstemp
    try:
        import vulnnote_manager.services as services_module

        def no_space(*_args, **_kwargs):
            raise OSError(errno.ENOSPC, "no space")

        monkeypatch.setattr(services_module.tempfile, "mkstemp", no_space)
        with pytest.raises(OSError):
            save_screenshots(db, note_id, settings.upload_dir, [_png_upload()])
        monkeypatch.setattr(services_module.tempfile, "mkstemp", original_mkstemp)

        original_replace = services_module.os.replace
        monkeypatch.setattr(services_module.os, "replace", lambda *_args: (_ for _ in ()).throw(OSError("move failed")))
        with pytest.raises(OSError):
            save_screenshots(db, note_id, settings.upload_dir, [_png_upload()])
        monkeypatch.setattr(services_module.os, "replace", original_replace)

        db.execute("CREATE TRIGGER block_screenshot_insert BEFORE INSERT ON screenshots BEGIN SELECT RAISE(ABORT, 'db failed'); END")
        with pytest.raises(Exception):
            save_screenshots(db, note_id, settings.upload_dir, [_png_upload()])
        db.execute("DROP TRIGGER block_screenshot_insert")

        assert db.execute("SELECT COUNT(*) FROM screenshots").fetchone()[0] == 0
        assert settings.upload_dir.is_dir()
        assert not list(settings.upload_dir.iterdir())
    finally:
        db.close()


def test_upload_directory_creation_failure_is_safe(settings) -> None:
    db, _project, _target, notes = _records(settings, count=1)
    settings.upload_dir.parent.mkdir(parents=True, exist_ok=True)
    settings.upload_dir.write_bytes(b"not a directory")
    try:
        with pytest.raises(OSError):
            save_screenshots(db, notes[0]["id"], settings.upload_dir, [_png_upload()])
        assert db.execute("SELECT COUNT(*) FROM screenshots").fetchone()[0] == 0
    finally:
        db.close()


def test_screenshot_edit_reorder_and_failed_cleanup_stays_in_recovery(settings, monkeypatch) -> None:
    db, _project, _target, notes = _records(settings, count=1)
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    settings.recovery_dir.mkdir(parents=True, exist_ok=True)
    first, second = save_screenshots(
        db, notes[0]["id"], settings.upload_dir, [_png_upload("a.png"), _png_upload("b.png")]
    )
    update_screenshot(db, first["id"], description="更新説明")
    reorder_screenshots(db, notes[0]["id"], [second["id"], first["id"]])
    rows = db.execute("SELECT id,description,display_order FROM screenshots ORDER BY display_order").fetchall()
    assert [row["id"] for row in rows] == [second["id"], first["id"]]
    assert rows[1]["description"] == "更新説明"

    original_unlink = Path.unlink

    def fail_recovery_unlink(path, *args, **kwargs):
        if path.parent == settings.recovery_dir:
            raise OSError("cleanup failed")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_recovery_unlink)
    delete_screenshot(db, second["id"], settings.upload_dir, settings.recovery_dir)
    assert db.execute("SELECT COUNT(*) FROM screenshots WHERE id=?", (second["id"],)).fetchone()[0] == 0
    assert len(list(settings.recovery_dir.iterdir())) == 1
    db.close()


def test_database_and_images_are_restored_after_reconnect(settings) -> None:
    db, project, _target, notes = _records(settings, count=1)
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    screenshot = save_screenshots(
        db, notes[0]["id"], settings.upload_dir, [_png_upload("restart.png")]
    )[0]
    db.close()
    reopened = connect_database(settings.database_path)
    migrate(reopened)
    try:
        assert ProjectRepository(reopened).get(project["id"])["name"] == "案件"
        assert VulnerabilityNoteRepository(reopened).get(notes[0]["id"])["title"] == "メモ0"
        assert reopened.execute("SELECT original_filename FROM screenshots WHERE id=?", (screenshot["id"],)).fetchone()[0] == "restart.png"
        assert (settings.upload_dir / screenshot["stored_filename"]).is_file()
    finally:
        reopened.close()
