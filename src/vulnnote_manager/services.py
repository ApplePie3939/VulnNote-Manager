"""削除、画像、出力に関する業務処理。"""

from __future__ import annotations

import csv
import io
import os
import re
import secrets
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from PIL import Image, UnidentifiedImageError

from .database import transaction
from .repositories import utc_now

Entity = Literal["project", "target", "note"]
TABLES = {"project": "projects", "target": "targets", "note": "vulnerability_notes"}
MIME_EXTENSIONS = {"image/png": ".png", "image/jpeg": ".jpg", "image/webp": ".webp"}
IMAGE_FORMATS = {"PNG": "image/png", "JPEG": "image/jpeg", "WEBP": "image/webp"}
MAX_IMAGE_BYTES = 10 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class DeleteAssessment:
    entity: Entity
    record_id: int
    allowed: bool
    reason: str | None
    projects: int
    targets: int
    notes: int
    screenshots: int


def assess_delete(connection: sqlite3.Connection, entity: Entity, record_id: int) -> DeleteAssessment:
    """自身と子孫のロック、削除件数を一度に評価する。"""

    table = TABLES[entity]
    row = connection.execute(f"SELECT deletion_locked FROM {table} WHERE id = ?", (record_id,)).fetchone()
    if row is None:
        raise LookupError(record_id)
    if entity == "project":
        targets = int(connection.execute("SELECT COUNT(*) FROM targets WHERE project_id=?", (record_id,)).fetchone()[0])
        notes = int(connection.execute("SELECT COUNT(*) FROM vulnerability_notes n JOIN targets t ON t.id=n.target_id WHERE t.project_id=?", (record_id,)).fetchone()[0])
        shots = int(connection.execute("SELECT COUNT(*) FROM screenshots s JOIN vulnerability_notes n ON n.id=s.note_id JOIN targets t ON t.id=n.target_id WHERE t.project_id=?", (record_id,)).fetchone()[0])
        locked = int(connection.execute("SELECT (SELECT COUNT(*) FROM targets WHERE project_id=? AND deletion_locked=1) + (SELECT COUNT(*) FROM vulnerability_notes n JOIN targets t ON t.id=n.target_id WHERE t.project_id=? AND n.deletion_locked=1)", (record_id, record_id)).fetchone()[0])
        counts = (1, targets, notes, shots)
    elif entity == "target":
        notes = int(connection.execute("SELECT COUNT(*) FROM vulnerability_notes WHERE target_id=?", (record_id,)).fetchone()[0])
        shots = int(connection.execute("SELECT COUNT(*) FROM screenshots s JOIN vulnerability_notes n ON n.id=s.note_id WHERE n.target_id=?", (record_id,)).fetchone()[0])
        locked = int(connection.execute("SELECT COUNT(*) FROM vulnerability_notes WHERE target_id=? AND deletion_locked=1", (record_id,)).fetchone()[0])
        counts = (0, 1, notes, shots)
    else:
        shots = int(connection.execute("SELECT COUNT(*) FROM screenshots WHERE note_id=?", (record_id,)).fetchone()[0])
        locked, counts = 0, (0, 0, 1, shots)
    reason = "自身が削除ロック中です。" if row[0] else ("配下に削除ロック中の項目があります。" if locked else None)
    return DeleteAssessment(entity, record_id, reason is None, reason, *counts)


def set_deletion_lock(connection: sqlite3.Connection, entity: Entity, record_id: int, locked: bool) -> None:
    with transaction(connection):
        cursor = connection.execute(
            f"UPDATE {TABLES[entity]} SET deletion_locked=?, updated_at=? WHERE id=?",
            (int(locked), utc_now(), record_id),
        )
        if cursor.rowcount != 1:
            raise LookupError(record_id)


def delete_entity(connection: sqlite3.Connection, entity: Entity, record_id: int, upload_dir: Path) -> DeleteAssessment:
    """ロックを再評価し、画像を回収してから階層を削除する。"""

    assessment = assess_delete(connection, entity, record_id)
    if not assessment.allowed:
        return assessment
    if entity == "project":
        sql = "SELECT s.stored_filename FROM screenshots s JOIN vulnerability_notes n ON n.id=s.note_id JOIN targets t ON t.id=n.target_id WHERE t.project_id=?"
    elif entity == "target":
        sql = "SELECT s.stored_filename FROM screenshots s JOIN vulnerability_notes n ON n.id=s.note_id WHERE n.target_id=?"
    else:
        sql = "SELECT stored_filename FROM screenshots WHERE note_id=?"
    files = [upload_dir / row[0] for row in connection.execute(sql, (record_id,))]
    with transaction(connection):
        connection.execute(f"DELETE FROM {TABLES[entity]} WHERE id=?", (record_id,))
    for path in files:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass  # DBから参照不能。起動時清掃の対象として安全に残す。
    return assessment


def sanitize_filename(value: str) -> str:
    name = Path(value.replace("\\", "/")).name
    name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip().strip(".")
    return name[:255] or "image"


def save_screenshot(connection: sqlite3.Connection, note_id: int, upload_dir: Path, upload: Any, description: str = "") -> dict[str, Any]:
    """画像を完全デコード検証し、原子的に保存してDBへ登録する。"""

    original = sanitize_filename(upload.filename or "")
    suffix = Path(original).suffix.lower()
    claimed = (upload.mimetype or "").lower()
    if claimed not in MIME_EXTENSIONS or suffix not in ({".jpg", ".jpeg"} if claimed == "image/jpeg" else {MIME_EXTENSIONS[claimed]}):
        raise ValueError("拡張子とMIMEタイプが対応するPNG、JPEG、WebP画像を選択してください。")
    data = upload.stream.read(MAX_IMAGE_BYTES + 1)
    if not data or len(data) > MAX_IMAGE_BYTES:
        raise ValueError("画像は空でない10MB以下のファイルを選択してください。")
    try:
        with Image.open(io.BytesIO(data)) as image:
            actual = IMAGE_FORMATS.get(image.format or "")
            image.verify()
        with Image.open(io.BytesIO(data)) as image:
            image.load()
    except (UnidentifiedImageError, OSError, ValueError) as error:
        raise ValueError("画像が破損しているか、対応形式ではありません。") from error
    if actual != claimed:
        raise ValueError("ファイル内容とMIMEタイプが一致しません。")
    stored = secrets.token_hex(24) + MIME_EXTENSIONS[claimed]
    upload_dir.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".upload-", dir=upload_dir)
    final = upload_dir / stored
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, final)
        now = utc_now()
        with transaction(connection):
            order = int(connection.execute("SELECT COALESCE(MAX(display_order), -1)+1 FROM screenshots WHERE note_id=?", (note_id,)).fetchone()[0])
            cursor = connection.execute("INSERT INTO screenshots(note_id,original_filename,stored_filename,mime_type,byte_size,description,display_order,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", (note_id, original, stored, claimed, len(data), description.strip() or None, order, now, now))
    except BaseException:
        Path(temporary).unlink(missing_ok=True); final.unlink(missing_ok=True)
        raise
    return dict(connection.execute("SELECT * FROM screenshots WHERE id=?", (cursor.lastrowid,)).fetchone())


def csv_safe(value: Any) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(("=", "+", "-", "@", "\t", "\r")) else text


CSV_COLUMNS = ("project_name", "client_name", "project_summary", "target_name", "base_url", "target_summary", "title", "target_url", "vulnerability_type", "severity", "discovered_at", "summary", "reproduction_steps", "evidence", "impact", "remediation", "status", "created_at", "updated_at", "screenshots")


def export_rows(connection: sqlite3.Connection, *, note_id: int | None = None, project_id: int | None = None) -> list[dict[str, Any]]:
    where, value = ("n.id", note_id) if note_id is not None else ("p.id", project_id)
    rows = connection.execute(f"SELECT p.name project_name,p.client_name,p.summary project_summary,t.name target_name,t.base_url,t.summary target_summary,n.* FROM vulnerability_notes n JOIN targets t ON t.id=n.target_id JOIN projects p ON p.id=t.project_id WHERE {where}=? ORDER BY CASE n.severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END,t.name,n.discovered_at", (value,)).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        shots = connection.execute("SELECT id,original_filename FROM screenshots WHERE note_id=? ORDER BY display_order", (item["id"],)).fetchall()
        item["screenshots"] = "; ".join(f"{shot[0]}:{shot[1]}" for shot in shots)
        result.append(item)
    return result


def make_csv(rows: list[dict[str, Any]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: csv_safe(row.get(key)) for key in CSV_COLUMNS})
    return b"\xef\xbb\xbf" + output.getvalue().encode("utf-8")


def markdown_escape(value: Any) -> str:
    text = "未記入" if value in (None, "") else str(value)
    return re.sub(r"([\\`*_{}\[\]()#+.!|<>-])", r"\\\1", text)


def make_markdown(rows: list[dict[str, Any]]) -> str:
    if not rows:
        raise LookupError
    lines = [f"# {markdown_escape(rows[0]['project_name'])}", ""]
    current_target = None
    for row in rows:
        if row["target_name"] != current_target:
            current_target = row["target_name"]
            lines += [f"## 対象: {markdown_escape(current_target)}", ""]
        lines += [f"### {markdown_escape(row['title'])}", ""]
        for key, label in (("target_url","対象URL"),("vulnerability_type","種類"),("severity","危険度"),("discovered_at","発見日時"),("summary","概要"),("reproduction_steps","再現手順"),("impact","影響"),("remediation","対策方法"),("status","対応状況")):
            lines += [f"#### {label}", "", markdown_escape(row.get(key)), ""]
        evidence = str(row.get("evidence") or "未記入")
        longest = max((len(m.group()) for m in re.finditer(r"`+", evidence)), default=2)
        fence = "`" * max(3, longest + 1)
        lines += ["#### リクエスト・レスポンス", "", fence + "text", evidence, fence, ""]
    return "\n".join(lines)
