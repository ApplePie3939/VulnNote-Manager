"""削除、画像、出力に関する業務処理。"""

from __future__ import annotations

import csv
import io
import os
import re
import secrets
import sqlite3
import tempfile
import zipfile
from dataclasses import dataclass, replace
from pathlib import Path
from collections.abc import Iterable
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


def _stage_files(paths: Iterable[Path], recovery_dir: Path) -> list[tuple[Path, Path]]:
    """削除対象を回復領域へ移し、途中失敗時は元へ戻す。"""

    recovery_dir.mkdir(parents=True, exist_ok=True)
    staged: list[tuple[Path, Path]] = []
    try:
        for source in paths:
            if not source.is_file():
                continue
            recovery = recovery_dir / f"{secrets.token_hex(24)}{source.suffix}"
            os.replace(source, recovery)
            staged.append((source, recovery))
    except OSError:
        for source, recovery in reversed(staged):
            try:
                os.replace(recovery, source)
            except OSError:
                pass
        raise
    return staged


def _restore_staged_files(staged: Iterable[tuple[Path, Path]]) -> None:
    for source, recovery in reversed(list(staged)):
        if recovery.exists():
            os.replace(recovery, source)


def delete_entity(
    connection: sqlite3.Connection,
    entity: Entity,
    record_id: int,
    upload_dir: Path,
    recovery_dir: Path | None = None,
) -> DeleteAssessment:
    """画像を回復領域へ退避し、DB失敗時に元へ戻して階層を削除する。"""

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
    staged = _stage_files(files, recovery_dir or upload_dir / ".recovery")
    try:
        with transaction(connection):
            cursor = connection.execute(f"DELETE FROM {TABLES[entity]} WHERE id=?", (record_id,))
            if cursor.rowcount != 1:
                raise LookupError(record_id)
    except BaseException:
        _restore_staged_files(staged)
        raise
    for _source, path in staged:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass  # 回復領域の孤立ファイルは起動時清掃でき、公開経路から参照されない。
    return assessment


def delete_entities(
    connection: sqlite3.Connection,
    entity: Entity,
    record_ids: Iterable[int],
    upload_dir: Path,
    recovery_dir: Path,
) -> tuple[list[DeleteAssessment], list[DeleteAssessment]]:
    """重複を除いた複数項目を評価し、削除可能分だけ安全に削除する。"""

    deleted: list[DeleteAssessment] = []
    retained: list[DeleteAssessment] = []
    for record_id in dict.fromkeys(record_ids):
        assessment = assess_delete(connection, entity, record_id)
        if not assessment.allowed:
            retained.append(assessment)
            continue
        try:
            delete_entity(connection, entity, record_id, upload_dir, recovery_dir)
        except (OSError, sqlite3.Error):
            retained.append(replace(
                assessment, allowed=False,
                reason="保存処理に失敗したため削除せず残しました。保存先を確認して再実行してください。",
            ))
        else:
            deleted.append(assessment)
    return deleted, retained


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


def save_screenshots(
    connection: sqlite3.Connection, note_id: int, upload_dir: Path,
    uploads: Iterable[Any], description: str = "",
) -> list[dict[str, Any]]:
    """複数画像を先に検証し、全ファイルと全DB行を一括で保存する。"""

    prepared: list[tuple[str, str, str, bytes]] = []
    for upload in uploads:
        original = sanitize_filename(upload.filename or "")
        suffix = Path(original).suffix.lower()
        claimed = (upload.mimetype or "").lower()
        valid_suffixes = {".jpg", ".jpeg"} if claimed == "image/jpeg" else {MIME_EXTENSIONS.get(claimed, "")}
        if claimed not in MIME_EXTENSIONS or suffix not in valid_suffixes:
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
        prepared.append((original, secrets.token_hex(24) + MIME_EXTENSIONS[claimed], claimed, data))
    if not prepared:
        raise ValueError("アップロードする画像を選択してください。")

    upload_dir.mkdir(parents=True, exist_ok=True)
    temporary_paths: list[Path] = []
    final_paths: list[Path] = []
    try:
        for _original, stored, _claimed, data in prepared:
            fd, temporary = tempfile.mkstemp(prefix=".upload-", dir=upload_dir)
            temporary_path = Path(temporary)
            temporary_paths.append(temporary_path)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            final = upload_dir / stored
            os.replace(temporary_path, final)
            final_paths.append(final)
        inserted_ids: list[int] = []
        with transaction(connection):
            order = int(connection.execute(
                "SELECT COALESCE(MAX(display_order), -1)+1 FROM screenshots WHERE note_id=?", (note_id,)
            ).fetchone()[0])
            now = utc_now()
            for index, (original, stored, claimed, data) in enumerate(prepared):
                cursor = connection.execute(
                    "INSERT INTO screenshots(note_id,original_filename,stored_filename,mime_type,byte_size,description,display_order,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (note_id, original, stored, claimed, len(data), description.strip() or None, order + index, now, now),
                )
                inserted_ids.append(int(cursor.lastrowid))
    except BaseException:
        for path in (*temporary_paths, *final_paths):
            path.unlink(missing_ok=True)
        raise
    return [dict(connection.execute("SELECT * FROM screenshots WHERE id=?", (value,)).fetchone()) for value in inserted_ids]


def update_screenshot(
    connection: sqlite3.Connection, screenshot_id: int, *, description: str
) -> dict[str, Any]:
    """画像説明だけを更新する。ファイル名と保存先は変更しない。"""

    with transaction(connection):
        cursor = connection.execute(
            "UPDATE screenshots SET description=?,updated_at=? WHERE id=?",
            (description.strip() or None, utc_now(), screenshot_id),
        )
        if cursor.rowcount != 1:
            raise LookupError(screenshot_id)
    return dict(connection.execute("SELECT * FROM screenshots WHERE id=?", (screenshot_id,)).fetchone())


def reorder_screenshots(
    connection: sqlite3.Connection, note_id: int, ordered_ids: Iterable[int]
) -> None:
    """所属IDを完全一致で検証し、一時値を経由して表示順を重複なく保存する。"""

    requested = list(ordered_ids)
    current = [int(row[0]) for row in connection.execute(
        "SELECT id FROM screenshots WHERE note_id=? ORDER BY display_order", (note_id,)
    )]
    if len(requested) != len(set(requested)) or set(requested) != set(current):
        raise ValueError("画像の並び順が最新状態と一致しません。画面を再読み込みしてください。")
    with transaction(connection):
        temporary_start = len(current) * 2 + 1
        for index, screenshot_id in enumerate(requested):
            connection.execute(
                "UPDATE screenshots SET display_order=?,updated_at=? WHERE id=? AND note_id=?",
                (temporary_start + index, utc_now(), screenshot_id, note_id),
            )
        for index, screenshot_id in enumerate(requested):
            connection.execute(
                "UPDATE screenshots SET display_order=?,updated_at=? WHERE id=? AND note_id=?",
                (index, utc_now(), screenshot_id, note_id),
            )


def delete_screenshot(
    connection: sqlite3.Connection,
    screenshot_id: int,
    upload_dir: Path,
    recovery_dir: Path,
) -> int:
    """画像を非公開領域へ退避し、DB削除失敗時は元へ戻す。"""

    row = connection.execute("SELECT * FROM screenshots WHERE id=?", (screenshot_id,)).fetchone()
    if row is None:
        raise LookupError(screenshot_id)
    staged = _stage_files([upload_dir / row["stored_filename"]], recovery_dir)
    try:
        with transaction(connection):
            cursor = connection.execute("DELETE FROM screenshots WHERE id=?", (screenshot_id,))
            if cursor.rowcount != 1:
                raise LookupError(screenshot_id)
            remaining = connection.execute(
                "SELECT id FROM screenshots WHERE note_id=? ORDER BY display_order", (row["note_id"],)
            ).fetchall()
            for index, item in enumerate(remaining):
                connection.execute("UPDATE screenshots SET display_order=? WHERE id=?", (index, item[0]))
    except BaseException:
        _restore_staged_files(staged)
        raise
    for _source, recovery in staged:
        try:
            recovery.unlink(missing_ok=True)
        except OSError:
            pass
    return int(row["note_id"])


def csv_safe(value: Any) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(("=", "+", "-", "@", "\t", "\r")) else text


CSV_COLUMNS = (
    "project_name", "client_name", "project_summary", "project_start_date", "project_end_date",
    "target_name", "base_url", "target_summary", "title", "target_url",
    "vulnerability_type", "severity", "discovered_at", "summary", "reproduction_steps",
    "evidence", "impact", "remediation", "status", "deletion_locked", "created_at",
    "updated_at", "screenshots",
)


def export_rows(connection: sqlite3.Connection, *, note_id: int | None = None, project_id: int | None = None) -> list[dict[str, Any]]:
    where, value = ("n.id", note_id) if note_id is not None else ("p.id", project_id)
    rows = connection.execute(f"SELECT p.name project_name,p.client_name,p.summary project_summary,p.start_date project_start_date,p.end_date project_end_date,p.created_at project_created_at,p.updated_at project_updated_at,t.name target_name,t.base_url,t.summary target_summary,t.created_at target_created_at,t.updated_at target_updated_at,n.* FROM vulnerability_notes n JOIN targets t ON t.id=n.target_id JOIN projects p ON p.id=t.project_id WHERE {where}=? ORDER BY CASE n.severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END,t.name,n.discovered_at", (value,)).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        shots = connection.execute("SELECT id,original_filename FROM screenshots WHERE note_id=? ORDER BY display_order", (item["id"],)).fetchall()
        item["screenshots"] = "; ".join(f"{shot[0]}:{shot[1]}" for shot in shots)
        item["screenshot_items"] = [dict(shot) for shot in connection.execute(
            "SELECT id,original_filename,stored_filename,mime_type,description,display_order FROM screenshots WHERE note_id=? ORDER BY display_order",
            (item["id"],),
        )]
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
    first = rows[0]
    lines = [f"# {markdown_escape(first['project_name'])}", ""]
    for key, label in (("client_name", "顧客名"), ("project_summary", "案件概要"), ("project_start_date", "開始日"), ("project_end_date", "終了日")):
        lines += [f"## {label}", "", markdown_escape(first.get(key)), ""]
    current_target = None
    for row in rows:
        if row["target_name"] != current_target:
            current_target = row["target_name"]
            lines += [f"## 対象: {markdown_escape(current_target)}", "", "### ベースURL", "", markdown_escape(row.get("base_url")), "", "### 対象概要", "", markdown_escape(row.get("target_summary")), ""]
        lines += [f"### {markdown_escape(row['title'])}", ""]
        for key, label in (("target_url","対象URL"),("vulnerability_type","種類"),("severity","危険度"),("discovered_at","発見日時"),("summary","概要"),("reproduction_steps","再現手順"),("impact","影響"),("remediation","対策方法"),("status","対応状況")):
            lines += [f"#### {label}", "", markdown_escape(row.get(key)), ""]
        evidence = str(row.get("evidence") or "未記入")
        longest = max((len(m.group()) for m in re.finditer(r"`+", evidence)), default=2)
        fence = "`" * max(3, longest + 1)
        lines += ["#### リクエスト・レスポンス", "", fence + "text", evidence, fence, ""]
        for shot in row.get("screenshot_items", []):
            archive_name = safe_archive_name(f"images/{row['id']}-{shot['id']}-{shot['original_filename']}")
            lines += [f"![{markdown_escape(shot.get('description') or shot['original_filename'])}]({markdown_escape(archive_name)})", ""]
    return "\n".join(lines)


def safe_archive_name(value: str) -> str:
    """ZIP内で絶対パスや親参照にならない相対名を返す。"""

    normalized = value.replace("\\", "/")
    parts = [sanitize_filename(part) for part in normalized.split("/") if part not in {"", ".", ".."}]
    return "/".join(parts) or "export"


def make_markdown_zip(rows: list[dict[str, Any]], upload_dir: Path, markdown_name: str) -> bytes:
    """Markdownと参照画像を安全なエントリ名でZIP化する。"""

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(safe_archive_name(markdown_name), make_markdown(rows).encode("utf-8"))
        for row in rows:
            for shot in row.get("screenshot_items", []):
                source = upload_dir / shot["stored_filename"]
                if not source.is_file():
                    continue
                name = safe_archive_name(f"images/{row['id']}-{shot['id']}-{shot['original_filename']}")
                archive.writestr(name, source.read_bytes())
    return output.getvalue()
