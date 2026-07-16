"""主要エンティティのプレースホルダーSQLリポジトリ。"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from .database import transaction


class RecordNotFoundError(LookupError):
    pass


class ConcurrentUpdateError(RuntimeError):
    pass


def utc_now(previous: str | None = None) -> str:
    """UTC ISO 8601日時を返し、更新時は直前値より必ず新しくする。"""

    now = datetime.now(UTC)
    if previous:
        old = datetime.fromisoformat(previous)
        if now <= old:
            now = old + timedelta(microseconds=1)
    return now.isoformat(timespec="microseconds")


class BaseRepository:
    table: str
    writable_fields: tuple[str, ...]

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def get(self, record_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            f"SELECT * FROM {self.table} WHERE id = ?", (record_id,)
        ).fetchone()
        return dict(row) if row is not None else None

    def list(self, *, limit: int = 25, offset: int = 0) -> list[dict[str, Any]]:
        if limit < 1 or limit > 100 or offset < 0:
            raise ValueError("取得件数と開始位置を確認してください。")
        rows = self.connection.execute(
            f"SELECT * FROM {self.table} ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset)
        ).fetchall()
        return [dict(row) for row in rows]

    def create(self, values: Mapping[str, Any]) -> dict[str, Any]:
        supplied = tuple(field for field in self.writable_fields if field in values)
        if not supplied:
            raise ValueError("登録する項目がありません。")
        now = utc_now()
        columns = (*supplied, "created_at", "updated_at")
        parameters = tuple(values[field] for field in supplied) + (now, now)
        placeholders = ", ".join("?" for _ in columns)
        with transaction(self.connection):
            cursor = self.connection.execute(
                f"INSERT INTO {self.table} ({', '.join(columns)}) VALUES ({placeholders})",
                parameters,
            )
        return self.get(cursor.lastrowid)  # type: ignore[return-value]

    def update(
        self, record_id: int, values: Mapping[str, Any], *, expected_updated_at: str
    ) -> dict[str, Any]:
        supplied = tuple(field for field in self.writable_fields if field in values)
        if not supplied:
            raise ValueError("更新する項目がありません。")
        new_updated_at = utc_now(expected_updated_at)
        assignments = ", ".join(f"{field} = ?" for field in supplied)
        parameters = tuple(values[field] for field in supplied)
        with transaction(self.connection):
            cursor = self.connection.execute(
                f"UPDATE {self.table} SET {assignments}, updated_at = ? "
                "WHERE id = ? AND updated_at = ?",
                (*parameters, new_updated_at, record_id, expected_updated_at),
            )
            if cursor.rowcount != 1:
                if self.get(record_id) is None:
                    raise RecordNotFoundError(record_id)
                raise ConcurrentUpdateError(record_id)
        return self.get(record_id)  # type: ignore[return-value]


class ProjectRepository(BaseRepository):
    table = "projects"
    writable_fields = ("name", "client_name", "summary", "start_date", "end_date", "deletion_locked")


class TargetRepository(BaseRepository):
    table = "targets"
    writable_fields = ("project_id", "name", "base_url", "summary", "deletion_locked")


class VulnerabilityNoteRepository(BaseRepository):
    table = "vulnerability_notes"
    writable_fields = (
        "target_id", "title", "target_url", "vulnerability_type", "severity", "discovered_at",
        "summary", "reproduction_steps", "evidence", "impact", "remediation", "status",
        "deletion_locked",
    )


class ScreenshotRepository(BaseRepository):
    table = "screenshots"
    writable_fields = (
        "note_id", "original_filename", "stored_filename", "mime_type", "byte_size",
        "description", "display_order",
    )
