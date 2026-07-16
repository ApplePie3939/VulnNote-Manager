"""SQLite接続、マイグレーション、トランザクション境界。"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from flask import Flask, current_app, g


class MigrationError(RuntimeError):
    """DBを変更せずに起動を中止すべきマイグレーションエラー。"""


INITIAL_SCHEMA = (
    """
    CREATE TABLE projects (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL CHECK (length(trim(name)) > 0),
        client_name TEXT,
        summary TEXT,
        start_date TEXT,
        end_date TEXT,
        deletion_locked INTEGER NOT NULL DEFAULT 0 CHECK (deletion_locked IN (0, 1)),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        CHECK (start_date IS NULL OR date(start_date) IS NOT NULL),
        CHECK (end_date IS NULL OR date(end_date) IS NOT NULL),
        CHECK (start_date IS NULL OR end_date IS NULL OR end_date >= start_date)
    )
    """,
    """
    CREATE TABLE targets (
        id INTEGER PRIMARY KEY,
        project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        name TEXT NOT NULL CHECK (length(trim(name)) > 0),
        base_url TEXT,
        summary TEXT,
        deletion_locked INTEGER NOT NULL DEFAULT 0 CHECK (deletion_locked IN (0, 1)),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE vulnerability_notes (
        id INTEGER PRIMARY KEY,
        target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
        title TEXT NOT NULL CHECK (length(trim(title)) > 0),
        target_url TEXT,
        vulnerability_type TEXT,
        severity TEXT NOT NULL CHECK (severity IN ('Critical','High','Medium','Low','Info')),
        discovered_at TEXT NOT NULL,
        summary TEXT,
        reproduction_steps TEXT,
        evidence TEXT,
        impact TEXT,
        remediation TEXT,
        status TEXT NOT NULL DEFAULT '未確認' CHECK (
            status IN ('未確認','確認済み','報告済み','対応中','修正済み','再診断済み','対象外')
        ),
        deletion_locked INTEGER NOT NULL DEFAULT 0 CHECK (deletion_locked IN (0, 1)),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE screenshots (
        id INTEGER PRIMARY KEY,
        note_id INTEGER NOT NULL REFERENCES vulnerability_notes(id) ON DELETE CASCADE,
        original_filename TEXT NOT NULL CHECK (length(original_filename) > 0),
        stored_filename TEXT NOT NULL UNIQUE CHECK (length(stored_filename) > 0),
        mime_type TEXT NOT NULL CHECK (mime_type IN ('image/png','image/jpeg','image/webp')),
        byte_size INTEGER NOT NULL CHECK (byte_size > 0 AND byte_size <= 10485760),
        description TEXT,
        display_order INTEGER NOT NULL CHECK (display_order >= 0),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE (note_id, display_order)
    )
    """,
    "CREATE INDEX idx_targets_project_id ON targets(project_id)",
    "CREATE INDEX idx_notes_target_id ON vulnerability_notes(target_id)",
    "CREATE INDEX idx_notes_severity ON vulnerability_notes(severity)",
    "CREATE INDEX idx_notes_status ON vulnerability_notes(status)",
    "CREATE INDEX idx_notes_discovered_at ON vulnerability_notes(discovered_at)",
    "CREATE INDEX idx_notes_updated_at ON vulnerability_notes(updated_at)",
    "CREATE INDEX idx_screenshots_note_id ON screenshots(note_id)",
)

MIGRATIONS: tuple[tuple[str, ...], ...] = (INITIAL_SCHEMA,)


def connect_database(path: str | Path) -> sqlite3.Connection:
    """外部キー制約と行名アクセスを有効にした接続を返す。"""

    connection = sqlite3.connect(str(path), isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


def get_db() -> sqlite3.Connection:
    """現在のリクエストで共有するDB接続を取得する。"""

    if "db" not in g:
        g.db = connect_database(current_app.config["DATABASE"])
    return g.db


def close_db(_error: BaseException | None = None) -> None:
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


@contextmanager
def transaction(connection: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """ネストを拒否し、失敗時に必ずロールバックする書込境界。"""

    if connection.in_transaction:
        raise RuntimeError("既存のトランザクション内で新しい書き込みを開始できません。")
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield connection
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()


def migrate(connection: sqlite3.Connection) -> None:
    """未適用マイグレーションを番号順に個別トランザクションで適用する。"""

    current_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if current_version > len(MIGRATIONS):
        raise MigrationError(
            "データベースのバージョンがこのアプリより新しいため起動できません。"
        )
    for version in range(current_version + 1, len(MIGRATIONS) + 1):
        try:
            with transaction(connection):
                for statement in MIGRATIONS[version - 1]:
                    connection.execute(statement)
                connection.execute(f"PRAGMA user_version = {version:d}")
        except sqlite3.Error as error:
            raise MigrationError(
                f"データベース更新 {version} を適用できませんでした。"
                "既存データは変更されていません。"
            ) from error


def init_database(app: Flask) -> None:
    """アプリへ接続後処理を登録し、起動時マイグレーションを行う。"""

    app.teardown_appcontext(close_db)
    connection = connect_database(app.config["DATABASE"])
    try:
        migrate(connection)
    finally:
        connection.close()
