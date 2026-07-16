from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

import vulnnote_manager.database as database_module
from vulnnote_manager.database import MigrationError, connect_database, migrate, transaction
from vulnnote_manager.repositories import (
    ConcurrentUpdateError,
    ProjectRepository,
    TargetRepository,
    VulnerabilityNoteRepository,
)


@pytest.fixture
def connection(tmp_path: Path):
    db = connect_database(tmp_path / "test.sqlite3")
    migrate(db)
    yield db
    db.close()


def test_initial_migration_creates_schema_indexes_and_version(connection) -> None:
    assert connection.execute("PRAGMA user_version").fetchone()[0] == len(database_module.MIGRATIONS)
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"projects", "targets", "vulnerability_notes", "screenshots"} <= tables
    indexes = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert {"idx_targets_project_id", "idx_notes_target_id", "idx_notes_status"} <= indexes


def test_every_connection_enables_foreign_keys(tmp_path: Path) -> None:
    db = connect_database(tmp_path / "foreign-keys.sqlite3")
    try:
        assert db.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    finally:
        db.close()


def test_failed_migration_rolls_back_whole_version(tmp_path: Path, monkeypatch) -> None:
    db = connect_database(tmp_path / "broken.sqlite3")
    monkeypatch.setattr(
        database_module,
        "MIGRATIONS",
        (("CREATE TABLE should_rollback (id INTEGER PRIMARY KEY)", "INVALID SQL"),),
    )
    try:
        with pytest.raises(MigrationError):
            migrate(db)
        assert db.execute("PRAGMA user_version").fetchone()[0] == 0
        assert db.execute(
            "SELECT name FROM sqlite_master WHERE name = ?", ("should_rollback",)
        ).fetchone() is None
    finally:
        db.close()


def test_constraints_reject_invalid_parent_enums_and_dates(connection) -> None:
    projects = ProjectRepository(connection)
    with pytest.raises(sqlite3.IntegrityError):
        projects.create({"name": "案件", "start_date": "2026-02-02", "end_date": "2026-01-01"})
    with pytest.raises(sqlite3.IntegrityError):
        TargetRepository(connection).create({"project_id": 999, "name": "対象"})

    project = projects.create({"name": "案件"})
    target = TargetRepository(connection).create({"project_id": project["id"], "name": "対象"})
    with pytest.raises(sqlite3.IntegrityError):
        VulnerabilityNoteRepository(connection).create(
            {
                "target_id": target["id"], "title": "メモ", "severity": "Unknown",
                "discovered_at": "2026-07-16T00:00:00.000000+00:00", "status": "未確認",
            }
        )


def test_repository_crud_uses_optimistic_concurrency(connection) -> None:
    repository = ProjectRepository(connection)
    created = repository.create({"name": "  SQL' OR 1=1 --  ", "client_name": "顧客"})
    assert created["name"] == "  SQL' OR 1=1 --  "
    assert repository.get(created["id"])["client_name"] == "顧客"

    updated = repository.update(
        created["id"], {"name": "更新後"}, expected_updated_at=created["updated_at"]
    )
    assert updated["name"] == "更新後"
    with pytest.raises(ConcurrentUpdateError):
        repository.update(
            created["id"], {"name": "古い画面から更新"}, expected_updated_at=created["updated_at"]
        )


def test_transaction_rolls_back_all_statements(connection) -> None:
    with pytest.raises(RuntimeError):
        with transaction(connection):
            connection.execute(
                "INSERT INTO projects (name, created_at, updated_at) VALUES (?, ?, ?)",
                ("残らない案件", "2026-01-01T00:00:00.000000+00:00", "2026-01-01T00:00:00.000000+00:00"),
            )
            raise RuntimeError("失敗を模擬")
    assert connection.execute("SELECT count(*) FROM projects").fetchone()[0] == 0
