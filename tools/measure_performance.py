"""一時DBへメモ1万件を生成し、主要一覧クエリを再現可能に計測する。"""

from __future__ import annotations

import argparse
import statistics
import tempfile
import time
from pathlib import Path

from vulnnote_manager.database import connect_database, migrate
from vulnnote_manager.repositories import utc_now


def seed(path: Path, count: int) -> None:
    db = connect_database(path)
    migrate(db)
    now = utc_now()
    db.execute("BEGIN IMMEDIATE")
    try:
        db.execute("INSERT INTO projects(name,created_at,updated_at) VALUES(?,?,?)", ("性能試験案件", now, now))
        for index in range(20):
            db.execute("INSERT INTO targets(project_id,name,base_url,created_at,updated_at) VALUES(1,?,?,?,?)", (f"対象{index:02d}", f"https://example.test/{index}", now, now))
        rows = []
        severities = ("Critical", "High", "Medium", "Low", "Info")
        statuses = ("未確認", "確認済み", "報告済み", "対応中", "修正済み", "再診断済み", "対象外")
        for index in range(count):
            rows.append((index % 20 + 1, f"脆弱性メモ {index:05d}", "SQLインジェクション" if index % 3 == 0 else "XSS", severities[index % 5], "2026-07-16T00:00:00+00:00", f"検索本文 evidence-{index}", statuses[index % 7], now, now))
        db.executemany("INSERT INTO vulnerability_notes(target_id,title,vulnerability_type,severity,discovered_at,summary,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", rows)
        db.commit()
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=10_000)
    parser.add_argument("--runs", type=int, default=20)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="vulnnote-performance-") as directory:
        path = Path(directory) / "performance.sqlite3"
        seed(path, args.count)
        db = connect_database(path)
        queries = {
            "一覧": ("SELECT id,title,severity,status,updated_at FROM vulnerability_notes ORDER BY updated_at DESC LIMIT 25", ()),
            "本文検索": ("SELECT id,title FROM vulnerability_notes WHERE title LIKE ? OR summary LIKE ? LIMIT 25", ("%evidence-999%", "%evidence-999%")),
            "複合絞り込み": ("SELECT id,title FROM vulnerability_notes WHERE target_id=? AND severity=? AND status=? ORDER BY updated_at DESC LIMIT 25", (3, "High", "対応中")),
        }
        for name, (sql, parameters) in queries.items():
            durations = []
            for _ in range(args.runs):
                started = time.perf_counter()
                db.execute(sql, parameters).fetchall()
                durations.append(time.perf_counter() - started)
            plan = " | ".join(str(row[3]) for row in db.execute("EXPLAIN QUERY PLAN " + sql, parameters))
            print(f"{name}: p95={statistics.quantiles(durations, n=20)[18]:.6f}s plan={plan}")
        db.close()


if __name__ == "__main__":
    main()
