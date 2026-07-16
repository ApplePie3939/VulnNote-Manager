"""ホーム画面の経路。"""

from __future__ import annotations

from flask import Blueprint, render_template

from ..database import get_db

main_blueprint = Blueprint("main", __name__)


@main_blueprint.get("/")
def index() -> str:
    """データ登録前にも表示できる最小ホーム画面を返す。"""

    db = get_db()
    projects = db.execute("SELECT id,name,updated_at FROM projects ORDER BY updated_at DESC LIMIT 5").fetchall()
    notes = db.execute("SELECT id,title,severity,status,updated_at FROM vulnerability_notes ORDER BY updated_at DESC LIMIT 5").fetchall()
    severity_counts = db.execute("SELECT severity,COUNT(*) count FROM vulnerability_notes GROUP BY severity").fetchall()
    status_counts = db.execute("SELECT status,COUNT(*) count FROM vulnerability_notes GROUP BY status").fetchall()
    totals = {
        "projects": db.execute("SELECT COUNT(*) FROM projects").fetchone()[0],
        "targets": db.execute("SELECT COUNT(*) FROM targets").fetchone()[0],
        "notes": db.execute("SELECT COUNT(*) FROM vulnerability_notes").fetchone()[0],
    }
    return render_template("index.html", projects=projects, notes=notes, severity_counts=severity_counts, status_counts=status_counts, totals=totals)
