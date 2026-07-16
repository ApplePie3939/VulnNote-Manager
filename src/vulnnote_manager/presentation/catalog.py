"""案件・対象・脆弱性メモのCRUD画面。"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for

from ..database import get_db
from ..repositories import (
    ConcurrentUpdateError,
    ProjectRepository,
    RecordNotFoundError,
    TargetRepository,
    VulnerabilityNoteRepository,
)
from ..validation import (
    SEVERITIES,
    STATUSES,
    validate_note,
    validate_project,
    validate_target,
    vulnerability_type_options,
)

catalog_blueprint = Blueprint("catalog", __name__)


@dataclass(frozen=True, slots=True)
class ListResult:
    """一覧テンプレートへ渡すページ情報。"""

    items: list[dict[str, Any]]
    page: int
    page_size: int
    total: int
    unfiltered_total: int

    @property
    def total_pages(self) -> int:
        return max(1, (self.total + self.page_size - 1) // self.page_size)

    @property
    def first_item(self) -> int:
        return (self.page - 1) * self.page_size + 1 if self.total else 0

    @property
    def last_item(self) -> int:
        return min(self.page * self.page_size, self.total)


def _page() -> int:
    try:
        page = int(request.args.get("page", "1"))
    except ValueError:
        abort(400)
    if page < 1:
        abort(400)
    return page


def _positive_id(name: str) -> int | None:
    raw = request.args.get(name, "").strip()
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        abort(400)
    if value < 1:
        abort(400)
    return value


def _sort(allowed: dict[str, str], default: str) -> tuple[str, str, str]:
    key = request.args.get("sort", default)
    direction = request.args.get("direction", "desc")
    if key not in allowed or direction not in {"asc", "desc"}:
        abort(400)
    return key, allowed[key], direction.upper()


def _like(value: str) -> str:
    """LIKEのワイルドカードを入力文字として検索する。"""

    return f"%{value.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')}%"


def _run_list(
    *,
    select_sql: str,
    from_sql: str,
    where: list[str],
    parameters: list[object],
    order_sql: str,
) -> ListResult:
    db = get_db()
    page = _page()
    size = current_app.config["PAGE_SIZE"]
    predicate = f" WHERE {' AND '.join(where)}" if where else ""
    total = int(db.execute(f"SELECT COUNT(*) {from_sql}{predicate}", parameters).fetchone()[0])
    unfiltered_total = int(db.execute(f"SELECT COUNT(*) {from_sql}").fetchone()[0])
    rows = db.execute(
        f"{select_sql} {from_sql}{predicate} ORDER BY {order_sql} LIMIT ? OFFSET ?",
        (*parameters, size, (page - 1) * size),
    ).fetchall()
    return ListResult([dict(row) for row in rows], page, size, total, unfiltered_total)


def _required(repository, record_id: int):
    record = repository.get(record_id)
    if record is None:
        abort(404)
    return record


def _type_options() -> tuple[str, ...]:
    rows = get_db().execute(
        "SELECT DISTINCT vulnerability_type FROM vulnerability_notes "
        "WHERE vulnerability_type IS NOT NULL ORDER BY vulnerability_type"
    ).fetchall()
    return vulnerability_type_options([row[0] for row in rows])


@catalog_blueprint.get("/projects")
def projects():
    q = request.args.get("q", "").strip()
    _, order, direction = _sort(
        {
            "name": "name", "client_name": "client_name", "start_date": "start_date",
            "end_date": "end_date", "updated_at": "updated_at",
        },
        "updated_at",
    )
    where: list[str] = []
    parameters: list[object] = []
    if q:
        where.append("(name LIKE ? ESCAPE '\\' OR client_name LIKE ? ESCAPE '\\' OR summary LIKE ? ESCAPE '\\')")
        parameters.extend([_like(q)] * 3)
    result = _run_list(
        select_sql="SELECT *", from_sql="FROM projects", where=where, parameters=parameters,
        order_sql=f"{order} {direction}, id DESC",
    )
    return render_template(
        "projects/list.html", projects=result.items, listing=result,
        query_args={key: value for key, value in request.args.items() if key != "page"},
    )


@catalog_blueprint.route("/projects/new", methods=["GET", "POST"])
def project_new():
    errors: dict[str, str] = {}
    values = dict(request.form) if request.method == "POST" else {}
    if request.method == "POST":
        result = validate_project(values)
        errors = result.errors
        if result.is_valid:
            project = ProjectRepository(get_db()).create(result.values)
            flash("案件を登録しました。", "success")
            return redirect(url_for("catalog.project_detail", project_id=project["id"]))
    return render_template("projects/form.html", values=values, errors=errors, project=None), (422 if errors else 200)


@catalog_blueprint.get("/projects/<int:project_id>")
def project_detail(project_id: int):
    project = _required(ProjectRepository(get_db()), project_id)
    targets = get_db().execute(
        "SELECT id, name, base_url, deletion_locked FROM targets WHERE project_id = ? ORDER BY id DESC LIMIT 10",
        (project_id,),
    ).fetchall()
    return render_template("projects/detail.html", project=project, targets=targets)


@catalog_blueprint.route("/projects/<int:project_id>/edit", methods=["GET", "POST"])
def project_edit(project_id: int):
    repository = ProjectRepository(get_db())
    project = _required(repository, project_id)
    errors: dict[str, str] = {}
    values = dict(project)
    if request.method == "POST":
        values = dict(request.form)
        result = validate_project(values)
        errors = result.errors
        if result.is_valid:
            try:
                repository.update(
                    project_id, result.values, expected_updated_at=request.form.get("updated_at", "")
                )
            except (ConcurrentUpdateError, RecordNotFoundError):
                abort(409)
            flash("案件を更新しました。", "success")
            return redirect(url_for("catalog.project_detail", project_id=project_id))
    return render_template("projects/form.html", project=project, values=values, errors=errors), (422 if errors else 200)


@catalog_blueprint.get("/targets")
def targets():
    q = request.args.get("q", "").strip()
    project_id = _positive_id("project_id")
    _, order, direction = _sort(
        {
            "project": "p.name", "name": "t.name", "base_url": "t.base_url",
            "updated_at": "t.updated_at",
        },
        "updated_at",
    )
    where: list[str] = []
    parameters: list[object] = []
    if q:
        where.append("(t.name LIKE ? ESCAPE '\\' OR t.base_url LIKE ? ESCAPE '\\' OR t.summary LIKE ? ESCAPE '\\' OR p.name LIKE ? ESCAPE '\\')")
        parameters.extend([_like(q)] * 4)
    if project_id:
        where.append("t.project_id = ?")
        parameters.append(project_id)
    result = _run_list(
        select_sql="SELECT t.*, p.name AS project_name",
        from_sql="FROM targets t JOIN projects p ON p.id=t.project_id",
        where=where, parameters=parameters, order_sql=f"{order} {direction}, t.id DESC",
    )
    projects = get_db().execute("SELECT id, name FROM projects ORDER BY name, id").fetchall()
    return render_template(
        "targets/list.html", targets=result.items, listing=result, projects=projects,
        query_args={key: value for key, value in request.args.items() if key != "page"},
    )


@catalog_blueprint.route("/projects/<int:project_id>/targets/new", methods=["GET", "POST"])
def target_new(project_id: int):
    project = _required(ProjectRepository(get_db()), project_id)
    errors: dict[str, str] = {}
    warnings: dict[str, str] = {}
    values = dict(request.form) if request.method == "POST" else {"project_id": project_id}
    if request.method == "POST":
        submitted = {**values, "project_id": project_id}
        result = validate_target(submitted)
        errors, warnings = result.errors, result.warnings
        if result.is_valid:
            target = TargetRepository(get_db()).create(result.values)
            flash("対象を登録しました。", "success")
            for warning in warnings.values():
                flash(warning, "warning")
            return redirect(url_for("catalog.target_detail", target_id=target["id"]))
    return render_template("targets/form.html", project=project, target=None, values=values, errors=errors, warnings=warnings), (422 if errors else 200)


@catalog_blueprint.get("/targets/<int:target_id>")
def target_detail(target_id: int):
    target = _required(TargetRepository(get_db()), target_id)
    project = _required(ProjectRepository(get_db()), target["project_id"])
    notes = get_db().execute(
        "SELECT id, title, severity, status, deletion_locked FROM vulnerability_notes "
        "WHERE target_id = ? ORDER BY id DESC LIMIT 10", (target_id,),
    ).fetchall()
    return render_template("targets/detail.html", target=target, project=project, notes=notes)


@catalog_blueprint.route("/targets/<int:target_id>/edit", methods=["GET", "POST"])
def target_edit(target_id: int):
    repository = TargetRepository(get_db())
    target = _required(repository, target_id)
    project = _required(ProjectRepository(get_db()), target["project_id"])
    values, errors, warnings = dict(target), {}, {}
    if request.method == "POST":
        values = dict(request.form)
        result = validate_target({**values, "project_id": target["project_id"]})
        errors, warnings = result.errors, result.warnings
        if result.is_valid:
            try:
                repository.update(target_id, result.values, expected_updated_at=request.form.get("updated_at", ""))
            except (ConcurrentUpdateError, RecordNotFoundError):
                abort(409)
            flash("対象を更新しました。", "success")
            for warning in warnings.values():
                flash(warning, "warning")
            return redirect(url_for("catalog.target_detail", target_id=target_id))
    return render_template("targets/form.html", project=project, target=target, values=values, errors=errors, warnings=warnings), (422 if errors else 200)


@catalog_blueprint.get("/notes")
def notes():
    q = request.args.get("q", "").strip()
    project_id, target_id = _positive_id("project_id"), _positive_id("target_id")
    filters = {
        "severity": (request.args.get("severity", ""), SEVERITIES),
        "status": (request.args.get("status", ""), STATUSES),
        "locked": (request.args.get("locked", ""), ("0", "1")),
    }
    for value, choices in filters.values():
        if value and value not in choices:
            abort(400)
    vulnerability_type = request.args.get("vulnerability_type", "").strip()
    severity_order = "CASE n.severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END"
    status_order = "CASE n.status WHEN '未確認' THEN 0 WHEN '確認済み' THEN 1 WHEN '報告済み' THEN 2 WHEN '対応中' THEN 3 WHEN '修正済み' THEN 4 WHEN '再診断済み' THEN 5 ELSE 6 END"
    _, order, direction = _sort(
        {
            "title": "n.title", "severity": severity_order,
            "vulnerability_type": "n.vulnerability_type", "discovered_at": "n.discovered_at",
            "status": status_order, "created_at": "n.created_at", "updated_at": "n.updated_at",
        },
        "updated_at",
    )
    where: list[str] = []
    parameters: list[object] = []
    if q:
        columns = (
            "n.title", "p.name", "t.name", "n.target_url", "n.vulnerability_type", "n.summary",
            "n.reproduction_steps", "n.evidence", "n.impact", "n.remediation",
        )
        where.append("(" + " OR ".join(f"{column} LIKE ? ESCAPE '\\'" for column in columns) + ")")
        parameters.extend([_like(q)] * len(columns))
    for column, value in (("p.id", project_id), ("t.id", target_id)):
        if value:
            where.append(f"{column} = ?")
            parameters.append(value)
    for column, name in (("n.severity", "severity"), ("n.status", "status"), ("n.deletion_locked", "locked")):
        value = filters[name][0]
        if value:
            where.append(f"{column} = ?")
            parameters.append(int(value) if name == "locked" else value)
    if vulnerability_type:
        where.append("n.vulnerability_type = ?")
        parameters.append(vulnerability_type)
    from_sql = "FROM vulnerability_notes n JOIN targets t ON t.id=n.target_id JOIN projects p ON p.id=t.project_id"
    result = _run_list(
        select_sql="SELECT n.*, t.name AS target_name, p.name AS project_name, p.id AS project_id",
        from_sql=from_sql, where=where, parameters=parameters,
        order_sql=f"{order} {direction}, n.id DESC",
    )
    projects = get_db().execute("SELECT id, name FROM projects ORDER BY name, id").fetchall()
    targets = get_db().execute(
        "SELECT id, project_id, name FROM targets ORDER BY name, id"
    ).fetchall()
    return render_template(
        "notes/list.html", notes=result.items, listing=result, projects=projects, targets=targets,
        severities=SEVERITIES, statuses=STATUSES, type_options=_type_options(),
        query_args={key: value for key, value in request.args.items() if key != "page"},
    )


@catalog_blueprint.route("/targets/<int:target_id>/notes/new", methods=["GET", "POST"])
def note_new(target_id: int):
    target = _required(TargetRepository(get_db()), target_id)
    project = _required(ProjectRepository(get_db()), target["project_id"])
    values = dict(request.form) if request.method == "POST" else {"target_id": target_id, "status": "未確認"}
    errors: dict[str, str] = {}
    warnings: dict[str, str] = {}
    if request.method == "POST":
        result = validate_note({**values, "target_id": target_id})
        errors, warnings = result.errors, result.warnings
        if result.is_valid:
            try:
                note = VulnerabilityNoteRepository(get_db()).create(result.values)
            except sqlite3.IntegrityError:
                abort(400)
            flash("脆弱性メモを登録しました。", "success")
            for warning in warnings.values():
                flash(warning, "warning")
            return redirect(url_for("catalog.note_detail", note_id=note["id"]))
    return render_template("notes/form.html", target=target, project=project, note=None, values=values, errors=errors, warnings=warnings, severities=SEVERITIES, statuses=STATUSES, type_options=_type_options()), (422 if errors else 200)


@catalog_blueprint.get("/notes/<int:note_id>")
def note_detail(note_id: int):
    note = _required(VulnerabilityNoteRepository(get_db()), note_id)
    target = _required(TargetRepository(get_db()), note["target_id"])
    project = _required(ProjectRepository(get_db()), target["project_id"])
    return render_template("notes/detail.html", note=note, target=target, project=project)


@catalog_blueprint.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
def note_edit(note_id: int):
    repository = VulnerabilityNoteRepository(get_db())
    note = _required(repository, note_id)
    target = _required(TargetRepository(get_db()), note["target_id"])
    project = _required(ProjectRepository(get_db()), target["project_id"])
    values, errors, warnings = dict(note), {}, {}
    if request.method == "POST":
        result = validate_note({**dict(request.form), "target_id": target["id"]})
        values, errors, warnings = dict(request.form), result.errors, result.warnings
        if result.is_valid:
            try:
                repository.update(note_id, result.values, expected_updated_at=request.form.get("updated_at", ""))
            except (ConcurrentUpdateError, RecordNotFoundError):
                abort(409)
            flash("脆弱性メモを更新しました。", "success")
            for warning in warnings.values():
                flash(warning, "warning")
            return redirect(url_for("catalog.note_detail", note_id=note_id))
    return render_template("notes/form.html", target=target, project=project, note=note, values=values, errors=errors, warnings=warnings, severities=SEVERITIES, statuses=STATUSES, type_options=_type_options()), (422 if errors else 200)
