"""案件・対象・脆弱性メモのCRUD画面。"""

from __future__ import annotations

import sqlite3

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


def _page() -> int:
    try:
        return max(1, int(request.args.get("page", "1")))
    except ValueError:
        abort(400)


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
    page = _page()
    size = current_app.config["PAGE_SIZE"]
    items = ProjectRepository(get_db()).list(limit=size, offset=(page - 1) * size)
    return render_template("projects/list.html", projects=items, page=page)


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
    page = _page()
    size = current_app.config["PAGE_SIZE"]
    rows = get_db().execute(
        "SELECT t.*, p.name AS project_name FROM targets t JOIN projects p ON p.id=t.project_id "
        "ORDER BY t.id DESC LIMIT ? OFFSET ?", (size, (page - 1) * size),
    ).fetchall()
    return render_template("targets/list.html", targets=rows, page=page)


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
    page = _page()
    size = current_app.config["PAGE_SIZE"]
    rows = get_db().execute(
        "SELECT n.*, t.name AS target_name, p.name AS project_name FROM vulnerability_notes n "
        "JOIN targets t ON t.id=n.target_id JOIN projects p ON p.id=t.project_id "
        "ORDER BY n.updated_at DESC LIMIT ? OFFSET ?", (size, (page - 1) * size),
    ).fetchall()
    return render_template("notes/list.html", notes=rows, page=page)


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
