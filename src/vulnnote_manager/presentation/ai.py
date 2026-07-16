"""AI送信確認、比較、選択採用、報告書下書きの画面経路。"""

from __future__ import annotations

import io

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, send_file, url_for

from ..ai_service import (
    AIServiceError, FIELD_LABELS, NOTE_AI_FIELDS, detect_secret_warnings, draft_report,
    polish_note, temporary_ai_state,
)
from ..database import get_db
from ..repositories import ConcurrentUpdateError, ProjectRepository, VulnerabilityNoteRepository
from ..services import export_rows, make_markdown

ai_blueprint = Blueprint("ai", __name__)


def _note(note_id: int) -> dict:
    note = VulnerabilityNoteRepository(get_db()).get(note_id)
    if note is None:
        abort(404)
    return note


@ai_blueprint.route("/notes/<int:note_id>/ai-polish", methods=["GET", "POST"])
def note_polish(note_id: int):
    note = _note(note_id)
    if request.method == "GET":
        return render_template("ai/note_select.html", note=note, fields=FIELD_LABELS)
    selected = request.form.getlist("field")
    if not selected or len(selected) != len(set(selected)) or any(field not in NOTE_AI_FIELDS for field in selected):
        flash("AIへ送る項目を1つ以上選択してください。", "error")
        return redirect(url_for("ai.note_polish", note_id=note_id))
    fields = {field: str(note.get(field) or "") for field in selected}
    token = temporary_ai_state.put({"kind": "note-confirm", "note_id": note_id, "updated_at": note["updated_at"], "fields": selected})
    return render_template(
        "ai/note_confirm.html", note=note, fields=fields, labels=FIELD_LABELS,
        warnings=detect_secret_warnings(fields), state_token=token,
    )


@ai_blueprint.post("/notes/<int:note_id>/ai-polish/send")
def note_polish_send(note_id: int):
    if request.form.get("agreed") != "1":
        abort(400)
    try:
        state = temporary_ai_state.pop(request.form.get("state_token", ""))
        if state.get("kind") != "note-confirm" or state.get("note_id") != note_id:
            abort(400)
        fields = {field: request.form.get(field, "") for field in state["fields"]}
        generated = polish_note(
            fields, model=current_app.config["OPENAI_MODEL"], timeout=current_app.config["AI_TIMEOUT_SECONDS"],
            client_factory=current_app.config.get("OPENAI_CLIENT_FACTORY"),
        )
    except AIServiceError as error:
        flash(str(error), "error")
        return redirect(url_for("ai.note_polish", note_id=note_id))
    result_token = temporary_ai_state.put({
        "kind": "note-result", "note_id": note_id, "updated_at": state["updated_at"],
        "original": fields, "generated": generated,
    })
    return render_template(
        "ai/note_result.html", note=_note(note_id), original=fields, generated=generated,
        labels=FIELD_LABELS, state_token=result_token,
    )


@ai_blueprint.post("/notes/<int:note_id>/ai-polish/apply")
def note_polish_apply(note_id: int):
    try:
        state = temporary_ai_state.pop(request.form.get("state_token", ""))
    except AIServiceError as error:
        flash(str(error), "error")
        return redirect(url_for("ai.note_polish", note_id=note_id))
    if state.get("kind") != "note-result" or state.get("note_id") != note_id:
        abort(400)
    selected = request.form.getlist("field")
    if len(selected) != len(set(selected)) or any(field not in state["generated"] for field in selected):
        abort(400)
    if not selected:
        flash("AIの結果は採用しませんでした。元のメモは変更されていません。", "success")
        return redirect(url_for("catalog.note_detail", note_id=note_id))
    values = {field: state["generated"][field] for field in selected}
    try:
        VulnerabilityNoteRepository(get_db()).update(
            note_id, values, expected_updated_at=state["updated_at"]
        )
    except ConcurrentUpdateError:
        abort(409)
    flash(f"AIの結果から{len(values)}項目を採用しました。", "success")
    return redirect(url_for("catalog.note_detail", note_id=note_id))


@ai_blueprint.route("/projects/<int:project_id>/ai-report", methods=["GET", "POST"])
def project_report(project_id: int):
    project = ProjectRepository(get_db()).get(project_id)
    if project is None:
        abort(404)
    rows = export_rows(get_db(), project_id=project_id)
    source = make_markdown(rows) if rows else f"# {project['name']}\n\n脆弱性メモ: 未記入"
    if request.method == "GET":
        notes = get_db().execute(
            "SELECT n.id,n.title,t.name target_name FROM vulnerability_notes n JOIN targets t ON t.id=n.target_id WHERE t.project_id=? ORDER BY t.name,n.id",
            (project_id,),
        ).fetchall()
        return render_template("ai/report_select.html", project=project, notes=notes)
    if request.form.get("stage") == "confirm":
        selected = request.form.getlist("note_id")
        if request.form.get("scope") == "all":
            selected_rows = rows
        else:
            try:
                selected_ids = [int(value) for value in selected]
            except ValueError:
                abort(400)
            allowed_ids = {int(row["id"]) for row in rows}
            if not selected_ids or len(selected_ids) != len(set(selected_ids)) or not set(selected_ids) <= allowed_ids:
                flash("報告書へ含めるメモを1件以上選択してください。", "error")
                return redirect(url_for("ai.project_report", project_id=project_id))
            selected_rows = [row for row in rows if int(row["id"]) in set(selected_ids)]
        selected_source = make_markdown(selected_rows) if selected_rows else source
        return render_template(
            "ai/report_confirm.html", project=project, source=selected_source,
            warnings=detect_secret_warnings({"report": selected_source}),
        )
    if request.form.get("agreed") != "1":
        abort(400)
    confirmed_source = request.form.get("source", "")
    if not confirmed_source.strip():
        flash("送信内容が空です。内容を確認してください。", "error")
        return redirect(url_for("ai.project_report", project_id=project_id))
    try:
        draft = draft_report(
            confirmed_source, model=current_app.config["OPENAI_MODEL"],
            timeout=current_app.config["AI_TIMEOUT_SECONDS"],
            client_factory=current_app.config.get("OPENAI_CLIENT_FACTORY"),
        )
    except AIServiceError as error:
        flash(str(error), "error")
        return redirect(url_for("ai.project_report", project_id=project_id))
    token = temporary_ai_state.put({"kind": "report-result", "project_id": project_id})
    return render_template("ai/report_result.html", project=project, draft=draft, state_token=token)


@ai_blueprint.post("/projects/<int:project_id>/ai-report/download")
def project_report_download(project_id: int):
    try:
        state = temporary_ai_state.pop(request.form.get("state_token", ""))
    except AIServiceError as error:
        flash(str(error), "error")
        return redirect(url_for("ai.project_report", project_id=project_id))
    if state.get("kind") != "report-result" or state.get("project_id") != project_id:
        abort(400)
    body = request.form.get("draft", "")
    if not body.strip():
        abort(400)
    return send_file(
        io.BytesIO(body.encode("utf-8")), mimetype="text/markdown; charset=utf-8",
        as_attachment=True, download_name=f"project-{project_id}-ai-draft.md",
    )
