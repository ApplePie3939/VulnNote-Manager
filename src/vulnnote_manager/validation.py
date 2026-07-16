"""画面と業務処理から共用する入力検証。"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from urllib.parse import urlsplit

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
STATUSES = ("未確認", "確認済み", "報告済み", "対応中", "修正済み", "再診断済み", "対象外")
VULNERABILITY_TYPES = (
    "SQLインジェクション", "クロスサイトスクリプティング（XSS）",
    "クロスサイトリクエストフォージェリ（CSRF）", "OSコマンドインジェクション",
    "サーバーサイドリクエストフォージェリ（SSRF）", "パストラバーサル", "認証不備",
    "認可・アクセス制御不備", "セッション管理不備", "ファイルアップロード不備",
    "情報漏えい", "セキュリティ設定不備", "オープンリダイレクト", "その他",
)


@dataclass(frozen=True, slots=True)
class ValidationResult:
    values: dict[str, object]
    errors: dict[str, str]
    warnings: dict[str, str]

    @property
    def is_valid(self) -> bool:
        return not self.errors


def _text(raw: object, *, required: bool = False) -> tuple[str | None, str | None]:
    value = "" if raw is None else str(raw).strip()
    if not value:
        if required:
            return None, "この項目は必須です。空白以外の文字を入力してください。"
        return None, None
    return value, None


def _date(raw: object) -> tuple[str | None, str | None]:
    value, _ = _text(raw)
    if value is None:
        return None, None
    try:
        return date.fromisoformat(value).isoformat(), None
    except ValueError:
        return None, "日付は YYYY-MM-DD 形式で入力してください。"


def validate_url(raw: object) -> tuple[str | None, str | None]:
    """HTTP(S) URL以外は保存可能な警告として返す。"""

    value, _ = _text(raw)
    if value is None:
        return None, None
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return value, "HTTPまたはHTTPSの完全なURLではありません。保存前に値を確認してください。"
    if parsed.username or parsed.password:
        return value, "URLに認証情報が含まれている可能性があります。保存してよい内容か確認してください。"
    return value, None


def parse_local_datetime(raw: object, offset_minutes: object) -> tuple[str | None, str | None]:
    """datetime-local値とブラウザのUTCオフセット（UTCとの差）をUTCへ変換する。"""

    value, _ = _text(raw, required=True)
    if value is None:
        return None, "発見日時は必須です。"
    try:
        local = datetime.fromisoformat(value)
        if local.tzinfo is not None:
            return local.astimezone(UTC).isoformat(timespec="microseconds"), None
        offset = int(str(offset_minutes))
        if not -840 <= offset <= 840:
            raise ValueError
        return (local + timedelta(minutes=offset)).replace(tzinfo=UTC).isoformat(timespec="microseconds"), None
    except (TypeError, ValueError):
        return None, "発見日時またはタイムゾーン情報が正しくありません。再入力してください。"


def validate_project(data: dict[str, object]) -> ValidationResult:
    values: dict[str, object] = {}
    errors: dict[str, str] = {}
    warnings: dict[str, str] = {}
    for field, required in (("name", True), ("client_name", False), ("summary", False)):
        values[field], error = _text(data.get(field), required=required)
        if error:
            errors[field] = error
    for field in ("start_date", "end_date"):
        values[field], error = _date(data.get(field))
        if error:
            errors[field] = error
    if not errors.get("start_date") and not errors.get("end_date"):
        start, end = values["start_date"], values["end_date"]
        if start and end and str(end) < str(start):
            errors["end_date"] = "終了日は開始日以降の日付を指定してください。"
    values["deletion_locked"] = 1 if data.get("deletion_locked") in (True, 1, "1", "on") else 0
    return ValidationResult(values, errors, warnings)


def validate_target(data: dict[str, object]) -> ValidationResult:
    values: dict[str, object] = {}
    errors: dict[str, str] = {}
    warnings: dict[str, str] = {}
    try:
        values["project_id"] = int(str(data.get("project_id")))
        if values["project_id"] < 1:  # type: ignore[operator]
            raise ValueError
    except (TypeError, ValueError):
        errors["project_id"] = "所属案件を選択してください。"
    for field, required in (("name", True), ("summary", False)):
        values[field], error = _text(data.get(field), required=required)
        if error:
            errors[field] = error
    values["base_url"], warning = validate_url(data.get("base_url"))
    if warning:
        warnings["base_url"] = warning
    values["deletion_locked"] = 1 if data.get("deletion_locked") in (True, 1, "1", "on") else 0
    return ValidationResult(values, errors, warnings)


def validate_note(data: dict[str, object]) -> ValidationResult:
    result = validate_target({"project_id": data.get("target_id"), "name": data.get("title")})
    values = {"target_id": result.values.get("project_id"), "title": result.values.get("name")}
    errors = {("target_id" if k == "project_id" else "title"): v for k, v in result.errors.items()}
    warnings: dict[str, str] = {}
    for field in ("target_url",):
        values[field], warning = validate_url(data.get(field))
        if warning:
            warnings[field] = warning
    for field in ("vulnerability_type", "summary", "reproduction_steps", "evidence", "impact", "remediation"):
        values[field], _ = _text(data.get(field))
    severity = str(data.get("severity", ""))
    if severity not in SEVERITIES:
        errors["severity"] = "危険度は Critical、High、Medium、Low、Info から選択してください。"
    else:
        values["severity"] = severity
    status = str(data.get("status", "未確認"))
    if status not in STATUSES:
        errors["status"] = "対応状況は表示された候補から選択してください。"
    else:
        values["status"] = status
    values["discovered_at"], error = parse_local_datetime(data.get("discovered_at"), data.get("timezone_offset"))
    if error:
        errors["discovered_at"] = error
    values["deletion_locked"] = 1 if data.get("deletion_locked") in (True, 1, "1", "on") else 0
    return ValidationResult(values, errors, warnings)


def vulnerability_type_options(past_values: list[str | None]) -> tuple[str, ...]:
    """初期候補と過去入力を前後空白除去後の完全一致で重複排除する。"""

    return tuple(dict.fromkeys((*VULNERABILITY_TYPES, *(value.strip() for value in past_values if value and value.strip()))))
