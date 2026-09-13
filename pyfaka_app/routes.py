import json
import logging
import os
import re
import shutil
import time
import zipfile
from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from datetime import date, datetime, timedelta, timezone
from functools import wraps
from io import BytesIO
from secrets import token_urlsafe
from threading import Lock, RLock, Thread
from types import SimpleNamespace
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    Response,
    send_file,
    send_from_directory,
    session,
    url_for,
)
from sqlalchemy import func
from sqlalchemy.orm import joinedload
from werkzeug.security import check_password_hash, generate_password_hash

from .database import DATA_DIR, SessionLocal
from .models import AdminUser, AuditLog, Cdkey, CdkeyBatch, FileRecord, FileRecordPayload, UploadBatch, UploadResult
from .services import (
    BusinessError,
    BUSINESS_TYPES_SETTING_KEY,
    DEFAULT_UNSHIPPABLE_HTTP_STATUSES,
    DEFAULT_LIVE_CHECK_WORKERS,
    DEFAULT_BUSINESS_TYPE,
    DEFAULT_GROUP_TAG,
    access_cdkeys_bulk,
    admin_live_check_files,
    bound_files,
    capacity_for_owner,
    cdkey_filters,
    cdkeys_csv,
    count_files,
    count_scoped_cdkeys,
    count_scoped_files,
    LIVE_CHECK_TIMEOUT_KEY,
    LIVE_CHECK_USER_AGENT_KEY,
    QUERY_TOTP_ENABLED_KEY,
    UNSHIPPABLE_HTTP_STATUSES_KEY,
    TASK_WORKERS_KEY,
    active_business_type_keys,
    business_type_options,
    business_type_options_json,
    business_type_options_json_for_update,
    create_cdkey_batch,
    delete_cdkeys_with_bound_files,
    file_filters,
    get_setting,
    import_cdkey_batch,
    normalize_unshippable_http_statuses,
    normalize_active_business_type,
    normalize_business_type,
    normalize_group_tag,
    owner_scope,
    payload_for_record,
    payloads_for_records,
    query_business_type_options,
    query_totp_enabled,
    safe_name,
    save_upload_batch,
    set_configured_over_issue_files,
    set_setting,
    sum_scoped_cdkey_files,
    sub2api_json_for_files,
    sub2api_json_for_payloads,
    task_workers,
    TaskAbortError,
    unshippable_http_statuses,
    upload_payload_files,
    writable_owner_id,
    zip_for_files,
)

bp = Blueprint("main", __name__)
LOGGER = logging.getLogger(__name__)
QUERY_ATTEMPTS: dict[str, list[datetime]] = {}
LOGIN_FAILURES: dict[str, dict] = {}
EXTRACTION_JOBS: dict[str, dict] = {}
JOBS_LOCK = Lock()
JOB_HISTORY_LOCK = RLock()
REAUTH_RATE_LIMIT_COOLDOWN_SECONDS = 5 * 60
JOB_HISTORY_PATH = DATA_DIR / "task_history.json"
JOB_HISTORY_LIMIT = 200
JOB_HISTORY_PERSIST_INTERVAL = 1.0
JOB_HISTORY_LAST_PERSIST: dict[str, float] = {}
SQL_IN_CHUNK_SIZE = 500
POOL_OWNER_SESSION_KEY = "admin_pool_owner_id"
POOL_BUSINESS_SESSION_KEY = "admin_pool_business_type"
POOL_GROUP_SESSION_KEY = "admin_pool_group_tag"
POOL_SWITCH_TARGETS = {
    "main.dashboard",
    "main.files",
    "main.cdkeys",
    "main.create_cdkeys",
}
FILTER_DELETE_CONFIRM_TEXT = "确认删除"
LOGIN_WINDOW_SECONDS = 600
LOGIN_LOCK_SECONDS = 1800
LOGIN_USER_LIMIT = 10
LOGIN_IP_LIMIT = 10
LOGIN_FAILURE_DELAY_SECONDS = 0.35
DUMMY_PASSWORD_HASH = generate_password_hash("pyfaka-dummy-login-password")
QUERY_FAILURES: dict[str, dict] = {}
QUERY_INVALID_LIMIT = 10
QUERY_INVALID_LOCK_SECONDS = 1800
QUERY_INVALID_WINDOW_SECONDS = 600
QUERY_RATE_LIMIT = 20
QUERY_ACCESS_TOKEN_SESSION_KEY = "query_access_token"
QUERY_ACCESS_JOB_SESSION_KEY = "query_access_job_id"
QUERY_ACCESS_CDKEY_IDS_SESSION_KEY = "query_access_cdkey_ids"
QUERY_REAUTH_TOKEN_SESSION_KEY = "query_reauth_token"
QUERY_REAUTH_JOB_SESSION_KEY = "query_reauth_job_id"
ACTIVE_JOB_TIMEOUT_SECONDS = {
    "query_access": 1800,
    "file_live_check": 1800,
    "upload": 1800,
    "file_delete": 1800,
    "file_download": 1800,
    "query_reauth": 3600,
}
QUERY_REAUTH_DEFAULT_WORKERS = 10
QUERY_REAUTH_MAX_WORKERS = 10
COMMON_WEAK_PASSWORDS = {
    "123456",
    "12345678",
    "123456789",
    "password",
    "admin123",
    "change-me",
    "qwerty123",
}


def app_timezone():
    try:
        return ZoneInfo(os.environ.get("PYFAKA_TIMEZONE", "Asia/Shanghai"))
    except ZoneInfoNotFoundError:
        return timezone(timedelta(hours=8))


APP_TIMEZONE = app_timezone()


def clock_text() -> str:
    return datetime.now(APP_TIMEZONE).strftime("%H:%M:%S")


def full_clock_text() -> str:
    return datetime.now(APP_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")


def db():
    return SessionLocal()


def current_user() -> AdminUser | None:
    user_id = session.get("admin_user_id")
    if not user_id:
        return None
    return db().get(AdminUser, user_id)


def bump_session_version(user: AdminUser) -> None:
    user.session_version = int(user.session_version or 0) + 1


def establish_admin_session(user: AdminUser) -> None:
    session.clear()
    session.permanent = True
    session["admin_user_id"] = user.id
    session["admin_session_version"] = int(user.session_version or 1)
    session[POOL_OWNER_SESSION_KEY] = user.id
    session[POOL_BUSINESS_SESSION_KEY] = normalize_active_business_type(None)
    session[POOL_GROUP_SESSION_KEY] = DEFAULT_GROUP_TAG
    csrf_token()


def client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    return (forwarded.split(",", 1)[0].strip() or request.remote_addr or "")[:64]


def csrf_token() -> str:
    token = session.get("_csrf_token")
    if not token:
        token = token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def is_admin_api_request() -> bool:
    return request.path.startswith("/api/admin")


def validate_csrf():
    expected = session.get("_csrf_token")
    submitted = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token")
    if not expected or submitted != expected:
        if is_admin_api_request():
            return jsonify({"ok": False, "error": "CSRF 校验失败，请刷新后重试", "code": "CSRF_INVALID"}), 400
        abort(400)
    return None


def rate_limited(key: str, limit: int, window_seconds: int) -> bool:
    now = datetime.now()
    window_start = now - timedelta(seconds=window_seconds)
    attempts = [item for item in QUERY_ATTEMPTS.get(key, []) if item >= window_start]
    if len(attempts) >= limit:
        QUERY_ATTEMPTS[key] = attempts
        return True
    attempts.append(now)
    QUERY_ATTEMPTS[key] = attempts
    return False


def login_lock_key(username: str, ip: str) -> str:
    return f"user:{ip}:{username.strip().lower()}"


def login_ip_lock_key(ip: str) -> str:
    return f"ip:{ip}"


def login_lock_remaining(key: str) -> int:
    item = LOGIN_FAILURES.get(key) or {}
    locked_until = item.get("locked_until")
    if not isinstance(locked_until, datetime):
        return 0
    remaining = int((locked_until - datetime.now()).total_seconds())
    if remaining <= 0:
        item["locked_until"] = None
        LOGIN_FAILURES[key] = item
        return 0
    return remaining


def record_login_failure(key: str, limit: int = LOGIN_USER_LIMIT, window_seconds: int = LOGIN_WINDOW_SECONDS, lock_seconds: int = LOGIN_LOCK_SECONDS) -> int:
    now = datetime.now()
    item = LOGIN_FAILURES.get(key) or {}
    attempts = [value for value in item.get("attempts", []) if isinstance(value, datetime) and value >= now - timedelta(seconds=window_seconds)]
    attempts.append(now)
    locked_until = None
    if len(attempts) >= limit:
        locked_until = now + timedelta(seconds=lock_seconds)
    LOGIN_FAILURES[key] = {"attempts": attempts, "locked_until": locked_until}
    return int((locked_until - now).total_seconds()) if locked_until else 0


def clear_login_failures(key: str) -> None:
    LOGIN_FAILURES.pop(key, None)


def login_attempt_lock_remaining(username: str, ip: str) -> int:
    return max(login_lock_remaining(login_lock_key(username, ip)), login_lock_remaining(login_ip_lock_key(ip)))


def record_login_attempt_failure(username: str, ip: str) -> int:
    user_locked = record_login_failure(login_lock_key(username, ip), LOGIN_USER_LIMIT, LOGIN_WINDOW_SECONDS, LOGIN_LOCK_SECONDS)
    ip_locked = record_login_failure(login_ip_lock_key(ip), LOGIN_IP_LIMIT, LOGIN_WINDOW_SECONDS, LOGIN_LOCK_SECONDS)
    return max(user_locked, ip_locked)


def clear_login_attempt_failures(username: str, ip: str) -> None:
    clear_login_failures(login_lock_key(username, ip))
    clear_login_failures(login_ip_lock_key(ip))


def verify_login_password(user: AdminUser | None, password: str) -> bool:
    if not user or not user.enabled:
        check_password_hash(DUMMY_PASSWORD_HASH, password)
        return False
    return check_password_hash(user.password_hash, password)


def slow_failed_login() -> None:
    if LOGIN_FAILURE_DELAY_SECONDS > 0:
        time.sleep(LOGIN_FAILURE_DELAY_SECONDS)


def password_policy_error(password: str, username: str | None = None) -> str | None:
    if len(password) < 10:
        return "密码至少 10 位"
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "密码需同时包含字母和数字"
    if password.lower() in COMMON_WEAK_PASSWORDS:
        return "密码过于常见，请更换更强密码"
    if username and username.strip() and username.strip().lower() in password.lower():
        return "密码不能包含用户名"
    return None


def query_lock_key(ip: str) -> str:
    return f"query:{ip}"


def query_lock_remaining(ip: str) -> int:
    item = QUERY_FAILURES.get(query_lock_key(ip)) or {}
    locked_until = item.get("locked_until")
    if not isinstance(locked_until, datetime):
        return 0
    remaining = int((locked_until - datetime.now()).total_seconds())
    if remaining <= 0:
        item["locked_until"] = None
        QUERY_FAILURES[query_lock_key(ip)] = item
        return 0
    return remaining


def record_query_invalid_attempt(ip: str) -> int:
    now = datetime.now()
    key = query_lock_key(ip)
    item = QUERY_FAILURES.get(key) or {}
    attempts = [
        value
        for value in item.get("attempts", [])
        if isinstance(value, datetime) and value >= now - timedelta(seconds=QUERY_INVALID_WINDOW_SECONDS)
    ]
    attempts.append(now)
    locked_until = None
    if len(attempts) >= QUERY_INVALID_LIMIT:
        locked_until = now + timedelta(seconds=QUERY_INVALID_LOCK_SECONDS)
    QUERY_FAILURES[key] = {"attempts": attempts, "locked_until": locked_until}
    return int((locked_until - now).total_seconds()) if locked_until else 0


def clear_query_invalid_attempts(ip: str) -> None:
    QUERY_FAILURES.pop(query_lock_key(ip), None)


def session_int_list(key: str) -> list[int]:
    values = session.get(key) or []
    if not isinstance(values, list):
        return []
    result: list[int] = []
    for value in values:
        try:
            result.append(int(value))
        except (TypeError, ValueError):
            continue
    return result


def issue_query_access(job_id: str, cdkey_ids: list[int] | None = None) -> str:
    token = token_urlsafe(32)
    session.permanent = True
    session[QUERY_ACCESS_JOB_SESSION_KEY] = job_id
    session[QUERY_ACCESS_TOKEN_SESSION_KEY] = token
    if cdkey_ids is not None:
        session[QUERY_ACCESS_CDKEY_IDS_SESSION_KEY] = list(dict.fromkeys(int(item) for item in cdkey_ids if item))
    return token


def query_access_allowed(job_id: str, token: str | None = None) -> bool:
    if session.get(QUERY_ACCESS_JOB_SESSION_KEY) != job_id:
        return False
    expected = session.get(QUERY_ACCESS_TOKEN_SESSION_KEY)
    if token is None:
        token = request.args.get("token") or request.headers.get("X-Query-Token")
    return bool(expected and token and expected == token)


def authorize_query_job(job_id: str) -> bool:
    return query_access_allowed(job_id) or (
        not session.get(QUERY_ACCESS_TOKEN_SESSION_KEY)
        and (session.get("query_pending_job_id") == job_id or session.get("query_job_id") == job_id)
    )


def query_token_from_payload(payload: dict) -> str:
    return str(payload.get("access_token") or payload.get("token") or "").strip()


def issue_query_reauth_access(job_id: str) -> str:
    token = token_urlsafe(32)
    session.permanent = True
    session[QUERY_REAUTH_JOB_SESSION_KEY] = job_id
    session[QUERY_REAUTH_TOKEN_SESSION_KEY] = token
    return token


def authorized_query_result_ids(job_id: str | None) -> tuple[list[int], dict]:
    if not job_id or not authorize_query_job(job_id):
        return [], {}
    job = job_payload(job_id, allow_public=True) or {}
    if job.get("status") != "done":
        return [], job
    scoped_ids = scoped_query_cdkey_ids(job)
    ids = scoped_ids if scoped_ids is not None else query_job_cdkey_ids(job)
    return ids, job


def log_audit(action: str, target_type: str | None = None, target_id: str | int | None = None, detail: str | None = None) -> None:
    user = current_user()
    db().add(AuditLog(
        user_id=user.id if user else None,
        username=user.username if user else None,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        ip=client_ip(),
        detail=detail,
    ))
    db().commit()


def commit_audit_best_effort(session_db, audit_log: AuditLog, label: str) -> None:
    try:
        session_db.add(audit_log)
        session_db.commit()
    except Exception as audit_exc:
        session_db.rollback()
        LOGGER.warning("%s audit skipped: %s", label, audit_exc)


def cdkey_target_text(codes: list[str]) -> str:
    values = [str(code or "").strip() for code in codes if str(code or "").strip()]
    if not values:
        return ""
    if len(values) <= 5:
        return "、".join(values)
    return "、".join(values[:5]) + f" 等 {len(values)} 张"


def audit_target_text(item: AuditLog, cdkey_code_map: dict[int, str] | None = None) -> str:
    target_type = item.target_type or ""
    target_id = str(item.target_id or "").strip()
    if target_type in {"cdkey", "卡密"}:
        if not target_id:
            return "卡密"
        if cdkey_code_map:
            parts = [part.strip() for part in target_id.split(",") if part.strip()]
            mapped = []
            all_mapped = True
            for part in parts:
                if part.isdigit() and int(part) in cdkey_code_map:
                    mapped.append(cdkey_code_map[int(part)])
                else:
                    mapped.append(part)
                    if part.isdigit():
                        all_mapped = False
            if mapped and all_mapped:
                return cdkey_target_text(mapped)
        return target_id
    if target_type == "cdkey_batch":
        return f"卡密批次 {target_id}" if target_id else "卡密批次"
    if target_type and target_id:
        return f"{target_type} {target_id}"
    return target_type or target_id or "-"


@bp.before_app_request
def protect_post_requests():
    user_id = session.get("admin_user_id")
    if user_id:
        user = current_user()
        expected_version = session.get("admin_session_version")
        actual_version = int(user.session_version or 0) if user else None
        if not user or not user.enabled or expected_version != actual_version:
            session.clear()
            if request.endpoint not in {"main.login"}:
                if is_admin_api_request():
                    return api_error("登录已失效，请重新登录", 401, "SESSION_EXPIRED")
                flash("登录已失效，请重新登录", "error")
                return redirect(url_for("main.login", next=request.full_path))
        ensure_pool_context(user)
        source = request.form if request.method == "POST" else request.args
        update_pool_context_from_source(user, source)
    if request.method == "POST" and request.endpoint not in {
        "main.query_access",
        "main.api_query_access",
        "main.api_query_totp_accounts",
        "main.api_query_totp_code",
        "main.api_query_reauth",
        "main.api_query_reauth_terminate",
        "main.api_login",
    }:
        response = validate_csrf()
        if response is not None:
            return response


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("main.login", next=request.full_path))
        if current_user().login_password == "must_change" and request.endpoint not in {"main.change_password", "main.logout"}:
            return redirect(url_for("main.change_password"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user or not user.is_admin:
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def api_error(message: str, status: int = 400, code: str | None = None):
    payload = {"ok": False, "error": message}
    if code:
        payload["code"] = code
    return jsonify(payload), status


def api_ok(data: dict | None = None, status: int = 200):
    payload = {"ok": True}
    if data:
        payload.update(data)
    return jsonify(payload), status


def api_login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            return api_error("未登录或登录已失效", 401, "UNAUTHORIZED")
        if user.login_password == "must_change" and request.endpoint not in {"main.api_change_password", "main.api_logout"}:
            return api_error("当前账号需要先修改密码", 403, "PASSWORD_CHANGE_REQUIRED")
        return view(*args, **kwargs)

    return wrapped


def api_admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user or not user.is_admin:
            return api_error("当前账号没有权限执行此操作", 403, "FORBIDDEN")
        return view(*args, **kwargs)

    return wrapped


@bp.app_context_processor
def inject_globals():
    pool = current_pool_state()
    return {
        "current_user": current_user(),
        "owners": owner_options(),
        "business_types": active_business_type_keys(),
        "business_type_options": business_type_options(False),
        "csrf_token": csrf_token,
        "mask_email": mask_email,
        "format_time_text": format_time_text,
        "page_url": page_url,
        "current_pool": pool,
        "current_pool_scope": pool.get("scope", {}),
        "pool_switch_target": pool_switch_target(),
    }


def page_url(page_number: int):
    args = request.args.to_dict()
    args["page"] = str(page_number)
    return url_for(request.endpoint, **args)


def format_time_text(value) -> str:
    if value is None:
        return "-"
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    text = str(value).strip()
    if not text:
        return "-"
    normalized = text.replace("Z", "+00:00")
    if len(normalized) >= 5 and normalized[-5] in {"+", "-"} and normalized[-3] != ":":
        normalized = normalized[:-2] + ":" + normalized[-2:]
    try:
        parsed = datetime.fromisoformat(normalized)
        return parsed.replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return text.replace("T", " ").replace("Z", "")


def mask_email(value: str | None) -> str:
    if not value or "@" not in value:
        return value or "-"
    name, domain = value.split("@", 1)
    if len(name) <= 2:
        masked = name[0] + "*" if name else "*"
    else:
        masked = name[:2] + "***" + name[-1]
    return masked + "@" + domain


def quota_label(quota: dict | None) -> str:
    if not quota:
        return "暂无"
    used_text = quota.get("x-codex-primary-used-percent")
    try:
        used = int(float(str(used_text)))
    except (TypeError, ValueError):
        return "暂无"
    remaining = max(0, 100 - used)
    return f"{remaining}%"


def quota_period_label(quota: dict | None) -> str:
    if not quota:
        return "暂无"
    try:
        seconds = int(float(str(quota.get("x-codex-primary-limit-window-seconds"))))
    except (TypeError, ValueError):
        return "暂无"
    if seconds <= 0:
        return "暂无"
    if seconds % 86400 == 0:
        return f"{seconds // 86400}天"
    if seconds % 3600 == 0:
        return f"{seconds // 3600}小时"
    if seconds % 60 == 0:
        return f"{seconds // 60}分钟"
    return f"{seconds}秒"


def plan_type_label(quota: dict | None) -> str:
    if not quota:
        return "暂无"
    value = str(quota.get("x-codex-plan-type") or "").strip()
    if not value:
        return "暂无"
    labels = {
        "free": "Free",
        "plus": "Plus",
        "pro": "Pro",
        "team": "Team",
        "business": "Business",
        "enterprise": "Enterprise",
        "edu": "Edu",
    }
    return labels.get(value.lower(), value)


def quota_display_text(value) -> str:
    text = str(value or "").strip()
    if not text:
        return "暂无"
    match = re.search(r"(\d+)\s*%", text)
    if match:
        return f"{int(match.group(1))}%"
    return text


def upload_batch_no_text(batch: UploadBatch | None) -> str:
    if not batch:
        return "-"
    created = batch.created_at or datetime.now()
    return f"UP-{created.strftime('%Y%m%d')}-{int(batch.id)}"


def extraction_no_text(job_id: str) -> str:
    return f"EX-{datetime.now(APP_TIMEZONE):%Y%m%d}-{str(job_id)[:12].upper()}"


def quota_sort_value(value) -> int:
    text = str(value or "").strip()
    if not text:
        return -1
    match = re.search(r"(\d+)\s*%", text)
    if not match:
        return -1
    try:
        return int(match.group(1))
    except ValueError:
        return -1


def sort_items_by_quota_desc(items: list[dict], quota_key: str = "quota") -> list[dict]:
    return sorted(
        items,
        key=lambda item: (-quota_sort_value((item or {}).get(quota_key)), str((item or {}).get("email") or "")),
    )


def owner_options():
    user = current_user()
    if not user or not user.is_admin:
        return []
    return db().query(AdminUser).order_by(AdminUser.id.asc()).all()


def parse_int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_bool(value, default=False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def parse_day(value) -> date | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None


def compact_params(**values):
    return {key: value for key, value in values.items() if value not in (None, "")}


def ensure_pool_context(user: AdminUser | None = None) -> None:
    user = user or current_user()
    if not user:
        return
    if POOL_OWNER_SESSION_KEY not in session:
        session[POOL_OWNER_SESSION_KEY] = user.id
    session[POOL_BUSINESS_SESSION_KEY] = normalize_active_business_type(session.get(POOL_BUSINESS_SESSION_KEY))
    if not session.get(POOL_GROUP_SESSION_KEY):
        session[POOL_GROUP_SESSION_KEY] = DEFAULT_GROUP_TAG


def source_has_key(source, key: str) -> bool:
    try:
        return key in source
    except TypeError:
        return False


def update_pool_context_from_source(user: AdminUser | None = None, source=None) -> None:
    user = user or current_user()
    if not user or source is None:
        return
    ensure_pool_context(user)
    if source_has_key(source, "owner_id"):
        raw_owner = str(source.get("owner_id") or "").strip()
        requested = parse_int(raw_owner) if raw_owner else user.id
        session[POOL_OWNER_SESSION_KEY] = owner_scope(user, requested) or user.id
    if source_has_key(source, "business_type"):
        session[POOL_BUSINESS_SESSION_KEY] = normalize_active_business_type(source.get("business_type"))
    if source_has_key(source, "group_tag"):
        session[POOL_GROUP_SESSION_KEY] = normalize_group_tag(source.get("group_tag"))


def session_pool_owner_id(user: AdminUser | None = None) -> int | None:
    user = user or current_user()
    if not user:
        return None
    ensure_pool_context(user)
    return owner_scope(user, parse_int(session.get(POOL_OWNER_SESSION_KEY))) or user.id


def request_owner_id(source=None) -> int | None:
    user = current_user()
    if not user:
        return None
    ensure_pool_context(user)
    source = source or request.values
    if source_has_key(source, "owner_id"):
        raw_owner = str(source.get("owner_id") or "").strip()
        requested_owner_id = parse_int(raw_owner) if raw_owner else None
    else:
        requested_owner_id = session_pool_owner_id(user)
    return owner_scope(user, requested_owner_id) or user.id


def pool_owner_label(user: AdminUser, owner_id: int | None) -> str:
    if not user.is_admin:
        return user.username
    if owner_id is None:
        return "全部用户"
    owner = db().get(AdminUser, owner_id)
    if owner:
        return owner.username
    return f"用户 {owner_id}"


def pool_summary(owner_id: int | None, business_type: str, group_tag: str) -> dict:
    session_db = db()
    live_error_query = session_db.query(FileRecord.id).filter(
        FileRecord.business_type == business_type,
        FileRecord.group_tag == group_tag,
        FileRecord.live_status == "ERROR",
    )
    if owner_id is not None:
        live_error_query = live_error_query.filter(FileRecord.uploaded_by == owner_id)
    return {
        "total_files": count_scoped_files(session_db, owner_id, business_type, group_tag),
        "available_files": count_scoped_files(session_db, owner_id, business_type, group_tag, "AVAILABLE"),
        "bound_files": count_scoped_files(session_db, owner_id, business_type, group_tag, "BOUND"),
        "dead_files": count_scoped_files(session_db, owner_id, business_type, group_tag, "DEAD"),
        "checking_files": count_scoped_files(session_db, owner_id, business_type, group_tag, "CHECKING"),
        "live_error_files": live_error_query.count(),
        "total_cdkeys": count_scoped_cdkeys(session_db, owner_id, business_type, group_tag),
        "pending_cdkeys": count_scoped_cdkeys(session_db, owner_id, business_type, group_tag, "PENDING"),
        "extracted_cdkeys": count_scoped_cdkeys(session_db, owner_id, business_type, group_tag, "EXTRACTED"),
        "pending_cdkey_files": sum_scoped_cdkey_files(session_db, owner_id, business_type, group_tag, "PENDING"),
        "extracted_cdkey_files": sum_scoped_cdkey_files(session_db, owner_id, business_type, group_tag, "EXTRACTED"),
    }


def current_pool_scope(user: AdminUser | None = None) -> dict:
    user = user or current_user()
    if not user:
        return {}
    ensure_pool_context(user)
    owner_id = session_pool_owner_id(user)
    return compact_params(
        owner_id=owner_id if user.is_admin else None,
        business_type=session.get(POOL_BUSINESS_SESSION_KEY, DEFAULT_BUSINESS_TYPE),
        group_tag=session.get(POOL_GROUP_SESSION_KEY, DEFAULT_GROUP_TAG),
    )


def current_pool_state() -> dict:
    user = current_user()
    if not user:
        return {}
    ensure_pool_context(user)
    owner_id = session_pool_owner_id(user)
    business_type = normalize_active_business_type(session.get(POOL_BUSINESS_SESSION_KEY))
    group_tag = normalize_group_tag(session.get(POOL_GROUP_SESSION_KEY))
    return {
        "owner_id": owner_id,
        "business_type": business_type,
        "group_tag": group_tag,
        "owner_label": pool_owner_label(user, owner_id),
        "scope": compact_params(
            owner_id=owner_id if user.is_admin else None,
            business_type=business_type,
            group_tag=group_tag,
        ),
    }


def pool_switch_target() -> str:
    endpoint = request.endpoint or "main.dashboard"
    if endpoint in POOL_SWITCH_TARGETS:
        return endpoint
    return "main.dashboard"


def require_write_owner(user: AdminUser, requested_owner_id: int | None) -> int:
    if user.is_admin and not requested_owner_id:
        raise BusinessError("请先选择具体用户，再执行当前操作")
    return writable_owner_id(user, requested_owner_id)


def parse_text_codes(raw: str | None) -> list[str]:
    text = str(raw or "")
    return [item.strip().upper() for item in text.replace(",", "\n").replace("，", "\n").splitlines() if item.strip()]


def request_business_type(source=None) -> str:
    user = current_user()
    source = source or request.values
    getter = getattr(source, "get", None)
    if getter and source_has_key(source, "business_type"):
        value = getter("business_type")
    else:
        ensure_pool_context(user)
        value = session.get(POOL_BUSINESS_SESSION_KEY, DEFAULT_BUSINESS_TYPE)
    return normalize_active_business_type(value)


def request_group_tag(source=None) -> str:
    user = current_user()
    source = source or request.values
    getter = getattr(source, "get", None)
    if getter and source_has_key(source, "group_tag"):
        value = getter("group_tag")
    else:
        ensure_pool_context(user)
        value = session.get(POOL_GROUP_SESSION_KEY, DEFAULT_GROUP_TAG)
    return normalize_group_tag(value)


def paginate(query, page: int, per_page: int = 20):
    page = max(page, 1)
    total = query.order_by(None).count()
    items = query.limit(per_page).offset((page - 1) * per_page).all()
    pages = max((total + per_page - 1) // per_page, 1)
    return SimpleNamespace(items=items, page=page, pages=pages, total=total)


def one_or_404(query):
    item = query.first()
    if not item:
        abort(404)
    return item


def public_inventory() -> dict:
    session_db = db()
    available_files = count_files(session_db, None, "AVAILABLE")
    visible_options = query_business_type_options()
    visible_keys = {item["key"] for item in visible_options}
    by_business_type = {item["key"]: 0 for item in visible_options}
    rows = (
        session_db.query(FileRecord.business_type, func.count(FileRecord.id))
        .filter(FileRecord.status == "AVAILABLE")
        .group_by(FileRecord.business_type)
        .all()
    )
    for business_type, total in rows:
        normalized = normalize_business_type(business_type)
        if normalized in visible_keys:
            by_business_type[normalized] = by_business_type.get(normalized, 0) + int(total or 0)
    return {
        "available_files": available_files,
        "by_business_type": by_business_type,
        "business_type_options": visible_options,
        "updated_at": clock_text(),
    }


def serve_admin_frontend():
    static_folder = current_app.static_folder or ""
    admin_dir = os.path.join(static_folder, "app")
    index_path = os.path.join(admin_dir, "index.html")
    if not static_folder or not os.path.exists(index_path):
        return Response(
            "Frontend app is not built yet. Run `npm run build` in frontend-admin first.",
            status=503,
            mimetype="text/plain; charset=utf-8",
        )
    return send_from_directory(admin_dir, "index.html")


def distinct_group_tags(session_db) -> list[str]:
    tags = {DEFAULT_GROUP_TAG}
    for (value,) in session_db.query(FileRecord.group_tag).distinct().all():
        tags.add(normalize_group_tag(value))
    for (value,) in session_db.query(CdkeyBatch.group_tag).distinct().all():
        tags.add(normalize_group_tag(value))
    ordered = [DEFAULT_GROUP_TAG]
    ordered.extend(sorted(item for item in tags if item != DEFAULT_GROUP_TAG))
    return ordered


def user_payload(user: AdminUser | None) -> dict | None:
    if not user:
        return None
    return {
        "id": user.id,
        "username": user.username,
        "enabled": bool(user.enabled),
        "is_admin": bool(user.is_admin),
        "last_login_at": format_time_text(user.last_login_at),
        "cdkey_prefix": user.cdkey_prefix,
        "over_issue_files": int(user.over_issue_files or 0),
        "must_change_password": user.login_password == "must_change",
    }


def session_payload(user: AdminUser | None = None) -> dict:
    session_db = db()
    user = user or current_user()
    authenticated = bool(user)
    pool = current_pool_state() if authenticated else {
        "owner_id": None,
        "business_type": DEFAULT_BUSINESS_TYPE,
        "group_tag": DEFAULT_GROUP_TAG,
        "owner_label": "未登录",
        "scope": {},
    }
    owners = []
    if user and user.is_admin:
        owners = [
            {"id": item.id, "username": item.username, "enabled": bool(item.enabled)}
            for item in session_db.query(AdminUser).order_by(AdminUser.id.asc()).all()
        ]
    return {
        "authenticated": authenticated,
        "csrf_token": csrf_token(),
        "user": user_payload(user),
        "must_change_password": bool(user and user.login_password == "must_change"),
        "pool": pool,
        "owners": owners,
        "business_types": list(active_business_type_keys()),
        "business_type_options": business_type_options(False),
        "group_tags": distinct_group_tags(session_db) if authenticated else [DEFAULT_GROUP_TAG],
    }


def dashboard_summary_payload(session_db, user: AdminUser, owner_id: int | None, business_type: str, group_tag: str) -> dict:
    business_type = normalize_business_type(business_type)
    group_tag = normalize_group_tag(group_tag)
    now = datetime.now(APP_TIMEZONE)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).replace(tzinfo=None)
    tomorrow_start = today_start + timedelta(days=1)
    trend_days = 7
    trend_start = today_start - timedelta(days=trend_days - 1)

    uploaded_today_query = session_db.query(FileRecord.id).filter(
        FileRecord.upload_time >= today_start,
        FileRecord.upload_time < tomorrow_start,
        FileRecord.business_type == business_type,
        FileRecord.group_tag == group_tag,
    )
    extracted_today_query = session_db.query(Cdkey.id).join(CdkeyBatch).filter(
        Cdkey.extracted_at.is_not(None),
        Cdkey.extracted_at >= today_start,
        Cdkey.extracted_at < tomorrow_start,
        CdkeyBatch.business_type == business_type,
        CdkeyBatch.group_tag == group_tag,
    )
    extracted_files_today_query = session_db.query(func.coalesce(func.sum(Cdkey.files_per_key), 0)).join(CdkeyBatch).filter(
        Cdkey.extracted_at.is_not(None),
        Cdkey.extracted_at >= today_start,
        Cdkey.extracted_at < tomorrow_start,
        CdkeyBatch.business_type == business_type,
        CdkeyBatch.group_tag == group_tag,
    )
    if owner_id is not None:
        uploaded_today_query = uploaded_today_query.filter(FileRecord.uploaded_by == owner_id)
        extracted_today_query = extracted_today_query.filter(CdkeyBatch.created_by == owner_id)
        extracted_files_today_query = extracted_files_today_query.filter(CdkeyBatch.created_by == owner_id)

    upload_trend_query = session_db.query(FileRecord.upload_time).filter(
        FileRecord.upload_time >= trend_start,
        FileRecord.upload_time < tomorrow_start,
        FileRecord.business_type == business_type,
        FileRecord.group_tag == group_tag,
    )
    extracted_files_trend_query = session_db.query(Cdkey.extracted_at, Cdkey.files_per_key).join(CdkeyBatch).filter(
        Cdkey.extracted_at.is_not(None),
        Cdkey.extracted_at >= trend_start,
        Cdkey.extracted_at < tomorrow_start,
        CdkeyBatch.business_type == business_type,
        CdkeyBatch.group_tag == group_tag,
    )
    if owner_id is not None:
        upload_trend_query = upload_trend_query.filter(FileRecord.uploaded_by == owner_id)
        extracted_files_trend_query = extracted_files_trend_query.filter(CdkeyBatch.created_by == owner_id)

    uploaded_trend_map: dict[str, int] = {}
    for (uploaded_at,) in upload_trend_query.all():
        key = uploaded_at.strftime("%Y-%m-%d")
        uploaded_trend_map[key] = uploaded_trend_map.get(key, 0) + 1

    extracted_files_trend_map: dict[str, int] = {}
    for extracted_at, files_per_key in extracted_files_trend_query.all():
        key = extracted_at.strftime("%Y-%m-%d")
        extracted_files_trend_map[key] = extracted_files_trend_map.get(key, 0) + int(files_per_key or 0)

    trend_points = []
    for offset in range(trend_days):
        day = (trend_start + timedelta(days=offset)).date()
        key = day.isoformat()
        trend_points.append({
            "date": key,
            "label": day.strftime("%m-%d"),
            "uploaded_count": uploaded_trend_map.get(key, 0),
            "extracted_files_count": extracted_files_trend_map.get(key, 0),
        })

    return {
        "uploaded_today": uploaded_today_query.count(),
        "extracted_today": extracted_today_query.count(),
        "extracted_files_today": int(extracted_files_today_query.scalar() or 0),
        "available_files": count_scoped_files(session_db, owner_id, business_type, group_tag, "AVAILABLE"),
        "uploaded_total": count_scoped_files(session_db, owner_id, business_type, group_tag),
        "extracted_total": count_scoped_cdkeys(session_db, owner_id, business_type, group_tag, "EXTRACTED"),
        "extracted_files_total": sum_scoped_cdkey_files(session_db, owner_id, business_type, group_tag, "EXTRACTED"),
        "date_label": now.strftime("%Y-%m-%d"),
        "scope_label": pool_owner_label(user, owner_id),
        "trend_points": trend_points,
    }


def file_status_text(status: str | None) -> str:
    mapping = {
        "AVAILABLE": "未提取",
        "CHECKING": "提取测活中",
        "BOUND": "已提取",
        "DEAD": "不可出库",
    }
    return mapping.get(str(status or "").upper(), str(status or "-"))


def live_status_text(status: str | None) -> str:
    mapping = {
        None: "未测活",
        "NORMAL": "正常",
        "ERROR": "异常",
    }
    return mapping.get(status, str(status or "未测活"))


def cdkey_status_text(status: str | None) -> str:
    mapping = {
        "PENDING": "待提取",
        "CHECKING": "提取中",
        "EXTRACTED": "已提取",
    }
    return mapping.get(str(status or "").upper(), str(status or "-"))


def file_size_text(value: int | None) -> str:
    size = float(int(value or 0))
    units = ["B", "KB", "MB", "GB", "TB"]
    index = 0
    while size >= 1024 and index < len(units) - 1:
        size /= 1024
        index += 1
    if index == 0:
        return f"{int(size)} {units[index]}"
    return f"{size:.2f} {units[index]}"


def scoped_route_params(owner_id: int | None, business_type: str, group_tag: str) -> dict:
    return compact_params(
        owner_id=owner_id,
        business_type=business_type,
        group_tag=group_tag,
    )


def file_payload_summary(raw_payload: dict | None) -> dict:
    payload = raw_payload or {}
    if not payload:
        return {"available": False}
    return {
        "available": True,
        "email": payload.get("email") or "",
        "account_id": payload.get("account_id") or "",
        "type": payload.get("type") or "",
        "expired_at": format_time_text(payload.get("expired")),
        "last_refresh": format_time_text(payload.get("last_refresh")),
        "has_access_token": bool(payload.get("access_token")),
        "has_refresh_token": bool(payload.get("refresh_token")),
        "has_id_token": bool(payload.get("id_token")),
    }


def file_item_payload(item: FileRecord) -> dict:
    raw = item.payload.reauth_info if item.payload else ""
    try:
        auth_info = json.loads(raw or "{}")
    except (TypeError, ValueError):
        auth_info = {}
    has_two_factor = bool(isinstance(auth_info, dict) and auth_info.get("password") and auth_info.get("totp_secret"))
    return {
        "id": item.id,
        "original_filename": item.original_filename,
        "email_name": item.email_name,
        "status": item.status,
        "status_text": file_status_text(item.status),
        "live_status": item.live_status or "UNCHECKED",
        "live_status_text": live_status_text(item.live_status),
        "live_quota": quota_display_text(item.live_quota),
        "live_http_status": item.live_http_status,
        "live_message": item.live_message or "",
        "extraction_no": item.extraction_no or "",
        "upload_time": format_time_text(item.upload_time),
        "live_checked_at": format_time_text(item.live_checked_at),
        "bound_cdkey_code": item.bound_cdkey.code if item.bound_cdkey else "",
        "owner_username": item.owner.username if item.owner else "",
        "can_delete": item.status != "CHECKING",
        "can_recover": item.status == "CHECKING",
        "has_2fa": has_two_factor,
        "two_factor_status": "已导入" if has_two_factor else "未导入",
    }


def cdkey_item_payload(item: Cdkey) -> dict:
    return {
        "id": item.id,
        "code": item.code,
        "extract_status": item.extract_status,
        "extract_status_text": cdkey_status_text(item.extract_status),
        "files_per_key": item.files_per_key,
        "extraction_no": item.extraction_no or "",
        "batch_id": item.batch.id if item.batch else None,
        "batch_no": item.batch.batch_no if item.batch else "",
        "business_type": item.batch.business_type if item.batch else DEFAULT_BUSINESS_TYPE,
        "group_tag": item.batch.group_tag if item.batch else DEFAULT_GROUP_TAG,
        "created_at": format_time_text(item.created_at),
        "extracted_at": format_time_text(item.extracted_at),
        "can_download": item.extract_status == "EXTRACTED",
    }


def file_detail_payload(item: FileRecord, raw_payload: dict | None, owner_id: int | None, business_type: str, group_tag: str) -> dict:
    scope = scoped_route_params(owner_id, business_type, group_tag)
    bound_cdkey = item.bound_cdkey
    return {
        **file_item_payload(item),
        "file_size": int(item.file_size or 0),
        "file_size_text": file_size_text(item.file_size),
        "file_ext": item.file_ext,
        "business_type": item.business_type,
        "group_tag": item.group_tag,
        "bound_at": format_time_text(item.bound_at),
        "owner": {
            "id": item.owner.id if item.owner else None,
            "username": item.owner.username if item.owner else "",
        },
        "bound_cdkey": ({
            "id": bound_cdkey.id,
            "code": bound_cdkey.code,
            "extract_status": bound_cdkey.extract_status,
            "extract_status_text": cdkey_status_text(bound_cdkey.extract_status),
            "extraction_no": bound_cdkey.extraction_no or "",
            "batch_no": bound_cdkey.batch.batch_no if bound_cdkey.batch else "",
        } if bound_cdkey else None),
        "payload": file_payload_summary(raw_payload),
        "download_url": url_for("main.download_file", file_id=item.id, **scope),
    }


def cdkey_detail_payload(item: Cdkey, files: list[FileRecord], owner_id: int | None, business_type: str, group_tag: str) -> dict:
    scope = scoped_route_params(owner_id, business_type, group_tag)
    batch = item.batch
    return {
        **cdkey_item_payload(item),
        "first_extract_ip": item.first_extract_ip or "",
        "download_url": url_for("main.admin_cdkey_download", cdkey_id=item.id, **scope) if item.extract_status == "EXTRACTED" else "",
        "batch": ({
            "id": batch.id,
            "batch_no": batch.batch_no,
            "prefix": batch.prefix,
            "key_date": batch.key_date,
            "total_count": batch.total_count,
            "files_per_key": batch.files_per_key,
            "remark": batch.remark or "",
            "business_type": batch.business_type,
            "group_tag": batch.group_tag,
            "created_at": format_time_text(batch.created_at),
            "owner_username": batch.owner.username if batch.owner else "",
        } if batch else None),
        "files": [file_item_payload(file_item) for file_item in files],
        "bound_files_count": len(files),
    }


def audit_cdkey_code_map(session_db, items: list[AuditLog]) -> dict[int, str]:
    cdkey_ids: set[int] = set()
    for item in items:
        if item.target_type not in {"cdkey", "卡密"}:
            continue
        for part in str(item.target_id or "").split(","):
            value = part.strip()
            if value.isdigit():
                cdkey_ids.add(int(value))
    if not cdkey_ids:
        return {}
    return {
        row.id: row.code
        for row in session_db.query(Cdkey.id, Cdkey.code).filter(Cdkey.id.in_(cdkey_ids)).all()
    }


def audit_item_payload(item: AuditLog, cdkey_code_map: dict[int, str] | None = None) -> dict:
    return {
        "id": item.id,
        "username": item.username or "系统",
        "action": item.action,
        "target_type": item.target_type or "-",
        "target_text": audit_target_text(item, cdkey_code_map),
        "detail": item.detail or "",
        "ip": item.ip or "-",
        "created_at": format_time_text(item.created_at),
    }


def job_summary_payload(item: dict) -> dict:
    job = dict(item or {})
    events = list(job.get("events") or [])
    result_rows = [
        {**row, "quota": quota_display_text(row.get("quota"))}
        for row in list(job.get("result_rows") or [])
    ]
    result_rows = sort_items_by_quota_desc(result_rows)
    live_check_result_rows = [
        {**row, "quota": quota_display_text(row.get("quota"))}
        for row in list(job.get("live_check_result_rows") or [])
    ]
    job_operation_time = job.get("operation_time") or job.get("completed_at") or job.get("updated_at") or ""
    if job.get("kind") in {"upload", "file_download", "file_delete"}:
        result_rows = [
            {
                **row,
                "operation_time": row.get("operation_time") or job_operation_time or "-",
            }
            for row in result_rows
        ]
    return {
        "id": job.get("id"),
        "kind": job.get("kind") or "",
        "status": job.get("status") or "",
        "phase": job.get("phase") or "",
        "processed": int(job.get("processed") or job.get("checked") or 0),
        "total": int(job.get("total") or job.get("needed") or 0),
        "success": int(job.get("success") or job.get("alive") or 0),
        "failure": int(job.get("failure") or job.get("dead") or 0),
        "skipped": int(job.get("skipped") or 0),
        "overwrite": int(job.get("overwrite") or 0),
        "workers": int(job.get("workers") or 0),
        "current_file": job.get("current_file") or "",
        "latest_quota": quota_display_text(job.get("latest_quota")) if job.get("latest_quota") else "",
        "latest_rt_ms": job.get("latest_rt_ms"),
        "health_status": job.get("health_status") or "",
        "error": job.get("error") or "",
        "cancel_requested": bool(job.get("cancel_requested")),
        "live_check_total": int(job.get("live_check_total") or 0),
        "live_check_checked": int(job.get("live_check_checked") or 0),
        "live_check_alive": int(job.get("live_check_alive") or 0),
        "live_check_dead": int(job.get("live_check_dead") or 0),
        "live_check_skipped": int(job.get("live_check_skipped") or 0),
        "batch_id": job.get("batch_id"),
        "batch_no": job.get("batch_no") or "",
        "extraction_no": job.get("extraction_no") or "",
        "created_at": job.get("created_at") or "",
        "started_at": job.get("started_at") or "",
        "completed_at": job.get("completed_at") or "",
        "updated_at": job.get("updated_at") or "",
        "operation_time": job_operation_time,
        "download_ready": bool(job.get("download_ready")),
        "download_url": job.get("download_url") or "",
        "download_filename": job.get("download_filename") or "",
        "events": events[-30:],
        "live_check_result_rows": live_check_result_rows if job.get("kind") == "query_reauth" else live_check_result_rows[-200:],
        "result_rows": result_rows[-200:],
    }


def user_row_payload(item: AdminUser) -> dict:
    return {
        "id": item.id,
        "username": item.username,
        "enabled": bool(item.enabled),
        "is_admin": bool(item.is_admin),
        "last_login_at": format_time_text(item.last_login_at),
        "created_at": format_time_text(item.created_at),
        "cdkey_prefix": item.cdkey_prefix,
        "over_issue_files": int(item.over_issue_files or 0),
        "must_change_password": item.login_password == "must_change",
    }


def settings_payload(session_db) -> dict:
    return {
        "live_check_timeout": get_setting(session_db, LIVE_CHECK_TIMEOUT_KEY, "10"),
        "live_check_user_agent": get_setting(session_db, LIVE_CHECK_USER_AGENT_KEY, "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"),
        "unshippable_http_statuses": list(unshippable_http_statuses(session_db)),
        "task_workers": get_setting(session_db, TASK_WORKERS_KEY, str(DEFAULT_LIVE_CHECK_WORKERS)),
        "query_totp_enabled": query_totp_enabled(session_db),
        "business_type_options": business_type_options(),
    }


def normalize_job_for_storage(job: dict) -> dict:
    payload = dict(job or {})
    payload.pop("reauth_results", None)
    payload.pop("reauth_inputs", None)
    payload["events"] = list(payload.get("events") or [])[-30:]
    result_rows = list(payload.get("result_rows") or [])
    payload["result_rows"] = result_rows[-200:]
    live_check_result_rows = list(payload.get("live_check_result_rows") or [])
    payload["live_check_result_rows"] = (
        live_check_result_rows
        if payload.get("kind") == "query_reauth"
        else live_check_result_rows[-200:]
    )
    extracted_files = list(payload.get("extracted_files") or [])
    payload["extracted_files"] = extracted_files[-500:]
    return payload


def job_int_list(job: dict | None, key: str) -> list[int]:
    if not isinstance(job, dict):
        return []
    values = job.get(key) or []
    if not isinstance(values, list):
        return []
    result: list[int] = []
    for item in values:
        try:
            result.append(int(item))
        except (TypeError, ValueError):
            continue
    return result


def active_protected_checking_file_ids(exclude_job_id: str | None = None) -> set[int]:
    protected: set[int] = set()
    excluded = str(exclude_job_id or "")
    with JOBS_LOCK:
        active_jobs = [
            dict(item)
            for item in EXTRACTION_JOBS.values()
            if item.get("status") in {"queued", "running"}
        ]
    for job in active_jobs:
        if excluded and str(job.get("id") or "") == excluded:
            continue
        if job.get("kind") == "file_live_check":
            protected.update(job_int_list(job, "file_ids"))
        elif job.get("kind") == "query_access":
            protected.update(job_int_list(job, "locked_file_ids"))
    return protected


def parse_full_clock_datetime(value: str | None) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def active_job_started_at(job: dict) -> datetime | None:
    return parse_full_clock_datetime(job.get("started_at")) or parse_full_clock_datetime(job.get("created_at"))


def active_job_timeout_reason(job: dict) -> str | None:
    timeout_seconds = int(ACTIVE_JOB_TIMEOUT_SECONDS.get(str(job.get("kind") or ""), 0) or 0)
    if timeout_seconds <= 0:
        return None
    started_at = active_job_started_at(job)
    if started_at is None:
        return None
    now = datetime.now(APP_TIMEZONE).replace(tzinfo=None)
    if now < started_at + timedelta(seconds=timeout_seconds):
        return None
    minutes = max(1, timeout_seconds // 60)
    return f"任务执行超时：超过 {minutes} 分钟，已自动终止"


def request_job_cancel(job_id: str, reason: str, phase: str = "正在终止任务") -> dict | None:
    snapshot = None
    already_requested = False
    with JOBS_LOCK:
        job = EXTRACTION_JOBS.get(job_id)
        if not job or job.get("status") not in {"queued", "running"}:
            return None
        already_requested = bool(job.get("cancel_requested"))
        if not already_requested:
            job["cancel_requested"] = True
            job["cancel_reason"] = reason
            job["cancel_requested_at"] = full_clock_text()
            if phase:
                job["phase"] = phase
            events = job.setdefault("events", [])
            events.append({"time": full_clock_text(), "text": reason})
            del events[:-30]
            job["updated_at"] = full_clock_text()
        snapshot = dict(job)
        if snapshot.get("events"):
            snapshot["events"] = list(snapshot["events"])
    if snapshot is not None and not already_requested:
        persist_job_snapshot(snapshot)
    return snapshot


def ensure_active_job_runnable(job_id: str) -> None:
    reason = None
    created_snapshot = None
    with JOBS_LOCK:
        job = EXTRACTION_JOBS.get(job_id)
        if not job or job.get("status") not in {"queued", "running"}:
            return
        if job.get("cancel_requested"):
            reason = str(job.get("cancel_reason") or "管理员手动终止任务")
        else:
            timeout_reason = active_job_timeout_reason(job)
            if timeout_reason:
                job["cancel_requested"] = True
                job["cancel_reason"] = timeout_reason
                job["cancel_requested_at"] = full_clock_text()
                job["phase"] = "任务执行超时，正在停止"
                events = job.setdefault("events", [])
                events.append({"time": full_clock_text(), "text": timeout_reason})
                del events[:-30]
                job["updated_at"] = full_clock_text()
                created_snapshot = dict(job)
                if created_snapshot.get("events"):
                    created_snapshot["events"] = list(created_snapshot["events"])
                reason = timeout_reason
    if created_snapshot is not None:
        persist_job_snapshot(created_snapshot)
    if reason:
        raise TaskAbortError(reason)


def finalize_active_job_abort(session_db, job_id: str, reason: str) -> None:
    with JOBS_LOCK:
        job = dict(EXTRACTION_JOBS.get(job_id) or {})
        if job.get("events"):
            job["events"] = list(job["events"])
    if not job:
        return
    kind = str(job.get("kind") or "")
    if kind == "query_access":
        released_files, released_cdkeys = release_query_job_locks(session_db, job, allow_scope_fallback=False)
        if released_files or released_cdkeys:
            error_text = f"{reason}，已释放任务锁定状态，请重新发起。"
        else:
            error_text = f"{reason}，未定位到可释放的任务锁；如仍有文件显示提取中，请按范围手动恢复。"
    elif kind == "file_live_check":
        released_files = release_file_live_check_locks(session_db, job, allow_scope_fallback=False)
        if released_files:
            error_text = f"{reason}，已释放测活锁定状态，请重新发起。"
        else:
            error_text = f"{reason}，未定位到可释放的测活锁；如仍有文件显示测活中，请按范围手动恢复。"
    else:
        error_text = reason
    session_db.commit()
    phase = "任务执行超时" if "超时" in reason else "任务已中断"
    update_job(job_id, status="error", phase=phase, error=error_text)
    append_job_event(job_id, reason)


def read_job_history() -> list[dict]:
    if not JOB_HISTORY_PATH.exists():
        return []
    try:
        data = json.loads(JOB_HISTORY_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def write_job_history(items: list[dict]) -> None:
    JOB_HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    limited = [item for item in items if isinstance(item, dict)][:JOB_HISTORY_LIMIT]
    last_error: OSError | None = None
    for attempt in range(3):
        tmp_path = JOB_HISTORY_PATH.with_name(f"{JOB_HISTORY_PATH.stem}.{os.getpid()}.{uuid4().hex}.tmp")
        try:
            tmp_path.write_text(json.dumps(limited, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp_path.replace(JOB_HISTORY_PATH)
            return
        except OSError as exc:
            last_error = exc
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            time.sleep(0.05 * (attempt + 1))
    if last_error:
        raise last_error


def release_query_job_locks(session_db, job: dict, allow_scope_fallback: bool = False) -> tuple[int, int]:
    released_files = 0
    released_cdkeys = 0
    locked_cdkey_ids = job_int_list(job, "locked_cdkey_ids")
    locked_file_ids = job_int_list(job, "locked_file_ids")
    codes = [str(code or "").strip() for code in (job.get("codes") or []) if str(code or "").strip()]
    cdkeys = session_db.query(Cdkey).filter(Cdkey.code.in_(codes)).all() if codes else []
    if not locked_cdkey_ids and cdkeys:
        locked_cdkey_ids = [int(item.id) for item in cdkeys]
    if locked_file_ids:
        for id_chunk in chunk_list(locked_file_ids):
            released_files += (
                session_db.query(FileRecord)
                .filter(
                    FileRecord.id.in_(id_chunk),
                    FileRecord.status == "CHECKING",
                    FileRecord.bound_cdkey_id.is_(None),
                )
                .update({"status": "AVAILABLE"}, synchronize_session=False)
            )
    elif allow_scope_fallback and cdkeys:
        seen_scopes: set[tuple[int | None, str, str]] = set()
        for item in cdkeys:
            scope = (
                item.batch.created_by,
                normalize_business_type(item.batch.business_type),
                normalize_group_tag(item.batch.group_tag),
            )
            if scope in seen_scopes:
                continue
            seen_scopes.add(scope)
            owner_id, business_type, group_tag = scope
            query = session_db.query(FileRecord).filter(
                FileRecord.status == "CHECKING",
                FileRecord.bound_cdkey_id.is_(None),
                FileRecord.business_type == business_type,
                FileRecord.group_tag == group_tag,
            )
            if owner_id is None:
                query = query.filter(FileRecord.uploaded_by.is_(None))
            else:
                query = query.filter(FileRecord.uploaded_by == owner_id)
            released_files += query.update({"status": "AVAILABLE"}, synchronize_session=False)
    if locked_cdkey_ids:
        for id_chunk in chunk_list(locked_cdkey_ids):
            released_cdkeys += (
                session_db.query(Cdkey)
                .filter(Cdkey.id.in_(id_chunk), Cdkey.extract_status == "CHECKING")
                .update({"extract_status": "PENDING"}, synchronize_session=False)
            )
    return released_files, released_cdkeys


def release_file_live_check_locks(session_db, job: dict, allow_scope_fallback: bool = False) -> int:
    file_ids = job_int_list(job, "file_ids")
    released_files = 0
    if file_ids:
        for id_chunk in chunk_list(file_ids):
            released_files += (
                session_db.query(FileRecord)
                .filter(
                    FileRecord.id.in_(id_chunk),
                    FileRecord.status == "CHECKING",
                    FileRecord.bound_cdkey_id.is_(None),
                )
                .update({"status": "AVAILABLE", "bound_cdkey_id": None, "bound_at": None}, synchronize_session=False)
            )
        return released_files
    if not allow_scope_fallback:
        return 0
    business_type = normalize_business_type(job.get("business_type"))
    group_tag = normalize_group_tag(job.get("group_tag"))
    owner_id = job.get("owner_id")
    query = session_db.query(FileRecord).filter(
        FileRecord.status == "CHECKING",
        FileRecord.bound_cdkey_id.is_(None),
        FileRecord.business_type == business_type,
        FileRecord.group_tag == group_tag,
    )
    if owner_id is None:
        query = query.filter(FileRecord.uploaded_by.is_(None))
    else:
        query = query.filter(FileRecord.uploaded_by == owner_id)
    return query.update({"status": "AVAILABLE", "bound_cdkey_id": None, "bound_at": None}, synchronize_session=False)


def interrupt_persisted_job(session_db, job: dict, reason: str, allow_scope_fallback: bool = False) -> bool:
    if job.get("status") not in {"queued", "running"}:
        return False
    now_text = full_clock_text()
    job_id = str(job.get("id") or "")
    if job.get("kind") == "query_access":
        codes = [str(code or "").strip() for code in (job.get("codes") or []) if str(code or "").strip()]
        cdkeys = session_db.query(Cdkey).filter(Cdkey.code.in_(codes)).all() if codes else []
        cdkey_ids = [int(item.id) for item in cdkeys]
        needed = sum(int(item.files_per_key or 0) for item in cdkeys)
        bound_count = session_db.query(FileRecord).filter(FileRecord.bound_cdkey_id.in_(cdkey_ids)).count() if cdkey_ids else 0
        if cdkeys and all(item.extract_status == "EXTRACTED" for item in cdkeys) and bound_count >= needed:
            job.update(
                status="done",
                phase="测活完成" if job.get("live_check", True) else "出库完成",
                cdkey_ids=cdkey_ids,
                alive=bound_count,
                checked=max(int(job.get("checked") or 0), bound_count),
                needed=needed,
                result_url=f"/query/result?job_id={job_id}",
                completed_at=job.get("completed_at") or now_text,
                updated_at=now_text,
            )
        else:
            released_files, released_cdkeys = release_query_job_locks(
                session_db,
                job,
                allow_scope_fallback=allow_scope_fallback,
            )
            if released_files or released_cdkeys:
                error_text = f"{reason}，已释放任务锁定状态，请重新发起。"
            else:
                error_text = f"{reason}，未定位到本任务锁定文件；若文件仍显示提取中，请在文件池按范围手动恢复。"
            job.update(
                status="error",
                phase="任务已中断",
                error=error_text,
                completed_at=job.get("completed_at") or now_text,
                updated_at=now_text,
            )
        return True
    if job.get("kind") == "file_live_check":
        released_files = release_file_live_check_locks(
            session_db,
            job,
            allow_scope_fallback=allow_scope_fallback,
        )
        if released_files:
            error_text = f"{reason}，已释放测活锁定状态，请重新发起。"
        else:
            error_text = f"{reason}，未定位到本任务锁定文件；若文件仍显示测活中，请在文件池按范围手动恢复。"
        job.update(
            status="error",
            phase="任务已中断",
            error=error_text,
            completed_at=job.get("completed_at") or now_text,
            updated_at=now_text,
        )
        return True
    job.update(
        status="error",
        phase="任务已终止",
        error=reason,
        completed_at=job.get("completed_at") or now_text,
        updated_at=now_text,
    )
    return True


def recover_interrupted_jobs() -> None:
    if not JOB_HISTORY_PATH.exists():
        return
    with JOB_HISTORY_LOCK:
        history = read_job_history()
        changed = False
        session_db = SessionLocal()
        try:
            interrupted = [
                dict(item)
                for item in history
                if item.get("status") in {"queued", "running"}
                and item.get("kind") in {"query_access", "file_live_check", "query_reauth"}
            ]
            if not interrupted:
                return
            for job in interrupted:
                changed = interrupt_persisted_job(
                    session_db,
                    job,
                    "服务重启或任务线程中断",
                    allow_scope_fallback=True,
                ) or changed
            if changed:
                by_id = {str(item.get("id") or ""): item for item in interrupted if item.get("id")}
                next_history = [by_id.get(str(item.get("id") or ""), item) for item in history]
                session_db.commit()
                write_job_history(next_history)
        except Exception as exc:
            session_db.rollback()
            LOGGER.warning("interrupted job recovery skipped: %s", exc)
        finally:
            session_db.close()


def persist_job_snapshot(job: dict | None) -> None:
    if not job or not job.get("id"):
        return
    try:
        with JOB_HISTORY_LOCK:
            snapshot = normalize_job_for_storage(job)
            history = [item for item in read_job_history() if item.get("id") != snapshot.get("id")]
            history.insert(0, snapshot)
            write_job_history(history)
    except OSError as exc:
        LOGGER.warning("task history snapshot skipped: %s", exc)


def persist_job_snapshot_throttled(job: dict | None, force: bool = False) -> None:
    if not job or not job.get("id"):
        return
    job_id = str(job.get("id"))
    now = time.monotonic()
    if not force and now - JOB_HISTORY_LAST_PERSIST.get(job_id, 0) < JOB_HISTORY_PERSIST_INTERVAL:
        return
    JOB_HISTORY_LAST_PERSIST[job_id] = now
    persist_job_snapshot(job)


def register_job(job: dict, exclusive_cdkey_ids: list[int] | None = None) -> dict | None:
    now_text = full_clock_text()
    if not job.get("created_at") or len(str(job.get("created_at"))) <= 8:
        job["created_at"] = now_text
    if not job.get("updated_at") or len(str(job.get("updated_at"))) <= 8:
        job["updated_at"] = job.get("created_at") or now_text
    requested_ids = {int(item) for item in (exclusive_cdkey_ids or [])}
    with JOBS_LOCK:
        if requested_ids:
            for item in EXTRACTION_JOBS.values():
                if item.get("kind") != "query_reauth" or item.get("status") not in {"queued", "running"}:
                    continue
                active_ids = set(job_int_list(item, "cdkey_ids"))
                if requested_ids.intersection(active_ids):
                    return dict(item)
        EXTRACTION_JOBS[job["id"]] = job
        snapshot = dict(job)
        if snapshot.get("events"):
            snapshot["events"] = list(snapshot["events"])
    persist_job_snapshot(snapshot)
    return None


def job_matches_scope(job: dict, business_type: str | None, group_tag: str | None = None) -> bool:
    if not business_type:
        return True
    expected_business = normalize_business_type(business_type)
    expected_tag = normalize_group_tag(group_tag)
    job_business = str(job.get("business_type") or "").strip()
    job_tag = str(job.get("group_tag") or "").strip()
    if not job_business:
        return expected_business == DEFAULT_BUSINESS_TYPE
    if normalize_business_type(job_business) != expected_business:
        return False
    if job_tag and normalize_group_tag(job_tag) != expected_tag:
        return False
    return True


def job_time_text(job: dict) -> str:
    return str(job.get("operation_time") or job.get("updated_at") or job.get("completed_at") or job.get("started_at") or job.get("created_at") or "")


def job_matches_filters(job: dict, day: date | None = None, kind: str | None = None, status: str | None = None) -> bool:
    if day and not job_time_text(job).startswith(day.isoformat()):
        return False
    if kind and str(job.get("kind") or "") != kind:
        return False
    if status and str(job.get("status") or "") != status:
        return False
    return True


def admin_can_manage_job(user: AdminUser | None, job: dict | None) -> bool:
    if not user or not isinstance(job, dict):
        return False
    owner_id = job.get("user_id")
    if owner_id == user.id:
        return True
    return bool(user.is_admin and owner_id is None and job.get("kind") == "query_reauth")


def jobs_for_user(
    user_id: int | None,
    limit: int = 50,
    business_type: str | None = None,
    group_tag: str | None = None,
    day: date | None = None,
    kind: str | None = None,
    status: str | None = None,
    include_guest_reauth: bool = False,
) -> list[dict]:
    if not user_id:
        return []
    merged: dict[str, dict] = {}
    for item in read_job_history():
        guest_reauth = bool(include_guest_reauth and item.get("user_id") is None and item.get("kind") == "query_reauth")
        if (
            (item.get("user_id") == user_id or guest_reauth)
            and item.get("id")
            and (guest_reauth or job_matches_scope(item, business_type, group_tag))
            and job_matches_filters(item, day, kind, status)
        ):
            merged[str(item["id"])] = item
    with JOBS_LOCK:
        for item in EXTRACTION_JOBS.values():
            guest_reauth = bool(include_guest_reauth and item.get("user_id") is None and item.get("kind") == "query_reauth")
            if (
                (item.get("user_id") == user_id or guest_reauth)
                and item.get("id")
                and (guest_reauth or job_matches_scope(item, business_type, group_tag))
                and job_matches_filters(item, day, kind, status)
            ):
                snapshot = dict(item)
                if snapshot.get("events"):
                    snapshot["events"] = list(snapshot["events"])
                merged[str(snapshot["id"])] = snapshot
    jobs = sorted(
        merged.values(),
        key=lambda item: (job_time_text(item), item.get("updated_at") or "", item.get("id") or ""),
        reverse=True,
    )
    jobs = [job_summary_payload(item) for item in jobs]
    return jobs[:limit]


def find_running_query_job_for_codes(codes: list[str]) -> dict | None:
    requested = {str(code or "").strip() for code in codes if str(code or "").strip()}
    if not requested:
        return None
    candidates: list[dict] = []
    with JOBS_LOCK:
        for item in EXTRACTION_JOBS.values():
            if item.get("kind") == "query_access" and item.get("status") in {"queued", "running"}:
                candidates.append(dict(item))
    for item in read_job_history():
        if item.get("kind") == "query_access" and item.get("status") in {"queued", "running"}:
            candidates.append(dict(item))
    for job in candidates:
        job_codes = set(str(code or "").strip() for code in (job.get("codes") or []) if str(code or "").strip())
        if job_codes and requested.intersection(job_codes):
            return job
    return None


def find_running_query_reauth_job_for_cdkeys(cdkey_ids: list[int]) -> dict | None:
    requested = {int(item) for item in (cdkey_ids or [])}
    if not requested:
        return None
    candidates: dict[str, dict] = {}
    with JOBS_LOCK:
        for item in EXTRACTION_JOBS.values():
            if item.get("kind") == "query_reauth" and item.get("status") in {"queued", "running"} and item.get("id"):
                candidates[str(item["id"])] = dict(item)
    for job in sorted(candidates.values(), key=job_time_text, reverse=True):
        active_ids = set(job_int_list(job, "cdkey_ids"))
        if requested.intersection(active_ids):
            return job
    return None


def latest_query_reauth_job(source_job_id: str) -> dict | None:
    matches: dict[str, dict] = {}
    for item in read_job_history():
        if item.get("kind") == "query_reauth" and item.get("source_job_id") == source_job_id and item.get("id"):
            matches[str(item["id"])] = dict(item)
    with JOBS_LOCK:
        for item in EXTRACTION_JOBS.values():
            if item.get("kind") == "query_reauth" and item.get("source_job_id") == source_job_id and item.get("id"):
                matches[str(item["id"])] = dict(item)
    if not matches:
        return None
    return max(matches.values(), key=lambda item: (job_time_text(item), str(item.get("id") or "")))


def job_payload(job_id: str, expected_kind: str | None = None, allow_public: bool = False) -> dict | None:
    with JOBS_LOCK:
        job = dict(EXTRACTION_JOBS.get(job_id) or {})
        if job.get("events"):
            job["events"] = list(job["events"])
    if not job:
        for item in read_job_history():
            if item.get("id") == job_id:
                job = dict(item)
                break
    if not job:
        return None
    if expected_kind and job.get("kind") != expected_kind:
        return None
    user = current_user()
    owner_id = job.get("user_id")
    if user:
        if owner_id is None and not allow_public:
            return None
        if owner_id is not None and owner_id != user.id:
            return None
    elif owner_id is not None and not allow_public:
        return None
    return job


def query_job_cdkey_ids(job: dict) -> list[int]:
    ids = [int(item) for item in (job.get("cdkey_ids") or []) if str(item).isdigit()]
    if ids:
        return ids
    codes = [str(code or "").strip() for code in (job.get("codes") or []) if str(code or "").strip()]
    if not codes:
        return []
    rows = db().query(Cdkey.id, Cdkey.code).filter(Cdkey.code.in_(codes)).all()
    id_by_code = {row.code: int(row.id) for row in rows}
    return [id_by_code[code] for code in codes if code in id_by_code]


def scoped_query_cdkey_ids(job: dict) -> list[int] | None:
    allowed_ids = session_int_list(QUERY_ACCESS_CDKEY_IDS_SESSION_KEY)
    session_matches_job = (
        session.get(QUERY_ACCESS_JOB_SESSION_KEY) == job.get("id")
        or session.get("query_pending_job_id") == job.get("id")
        or session.get("query_job_id") == job.get("id")
    )
    if not allowed_ids and session_matches_job:
        fallback_ids = session_int_list("query_cdkey_ids")
        if fallback_ids:
            allowed_ids = fallback_ids
        elif session.get(QUERY_ACCESS_TOKEN_SESSION_KEY):
            return []
    if not allowed_ids:
        return None
    job_ids = query_job_cdkey_ids(job)
    if not job_ids:
        return allowed_ids
    allowed_set = set(allowed_ids)
    return [item for item in job_ids if item in allowed_set]


def public_query_job_payload(job: dict) -> dict:
    scoped_ids = scoped_query_cdkey_ids(job)
    if scoped_ids is None:
        return job
    job_ids = query_job_cdkey_ids(job)
    if job_ids and set(job_ids).issubset(set(scoped_ids)):
        return job
    scoped = dict(job)
    if scoped.get("events"):
        scoped["events"] = list(scoped["events"])
    rows = db().query(Cdkey).filter(Cdkey.id.in_(scoped_ids)).all() if scoped_ids else []
    by_id = {int(item.id): item for item in rows}
    cdkeys = [by_id[item_id] for item_id in scoped_ids if item_id in by_id]
    needed = sum(int(item.files_per_key or 0) for item in cdkeys)
    live_check = bool(scoped.get("live_check", True))
    scoped["cdkey_ids"] = [int(item.id) for item in cdkeys]
    scoped["codes"] = [item.code for item in cdkeys]
    scoped["code_count"] = len(cdkeys)
    scoped["existing_count"] = sum(1 for item in cdkeys if item.extract_status == "EXTRACTED")
    scoped["needed"] = needed
    scoped["display_needed"] = needed
    scoped_files = extracted_files_for_cdkeys(scoped["cdkey_ids"], live_check)
    metadata_by_email = {
        str(item.get("email") or "").strip().lower(): item
        for item in list(job.get("extracted_files") or [])
        if isinstance(item, dict) and item.get("email")
    }
    for item in scoped_files:
        metadata = metadata_by_email.get(str(item.get("email") or "").strip().lower(), {})
        item["quota_period"] = metadata.get("quota_period") or item.get("quota_period") or "暂无"
        item["plan_type"] = metadata.get("plan_type") or item.get("plan_type") or "暂无"
    scoped["extracted_files"] = scoped_files
    scoped["alive"] = len(scoped["extracted_files"])
    return scoped


def json_payload() -> dict:
    payload = request.get_json(silent=True)
    return payload if isinstance(payload, dict) else {}


def list_int_payload(payload: dict, key: str) -> list[int]:
    values = payload.get(key) or []
    if not isinstance(values, list):
        return []
    return [int(item) for item in values if str(item).isdigit()]


def chunk_list(values: list[int], size: int = SQL_IN_CHUNK_SIZE):
    for index in range(0, len(values), size):
        yield values[index:index + size]


def query_session_payload() -> dict:
    return {
        "inventory": public_inventory(),
        "totp_enabled": query_totp_enabled(db()),
        "pending_job_id": session.get("query_pending_job_id"),
        "job_id": session.get("query_job_id"),
        "cdkey_ids": session_int_list("query_cdkey_ids"),
        "access_token": session.get(QUERY_ACCESS_TOKEN_SESSION_KEY) or "",
    }


def update_job(job_id: str, persist: bool = True, throttle: bool = False, **changes) -> None:
    snapshot = None
    with JOBS_LOCK:
        job = EXTRACTION_JOBS.get(job_id)
        if not job:
            return
        job.update(changes)
        job["updated_at"] = full_clock_text()
        if job.get("status") == "running" and not job.get("started_at"):
            job["started_at"] = full_clock_text()
        if job.get("status") in {"done", "error"} and not job.get("completed_at"):
            job["completed_at"] = full_clock_text()
        snapshot = dict(job)
        if snapshot.get("events"):
            snapshot["events"] = list(snapshot["events"])
    if persist:
        if throttle:
            persist_job_snapshot_throttled(snapshot)
        else:
            persist_job_snapshot(snapshot)


def extend_job_int_list(job_id: str, key: str, values: list[int], throttle: bool = False) -> None:
    additions = []
    for item in values or []:
        try:
            additions.append(int(item))
        except (TypeError, ValueError):
            continue
    if not additions:
        return
    snapshot = None
    with JOBS_LOCK:
        job = EXTRACTION_JOBS.get(job_id)
        if not job:
            return
        current = job_int_list(job, key)
        job[key] = list(dict.fromkeys(current + additions))
        job["updated_at"] = full_clock_text()
        snapshot = dict(job)
        if snapshot.get("events"):
            snapshot["events"] = list(snapshot["events"])
    if throttle:
        persist_job_snapshot_throttled(snapshot)
    else:
        persist_job_snapshot(snapshot)


def append_job_event(job_id: str, text: str, throttle: bool = False) -> None:
    snapshot = None
    with JOBS_LOCK:
        job = EXTRACTION_JOBS.get(job_id)
        if not job:
            return
        events = job.setdefault("events", [])
        events.append({"time": full_clock_text(), "text": text})
        del events[:-30]
        job["updated_at"] = full_clock_text()
        snapshot = dict(job)
        snapshot["events"] = list(events)
    if throttle:
        persist_job_snapshot_throttled(snapshot)
    else:
        persist_job_snapshot(snapshot)


def update_query_reauth_account_progress(job_id: str, email: str, log_text: str = "", **changes) -> None:
    email = str(email or "").strip()
    if not email:
        return
    now_text = full_clock_text()
    snapshot = None
    with JOBS_LOCK:
        job = EXTRACTION_JOBS.get(job_id)
        if not job:
            return
        rows = job.setdefault("live_check_result_rows", [])
        email_key = email.lower()
        row = next(
            (item for item in rows if str(item.get("email") or "").strip().lower() == email_key),
            None,
        )
        if row is None:
            row = {"email": email}
            rows.append(row)
        row.update(changes)
        if log_text:
            progress_logs = row.setdefault("progress_logs", [])
            progress_logs.append({"time": now_text, "text": str(log_text)})
            del progress_logs[:-30]
            row["progress_log"] = str(log_text)
            row["progress_time"] = now_text
        job["updated_at"] = now_text
        snapshot = dict(job)
        snapshot["live_check_result_rows"] = [
            {
                **item,
                "progress_logs": list(item.get("progress_logs") or []),
            }
            for item in rows
        ]
        if snapshot.get("events"):
            snapshot["events"] = list(snapshot["events"])
    persist_job_snapshot_throttled(snapshot)


def append_extracted_files(job_id: str, files: list[dict], throttle: bool = False) -> None:
    if not files:
        return
    snapshot = None
    with JOBS_LOCK:
        job = EXTRACTION_JOBS.get(job_id)
        if not job:
            return
        current = job.setdefault("extracted_files", [])
        existing = {
            str(item.get("email") or "").lower(): item
            for item in current
            if isinstance(item, dict)
        }
        for item in files:
            email = str(item.get("email") or "").strip()
            if not email:
                continue
            key = email.lower()
            if key in existing:
                existing[key]["quota"] = quota_display_text(item.get("quota") or existing[key].get("quota"))
                existing[key]["status"] = str(item.get("status") or existing[key].get("status") or "已出库")
                for field in ("quota_period", "plan_type"):
                    value = str(item.get(field) or "").strip()
                    if value not in {"", "-", "暂无"}:
                        existing[key][field] = value
                    else:
                        existing[key][field] = str(existing[key].get(field) or "暂无")
                registered_at = str(item.get("registered_at") or "")
                live_checked_at = str(item.get("live_checked_at") or "")
                http_status = str(item.get("http_status") or "")
                extracted_at = str(item.get("extracted_at") or "")
                if registered_at and registered_at != "-":
                    existing[key]["registered_at"] = registered_at
                else:
                    existing[key]["registered_at"] = str(existing[key].get("registered_at") or "-")
                if live_checked_at and live_checked_at != "-":
                    existing[key]["live_checked_at"] = live_checked_at
                else:
                    existing[key]["live_checked_at"] = str(existing[key].get("live_checked_at") or "-")
                if http_status and http_status != "-":
                    existing[key]["http_status"] = http_status
                else:
                    existing[key]["http_status"] = str(existing[key].get("http_status") or "-")
                if extracted_at and extracted_at != "-":
                    existing[key]["extracted_at"] = extracted_at
                else:
                    existing[key]["extracted_at"] = str(existing[key].get("extracted_at") or "-")
                operation_time = str(item.get("operation_time") or "")
                if operation_time and operation_time != "-":
                    existing[key]["operation_time"] = operation_time
                continue
            current.append({
                "email": email,
                "quota": quota_display_text(item.get("quota")),
                "quota_period": str(item.get("quota_period") or "暂无"),
                "plan_type": str(item.get("plan_type") or "暂无"),
                "status": str(item.get("status") or "已出库"),
                "registered_at": str(item.get("registered_at") or "-"),
                "live_checked_at": str(item.get("live_checked_at") or "-"),
                "http_status": str(item.get("http_status") or "-"),
                "extracted_at": str(item.get("extracted_at") or "-"),
                "operation_time": str(item.get("operation_time") or item.get("extracted_at") or "-"),
            })
            existing[key] = current[-1]
        current.sort(key=lambda item: (-quota_sort_value(item.get("quota")), str(item.get("email") or "")))
        job["updated_at"] = full_clock_text()
        snapshot = dict(job)
        if snapshot.get("events"):
            snapshot["events"] = list(snapshot["events"])
    if throttle:
        persist_job_snapshot_throttled(snapshot)
    else:
        persist_job_snapshot(snapshot)


def sync_extracted_files_from_db(job_id: str, cdkey_ids: list[int], live_check: bool = True) -> None:
    if not cdkey_ids:
        return
    append_extracted_files(job_id, extracted_files_for_cdkeys(cdkey_ids, live_check))


def historical_extraction_metadata(codes: list[str], emails: list[str]) -> dict[str, dict[str, str]]:
    requested_codes = {str(code or "").strip() for code in codes if str(code or "").strip()}
    requested_emails = {str(email or "").strip().lower() for email in emails if str(email or "").strip()}
    if not requested_codes or not requested_emails:
        return {}

    jobs_by_id = {
        str(item.get("id") or ""): dict(item)
        for item in read_job_history()
        if item.get("id")
    }
    with JOBS_LOCK:
        for item in EXTRACTION_JOBS.values():
            if item.get("id"):
                jobs_by_id[str(item["id"])] = dict(item)
    candidates = sorted(jobs_by_id.values(), key=job_time_text, reverse=True)
    metadata_by_email: dict[str, dict[str, str]] = {}
    missing_values = {"", "-", "暂无", "未测活"}
    for job in candidates:
        if job.get("kind") != "query_access" or job.get("status") != "done":
            continue
        job_codes = {str(code or "").strip() for code in (job.get("codes") or []) if str(code or "").strip()}
        if not requested_codes.intersection(job_codes):
            continue
        for item in job.get("extracted_files") or []:
            if not isinstance(item, dict):
                continue
            email = str(item.get("email") or "").strip().lower()
            if email not in requested_emails:
                continue
            metadata = metadata_by_email.setdefault(email, {})
            for field in ("quota_period", "plan_type"):
                value = str(item.get(field) or "").strip()
                if field not in metadata and value not in missing_values:
                    metadata[field] = value
        if all(
            all(field in metadata_by_email.get(email, {}) for field in ("quota_period", "plan_type"))
            for email in requested_emails
        ):
            break
    return metadata_by_email


def extracted_files_for_cdkeys(cdkey_ids: list[int], live_check: bool = True) -> list[dict]:
    if not cdkey_ids:
        return []
    records = bound_files(db(), cdkey_ids)
    payloads = payloads_for_records(db(), records)
    cdkey_by_id = {
        item.id: item
        for item in db().query(Cdkey).filter(Cdkey.id.in_(cdkey_ids)).all()
    }
    files = [
        extracted_file_item(record, payloads.get(record.id, {}), cdkey_by_id.get(record.bound_cdkey_id), live_check)
        for record in records
    ]
    if live_check:
        metadata_by_email = historical_extraction_metadata(
            [item.code for item in cdkey_by_id.values()],
            [record.email_name for record in records],
        )
        for item in files:
            metadata = metadata_by_email.get(str(item.get("email") or "").strip().lower(), {})
            item["quota_period"] = metadata.get("quota_period") or item["quota_period"]
            item["plan_type"] = metadata.get("plan_type") or item["plan_type"]
    return files


def extracted_file_item(record: FileRecord, payload: dict | None, cdkey: Cdkey | None, live_check: bool) -> dict:
    payload = payload or {}
    registered_at = format_time_text(payload.get("last_refresh"))
    if registered_at == "-":
        registered_at = format_time_text(record.upload_time)
    extracted_at = format_time_text(record.bound_at)
    if extracted_at == "-" and cdkey is not None:
        extracted_at = format_time_text(cdkey.extracted_at)
    return {
        "email": record.email_name,
        "quota": quota_display_text(record.live_quota) if record.live_quota else ("未测活" if not live_check else "暂无"),
        "quota_period": "未测活" if not live_check else "暂无",
        "plan_type": "未测活" if not live_check else "暂无",
        "status": "已出库",
        "registered_at": registered_at,
        "live_checked_at": format_time_text(record.live_checked_at),
        "http_status": record.live_http_status or "-",
        "extracted_at": extracted_at,
    }


def extraction_progress_callback(job_id: str):
    def callback(event: dict) -> None:
        if event.get("event") == "start_bulk":
            live_check = event.get("live_check", True)
            phase = "正在合并测活任务" if live_check else "正在准备出库"
            update_job(
                job_id,
                phase=phase,
                needed=event.get("needed", 0),
                workers=event.get("workers", DEFAULT_LIVE_CHECK_WORKERS),
                code_count=event.get("code_count", 0),
                existing_count=event.get("existing_count", 0),
                locked_cdkey_ids=job_int_list({"locked_cdkey_ids": event.get("locked_cdkey_ids") or []}, "locked_cdkey_ids"),
            )
            existing_text = f"，其中 {event.get('existing_count')} 张已提取" if event.get("existing_count") else ""
            target_text = "目标活号" if live_check else "目标文件"
            append_job_event(job_id, f"已合并 {event.get('code_count')} 张卡密，{target_text} {event.get('needed')} 个，并发 {event.get('workers')}{existing_text}。")
        elif event.get("event") == "owner_group":
            update_job(job_id, phase=f"正在统一测活：{event.get('code_count')} 张卡密", needed=event.get("needed", 0), checked=event.get("checked", 0), alive=event.get("alive", 0), dead=event.get("dead", 0))
            append_job_event(job_id, f"开始处理一组文件池，{event.get('code_count')} 张卡密合计需要 {event.get('group_needed') or event.get('needed')} 个活号。")
        elif event.get("event") == "start_code":
            update_job(job_id, phase=f"正在测活：{event.get('code')}", needed=event.get("needed", 0), workers=event.get("workers", DEFAULT_LIVE_CHECK_WORKERS))
            append_job_event(job_id, f"开始测活，目标活号 {event.get('needed')} 个，并发 {event.get('workers')}。")
        elif event.get("event") == "batch":
            extend_job_int_list(job_id, "locked_file_ids", event.get("claimed_file_ids") or [], throttle=True)
            append_job_event(job_id, f"取出 {event.get('candidate_count')} 个候选账号并发测活。")
        elif event.get("event") == "claimed_without_live_check":
            extend_job_int_list(job_id, "locked_file_ids", event.get("claimed_file_ids") or [], throttle=True)
        elif event.get("event") == "checked":
            outcome = event.get("outcome")
            quota_text = quota_label(event.get("quota"))
            quota_period = quota_period_label(event.get("quota"))
            plan_type = plan_type_label(event.get("quota"))
            checked_at = clock_text()
            http_status_text = str(event.get("http_status") or "-")
            if outcome == "alive":
                extracted_at = full_clock_text()
                append_extracted_files(job_id, [{
                    "email": event.get("email"),
                    "quota": quota_text,
                    "quota_period": quota_period,
                    "plan_type": plan_type,
                    "status": "已选中",
                    "registered_at": format_time_text(event.get("registered_at")),
                    "live_checked_at": checked_at,
                    "http_status": http_status_text,
                    "extracted_at": extracted_at,
                    "operation_time": extracted_at,
                }], throttle=True)
            update_job(
                job_id,
                persist=False,
                checked=event.get("checked", 0),
                alive=event.get("alive", 0),
                dead=event.get("dead", 0),
                needed=event.get("needed", 0),
                latest_quota=quota_text,
            )
            with JOBS_LOCK:
                job = EXTRACTION_JOBS.get(job_id)
                snapshot = dict(job) if job else None
                if snapshot and snapshot.get("events"):
                    snapshot["events"] = list(snapshot["events"])
            persist_job_snapshot_throttled(snapshot)
        elif event.get("event") == "bound":
            update_job(job_id, checked=event.get("checked", 0), alive=event.get("alive", event.get("bound", 0)), dead=event.get("dead", 0))
            code_count = event.get("code_count")
            if code_count:
                append_job_event(job_id, f"已为 {code_count} 张卡密绑定出库 {event.get('bound')} 个活号。")
            else:
                append_job_event(job_id, f"已绑定出库 {event.get('bound')} 个活号。")
        elif event.get("event") == "bound_without_live_check":
            append_extracted_files(job_id, event.get("files") or [])
            update_job(
                job_id,
                phase="正在整理结果",
                checked=0,
                alive=event.get("bound", 0),
                dead=0,
                needed=event.get("needed", 0),
                latest_quota="未测活",
            )
            append_job_event(job_id, f"已跳过测活并直接出库 {event.get('bound', 0)} 个文件，不提供测活质保。")
    return callback


def file_live_check_progress_callback(job_id: str):
    def callback(event: dict) -> None:
        if event.get("event") == "start_admin_file_check":
            update_job(
                job_id,
                phase="正在测活文件",
                needed=event.get("total", 0),
                workers=event.get("workers", DEFAULT_LIVE_CHECK_WORKERS),
            )
            append_job_event(job_id, f"开始测活 {event.get('total')} 个文件，并发 {event.get('workers')}。")
        elif event.get("event") == "batch":
            append_job_event(job_id, f"取出 {event.get('candidate_count')} 个文件并发测活。")
        elif event.get("event") == "checked":
            outcome = event.get("outcome")
            quota_text = quota_label(event.get("quota"))
            detail_row = {
                "email": event.get("email") or "-",
                "registered_at": format_time_text(event.get("registered_at")),
                "live_checked_at": format_time_text(event.get("live_checked_at")),
                "quota": quota_text,
                "quota_period": quota_period_label(event.get("quota")),
                "plan_type": plan_type_label(event.get("quota")),
                "http_status": str(event.get("http_status") or "-"),
            }
            if outcome == "alive":
                health_status = "正常"
            elif outcome == "skipped":
                health_status = "跳过"
            else:
                health_status = "异常"
            update_job(
                job_id,
                persist=False,
                checked=event.get("checked", 0),
                alive=event.get("alive", 0),
                dead=event.get("dead", 0),
                skipped=event.get("skipped", 0),
                needed=event.get("needed", 0),
                latest_quota=quota_text,
                latest_rt_ms=event.get("rt_ms"),
                health_status=health_status,
            )
            snapshot = None
            with JOBS_LOCK:
                job = EXTRACTION_JOBS.get(job_id)
                if job is not None:
                    rows = job.setdefault("result_rows", [])
                    key = str(detail_row.get("email") or "").lower()
                    matched = next((row for row in rows if str(row.get("email") or "").lower() == key), None)
                    if matched is not None:
                        matched.update(detail_row)
                    else:
                        rows.append(detail_row)
                    del rows[:-200]
                    job["updated_at"] = full_clock_text()
                    snapshot = dict(job)
                    if snapshot.get("events"):
                        snapshot["events"] = list(snapshot["events"])
            persist_job_snapshot_throttled(snapshot)
    return callback


class DiskUploadFile:
    def __init__(self, filename: str, path):
        self.filename = filename
        self.path = path
        self.stream = open(path, "rb")

    def close(self) -> None:
        self.stream.close()


def upload_progress_callback(job_id: str):
    def callback(event: dict) -> None:
        if event.get("event") == "upload_start":
            update_job(
                job_id,
                phase="正在写入账号字段",
                total=event.get("total", 0),
                workers=event.get("workers", DEFAULT_LIVE_CHECK_WORKERS),
            )
            append_job_event(job_id, f"开始处理 {event.get('total', 0)} 个文件，并发 {event.get('workers', DEFAULT_LIVE_CHECK_WORKERS)}。")
        elif event.get("event") == "upload_item_done":
            success = int(event.get("success") or 0)
            failure = int(event.get("failure") or 0)
            overwrite = int(event.get("overwrite") or 0)
            processed = success + failure
            status = "成功" if event.get("status") == "SUCCESS" else "失败"
            detail_row = {
                "batch_no": event.get("batch_no") or "-",
                "email": event.get("email") or "-",
                "result": status,
                "reason": event.get("message") or "-",
                "operation_time": full_clock_text(),
            }
            update_job(
                job_id,
                persist=False,
                phase=f"正在写入元数据：{status}",
                processed=processed,
                success=success,
                failure=failure,
                overwrite=overwrite,
                current_file=event.get("filename") or event.get("email") or "-",
            )
            snapshot = None
            with JOBS_LOCK:
                job = EXTRACTION_JOBS.get(job_id)
                if job is not None:
                    rows = job.setdefault("result_rows", [])
                    key = str(event.get("email") or event.get("filename") or f"row-{processed}").lower()
                    matched = next((row for row in rows if str(row.get("_key") or "").lower() == key), None)
                    if matched is not None:
                        matched.update(detail_row)
                    else:
                        rows.append({"_key": key, **detail_row})
                    del rows[:-200]
                    job["updated_at"] = full_clock_text()
                    snapshot = dict(job)
                    if snapshot.get("events"):
                        snapshot["events"] = list(snapshot["events"])
            persist_job_snapshot_throttled(snapshot)
    return callback


def run_upload_job(
    job_id: str,
    saved_files: list[dict],
    owner_id: int,
    business_type: str,
    group_tag: str,
    uploaded_by: int | None,
    username: str | None,
    ip: str,
) -> None:
    worker_db = SessionLocal()
    disk_files: list[DiskUploadFile] = []
    temp_dir = DATA_DIR / "upload_jobs" / job_id
    try:
        ensure_active_job_runnable(job_id)
        update_job(job_id, status="running", phase="正在读取上传文件")
        workers = task_workers(worker_db)
        update_job(job_id, workers=workers)
        disk_files = [DiskUploadFile(item["filename"], item["path"]) for item in saved_files]
        summary = upload_payload_files(
            worker_db,
            disk_files,
            owner_id,
            business_type,
            group_tag,
            progress_callback=upload_progress_callback(job_id),
            workers=workers,
            abort_check=lambda: ensure_active_job_runnable(job_id),
        )
        if summary.failure_count:
            raise BusinessError(f"整批上传失败，已取消入库：失败 {summary.failure_count} 个")
        ensure_active_job_runnable(job_id)
        batch = save_upload_batch(worker_db, summary, owner_id, uploaded_by, business_type, group_tag)
        batch_no = upload_batch_no_text(batch)
        with JOBS_LOCK:
            job = EXTRACTION_JOBS.get(job_id)
            current_rows = list((job or {}).get("result_rows") or [])
        if current_rows:
            rows = [{**row, "batch_no": batch_no} for row in current_rows]
        else:
            rows = []
            for item in summary.results:
                rows.append({
                    "_key": str(item.email or item.filename or f"upload-{batch.id}-{len(rows)}").lower(),
                    "batch_no": batch_no,
                    "email": item.email or "-",
                    "result": "成功" if item.status == "SUCCESS" else "失败",
                    "reason": item.message or "-",
                    "operation_time": full_clock_text(),
                })
        worker_db.add(AuditLog(
            user_id=uploaded_by,
            username=username,
            action="UPLOAD_FILES",
            target_type="upload_batch",
            target_id=batch.id,
            ip=ip,
            detail=f"success={summary.success_count}, failure={summary.failure_count}, overwrite={summary.overwrite_count}, business={business_type}, tag={group_tag}, job={job_id}",
        ))
        ensure_active_job_runnable(job_id)
        worker_db.commit()
        update_job(
            job_id,
            status="done",
            phase="上传完成",
            processed=summary.total_count,
            total=summary.total_count,
            success=summary.success_count,
            failure=summary.failure_count,
            overwrite=summary.overwrite_count,
            batch_id=batch.id,
            batch_no=batch_no,
            result_rows=rows,
            result_url=f"/admin/files/uploads/{batch.id}",
        )
        append_job_event(job_id, f"上传完成：批次号 {batch_no}，成功 {summary.success_count} 个，失败 {summary.failure_count} 个，覆盖 {summary.overwrite_count} 个。")
    except TaskAbortError as exc:
        worker_db.rollback()
        finalize_active_job_abort(worker_db, job_id, str(exc))
    except Exception as exc:
        worker_db.rollback()
        error_type = type(exc).__name__
        error_message = "上传处理失败，请重试"
        commit_audit_best_effort(
            worker_db,
            AuditLog(user_id=uploaded_by, username=username, action="UPLOAD_FILES_FAILURE", target_type="upload_batch", ip=ip, detail=f"error_type={error_type}, job={job_id}"),
            "upload failure",
        )
        update_job(job_id, status="error", phase="上传失败", error=error_message)
        append_job_event(job_id, error_message)
    finally:
        for item in disk_files:
            item.close()
        worker_db.close()
        shutil.rmtree(temp_dir, ignore_errors=True)


def file_delete_progress_callback(job_id: str):
    def callback(event: dict) -> None:
        if event.get("event") == "local_delete_done":
            email = event.get("email") or "-"
            detail_row = {
                "email": email,
                "result": "成功" if event.get("success") else "失败",
                "reason": event.get("message") or "-",
                "operation_time": full_clock_text(),
            }
            snapshot = None
            with JOBS_LOCK:
                job = EXTRACTION_JOBS.get(job_id)
                if not job:
                    return
                local_done = int(job.get("local_done") or 0) + 1
                local_success = int(job.get("local_success") or 0) + (1 if event.get("success") else 0)
                local_failure = int(job.get("local_failure") or 0) + (0 if event.get("success") else 1)
                job.update(
                    phase="正在删除账号字段",
                    local_done=local_done,
                    local_success=local_success,
                    local_failure=local_failure,
                    processed=local_done,
                    current_file=email,
                    updated_at=full_clock_text(),
                )
                rows = job.setdefault("result_rows", [])
                key = str(detail_row.get("email") or "").lower()
                matched = next((row for row in rows if str(row.get("email") or "").lower() == key), None)
                if matched is not None:
                    matched.update(detail_row)
                else:
                    rows.append(detail_row)
                del rows[:-200]
                events = job.setdefault("events", [])
                status = "成功" if event.get("success") else "失败"
                events.append({"time": full_clock_text(), "text": f"账号字段删除{status}：{email}"})
                del events[:-30]
                snapshot = dict(job)
                snapshot["events"] = list(events)
            persist_job_snapshot_throttled(snapshot)
    return callback


def run_file_delete_job(job_id: str, file_ids: list[int], owner_id: int | None, user_id: int | None, username: str | None, ip: str, mode: str) -> None:
    worker_db = SessionLocal()
    try:
        ensure_active_job_runnable(job_id)
        update_job(job_id, status="running", phase="正在准备删除")
        workers = task_workers(worker_db)
        update_job(job_id, workers=workers)
        rows = []
        for id_chunk in chunk_list(file_ids):
            ensure_active_job_runnable(job_id)
            query = worker_db.query(FileRecord.id, FileRecord.email_name, FileRecord.status).filter(FileRecord.id.in_(id_chunk))
            if owner_id is not None:
                query = query.filter(FileRecord.uploaded_by == owner_id)
            rows.extend(query.all())
        deletable_rows = [row for row in rows if row.status != "CHECKING"]
        skipped_checking = len(rows) - len(deletable_rows)
        update_job(job_id, total=len(deletable_rows), skipped=skipped_checking, phase="正在删除账号字段")
        if skipped_checking:
            append_job_event(job_id, f"已跳过 {skipped_checking} 个提取测活中的文件。")

        records = deletable_rows
        deleted_ids: list[int] = []
        failed_names: list[str] = []
        progress_callback = file_delete_progress_callback(job_id)
        for record in records:
            ensure_active_job_runnable(job_id)
            try:
                progress_callback({
                    "event": "local_delete_done",
                    "email": record.email_name,
                    "success": True,
                    "message": "账号字段删除成功",
                })
                deleted_ids.append(record.id)
            except Exception as exc:
                failed_names.append(record.email_name)
                progress_callback({
                    "event": "local_delete_done",
                    "email": record.email_name,
                    "success": False,
                    "message": str(exc),
                })
        ensure_active_job_runnable(job_id)
        update_job(job_id, phase="正在删除账号元数据", current_file="-")
        if deleted_ids:
            for id_chunk in chunk_list(deleted_ids):
                ensure_active_job_runnable(job_id)
                worker_db.query(UploadResult).filter(UploadResult.record_id.in_(id_chunk)).update(
                    {UploadResult.record_id: None},
                    synchronize_session=False,
                )
            for id_chunk in chunk_list(deleted_ids):
                ensure_active_job_runnable(job_id)
                worker_db.query(FileRecordPayload).filter(FileRecordPayload.file_record_id.in_(id_chunk)).delete(synchronize_session=False)
            for id_chunk in chunk_list(deleted_ids):
                ensure_active_job_runnable(job_id)
                worker_db.query(FileRecord).filter(FileRecord.id.in_(id_chunk)).delete(synchronize_session=False)
        worker_db.add(AuditLog(
            user_id=user_id,
            username=username,
            action="DELETE_FILES",
            target_type="file_record",
            ip=ip,
            detail=f"mode={mode}, count={len(deleted_ids)}, skipped_checking={skipped_checking}, local_failed={len(failed_names)}, owner_id={owner_id}, job={job_id}",
        ))
        ensure_active_job_runnable(job_id)
        worker_db.commit()
        update_job(
            job_id,
            status="done",
            phase="删除完成",
            deleted=len(deleted_ids),
            failure=len(failed_names),
            skipped=skipped_checking,
            processed=len(deletable_rows),
        )
        append_job_event(job_id, f"删除完成：账号字段删除 {len(deleted_ids)} 个，失败 {len(failed_names)} 个，跳过 {skipped_checking} 个。")
    except TaskAbortError as exc:
        worker_db.rollback()
        finalize_active_job_abort(worker_db, job_id, str(exc))
    except Exception as exc:
        worker_db.rollback()
        commit_audit_best_effort(
            worker_db,
            AuditLog(user_id=user_id, username=username, action="DELETE_FILES_FAILURE", target_type="file_record", ip=ip, detail=f"{exc}, job={job_id}"),
            "delete failure",
        )
        update_job(job_id, status="error", phase="删除失败", error=str(exc))
        append_job_event(job_id, str(exc))
    finally:
        worker_db.close()


def read_download_payload(record_data: SimpleNamespace) -> tuple[SimpleNamespace, dict]:
    return record_data, payload_for_record(record_data)


def run_file_download_job(job_id: str, file_ids: list[int], owner_id: int | None, user_id: int | None, username: str | None, ip: str, mode: str) -> None:
    worker_db = SessionLocal()
    output_path = DATA_DIR / "download_jobs" / f"{job_id}.zip"
    try:
        ensure_active_job_runnable(job_id)
        update_job(job_id, status="running", phase="正在准备下载")
        workers = task_workers(worker_db)
        update_job(job_id, workers=workers)
        records = []
        for id_chunk in chunk_list(file_ids):
            ensure_active_job_runnable(job_id)
            query = worker_db.query(FileRecord).options(joinedload(FileRecord.payload)).filter(FileRecord.id.in_(id_chunk))
            if owner_id is not None:
                query = query.filter(FileRecord.uploaded_by == owner_id)
            records.extend(query.all())
        records.sort(key=lambda record: (record.upload_time or datetime.min, record.id or 0), reverse=True)
        update_job(job_id, total=len(records), phase="正在打包文件")
        if not records:
            raise BusinessError("当前没有可下载文件")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        ensure_active_job_runnable(job_id)
        record_items = [
            SimpleNamespace(id=record.id, email_name=record.email_name, storage_path=record.storage_path, payload=record.payload)
            for record in records
        ]
        success = 0
        failure = 0
        rows: list[dict] = []
        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as archive:
            with ThreadPoolExecutor(max_workers=max(1, int(workers or DEFAULT_LIVE_CHECK_WORKERS))) as pool:
                futures = {
                    pool.submit(read_download_payload, record): record
                    for record in record_items
                }
                for future in as_completed(futures):
                    ensure_active_job_runnable(job_id)
                    record = futures[future]
                    try:
                        record, payload = future.result()
                    except Exception:
                        payload = {}
                    operation_time = full_clock_text()
                    if payload:
                        archive.writestr(f"{safe_name(record.email_name)}.json", json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"))
                        success += 1
                        result = "成功"
                        reason = "已打包"
                    else:
                        failure += 1
                        result = "失败"
                        reason = "账号字段内容不存在"
                    rows.append({
                        "email": record.email_name,
                        "result": result,
                        "reason": reason,
                        "operation_time": operation_time,
                    })
                    update_job(
                        job_id,
                        persist=False,
                        phase="正在打包文件",
                        processed=success + failure,
                        success=success,
                        failure=failure,
                        current_file=record.email_name,
                        result_rows=rows[-200:],
                    )
                    with JOBS_LOCK:
                        job = EXTRACTION_JOBS.get(job_id)
                        snapshot = dict(job) if job else None
                        if snapshot and snapshot.get("events"):
                            snapshot["events"] = list(snapshot["events"])
                    persist_job_snapshot_throttled(snapshot)
        filename = f"files-{datetime.now():%Y%m%d%H%M%S}-{success}files.zip"
        worker_db.add(AuditLog(
            user_id=user_id,
            username=username,
            action="DOWNLOAD_FILES",
            target_type="file_record",
            ip=ip,
            detail=f"mode={mode}, count={success}, failure={failure}, owner_id={owner_id}, job={job_id}",
        ))
        ensure_active_job_runnable(job_id)
        worker_db.commit()
        update_job(
            job_id,
            status="done",
            phase="下载包已生成",
            processed=success + failure,
            total=len(records),
            success=success,
            failure=failure,
            current_file="-",
            download_ready=success > 0,
            download_filename=filename,
            download_path=str(output_path),
            download_url=f"/api/admin/jobs/{job_id}/download",
            operation_time=full_clock_text(),
            result_rows=rows[-200:],
        )
        append_job_event(job_id, f"下载包已生成：成功 {success} 个，失败 {failure} 个。")
    except TaskAbortError as exc:
        worker_db.rollback()
        try:
            output_path.unlink(missing_ok=True)
        except OSError:
            pass
        finalize_active_job_abort(worker_db, job_id, str(exc))
    except BusinessError as exc:
        worker_db.rollback()
        try:
            output_path.unlink(missing_ok=True)
        except OSError:
            pass
        update_job(job_id, status="error", phase="下载失败", error=str(exc), operation_time=full_clock_text())
        append_job_event(job_id, str(exc))
    except Exception as exc:
        worker_db.rollback()
        try:
            output_path.unlink(missing_ok=True)
        except OSError:
            pass
        commit_audit_best_effort(
            worker_db,
            AuditLog(user_id=user_id, username=username, action="DOWNLOAD_FILES_FAILURE", target_type="file_record", ip=ip, detail=f"{exc}, job={job_id}"),
            "download failure",
        )
        update_job(job_id, status="error", phase="下载失败", error=str(exc), operation_time=full_clock_text())
        append_job_event(job_id, str(exc))
    finally:
        worker_db.close()


def run_extraction_job(job_id: str, codes: list[str], ip: str, live_check: bool = True) -> None:
    worker_db = SessionLocal()
    extraction_no = ""
    try:
        with JOBS_LOCK:
            job = EXTRACTION_JOBS.get(job_id) or {}
            extraction_no = str(job.get("extraction_no") or "")
        ensure_active_job_runnable(job_id)
        update_job(job_id, status="running", phase="正在准备测活" if live_check else "正在准备出库")
        workers = task_workers(worker_db)
        update_job(job_id, workers=workers)
        callback = extraction_progress_callback(job_id)
        cdkeys = access_cdkeys_bulk(
            worker_db,
            codes,
            ip,
            progress_callback=callback,
            live_check_workers=workers,
            live_check=live_check,
            extraction_no=extraction_no,
            abort_check=lambda: ensure_active_job_runnable(job_id),
        )
        cdkey_ids = [cdkey.id for cdkey in cdkeys]
        cdkey_codes = [cdkey.code for cdkey in cdkeys]
        update_job(job_id, phase="正在整理结果")
        worker_db.add(AuditLog(action="QUERY_ACCESS_SUCCESS", target_type="卡密", target_id=cdkey_target_text(cdkey_codes), ip=ip, detail=f"count={len(cdkey_ids)}, live_check={live_check}, extraction_no={extraction_no}, job={job_id}"))
        worker_db.commit()
        update_job(job_id, status="done", phase="测活完成" if live_check else "出库完成", cdkey_ids=cdkey_ids, result_url=f"/query/result?job_id={job_id}")
        append_job_event(job_id, "测活完成，结果已在下方显示。" if live_check else "出库完成，未测活无质保。")
    except TaskAbortError as exc:
        worker_db.rollback()
        finalize_active_job_abort(worker_db, job_id, str(exc))
    except BusinessError as exc:
        worker_db.rollback()
        commit_audit_best_effort(
            worker_db,
            AuditLog(action="QUERY_ACCESS_FAILURE", target_type="卡密", target_id=cdkey_target_text(codes), ip=ip, detail=f"{exc}, extraction_no={extraction_no}, job={job_id}"),
            "query access failure",
        )
        update_job(job_id, status="error", phase="测活失败" if live_check else "出库失败", error=str(exc))
        append_job_event(job_id, str(exc))
    except Exception as exc:
        worker_db.rollback()
        commit_audit_best_effort(
            worker_db,
            AuditLog(action="QUERY_ACCESS_FAILURE", target_type="卡密", target_id=cdkey_target_text(codes), ip=ip, detail=f"{exc}, extraction_no={extraction_no}, job={job_id}"),
            "query access failure",
        )
        update_job(job_id, status="error", phase="系统异常", error="测活任务异常，请稍后重试" if live_check else "出库任务异常，请稍后重试")
        append_job_event(job_id, str(exc))
    finally:
        worker_db.close()


def _reauth_payload(original: dict, result: dict, target_email: str) -> dict:
    updated = dict(original)
    updated["email"] = str(result.get("email") or target_email).strip().lower()
    for source, target in (
        ("id_token", "id_token"),
        ("access_token", "access_token"),
        ("refresh_token", "refresh_token"),
        ("last_refresh", "last_refresh"),
        ("expired", "expired"),
    ):
        value = str(result.get(source) or "").strip()
        if value:
            updated[target] = value
    updated.pop("reauth_info", None)
    return updated


def _reauth_credential(payload: dict) -> dict:
    info = payload.get("reauth_info")
    if not isinstance(info, dict) or not info.get("password") or not info.get("totp_secret"):
        raise BusinessError("账号尚未导入密码和 2FA 密钥")
    return {"password": info["password"], "totp_secret": info["totp_secret"]}


def _reauth_account_deactivated(exc: Exception) -> bool:
    from .reauth.oauth_client.auth_flow import EmailOtpValidationError

    return isinstance(exc, EmailOtpValidationError) and exc.status_code == 403


def _reauth_rate_limited(exc: Exception) -> bool:
    seen: set[int] = set()
    current: Exception | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        candidates = [str(current or ""), str(getattr(current, "body", "") or "")]
        if any("rate_limit_exceeded" in value.lower() for value in candidates):
            return True
        current = current.__cause__ or current.__context__
    return False


def _reauth_block_reason_for_exception(exc: Exception) -> str:
    if _reauth_account_deactivated(exc):
        return "account_deactivated"
    if _reauth_rate_limited(exc):
        return "rate_limit_exceeded"
    return ""


def _reauth_block_label(reason: str) -> str:
    return {
        "account_deactivated": "账户封禁",
        "rate_limit_exceeded": "账户已被限流，5分钟后再重试",
    }.get(str(reason or "").strip().lower(), "账户异常")


def _reauth_rate_limit_active(reauth_info: dict) -> bool:
    raw_blocked_at = str(reauth_info.get("oauth_blocked_at") or "").strip()
    if not raw_blocked_at:
        return True
    try:
        blocked_at = datetime.strptime(raw_blocked_at, "%Y-%m-%d %H:%M:%S").replace(tzinfo=APP_TIMEZONE)
    except ValueError:
        return True
    return datetime.now(APP_TIMEZONE) - blocked_at < timedelta(seconds=REAUTH_RATE_LIMIT_COOLDOWN_SECONDS)


def _reauth_block_reason(payload: dict) -> str:
    reauth_info = payload.get("reauth_info") if isinstance(payload, dict) else None
    if not isinstance(reauth_info, dict):
        return ""
    reason = str(reauth_info.get("oauth_blocked_reason") or "").strip().lower()
    if reason == "rate_limit_exceeded" and not _reauth_rate_limit_active(reauth_info):
        return ""
    return reason


def _persist_reauth_block(session_db, file_record_id: int, reason: str) -> None:
    payload_row = session_db.get(FileRecordPayload, file_record_id)
    if not payload_row:
        raise BusinessError("账号字段内容不存在")
    try:
        reauth_info = json.loads(payload_row.reauth_info or "")
    except (TypeError, ValueError):
        reauth_info = {}
    if not isinstance(reauth_info, dict):
        reauth_info = {}
    reauth_info["oauth_blocked_reason"] = str(reason or "").strip().lower()
    reauth_info["oauth_blocked_at"] = full_clock_text()
    payload_row.reauth_info = json.dumps(reauth_info, ensure_ascii=False, separators=(",", ":"))
    session_db.commit()


def _reauth_public_error(exc: Exception) -> str:
    block_reason = _reauth_block_reason_for_exception(exc)
    if block_reason:
        return _reauth_block_label(block_reason)
    text = str(exc or "")
    for marker, message in (
        ("尚未导入", "账号尚未导入密码和 2FA 密钥"),
        ("邮箱验证", "上游要求邮箱验证，本次 2FA 登录未完成"),
        ("2FA", "2FA 验证失败，请检查密钥和服务器时间"),
        ("phone", "OAuth 要求手机验证，当前任务不支持"),
        ("完整令牌", "OAuth 未返回完整令牌"),
        ("access_token", "OAuth 未返回有效访问令牌"),
        ("Refresh Token", "OAuth 未返回有效刷新令牌"),
    ):
        if marker.lower() in text.lower():
            return message
    return "OAuth 流程执行失败，请查看关键过程日志"


def _source_serialized_reauth_futures(records: list[dict], workers: int, process, abort_check):
    grouped: dict[str, deque] = {}
    for record in records:
        grouped.setdefault(str(record["source_key"]), deque()).append(record)
    if not grouped:
        return

    worker_count = min(max(1, int(workers or 1)), len(grouped))
    ready_sources = deque(grouped)
    in_flight = {}
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        while ready_sources or in_flight:
            abort_check()
            while ready_sources and len(in_flight) < worker_count:
                source_key = ready_sources.popleft()
                record = grouped[source_key].popleft()
                in_flight[pool.submit(process, record)] = (source_key, record)
            if not in_flight:
                break
            completed, _pending = wait(in_flight, return_when=FIRST_COMPLETED)
            abort_check()
            for future in completed:
                source_key, record = in_flight.pop(future)
                if grouped[source_key]:
                    ready_sources.append(source_key)
                yield record, future


def run_query_reauth_job(job_id: str, file_ids: list[int], download_file_ids: list[int], workers: int, ip: str) -> None:
    worker_db = SessionLocal()
    output_dir = DATA_DIR / "reauth_jobs" / job_id
    cpa_path = output_dir / "reauth-cpa.zip"
    sub_path = output_dir / "reauth-sub2api.json"
    card_cpa_path = output_dir / "card-cpa.zip"
    card_sub_path = output_dir / "card-sub2api.json"
    successful: list[tuple[str, dict]] = []
    successful_file_ids = []
    rows: list[dict] = []
    try:
        ensure_active_job_runnable(job_id)
        live_check_workers = task_workers(worker_db)
        update_job(
            job_id,
            status="running",
            phase="正在先测活卡密文件",
            total=len(download_file_ids),
            workers=workers,
            processed=0,
            success=0,
            failure=0,
            live_check_workers=live_check_workers,
            live_check_total=len(download_file_ids),
            live_check_checked=0,
            live_check_alive=0,
            live_check_dead=0,
            live_check_skipped=0,
            live_check_result_rows=[],
        )
        append_job_event(job_id, f"开始登录前测活：共 {len(download_file_ids)} 个账号，并发 {live_check_workers}。")

        def live_check_progress(event: dict) -> None:
            event_name = event.get("event")
            if event_name == "start_admin_file_check":
                update_job(
                    job_id,
                    phase="正在先测活卡密文件",
                    live_check_total=event.get("total", len(download_file_ids)),
                    live_check_checked=0,
                    live_check_alive=0,
                    live_check_dead=0,
                    live_check_skipped=0,
                    live_check_result_rows=[],
                )
            elif event_name == "checked":
                outcome = event.get("outcome")
                if outcome == "alive":
                    live_status = "正常"
                elif outcome == "skipped":
                    live_status = "跳过"
                else:
                    live_status = "异常"
                detail_row = {
                    "email": event.get("email") or "-",
                    "live_status": live_status,
                    "registered_at": format_time_text(event.get("registered_at")),
                    "quota": quota_label(event.get("quota")),
                    "quota_period": quota_period_label(event.get("quota")),
                    "plan_type": plan_type_label(event.get("quota")),
                    "http_status": str(event.get("http_status") or "-"),
                    "live_checked_at": format_time_text(event.get("live_checked_at")),
                    "message": str(event.get("message") or "-"),
                }
                needs_reauth = detail_row["http_status"] == "401"
                progress_text = f"登录前测活：{live_status}，HTTP {detail_row['http_status']}"
                detail_row.update({
                    "reauth_required": needs_reauth,
                    "reauth_status": "等待授权" if needs_reauth else "无需授权",
                })
                update_job(
                    job_id,
                    persist=False,
                    phase="正在先测活卡密文件",
                    current_file=event.get("email") or "-",
                    live_check_checked=event.get("checked", 0),
                    live_check_alive=event.get("alive", 0),
                    live_check_dead=event.get("dead", 0),
                    live_check_skipped=event.get("skipped", 0),
                )
                update_query_reauth_account_progress(
                    job_id,
                    detail_row["email"],
                    progress_text,
                    **{key: value for key, value in detail_row.items() if key != "email"},
                )

        admin_live_check_files(
            worker_db,
            download_file_ids,
            None,
            live_check_workers,
            progress_callback=live_check_progress,
            abort_check=lambda: ensure_active_job_runnable(job_id),
        )
        worker_db.expire_all()
        records = (
            worker_db.query(FileRecord)
            .options(joinedload(FileRecord.payload))
            .filter(FileRecord.id.in_(download_file_ids))
            .order_by(FileRecord.id.asc())
            .all()
        )
        if not records:
            raise BusinessError("当前卡密没有可重新授权的账号")
        oauth_records = [record for record in records if record.live_http_status == 401]
        blocked_records = []
        blocked_reasons: dict[int, str] = {}
        for record in oauth_records:
            block_reason = _reauth_block_reason(payload_for_record(record, include_reauth=True))
            if block_reason in {"account_deactivated", "rate_limit_exceeded"}:
                blocked_records.append(record)
                blocked_reasons[int(record.id)] = block_reason
        blocked_ids = {int(record.id) for record in blocked_records}
        for record in blocked_records:
            label = _reauth_block_label(blocked_reasons[int(record.id)])
            update_query_reauth_account_progress(
                job_id,
                record.email_name,
                f"{label}，已跳过重登授权",
                reauth_status="已跳过",
            )
        file_ids = [int(record.id) for record in oauth_records if int(record.id) not in blocked_ids]
        blocked_count_text = (
            f"账户封禁跳过 {sum(reason == 'account_deactivated' for reason in blocked_reasons.values())} 个，"
            f"账户已被限流跳过 {sum(reason == 'rate_limit_exceeded' for reason in blocked_reasons.values())} 个，"
        )
        append_job_event(
            job_id,
            f"登录前测活完成：{len(download_file_ids)} 个账号中 {len(oauth_records)} 个 HTTP 401，"
            f"{blocked_count_text}其余 {len(file_ids)} 个将进入重登授权。",
        )
        if not file_ids:
            if blocked_records:
                block_reason_set = set(blocked_reasons.values())
                if block_reason_set == {"rate_limit_exceeded"}:
                    raise BusinessError("当前卡密账号均在限流冷却期，请5分钟后再重试")
                if block_reason_set == {"account_deactivated"}:
                    raise BusinessError("当前卡密账号均为账户封禁，已跳过重登授权")
                raise BusinessError("当前卡密账号均为封禁或限流，已跳过重登授权")
            raise BusinessError("当前卡密没有检测到 401 账号")
        records = [record for record in records if record.id in file_ids]
        update_job(
            job_id,
            phase="正在准备重登授权",
            total=len(file_ids),
            processed=0,
            success=0,
            failure=0,
            file_ids=file_ids,
            current_file="-",
        )
        output_dir.mkdir(parents=True, exist_ok=True)
        record_inputs = []
        for record in records:
            record_payload = payload_for_record(record, include_reauth=True)
            record_inputs.append({
                "id": record.id,
                "email": record.email_name,
                "payload": record_payload,
                "source_key": record.email_name.strip().lower(),
            })

        def process(record: dict) -> tuple[dict, dict | None, str]:
            from .reauth.oauth_flow import reauthorize_account
            from .reauth.settings import ServiceSettings

            update_query_reauth_account_progress(
                job_id,
                record["email"],
                "开始重登授权",
                reauth_status="授权中",
            )
            original = record["payload"]
            credential = _reauth_credential(original)
            settings = ServiceSettings(
                default_workers=1,
                max_workers=1,
                proxy=os.environ.get("PYFAKA_REAUTH_PROXY", "").strip(),
            )

            def oauth_progress(message: str) -> None:
                update_query_reauth_account_progress(
                    job_id,
                    record["email"],
                    message,
                    reauth_status="授权中",
                )

            for attempt in range(1, 4):
                ensure_active_job_runnable(job_id)
                oauth_progress(f"重登授权第 {attempt}/3 次尝试")
                try:
                    refreshed = reauthorize_account(
                        record["email"],
                        credential,
                        settings,
                        oauth_progress,
                    )
                    if not str(refreshed.get("access_token") or "").strip() or not str(refreshed.get("refresh_token") or "").strip():
                        raise BusinessError("重登授权未返回完整令牌")
                    break
                except Exception as exc:
                    if attempt == 3 or _reauth_block_reason_for_exception(exc):
                        raise
                    oauth_progress(f"第 {attempt}/3 次失败：{_reauth_public_error(exc)}，准备重试")
            return record, _reauth_payload(original, refreshed, record["email"]), ""

        oauth_workers = max(1, min(QUERY_REAUTH_MAX_WORKERS, int(workers or QUERY_REAUTH_DEFAULT_WORKERS)))
        for record, future in _source_serialized_reauth_futures(
            record_inputs,
            oauth_workers,
            process,
            lambda: ensure_active_job_runnable(job_id),
        ):
            ensure_active_job_runnable(job_id)
            try:
                record, updated, _message = future.result()
                if not updated:
                    raise BusinessError("重登授权未返回有效结果")
                payload_row = worker_db.get(FileRecordPayload, record["id"])
                if not payload_row:
                    raise BusinessError("账号字段内容不存在")
                for field in ("id_token", "access_token", "refresh_token", "account_id", "last_refresh", "email", "type", "expired"):
                    if field in updated:
                        setattr(payload_row, field, str(updated.get(field) or ""))
                worker_db.commit()
                successful.append((record["email"], updated))
                successful_file_ids.append(record["id"])
                rows.append({"email": record["email"], "result": "成功", "reason": "已重新授权并回写", "operation_time": full_clock_text()})
                update_job(job_id, persist=False, phase="正在回写重新授权结果", processed=len(rows), success=len(successful), failure=len(rows) - len(successful), current_file=record["email"], result_rows=rows[-200:])
                update_query_reauth_account_progress(
                    job_id,
                    record["email"],
                    "重登授权成功，令牌已回写原账号",
                    reauth_status="授权成功",
                )
            except Exception as exc:
                worker_db.rollback()
                public_error = _reauth_public_error(exc)
                block_reason = _reauth_block_reason_for_exception(exc)
                if block_reason:
                    try:
                        _persist_reauth_block(worker_db, record["id"], block_reason)
                    except Exception:
                        worker_db.rollback()
                        LOGGER.exception("persist reauth block failed: file_record_id=%s", record["id"])
                rows.append({"email": record["email"], "result": "失败", "reason": public_error, "operation_time": full_clock_text()})
                update_job(job_id, persist=False, phase="正在执行重登授权", processed=len(rows), success=len(successful), failure=len(rows) - len(successful), current_file=record["email"], result_rows=rows[-200:])
                update_query_reauth_account_progress(
                    job_id,
                    record["email"],
                    f"重登授权失败：{public_error}",
                    reauth_status="授权失败",
                )

        if not successful:
            raise BusinessError("没有账号重新授权成功")
        with zipfile.ZipFile(cpa_path, "w", zipfile.ZIP_DEFLATED) as archive:
            for email, payload in successful:
                archive.writestr(f"{safe_name(email)}.json", json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"))
        sub_path.write_bytes(sub2api_json_for_payloads(successful))
        worker_db.expire_all()
        card_records = (
            worker_db.query(FileRecord)
            .options(joinedload(FileRecord.payload))
            .filter(FileRecord.id.in_(download_file_ids))
            .order_by(FileRecord.id.asc())
            .all()
        )
        if not card_records:
            raise BusinessError("当前卡密没有可下载文件")
        card_items = [(record.email_name, payload_for_record(record)) for record in card_records]
        with zipfile.ZipFile(card_cpa_path, "w", zipfile.ZIP_DEFLATED) as archive:
            for record, (_name, payload) in zip(card_records, card_items):
                if not payload:
                    raise BusinessError(f"账号字段内容不存在：{record.email_name}")
                archive.writestr(f"{safe_name(record.email_name)}.json", json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"))
        card_sub_path.write_bytes(sub2api_json_for_payloads(card_items))
        worker_db.add(AuditLog(action="QUERY_REAUTH", target_type="file_record", ip=ip, detail=f"job={job_id}, success={len(successful)}, failure={len(rows) - len(successful)}, workers={workers}"))
        worker_db.commit()
        update_job(
            job_id,
            status="done",
            phase="重登授权完成，已回写原文件",
            processed=len(rows),
            total=len(file_ids),
            success=len(successful),
            failure=len(rows) - len(successful),
            current_file="-",
            reauth_ready=True,
            successful_file_ids=successful_file_ids,
            cpa_download_url=f"/api/query/reauth/{job_id}/download?format=cpa",
            sub2api_download_url=f"/api/query/reauth/{job_id}/download?format=sub2api",
            card_cpa_download_url=f"/api/query/reauth/{job_id}/download?format=card-cpa",
            card_sub2api_download_url=f"/api/query/reauth/{job_id}/download?format=card-sub2api",
            download_file_ids=download_file_ids,
            result_rows=rows[-200:],
            operation_time=full_clock_text(),
        )
        append_job_event(job_id, f"重登授权完成：成功 {len(successful)} 个，失败 {len(rows) - len(successful)} 个，成功结果已回写原文件。")
    except TaskAbortError as exc:
        worker_db.rollback()
        finalize_active_job_abort(worker_db, job_id, str(exc))
    except BusinessError as exc:
        worker_db.rollback()
        update_job(job_id, status="error", phase="重登授权失败", error=str(exc), result_rows=rows[-200:], operation_time=full_clock_text())
        append_job_event(job_id, str(exc))
    except Exception as exc:
        worker_db.rollback()
        LOGGER.exception("query reauth failed: %s", exc)
        public_error = _reauth_public_error(exc)
        update_job(job_id, status="error", phase="重登授权失败", error=public_error, result_rows=rows[-200:], operation_time=full_clock_text())
        append_job_event(job_id, public_error)
    finally:
        worker_db.close()


def run_file_live_check_job(job_id: str, file_ids: list[int], owner_id: int | None, user_id: int | None, username: str | None, ip: str) -> None:
    worker_db = SessionLocal()
    try:
        ensure_active_job_runnable(job_id)
        update_job(job_id, status="running", phase="正在准备测活")
        workers = task_workers(worker_db)
        update_job(job_id, workers=workers)
        summary = admin_live_check_files(
            worker_db,
            file_ids,
            owner_id,
            workers,
            progress_callback=file_live_check_progress_callback(job_id),
            abort_check=lambda: ensure_active_job_runnable(job_id),
        )
        worker_db.add(AuditLog(
            user_id=user_id,
            username=username,
            action="LIVE_CHECK_FILES",
            target_type="file_record",
            ip=ip,
            detail=f"count={summary.total}, normal={summary.normal}, error={summary.error}, skipped={summary.skipped}, owner_id={owner_id}, job={job_id}",
        ))
        worker_db.commit()
        update_job(
            job_id,
            status="done",
            phase="测活完成",
            checked=summary.normal + summary.error + summary.skipped,
            alive=summary.normal,
            dead=summary.error,
            skipped=summary.skipped,
        )
        append_job_event(job_id, f"测活完成：正常 {summary.normal} 个，异常 {summary.error} 个，跳过 {summary.skipped} 个。")
    except TaskAbortError as exc:
        worker_db.rollback()
        finalize_active_job_abort(worker_db, job_id, str(exc))
    except BusinessError as exc:
        worker_db.rollback()
        commit_audit_best_effort(
            worker_db,
            AuditLog(user_id=user_id, username=username, action="LIVE_CHECK_FILES_FAILURE", target_type="file_record", ip=ip, detail=f"{exc}, job={job_id}"),
            "live check failure",
        )
        update_job(job_id, status="error", phase="测活失败", error=str(exc))
        append_job_event(job_id, str(exc))
    except Exception as exc:
        worker_db.rollback()
        commit_audit_best_effort(
            worker_db,
            AuditLog(user_id=user_id, username=username, action="LIVE_CHECK_FILES_FAILURE", target_type="file_record", ip=ip, detail=f"{exc}, job={job_id}"),
            "live check failure",
        )
        update_job(job_id, status="error", phase="系统异常", error="文件测活任务异常，请稍后重试")
        append_job_event(job_id, str(exc))
    finally:
        worker_db.close()


@bp.get("/")
def home():
    return redirect(url_for("main.query_index"))


@bp.route("/admin/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip = client_ip()
        remaining = login_attempt_lock_remaining(username, ip)
        if remaining > 0:
            return redirect("/admin/login")
        user = db().query(AdminUser).filter_by(username=username).first()
        if verify_login_password(user, password):
            clear_login_attempt_failures(username, ip)
            user.last_login_at = datetime.now()
            db().commit()
            establish_admin_session(user)
            log_audit("LOGIN_SUCCESS", "admin_user", user.id)
            return redirect("/admin/dashboard")
        slow_failed_login()
        record_login_attempt_failure(username, ip)
        log_audit("LOGIN_FAILURE", "admin_user", username, "用户名或密码错误")
        return redirect("/admin/login")
    return serve_admin_frontend()


@bp.post("/admin/logout")
def logout():
    if current_user():
        log_audit("LOGOUT", "admin_user", current_user().id)
    session.clear()
    return redirect("/admin/login")


@bp.get("/api/admin/session")
def api_session():
    user = current_user()
    business_type = request_business_type(request.args) if user else None
    group_tag = request_group_tag(request.args) if user else None
    return api_ok({
        "session": session_payload(user),
        "jobs": jobs_for_user(user.id, 20, business_type, group_tag, include_guest_reauth=bool(user.is_admin)) if user else [],
    })


@bp.post("/api/admin/login")
def api_login():
    payload = json_payload()
    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    ip = client_ip()
    remaining = login_attempt_lock_remaining(username, ip)
    if remaining > 0:
        minutes = max(1, (remaining + 59) // 60)
        log_audit("LOGIN_LOCKED", "admin_user", username, f"登录失败次数过多，剩余锁定 {minutes} 分钟")
        return api_error(f"登录失败次数过多，请 {minutes} 分钟后再试", 429, "LOGIN_LOCKED")
    user = db().query(AdminUser).filter_by(username=username).first()
    if verify_login_password(user, password):
        clear_login_attempt_failures(username, ip)
        user.last_login_at = datetime.now()
        db().commit()
        establish_admin_session(user)
        log_audit("LOGIN_SUCCESS", "admin_user", user.id)
        pool_scope = current_pool_scope(user)
        return api_ok({
            "session": session_payload(user),
            "jobs": jobs_for_user(
                user.id,
                20,
                pool_scope.get("business_type"),
                pool_scope.get("group_tag"),
                include_guest_reauth=bool(user.is_admin),
            ),
        })
    slow_failed_login()
    locked_seconds = record_login_attempt_failure(username, ip)
    log_audit("LOGIN_FAILURE", "admin_user", username, "用户名或密码错误")
    if locked_seconds:
        return api_error("用户名或密码错误，失败次数过多，已锁定 30 分钟", 401, "LOGIN_FAILED")
    return api_error("用户名或密码错误", 401, "LOGIN_FAILED")


@bp.post("/api/admin/logout")
@api_login_required
def api_logout():
    user = current_user()
    if user:
        log_audit("LOGOUT", "admin_user", user.id)
    session.clear()
    return api_ok()


@bp.post("/api/admin/password")
@api_login_required
def api_change_password():
    payload = json_payload()
    user = current_user()
    password = str(payload.get("password") or "")
    confirm = str(payload.get("confirm_password") or "")
    if password != confirm:
        return api_error("两次输入的密码不一致")
    policy_error = password_policy_error(password, user.username)
    if policy_error:
        return api_error(policy_error)
    user.password_hash = generate_password_hash(password)
    user.login_password = None
    bump_session_version(user)
    db().commit()
    log_audit("CHANGE_OWN_PASSWORD", "admin_user", user.id)
    session.clear()
    return api_ok({"message": "密码已更新，请重新登录"})


@bp.get("/api/admin/dashboard")
@api_login_required
def api_dashboard():
    user = current_user()
    owner_id = request_owner_id(request.args)
    business_type = request_business_type(request.args)
    group_tag = request_group_tag(request.args)
    return api_ok({
        "summary": dashboard_summary_payload(db(), user, owner_id, business_type, group_tag),
        "pool": current_pool_state(),
    })


@bp.get("/api/admin/files")
@api_login_required
def api_files():
    user = current_user()
    owner_id = request_owner_id(request.args)
    business_type = request_business_type(request.args)
    group_tag = request_group_tag(request.args)
    day = parse_day(request.args.get("date"))
    page = parse_int(request.args.get("page"), 1)
    per_page = min(100, max(1, parse_int(request.args.get("per_page"), 20) or 20))
    session_db = db()
    query = session_db.query(FileRecord).options(joinedload(FileRecord.bound_cdkey), joinedload(FileRecord.owner)).order_by(FileRecord.upload_time.desc(), FileRecord.id.desc())
    query = file_filters(
        query,
        request.args.get("filename"),
        request.args.get("cdkey_code"),
        request.args.get("extract_status"),
        request.args.get("live_status"),
        day,
        owner_id,
        business_type,
        group_tag,
        request.args.get("extraction_no"),
    )
    page_data = paginate(query, page, per_page)

    deletable_query = session_db.query(FileRecord.id)
    deletable_query = file_filters(
        deletable_query,
        request.args.get("filename"),
        request.args.get("cdkey_code"),
        request.args.get("extract_status"),
        request.args.get("live_status"),
        day,
        owner_id,
        business_type,
        group_tag,
        request.args.get("extraction_no"),
    )
    checking_query = session_db.query(FileRecord.id)
    checking_query = file_filters(
        checking_query,
        request.args.get("filename"),
        request.args.get("cdkey_code"),
        request.args.get("extract_status"),
        request.args.get("live_status"),
        day,
        owner_id,
        business_type,
        group_tag,
        request.args.get("extraction_no"),
    )
    payload = {
        "items": [file_item_payload(item) for item in page_data.items],
        "pagination": {
            "page": page_data.page,
            "pages": page_data.pages,
            "total": page_data.total,
            "per_page": per_page,
        },
        "filters": {
            "filename": request.args.get("filename", ""),
            "cdkey_code": request.args.get("cdkey_code", ""),
            "extract_status": request.args.get("extract_status", ""),
            "live_status": request.args.get("live_status", ""),
            "extraction_no": request.args.get("extraction_no", ""),
            "date": request.args.get("date", ""),
        },
        "pool": current_pool_state(),
        "pool_summary": pool_summary(owner_id, business_type, group_tag),
        "deletable_total": deletable_query.filter(FileRecord.status != "CHECKING").order_by(None).count(),
        "filtered_checking_total": checking_query.filter(FileRecord.status == "CHECKING").order_by(None).count(),
    }
    return api_ok(payload)


@bp.get("/api/admin/files/<int:file_id>")
@api_login_required
def api_file_detail(file_id: int):
    owner_id = request_owner_id(request.args)
    business_type = request_business_type(request.args)
    group_tag = request_group_tag(request.args)
    session_db = db()
    query = session_db.query(FileRecord).options(
        joinedload(FileRecord.bound_cdkey).joinedload(Cdkey.batch),
        joinedload(FileRecord.owner),
    ).filter(FileRecord.id == file_id)
    if owner_id is not None:
        query = query.filter(FileRecord.uploaded_by == owner_id)
    query = query.filter(FileRecord.business_type == business_type, FileRecord.group_tag == group_tag)
    record = one_or_404(query)
    raw_payload = payloads_for_records(session_db, [record]).get(record.id)
    return api_ok({
        "file": file_detail_payload(record, raw_payload, owner_id, business_type, group_tag),
        "pool": current_pool_state(),
    })


@bp.get("/api/admin/cdkeys")
@api_login_required
def api_cdkeys():
    user = current_user()
    owner_id = request_owner_id(request.args)
    business_type = request_business_type(request.args)
    group_tag = request_group_tag(request.args)
    day = parse_day(request.args.get("date"))
    page = parse_int(request.args.get("page"), 1)
    per_page = min(100, max(1, parse_int(request.args.get("per_page"), 20) or 20))
    session_db = db()
    query = session_db.query(Cdkey).options(joinedload(Cdkey.batch)).order_by(Cdkey.extracted_at.is_(None).asc(), Cdkey.extracted_at.desc(), Cdkey.created_at.desc(), Cdkey.id.desc())
    query = cdkey_filters(
        query,
        request.args.get("status"),
        request.args.get("batch_no"),
        request.args.get("code"),
        day,
        owner_id,
        business_type,
        group_tag,
        request.args.get("extraction_no"),
    )
    page_data = paginate(query, page, per_page)
    cap_owner_id = owner_id if user.is_admin else user.id
    capacity = capacity_for_owner(session_db, cap_owner_id, business_type, group_tag) if cap_owner_id is not None else None
    return api_ok({
        "items": [cdkey_item_payload(item) for item in page_data.items],
        "pagination": {
            "page": page_data.page,
            "pages": page_data.pages,
            "total": page_data.total,
            "per_page": per_page,
        },
        "filters": {
            "status": request.args.get("status", ""),
            "batch_no": request.args.get("batch_no", ""),
            "code": request.args.get("code", ""),
            "extraction_no": request.args.get("extraction_no", ""),
            "date": request.args.get("date", ""),
        },
        "pool": current_pool_state(),
        "pool_summary": pool_summary(owner_id, business_type, group_tag),
        "capacity": ({
            "available_files": capacity.available_files,
            "reserved_files": capacity.reserved_files,
            "remaining_capacity": capacity.remaining_capacity,
            "configured_over_issue_files": capacity.configured_over_issue_files,
            "used_over_issue_files": capacity.used_over_issue_files,
            "remaining_over_issue_files": capacity.remaining_over_issue_files,
            "total_bindable_files": capacity.total_bindable_files,
        } if capacity else None),
    })


@bp.get("/api/admin/cdkeys/<int:cdkey_id>")
@api_login_required
def api_cdkey_detail(cdkey_id: int):
    owner_id = request_owner_id(request.args)
    business_type = request_business_type(request.args)
    group_tag = request_group_tag(request.args)
    session_db = db()
    query = session_db.query(Cdkey).options(
        joinedload(Cdkey.batch).joinedload(CdkeyBatch.owner),
    ).join(CdkeyBatch).filter(Cdkey.id == cdkey_id)
    if owner_id is not None:
        query = query.filter(CdkeyBatch.created_by == owner_id)
    query = query.filter(CdkeyBatch.business_type == business_type, CdkeyBatch.group_tag == group_tag)
    cdkey = one_or_404(query)
    files = session_db.query(FileRecord).options(joinedload(FileRecord.owner)).filter(
        FileRecord.bound_cdkey_id == cdkey.id
    ).order_by(FileRecord.upload_time.desc(), FileRecord.id.desc()).all()
    return api_ok({
        "cdkey": cdkey_detail_payload(cdkey, files, owner_id, business_type, group_tag),
        "pool": current_pool_state(),
    })


@bp.get("/api/admin/audit")
@api_login_required
@api_admin_required
def api_audit():
    session_db = db()
    user_id = parse_int(request.args.get("user_id"))
    action = str(request.args.get("action") or "").strip()
    target_type = str(request.args.get("target_type") or "").strip()
    day = parse_day(request.args.get("date"))
    page = parse_int(request.args.get("page"), 1)
    per_page = min(100, max(1, parse_int(request.args.get("per_page"), 20) or 20))
    query = session_db.query(AuditLog).order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
    if user_id is not None:
        query = query.filter(AuditLog.user_id == user_id)
    if action:
        query = query.filter(AuditLog.action == action)
    if target_type:
        query = query.filter(AuditLog.target_type == target_type)
    if day is not None:
        start = datetime.combine(day, datetime.min.time())
        end = start + timedelta(days=1)
        query = query.filter(AuditLog.created_at >= start, AuditLog.created_at < end)
    page_data = paginate(query, page, per_page)
    cdkey_code_map = audit_cdkey_code_map(session_db, page_data.items)
    return api_ok({
        "items": [audit_item_payload(item, cdkey_code_map) for item in page_data.items],
        "pagination": {
            "page": page_data.page,
            "pages": page_data.pages,
            "total": page_data.total,
            "per_page": per_page,
        },
        "filters": {
            "user_id": user_id,
            "action": action,
            "target_type": target_type,
            "date": request.args.get("date", ""),
        },
        "options": {
            "actions": [
                value
                for (value,) in session_db.query(AuditLog.action).distinct().order_by(AuditLog.action.asc()).all()
                if value
            ],
            "target_types": [
                value
                for (value,) in session_db.query(AuditLog.target_type).distinct().order_by(AuditLog.target_type.asc()).all()
                if value
            ],
        },
    })


@bp.get("/api/admin/users")
@api_login_required
@api_admin_required
def api_users():
    all_users = db().query(AdminUser).order_by(AdminUser.id.asc()).all()
    return api_ok({"items": [user_row_payload(item) for item in all_users]})


@bp.get("/api/admin/settings")
@api_login_required
@api_admin_required
def api_settings():
    return api_ok({"settings": settings_payload(db())})


@bp.post("/api/admin/files/import-2fa")
@api_login_required
def api_import_two_factor():
    from .two_factor import import_two_factor

    payload = json_payload()
    try:
        owner_id = require_write_owner(current_user(), request_owner_id(payload))
        result = import_two_factor(
            db(), str(payload.get("text") or ""), owner_id,
            request_business_type(payload), request_group_tag(payload),
        )
    except BusinessError as exc:
        db().rollback()
        return api_error(str(exc), 400, "TOTP_IMPORT_INVALID")
    log_audit("IMPORT_2FA", "file_record", str(owner_id), f"matched_accounts={result['matched_accounts']}, updated_records={result['updated_records']}")
    return api_ok({"message": f"已匹配 {result['matched_accounts']} 个账号，更新 {result['updated_records']} 条记录，跳过 {result['skipped_accounts']} 条多余数据", **result})


@bp.post("/api/admin/files/upload")
@api_login_required
def api_upload_files():
    user = current_user()
    requested_owner_id = request_owner_id(request.form)
    try:
        owner_id = require_write_owner(user, requested_owner_id)
    except BusinessError as exc:
        return api_error(str(exc), 400, "OWNER_REQUIRED")
    business_type = request_business_type(request.form)
    group_tag = request_group_tag(request.form)
    files = [item for item in request.files.getlist("files") if item and item.filename]
    if not files:
        return api_error("请选择要上传的 JSON 文件", 400, "FILES_REQUIRED")
    job_id = uuid4().hex
    temp_dir = DATA_DIR / "upload_jobs" / job_id
    temp_dir.mkdir(parents=True, exist_ok=True)
    saved_files = []
    try:
        for index, item in enumerate(files):
            path = temp_dir / f"{index}.json"
            item.save(path)
            saved_files.append({"filename": item.filename, "path": str(path)})
    except Exception as exc:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return api_error(f"上传临时文件保存失败：{exc}", 500, "UPLOAD_SAVE_FAILED")
    initial_workers = task_workers(db())
    register_job({
        "id": job_id,
        "kind": "upload",
        "user_id": user.id,
        "status": "queued",
        "phase": "等待上传",
        "processed": 0,
        "total": len(saved_files),
        "success": 0,
        "failure": 0,
        "overwrite": 0,
        "business_type": business_type,
        "group_tag": group_tag,
        "batch_no": "",
        "workers": initial_workers,
        "current_file": "-",
        "events": [],
    })
    Thread(
        target=run_upload_job,
        args=(job_id, saved_files, owner_id, business_type, group_tag, user.id, user.username, client_ip()),
        daemon=True,
    ).start()
    return api_ok({"job_id": job_id}, 202)


@bp.post("/api/admin/files/delete")
@api_login_required
def api_delete_files():
    payload = json_payload()
    user = current_user()
    owner_id = request_owner_id(payload)
    business_type = request_business_type(payload)
    group_tag = request_group_tag(payload)
    session_db = db()
    day = parse_day(payload.get("date"))
    mode = str(payload.get("mode") or "selected").strip().lower()
    if mode == "filtered":
        query = session_db.query(FileRecord.id, FileRecord.status, FileRecord.bound_cdkey_id)
        query = file_filters(
            query,
            payload.get("filename"),
            payload.get("cdkey_code"),
            payload.get("extract_status"),
            payload.get("live_status"),
            day,
            owner_id,
            business_type,
            group_tag,
            payload.get("extraction_no"),
        )
        rows = query.all()
        file_ids = [row.id for row in rows]
        if payload.get("preview"):
            bound_count = sum(1 for row in rows if row.status == "BOUND")
            cdkey_count = len({row.bound_cdkey_id for row in rows if row.bound_cdkey_id})
            return api_ok({
                "preview": True,
                "file_count": len(file_ids),
                "cdkey_count": cdkey_count,
                "bound_file_count": bound_count,
                "confirm_text": FILTER_DELETE_CONFIRM_TEXT,
            })
        if str(payload.get("confirm_text") or "").strip() != FILTER_DELETE_CONFIRM_TEXT:
            return api_error("删除筛选结果需要二次确认", 400, "CONFIRM_REQUIRED")
    else:
        ids = list_int_payload(payload, "selected_ids")
        if not ids:
            return api_error("请选择要删除的文件")
        query = session_db.query(FileRecord.id, FileRecord.status).filter(FileRecord.id.in_(ids))
        if owner_id is not None:
            query = query.filter(FileRecord.uploaded_by == owner_id)
        query = query.filter(FileRecord.business_type == business_type, FileRecord.group_tag == group_tag)
        rows = query.all()
    file_ids = [row.id for row in rows]
    if not file_ids:
        return api_error("没有可删除的文件")
    job_id = uuid4().hex
    initial_workers = task_workers(session_db)
    register_job({
        "id": job_id,
        "kind": "file_delete",
        "user_id": user.id,
        "status": "queued",
        "phase": "等待删除",
        "processed": 0,
        "total": len(file_ids),
        "deleted": 0,
        "failure": 0,
        "skipped": 0,
        "local_done": 0,
        "local_success": 0,
        "local_failure": 0,
        "business_type": business_type,
        "group_tag": group_tag,
        "mode": mode,
        "workers": initial_workers,
        "current_file": "-",
        "events": [],
    })
    Thread(target=run_file_delete_job, args=(job_id, file_ids, owner_id, user.id, user.username, client_ip(), mode), daemon=True).start()
    return api_ok({"job_id": job_id}, 202)


@bp.post("/api/admin/files/download")
@api_login_required
def api_download_files():
    payload = json_payload()
    user = current_user()
    owner_id = request_owner_id(payload)
    business_type = request_business_type(payload)
    group_tag = request_group_tag(payload)
    session_db = db()
    day = parse_day(payload.get("date"))
    mode = str(payload.get("mode") or "selected").strip().lower()
    if mode == "filtered":
        query = session_db.query(FileRecord.id)
        query = file_filters(
            query,
            payload.get("filename"),
            payload.get("cdkey_code"),
            payload.get("extract_status"),
            payload.get("live_status"),
            day,
            owner_id,
            business_type,
            group_tag,
            payload.get("extraction_no"),
        )
        rows = query.all()
    else:
        ids = list_int_payload(payload, "selected_ids")
        if not ids:
            return api_error("请选择要下载的文件")
        query = session_db.query(FileRecord.id).filter(FileRecord.id.in_(ids))
        if owner_id is not None:
            query = query.filter(FileRecord.uploaded_by == owner_id)
        query = query.filter(FileRecord.business_type == business_type, FileRecord.group_tag == group_tag)
        rows = query.all()
    file_ids = [row.id for row in rows]
    if not file_ids:
        return api_error("没有可下载的文件")
    job_id = uuid4().hex
    register_job({
        "id": job_id,
        "kind": "file_download",
        "user_id": user.id,
        "status": "queued",
        "phase": "等待打包",
        "processed": 0,
        "total": len(file_ids),
        "success": 0,
        "failure": 0,
        "business_type": business_type,
        "group_tag": group_tag,
        "mode": mode,
        "current_file": "-",
        "events": [],
    })
    Thread(target=run_file_download_job, args=(job_id, file_ids, owner_id, user.id, user.username, client_ip(), mode), daemon=True).start()
    return api_ok({"job_id": job_id}, 202)


@bp.post("/api/admin/files/recover")
@api_login_required
def api_recover_files():
    payload = json_payload()
    owner_id = request_owner_id(payload)
    business_type = request_business_type(payload)
    group_tag = request_group_tag(payload)
    session_db = db()
    day = parse_day(payload.get("date"))
    mode = str(payload.get("mode") or "selected").strip().lower()
    if mode == "filtered":
        query = session_db.query(FileRecord.id, FileRecord.status)
        query = file_filters(
            query,
            payload.get("filename"),
            payload.get("cdkey_code"),
            payload.get("extract_status"),
            payload.get("live_status"),
            day,
            owner_id,
            business_type,
            group_tag,
            payload.get("extraction_no"),
        )
        rows = query.all()
    else:
        ids = list_int_payload(payload, "selected_ids")
        if not ids:
            return api_error("请选择要恢复的文件")
        query = session_db.query(FileRecord.id, FileRecord.status).filter(FileRecord.id.in_(ids))
        if owner_id is not None:
            query = query.filter(FileRecord.uploaded_by == owner_id)
        query = query.filter(FileRecord.business_type == business_type, FileRecord.group_tag == group_tag)
        rows = query.all()
    recover_ids = [row.id for row in rows if row.status == "CHECKING"]
    protected_ids = active_protected_checking_file_ids()
    blocked_ids = [item for item in recover_ids if item in protected_ids]
    recover_ids = [item for item in recover_ids if item not in protected_ids]
    if recover_ids:
        session_db.query(FileRecord).filter(FileRecord.id.in_(recover_ids), FileRecord.status == "CHECKING").update(
            {"status": "AVAILABLE", "bound_cdkey_id": None, "bound_at": None},
            synchronize_session=False,
        )
        session_db.commit()
    log_audit(
        "RECOVER_CHECKING_FILES",
        "file_record",
        None,
        f"mode={mode}, count={len(recover_ids)}, blocked_active={len(blocked_ids)}, owner_id={owner_id}, business={business_type}, tag={group_tag}",
    )
    skipped = len(rows) - len(recover_ids) - len(blocked_ids)
    message = f"已恢复 {len(recover_ids)} 个提取测活中的文件为未提取"
    if skipped:
        message += f"，跳过 {skipped} 个非提取测活中文件"
    if blocked_ids:
        message += f"，另有 {len(blocked_ids)} 个仍被活动任务占用，未恢复"
    return api_ok({"message": message})


@bp.post("/api/admin/files/live-check")
@api_login_required
def api_live_check_files():
    payload = json_payload()
    user = current_user()
    owner_id = request_owner_id(payload)
    business_type = request_business_type(payload)
    group_tag = request_group_tag(payload)
    day = parse_day(payload.get("date"))
    mode = str(payload.get("mode") or "selected").strip().lower()
    if mode == "filtered":
        query = db().query(FileRecord.id)
        query = file_filters(
            query,
            payload.get("filename"),
            payload.get("cdkey_code"),
            payload.get("extract_status"),
            payload.get("live_status"),
            day,
            owner_id,
            business_type,
            group_tag,
            payload.get("extraction_no"),
        )
        ids = [row.id for row in query.order_by(FileRecord.upload_time.desc(), FileRecord.id.desc()).all()]
    else:
        ids = list_int_payload(payload, "selected_ids")
    if not ids:
        return api_error("没有可测活的文件")
    job_id = uuid4().hex
    initial_workers = task_workers(db())
    register_job({
        "id": job_id,
        "kind": "file_live_check",
        "user_id": user.id,
        "owner_id": owner_id,
        "mode": mode,
        "status": "queued",
        "phase": "等待开始",
        "checked": 0,
        "alive": 0,
        "dead": 0,
        "skipped": 0,
        "needed": len(ids),
        "workers": initial_workers,
        "latest_quota": "暂无",
        "latest_rt_ms": None,
        "health_status": "等待测活",
        "business_type": business_type,
        "group_tag": group_tag,
        "file_ids": ids,
        "result_rows": [],
        "events": [],
    })
    Thread(target=run_file_live_check_job, args=(job_id, ids, owner_id, user.id, user.username, client_ip()), daemon=True).start()
    return api_ok({"job_id": job_id}, 202)


@bp.get("/api/admin/jobs/<job_id>")
@api_login_required
def api_job_detail(job_id: str):
    user = current_user()
    job = job_payload(job_id, allow_public=bool(user.is_admin))
    if not job or not admin_can_manage_job(user, job):
        return api_error("任务不存在或已过期", 404, "JOB_NOT_FOUND")
    business_type = request_business_type(request.args)
    group_tag = request_group_tag(request.args)
    guest_reauth = bool(job.get("user_id") is None and job.get("kind") == "query_reauth")
    if not guest_reauth and not job_matches_scope(job, business_type, group_tag):
        return api_error("任务不存在或已过期", 404, "JOB_NOT_FOUND")
    return api_ok({"job": job_summary_payload(job)})


@bp.post("/api/admin/jobs/<job_id>/terminate")
@api_login_required
def api_terminate_job(job_id: str):
    user = current_user()
    business_type = request_business_type(request.args)
    group_tag = request_group_tag(request.args)
    with JOBS_LOCK:
        active_job = dict(EXTRACTION_JOBS.get(job_id) or {})
        if active_job.get("events"):
            active_job["events"] = list(active_job["events"])
    if active_job.get("status") in {"queued", "running"}:
        guest_reauth = bool(active_job.get("user_id") is None and active_job.get("kind") == "query_reauth")
        if not admin_can_manage_job(user, active_job) or (not guest_reauth and not job_matches_scope(active_job, business_type, group_tag)):
            return api_error("任务不存在或已过期", 404, "JOB_NOT_FOUND")
        if active_job.get("kind") not in {"query_access", "query_reauth", "file_live_check", "upload", "file_delete", "file_download"}:
            return api_error("当前运行中的该任务暂不支持手动终止", 409, "JOB_TERMINATE_UNSUPPORTED")
        snapshot = request_job_cancel(job_id, "管理员手动终止任务")
        if not snapshot:
            return api_error("任务已经结束，无需终止", 409, "JOB_FINISHED")
        log_audit("TERMINATE_JOB", "task", job_id, f"kind={snapshot.get('kind')}, business={business_type}, tag={group_tag}, active=1")
        return api_ok({"message": "已请求终止，任务将在当前批次处理点停止。", "job": job_summary_payload(snapshot)})
    if active_job.get("id"):
        return api_error("任务已经结束，无需终止", 409, "JOB_FINISHED")
    session_db = db()
    with JOB_HISTORY_LOCK:
        history = read_job_history()
        target = None
        for item in history:
            if str(item.get("id") or "") == str(job_id):
                target = dict(item)
                break
        if not target:
            return api_error("任务不存在或已过期", 404, "JOB_NOT_FOUND")
        guest_reauth = bool(target.get("user_id") is None and target.get("kind") == "query_reauth")
        if not admin_can_manage_job(user, target) or (not guest_reauth and not job_matches_scope(target, business_type, group_tag)):
            return api_error("任务不存在或已过期", 404, "JOB_NOT_FOUND")
        if target.get("status") not in {"queued", "running"}:
            return api_error("任务已经结束，无需终止", 409, "JOB_FINISHED")
        if not interrupt_persisted_job(session_db, target, "管理员手动终止任务"):
            return api_error("任务无法终止", 409, "JOB_TERMINATE_UNSUPPORTED")
        next_history = [target if str(item.get("id") or "") == str(job_id) else item for item in history]
        session_db.commit()
        write_job_history(next_history)
    log_audit("TERMINATE_JOB", "task", job_id, f"kind={target.get('kind')}, business={business_type}, tag={group_tag}")
    return api_ok({"message": "任务已终止，残留锁定状态已释放。", "job": job_summary_payload(target)})


@bp.get("/api/admin/jobs/<job_id>/download")
@api_login_required
def api_job_download(job_id: str):
    job = job_payload(job_id, "file_download")
    if not job:
        return api_error("下载任务不存在或已过期", 404, "JOB_NOT_FOUND")
    if job.get("status") != "done" or not job.get("download_ready"):
        return api_error("下载包尚未生成", 409, "JOB_PENDING")
    path = str(job.get("download_path") or "")
    if not path or not os.path.exists(path):
        return api_error("下载包文件不存在", 404, "DOWNLOAD_NOT_FOUND")
    return send_file(path, mimetype="application/zip", as_attachment=True, download_name=job.get("download_filename") or f"{job_id}.zip")


@bp.get("/api/admin/jobs")
@api_login_required
def api_jobs():
    user = current_user()
    business_type = request_business_type(request.args)
    group_tag = request_group_tag(request.args)
    day = parse_day(request.args.get("date"))
    kind = str(request.args.get("kind") or "").strip()
    status = str(request.args.get("status") or "").strip()
    return api_ok({
        "items": jobs_for_user(
            user.id,
            100,
            business_type,
            group_tag,
            day,
            kind or None,
            status or None,
            include_guest_reauth=bool(user.is_admin),
        ),
    })


@bp.post("/api/admin/cdkeys/create")
@api_login_required
def api_create_cdkeys():
    payload = json_payload()
    user = current_user()
    requested_owner_id = request_owner_id(payload)
    business_type = request_business_type(payload)
    group_tag = request_group_tag(payload)
    try:
        owner_id = require_write_owner(user, requested_owner_id)
        batch = create_cdkey_batch(
            db(),
            owner_id,
            parse_int(payload.get("total_count"), 10),
            parse_int(payload.get("files_per_key"), 1),
            payload.get("remark"),
            business_type,
            group_tag,
        )
        rows = db().query(Cdkey).filter(Cdkey.batch_id == batch.id).order_by(Cdkey.id.asc()).all()
        log_audit("CREATE_CDKEY_BATCH", "卡密批次", batch.batch_no, f"total={batch.total_count}, files_per_key={batch.files_per_key}, owner_id={owner_id}, business={business_type}, tag={group_tag}")
        cap = capacity_for_owner(db(), owner_id, business_type, group_tag)
        return api_ok({
            "message": f"已生成 {batch.total_count} 张卡密",
            "batch_id": batch.id,
            "batch_no": batch.batch_no,
            "codes": [item.code for item in rows],
            "capacity": {
                "available_files": cap.available_files,
                "reserved_files": cap.reserved_files,
                "remaining_capacity": cap.remaining_capacity,
                "configured_over_issue_files": cap.configured_over_issue_files,
                "used_over_issue_files": cap.used_over_issue_files,
                "remaining_over_issue_files": cap.remaining_over_issue_files,
                "total_bindable_files": cap.total_bindable_files,
            },
        })
    except BusinessError as exc:
        return api_error(str(exc))


@bp.post("/api/admin/cdkeys/import")
@api_login_required
def api_import_cdkeys():
    payload = json_payload()
    user = current_user()
    requested_owner_id = request_owner_id(payload)
    try:
        owner_id = require_write_owner(user, requested_owner_id)
        raw_codes = re.split(r"[\s,，;；]+", str(payload.get("codes") or ""))
        summary = import_cdkey_batch(db(), owner_id, raw_codes, payload.get("remark"))
        batches = summary.batches
        total_count = summary.imported_count
        skipped_count = summary.duplicate_input_count + summary.existing_count
        message = f"已导入 {total_count} 张卡密，生成 {len(batches)} 个批次"
        if skipped_count:
            message += f"，自动跳过重复 {skipped_count} 张"
        log_audit(
            "IMPORT_CDKEY_BATCH",
            "卡密批次",
            ",".join(batch.batch_no for batch in batches),
            f"total={total_count}, duplicate_input={summary.duplicate_input_count}, existing={summary.existing_count}, batches={len(batches)}, owner_id={owner_id}, group_tag={DEFAULT_GROUP_TAG}",
        )
        return api_ok({
            "message": message,
            "total_count": total_count,
            "duplicate_input_count": summary.duplicate_input_count,
            "existing_count": summary.existing_count,
            "skipped_count": skipped_count,
            "batches": [{
                "batch_id": batch.id,
                "batch_no": batch.batch_no,
                "total_count": batch.total_count,
                "files_per_key": batch.files_per_key,
                "business_type": batch.business_type,
                "group_tag": batch.group_tag,
            } for batch in batches],
        })
    except BusinessError as exc:
        return api_error(str(exc))


@bp.post("/api/admin/cdkeys/delete")
@api_login_required
def api_delete_cdkeys():
    payload = json_payload()
    owner_id = request_owner_id(payload)
    business_type = request_business_type(payload)
    group_tag = request_group_tag(payload)
    session_db = db()
    day = parse_day(payload.get("date"))
    mode = str(payload.get("mode") or "selected").strip().lower()
    if mode == "filtered":
        query = session_db.query(Cdkey.id)
        query = cdkey_filters(
            query,
            payload.get("status"),
            payload.get("batch_no"),
            payload.get("code"),
            day,
            owner_id,
            business_type,
            group_tag,
            payload.get("extraction_no"),
        )
        cdkey_ids = [row.id for row in query.all()]
        if payload.get("preview"):
            bound_file_count = session_db.query(FileRecord.id).filter(FileRecord.bound_cdkey_id.in_(cdkey_ids)).count() if cdkey_ids else 0
            return api_ok({
                "preview": True,
                "cdkey_count": len(cdkey_ids),
                "bound_file_count": bound_file_count,
                "confirm_text": FILTER_DELETE_CONFIRM_TEXT,
            })
        if str(payload.get("confirm_text") or "").strip() != FILTER_DELETE_CONFIRM_TEXT:
            return api_error("删除筛选结果需要二次确认", 400, "CONFIRM_REQUIRED")
    else:
        ids = list_int_payload(payload, "selected_ids")
        if not ids:
            return api_error("请选择要删除的卡密")
        query = session_db.query(Cdkey.id).join(CdkeyBatch).filter(Cdkey.id.in_(ids))
        if owner_id is not None:
            query = query.filter(CdkeyBatch.created_by == owner_id)
        query = query.filter(CdkeyBatch.business_type == business_type, CdkeyBatch.group_tag == group_tag)
        cdkey_ids = [row.id for row in query.all()]
    if not cdkey_ids:
        return api_error("未找到可删除的卡密")
    result = delete_cdkeys_with_bound_files(session_db, cdkey_ids, workers=task_workers(session_db))
    delete_failed = int(result["delete_failed"])
    if delete_failed:
        return api_error(f"账号字段删除失败 {delete_failed} 个，已取消删除卡密")
    cdkey_codes = list(result["cdkey_codes"])
    deleted_files = int(result["deleted_files"])
    log_audit("DELETE_CDKEYS", "卡密", cdkey_target_text(cdkey_codes), f"mode={mode}, count={len(cdkey_ids)}, removed_files={deleted_files}, delete_failed={delete_failed}, owner_id={owner_id}, business={business_type}, tag={group_tag}")
    return api_ok({"message": f"已删除 {len(cdkey_ids)} 张卡密，清理绑定文件 {deleted_files} 个"})


@bp.post("/api/admin/cdkeys/delete-by-codes")
@api_login_required
def api_delete_cdkeys_by_codes():
    payload = json_payload()
    session_db = db()
    owner_id = request_owner_id(payload)
    business_type = request_business_type(payload)
    group_tag = request_group_tag(payload)
    codes = parse_text_codes(payload.get("codes"))
    if not codes:
        return api_error("请输入要删除的卡密")
    query = session_db.query(Cdkey.id).join(CdkeyBatch).filter(Cdkey.code.in_(codes))
    if owner_id is not None:
        query = query.filter(CdkeyBatch.created_by == owner_id)
    query = query.filter(CdkeyBatch.business_type == business_type, CdkeyBatch.group_tag == group_tag)
    cdkey_ids = [row.id for row in query.all()]
    if not cdkey_ids:
        return api_error("未找到匹配的卡密")
    result = delete_cdkeys_with_bound_files(session_db, cdkey_ids, workers=task_workers(session_db))
    delete_failed = int(result["delete_failed"])
    if delete_failed:
        return api_error(f"账号字段删除失败 {delete_failed} 个，已取消删除卡密")
    cdkey_codes = list(result["cdkey_codes"])
    deleted_files = int(result["deleted_files"])
    log_audit("DELETE_CDKEYS_BY_CODES", "卡密", cdkey_target_text(cdkey_codes), f"input_count={len(codes)}, matched={len(cdkey_ids)}, removed_files={deleted_files}, owner_id={owner_id}, business={business_type}, tag={group_tag}")
    return api_ok({"message": f"已删除 {len(cdkey_ids)} 张卡密，清理绑定文件 {deleted_files} 个"})


@bp.post("/api/admin/cdkeys/over-issue")
@api_login_required
def api_over_issue():
    payload = json_payload()
    user = current_user()
    requested_owner_id = request_owner_id(payload)
    try:
        owner_id = require_write_owner(user, requested_owner_id)
    except BusinessError as exc:
        return api_error(str(exc), 400, "OWNER_REQUIRED")
    business_type = request_business_type(payload)
    group_tag = request_group_tag(payload)
    value = set_configured_over_issue_files(
        db(),
        owner_id,
        business_type,
        max(0, parse_int(payload.get("over_issue_files"), 0) or 0),
    )
    log_audit("UPDATE_OVER_ISSUE", "admin_user", owner_id, f"business={business_type}, value={value}")
    cap = capacity_for_owner(db(), owner_id, business_type, group_tag)
    return api_ok({
        "message": "超发额度已更新",
        "capacity": {
            "available_files": cap.available_files,
            "reserved_files": cap.reserved_files,
            "remaining_capacity": cap.remaining_capacity,
            "configured_over_issue_files": cap.configured_over_issue_files,
            "used_over_issue_files": cap.used_over_issue_files,
            "remaining_over_issue_files": cap.remaining_over_issue_files,
            "total_bindable_files": cap.total_bindable_files,
        },
    })


@bp.post("/api/admin/users")
@api_login_required
@api_admin_required
def api_create_user():
    payload = json_payload()
    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    prefix = str(payload.get("cdkey_prefix") or "").strip()
    if not username or not password or not prefix:
        return api_error("用户名、密码和卡密前缀不能为空")
    policy_error = password_policy_error(password, username)
    if policy_error:
        return api_error(policy_error)
    if db().query(AdminUser).filter((AdminUser.username == username) | (AdminUser.cdkey_prefix == prefix)).first():
        return api_error("用户名或卡密前缀已存在")
    db().add(AdminUser(username=username, password_hash=generate_password_hash(password), enabled=True, cdkey_prefix=prefix))
    db().commit()
    log_audit("CREATE_USER", "admin_user", username)
    return api_ok({"message": f"已创建用户 {username}"}, 201)


@bp.post("/api/admin/users/<int:user_id>/toggle")
@api_login_required
@api_admin_required
def api_toggle_user(user_id: int):
    user = db().get(AdminUser, user_id) or abort(404)
    if user.id == current_user().id:
        return api_error("不能停用当前账号")
    user.enabled = not user.enabled
    db().commit()
    log_audit("TOGGLE_USER", "admin_user", user.id, f"enabled={user.enabled}")
    return api_ok({"message": "用户状态已更新"})


@bp.post("/api/admin/users/<int:user_id>/username")
@api_login_required
@api_admin_required
def api_change_username(user_id: int):
    payload = json_payload()
    user = db().get(AdminUser, user_id) or abort(404)
    username = str(payload.get("username") or "").strip()
    if not username:
        return api_error("用户名不能为空")
    if db().query(AdminUser).filter(AdminUser.username == username, AdminUser.id != user.id).first():
        return api_error("用户名已存在")
    old_username = user.username
    user.username = username
    bump_session_version(user)
    db().commit()
    log_audit("CHANGE_USER_USERNAME", "admin_user", user.id, f"{old_username} -> {username}")
    if current_user() and current_user().id == user.id:
        session.clear()
        return api_ok({"message": "用户名已更新，请重新登录", "require_relogin": True})
    return api_ok({"message": "用户名已更新"})


@bp.post("/api/admin/users/<int:user_id>/password")
@api_login_required
@api_admin_required
def api_change_user_password(user_id: int):
    payload = json_payload()
    user = db().get(AdminUser, user_id) or abort(404)
    password = str(payload.get("password") or "")
    policy_error = password_policy_error(password, user.username)
    if policy_error:
        return api_error(policy_error)
    user.password_hash = generate_password_hash(password)
    user.login_password = None
    bump_session_version(user)
    db().commit()
    log_audit("CHANGE_USER_PASSWORD", "admin_user", user.id)
    return api_ok({"message": "密码已更新"})


@bp.post("/api/admin/users/<int:user_id>/delete")
@api_login_required
@api_admin_required
def api_delete_user(user_id: int):
    user = db().get(AdminUser, user_id) or abort(404)
    if user.id == current_user().id:
        return api_error("不能删除当前登录账号")
    session_db = db()
    bound_files = session_db.query(FileRecord.id).filter(FileRecord.uploaded_by == user.id).count()
    bound_cdkey_batches = session_db.query(CdkeyBatch.id).filter(CdkeyBatch.created_by == user.id).count()
    upload_batches = session_db.query(UploadBatch.id).filter(
        (UploadBatch.owner_id == user.id) | (UploadBatch.uploaded_by == user.id)
    ).count()
    audit_logs = session_db.query(AuditLog.id).filter(AuditLog.user_id == user.id).count()
    if bound_files or bound_cdkey_batches or upload_batches or audit_logs:
        return api_error("该用户仍有关联数据，暂不支持直接删除；请先清空文件、卡密、上传记录和审计关联后再处理。")
    username = user.username
    session_db.delete(user)
    session_db.commit()
    log_audit("DELETE_USER", "admin_user", username)
    return api_ok({"message": f"已删除用户 {username}"})


@bp.post("/api/admin/settings")
@api_login_required
@api_admin_required
def api_update_settings():
    payload = json_payload()
    session_db = db()
    live_check_timeout = str(max(1, parse_int(payload.get("live_check_timeout"), 10) or 10))
    live_check_user_agent = str(payload.get("live_check_user_agent") or "").strip() or "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"
    raw_unshippable_http_statuses = payload.get(
        "unshippable_http_statuses",
        payload.get("unshippable_http_status", unshippable_http_statuses(session_db)),
    )
    try:
        unshippable_statuses_value = normalize_unshippable_http_statuses(raw_unshippable_http_statuses, strict=True)
    except BusinessError as exc:
        return api_error(str(exc), 400, "UNSHIPPABLE_HTTP_STATUSES_INVALID")
    task_workers_value = str(max(1, min(200, parse_int(payload.get("task_workers"), DEFAULT_LIVE_CHECK_WORKERS) or DEFAULT_LIVE_CHECK_WORKERS)))
    query_totp_enabled_value = "1" if parse_bool(payload.get("query_totp_enabled"), query_totp_enabled(session_db)) else "0"
    existing_business_type_options = business_type_options()
    raw_business_type_options = payload.get("business_type_options") if "business_type_options" in payload else existing_business_type_options
    try:
        business_types_value = business_type_options_json_for_update(raw_business_type_options, existing_business_type_options)
    except BusinessError as exc:
        return api_error(str(exc), 400, "BUSINESS_TYPES_INVALID")
    set_setting(session_db, LIVE_CHECK_TIMEOUT_KEY, live_check_timeout)
    set_setting(session_db, LIVE_CHECK_USER_AGENT_KEY, live_check_user_agent)
    set_setting(session_db, UNSHIPPABLE_HTTP_STATUSES_KEY, json.dumps(unshippable_statuses_value))
    set_setting(session_db, TASK_WORKERS_KEY, task_workers_value)
    set_setting(session_db, QUERY_TOTP_ENABLED_KEY, query_totp_enabled_value)
    set_setting(session_db, BUSINESS_TYPES_SETTING_KEY, business_types_value)
    session[POOL_BUSINESS_SESSION_KEY] = normalize_active_business_type(session.get(POOL_BUSINESS_SESSION_KEY))
    log_audit("UPDATE_SETTINGS", "app_setting", "local", f"live_check_timeout={live_check_timeout}, unshippable_http_statuses={list(unshippable_statuses_value)}, task_workers={task_workers_value}, query_totp_enabled={query_totp_enabled_value}, business_types=updated")
    return api_ok({"message": "系统设置已保存。", "settings": settings_payload(session_db), "session": session_payload(current_user())})


@bp.get("/api/query/session")
def api_query_session():
    return api_ok(query_session_payload())


@bp.get("/api/query/stock")
def api_query_stock():
    return api_ok({"inventory": public_inventory()})


@bp.post("/api/query/2fa/accounts")
def api_query_totp_accounts():
    if not query_totp_enabled(db()):
        return api_error("2FA 验证码功能未开启", 403, "TOTP_LOOKUP_DISABLED")
    payload = json_payload()
    ip = client_ip()
    locked_seconds = query_lock_remaining(ip)
    if locked_seconds > 0:
        minutes = max(1, (locked_seconds + 59) // 60)
        return api_error(f"查询失败次数过多，请 {minutes} 分钟后再试", 429, "QUERY_LOCKED")
    if rate_limited(f"query-totp-accounts:{ip}", QUERY_RATE_LIMIT, 600):
        return api_error("请求过于频繁，请稍后再试", 429, "RATE_LIMITED")
    code = str(payload.get("code") or "").strip()
    if not code:
        return api_error("请输入卡密")
    cdkey = db().query(Cdkey).filter(Cdkey.code == code).first()
    if not cdkey:
        record_query_invalid_attempt(ip)
        return api_error("卡密无效或不可用", 404, "CDKEY_NOT_FOUND")
    records = bound_files(db(), [int(cdkey.id)])
    accounts = sorted({
        str(record.email_name or "").strip().lower()
        for record in records
        if str(record.email_name or "").strip()
        and payload_for_record(record, include_reauth=True).get("reauth_info", {}).get("totp_secret")
    })
    if not accounts:
        return api_error("当前卡密尚未导入 2FA", 409, "NO_TOTP_ACCOUNTS")
    clear_query_invalid_attempts(ip)
    return api_ok({"accounts": accounts, "total": len(accounts)})


@bp.post("/api/query/2fa/code")
def api_query_totp_code():
    if not query_totp_enabled(db()):
        return api_error("2FA 验证码功能未开启", 403, "TOTP_LOOKUP_DISABLED")
    payload = json_payload()
    ip = client_ip()
    locked_seconds = query_lock_remaining(ip)
    if locked_seconds > 0:
        minutes = max(1, (locked_seconds + 59) // 60)
        return api_error(f"查询失败次数过多，请 {minutes} 分钟后再试", 429, "QUERY_LOCKED")
    code = str(payload.get("code") or "").strip()
    target = str(payload.get("email") or "").strip().lower()
    if not code or not target:
        return api_error("请输入卡密并选择邮箱")
    cdkey = db().query(Cdkey).filter(Cdkey.code == code).first()
    if not cdkey:
        record_query_invalid_attempt(ip)
        return api_error("卡密无效或不可用", 404, "CDKEY_NOT_FOUND")
    record = (
        db().query(FileRecord)
        .options(joinedload(FileRecord.payload))
        .filter(
            FileRecord.bound_cdkey_id == cdkey.id,
            func.lower(FileRecord.email_name) == target,
        )
        .order_by(FileRecord.id.asc())
        .first()
    )
    if not record:
        return api_error("所选邮箱不属于当前卡密", 404, "ACCOUNT_NOT_FOUND")
    cooldown_key = f"query-totp-code:{ip}:{cdkey.id}"
    if rate_limited(cooldown_key, 1, 5):
        return jsonify({
            "ok": False,
            "error": "刷新过于频繁，请 5 秒后再试",
            "code": "TOTP_REFRESH_COOLDOWN",
            "retry_after": 5,
        }), 429

    from .two_factor import account_credentials
    from .reauth.totp import totp_code

    try:
        credential = account_credentials(record)
        result = totp_code(credential["totp_secret"])
    except (BusinessError, ValueError) as exc:
        return api_error(str(exc), 409, "TOTP_NOT_READY")
    clear_query_invalid_attempts(ip)
    response = jsonify({"ok": True, "email": target, "password": credential["password"], **result, "refreshed_at": full_clock_text()})
    response.headers["Cache-Control"] = "no-store"
    return response



@bp.post("/api/query/access")
def api_query_access():
    payload = json_payload()
    ip = client_ip()
    locked_seconds = query_lock_remaining(ip)
    if locked_seconds > 0:
        minutes = max(1, (locked_seconds + 59) // 60)
        return api_error(f"提取失败次数过多，请 {minutes} 分钟后再试", 429, "QUERY_LOCKED")
    if rate_limited(f"query:{ip}", QUERY_RATE_LIMIT, 600):
        return api_error("请求过于频繁，请稍后再试", 429, "RATE_LIMITED")
    raw = str(payload.get("code") or "")
    live_check = bool(payload.get("live_check", True))
    codes = [item.strip() for item in raw.replace(",", "\n").replace("，", "\n").splitlines() if item.strip()]
    if not codes:
        return api_error("请输入卡密")
    unique_codes = list(dict.fromkeys(codes))
    cdkeys = db().query(Cdkey).options(joinedload(Cdkey.batch)).filter(Cdkey.code.in_(unique_codes)).all()
    cdkey_by_code = {item.code: item for item in cdkeys}
    missing_codes = [code for code in unique_codes if code not in cdkey_by_code]
    if missing_codes:
        locked_seconds = record_query_invalid_attempt(ip)
        if locked_seconds:
            return api_error("卡密无效或不可用，失败次数过多，已锁定 30 分钟", 401, "QUERY_INVALID")
        return api_error("卡密无效或不可用", 401, "QUERY_INVALID")
    requested_cdkey_ids = [cdkey_by_code[code].id for code in unique_codes]
    checking_codes = [code for code in unique_codes if cdkey_by_code[code].extract_status == "CHECKING"]
    if checking_codes:
        running_job = find_running_query_job_for_codes(checking_codes)
        if running_job:
            access_token = issue_query_access(running_job["id"], requested_cdkey_ids)
            extraction_no = str(running_job.get("extraction_no") or "")
            session["query_pending_job_id"] = running_job["id"]
            session.pop("query_cdkey_ids", None)
            session.pop("query_job_id", None)
            return api_ok({"job_id": running_job["id"], "access_token": access_token, "extraction_no": extraction_no, "reused": True}, 202)
        preview = "、".join(checking_codes[:5])
        suffix = f" 等 {len(checking_codes)} 张" if len(checking_codes) > 5 else ""
        return api_error(f"卡密正在提取中，请稍后查询：{preview}{suffix}")
    needed_by_scope: dict[tuple[int | None, str, str], int] = {}
    for code in unique_codes:
        cdkey = cdkey_by_code[code]
        if cdkey.extract_status == "EXTRACTED":
            continue
        scope_key = (
            cdkey.batch.created_by,
            normalize_business_type(cdkey.batch.business_type),
            normalize_group_tag(cdkey.batch.group_tag),
        )
        needed_by_scope[scope_key] = needed_by_scope.get(scope_key, 0) + cdkey.files_per_key
    shortage = False
    total_needed = 0
    total_available = 0
    for (owner_id, business_type, group_tag), needed in needed_by_scope.items():
        available_query = db().query(FileRecord).filter(
            FileRecord.status == "AVAILABLE",
            FileRecord.business_type == business_type,
            FileRecord.group_tag == group_tag,
        )
        if owner_id is None:
            available_query = available_query.filter(FileRecord.uploaded_by.is_(None))
        else:
            available_query = available_query.filter(FileRecord.uploaded_by == owner_id)
        available = available_query.count()
        total_needed += needed
        total_available += available
        if available < needed:
            shortage = True
    if shortage:
        return api_error(f"当前可用文件数不足：需要 {total_needed} 个，可用 {total_available} 个")
    job_scopes = {
        (
            cdkey_by_code[code].batch.created_by,
            normalize_business_type(cdkey_by_code[code].batch.business_type),
            normalize_group_tag(cdkey_by_code[code].batch.group_tag),
        )
        for code in unique_codes
    }
    if len(job_scopes) == 1:
        job_user_id, job_business_type, job_group_tag = next(iter(job_scopes))
    else:
        job_user_id = None
        job_business_type = DEFAULT_BUSINESS_TYPE
        job_group_tag = DEFAULT_GROUP_TAG
    job_id = uuid4().hex
    extraction_no = extraction_no_text(job_id)
    initial_workers = task_workers(db())
    access_token = issue_query_access(job_id, requested_cdkey_ids)
    session["query_pending_job_id"] = job_id
    session.pop("query_cdkey_ids", None)
    session.pop("query_job_id", None)
    clear_query_invalid_attempts(ip)
    existing_cdkey_ids = [cdkey_by_code[code].id for code in unique_codes if cdkey_by_code[code].extract_status == "EXTRACTED"]
    existing_files = extracted_files_for_cdkeys(existing_cdkey_ids, live_check)
    initial_needed = sum(cdkey_by_code[code].files_per_key for code in unique_codes)
    register_job({
        "id": job_id,
        "status": "queued",
        "phase": "正在读取历史结果" if existing_cdkey_ids else "等待开始",
        "kind": "query_access",
        "user_id": job_user_id,
        "business_type": job_business_type,
        "group_tag": job_group_tag,
        "extraction_no": extraction_no,
        "live_check": live_check,
        "code_count": len(unique_codes),
        "codes": unique_codes,
        "locked_cdkey_ids": [],
        "locked_file_ids": [],
        "existing_count": len(existing_cdkey_ids),
        "checked": 0,
        "alive": len(existing_files),
        "dead": 0,
        "needed": initial_needed,
        "display_needed": initial_needed,
        "workers": initial_workers,
        "latest_quota": "暂无",
        "extracted_files": existing_files,
        "events": [],
    })
    Thread(target=run_extraction_job, args=(job_id, unique_codes, ip, live_check), daemon=True).start()
    return api_ok({"job_id": job_id, "access_token": access_token, "extraction_no": extraction_no}, 202)


@bp.get("/api/query/jobs/<job_id>")
def api_query_job(job_id: str):
    job = job_payload(job_id, allow_public=True)
    if not job:
        return api_error("测活任务不存在或已过期", 404, "JOB_NOT_FOUND")
    access_token = request.args.get("token") or request.headers.get("X-Query-Token")
    if job.get("kind") == "query_reauth":
        if not query_reauth_job_allowed(job, access_token):
            return api_error("重新授权任务访问凭证无效", 403, "FORBIDDEN")
        return api_ok({"job": public_query_job_payload(job)})
    if not authorize_query_job(job_id):
        return api_error("请先输入卡密", 403, "FORBIDDEN")
    persist_job_snapshot(job)
    if job.get("status") == "done" and job.get("cdkey_ids"):
        sync_extracted_files_from_db(job_id, job.get("cdkey_ids") or [], job.get("live_check", True))
        with JOBS_LOCK:
            job = dict(EXTRACTION_JOBS.get(job_id) or job)
            if job.get("events"):
                job["events"] = list(job["events"])
        persist_job_snapshot(job)
        scoped_ids = scoped_query_cdkey_ids(job)
        ids = scoped_ids if scoped_ids is not None else query_job_cdkey_ids(job)
        session.permanent = True
        session["query_cdkey_ids"] = ids
        session["query_job_id"] = job_id
        session[QUERY_ACCESS_JOB_SESSION_KEY] = job_id
        session.pop("query_pending_job_id", None)
    return api_ok({"job": public_query_job_payload(job)})


@bp.get("/api/query/result")
def api_query_result():
    job_id = request.args.get("job_id")
    if job_id:
        if not authorize_query_job(job_id):
            return api_error("请先输入卡密", 403, "FORBIDDEN")
        job = job_payload(job_id, allow_public=True) or {}
        if job:
            persist_job_snapshot(job)
        if job.get("status") not in {"done"}:
            return api_error("任务尚未完成", 409, "JOB_PENDING")
        scoped_ids = scoped_query_cdkey_ids(job)
        ids = scoped_ids if scoped_ids is not None else query_job_cdkey_ids(job)
        session["query_cdkey_ids"] = ids
        session["query_job_id"] = job_id
        session[QUERY_ACCESS_JOB_SESSION_KEY] = job_id
        session.pop("query_pending_job_id", None)
    else:
        if session.get(QUERY_ACCESS_TOKEN_SESSION_KEY):
            return api_error("请先输入卡密", 403, "FORBIDDEN")
        ids = session.get("query_cdkey_ids") or []
        job_id = session.get("query_job_id")
        with JOBS_LOCK:
            job = EXTRACTION_JOBS.get(job_id) if job_id else None
    if not ids:
        return api_error("请先输入卡密", 403, "FORBIDDEN")
    cdkeys = db().query(Cdkey).filter(Cdkey.id.in_(ids)).all()
    files = bound_files(db(), ids)
    payloads = payloads_for_records(db(), files)
    metadata_by_email = {
        str(item.get("email") or "").strip().lower(): item
        for item in list((job or {}).get("extracted_files") or [])
        if isinstance(item, dict) and item.get("email")
    }
    missing_metadata_text = "未测活" if job and not job.get("live_check", True) else "暂无"
    items = []
    for record in files:
        payload = payloads.get(record.id, {})
        metadata = metadata_by_email.get(str(record.email_name or "").strip().lower(), {})
        items.append({
            "email": record.email_name,
            "quota": quota_display_text(record.live_quota) if record.live_quota else ("未测活" if job and not job.get("live_check", True) else "暂无"),
            "quota_period": metadata.get("quota_period") or missing_metadata_text,
            "plan_type": metadata.get("plan_type") or missing_metadata_text,
            "registered_at": format_time_text(payload.get("last_refresh")) if payload else format_time_text(record.upload_time),
            "live_checked_at": format_time_text(record.live_checked_at),
            "http_status": record.live_http_status or "-",
            "extracted_at": format_time_text(record.bound_at),
        })
    items = sort_items_by_quota_desc(items)
    reauth_job = latest_query_reauth_job(str(job_id or ""))
    return api_ok({
        "job_id": job_id,
        "job": public_query_job_payload(job) if job else {},
        "cdkeys": [{
            "id": item.id,
            "code": item.code,
            "extract_status": item.extract_status,
            "files_per_key": item.files_per_key,
            "extraction_no": item.extraction_no or "",
            "extracted_at": format_time_text(item.extracted_at),
        } for item in cdkeys],
        "files": items,
        "reauth_job": public_query_job_payload(reauth_job) if reauth_job else None,
    })


def query_reauth_job_allowed(job: dict | None, token: str | None = None) -> bool:
    if not isinstance(job, dict) or job.get("kind") != "query_reauth":
        return False
    job_id = str(job.get("id") or "").strip()
    expected = session.get(QUERY_REAUTH_TOKEN_SESSION_KEY)
    if job_id and session.get(QUERY_REAUTH_JOB_SESSION_KEY) == job_id and expected and token and expected == token:
        return True
    source_job_id = str(job.get("source_job_id") or "").strip()
    return bool(source_job_id and query_access_allowed(source_job_id, token))


@bp.post("/api/query/reauth")
def api_query_reauth():
    payload = json_payload()
    ip = client_ip()
    if rate_limited(f"query-reauth:{ip}", QUERY_RATE_LIMIT, 600):
        return api_error("请求过于频繁，请稍后再试", 429, "RATE_LIMITED")
    raw_codes = payload.get("codes") if payload.get("codes") is not None else payload.get("code")
    if isinstance(raw_codes, list):
        code_items = [str(item or "").strip() for item in raw_codes]
    else:
        code_items = [item.strip() for item in str(raw_codes or "").replace(",", "\n").replace("，", "\n").splitlines()]
    codes = list(dict.fromkeys(item for item in code_items if item))
    if not codes:
        return api_error("请输入卡密")
    cdkeys = db().query(Cdkey).filter(Cdkey.code.in_(codes)).order_by(Cdkey.id.asc()).all()
    cdkeys_by_code = {str(item.code or "").strip(): item for item in cdkeys}
    missing_codes = [code for code in codes if code not in cdkeys_by_code]
    if missing_codes:
        preview = "、".join(missing_codes[:5])
        suffix = f" 等 {len(missing_codes)} 张" if len(missing_codes) > 5 else ""
        return api_error(f"卡密不存在：{preview}{suffix}", 404, "CDKEY_NOT_FOUND")
    cdkey_ids = [int(cdkeys_by_code[code].id) for code in codes]
    card_records = bound_files(db(), cdkey_ids)
    download_file_ids = [int(record.id) for record in card_records]
    if not download_file_ids:
        return api_error("当前卡密没有可测活文件", 409, "NO_FILES")
    existing_reauth_job = find_running_query_reauth_job_for_cdkeys(cdkey_ids)
    if existing_reauth_job:
        existing_job_id = str(existing_reauth_job.get("id") or "")
        access_token = issue_query_reauth_access(existing_job_id)
        return api_ok({
            "job_id": existing_job_id,
            "access_token": access_token,
            "total": int(existing_reauth_job.get("total") or len(download_file_ids)),
            "reused": True,
        }, 202)
    file_ids = list(download_file_ids)
    emails = [str(record.email_name or "").strip().lower() for record in card_records]
    try:
        workers = max(1, min(QUERY_REAUTH_MAX_WORKERS, int(payload.get("workers") or QUERY_REAUTH_DEFAULT_WORKERS)))
    except (TypeError, ValueError):
        workers = QUERY_REAUTH_DEFAULT_WORKERS
    reauth_job_id = uuid4().hex
    token = issue_query_reauth_access(reauth_job_id)
    reauth_job = {
        "id": reauth_job_id,
        "kind": "query_reauth",
        "status": "queued",
        "codes": codes,
        "cdkey_ids": cdkey_ids,
        "emails": emails,
        "file_ids": file_ids,
        "download_file_ids": download_file_ids,
        "workers": workers,
        "total": len(file_ids),
        "processed": 0,
        "success": 0,
        "failure": 0,
        "live_check_total": len(file_ids),
        "live_check_checked": 0,
        "live_check_alive": 0,
        "live_check_dead": 0,
        "live_check_skipped": 0,
        "live_check_result_rows": [],
        "result_rows": [],
        "events": [],
    }
    existing_reauth_job = register_job(reauth_job, exclusive_cdkey_ids=cdkey_ids)
    if existing_reauth_job:
        existing_job_id = str(existing_reauth_job.get("id") or "")
        access_token = issue_query_reauth_access(existing_job_id)
        return api_ok({
            "job_id": existing_job_id,
            "access_token": access_token,
            "total": int(existing_reauth_job.get("total") or len(download_file_ids)),
            "reused": True,
        }, 202)
    Thread(target=run_query_reauth_job, args=(reauth_job_id, file_ids, download_file_ids, workers, ip), daemon=True).start()
    return api_ok({"job_id": reauth_job_id, "access_token": token, "total": len(file_ids)}, 202)


@bp.post("/api/query/reauth/<job_id>/terminate")
def api_query_reauth_terminate(job_id: str):
    job = job_payload(job_id, "query_reauth", allow_public=True)
    token = request.args.get("token") or request.headers.get("X-Query-Token")
    if not query_reauth_job_allowed(job, token):
        return api_error("重新授权任务访问凭证无效", 403, "FORBIDDEN")
    if job.get("status") not in {"queued", "running"}:
        return api_error("任务已经结束，无需停止", 409, "JOB_FINISHED")
    snapshot = request_job_cancel(job_id, "用户手动停止重登授权任务")
    if not snapshot:
        return api_error("任务已经结束，无需停止", 409, "JOB_FINISHED")
    return api_ok({
        "message": "已请求停止，正在执行的账号完成当前步骤后任务将终止。",
        "job": public_query_job_payload(snapshot),
    })


@bp.get("/api/query/reauth/<job_id>/download")
def api_query_reauth_download(job_id: str):
    job = job_payload(job_id, "query_reauth", allow_public=True)
    token = request.args.get("token") or request.headers.get("X-Query-Token")
    if not query_reauth_job_allowed(job, token):
        return api_error("重新授权任务访问凭证无效", 403, "FORBIDDEN")
    if job.get("status") != "done" or not job.get("reauth_ready"):
        return api_error("重新授权结果尚未生成", 409, "JOB_PENDING")
    output_format = str(request.args.get("format") or "cpa").strip().lower()
    if output_format in {"2fa", "card-2fa"}:
        from .two_factor import two_factor_txt

        ids = job.get("download_file_ids", []) if output_format == "card-2fa" else job.get("successful_file_ids", [])
        query = db().query(FileRecord).options(joinedload(FileRecord.payload)).filter(FileRecord.id.in_(ids))
        if job.get("source_job_id") and query_access_allowed(job["source_job_id"], token):
            source = job_payload(job["source_job_id"], allow_public=True) or {}
            scoped_ids = scoped_query_cdkey_ids(source)
            if scoped_ids is not None:
                query = query.filter(FileRecord.bound_cdkey_id.in_(scoped_ids))
        records = query.order_by(FileRecord.id.asc()).all()
        try:
            content = two_factor_txt(records)
        except BusinessError as exc:
            return api_error(str(exc), 409, "TOTP_NOT_READY")
        response = send_file(BytesIO(content), mimetype="text/plain", as_attachment=True, download_name=f"{output_format}-{job_id[:8]}.txt")
        response.headers["Cache-Control"] = "no-store"
        return response
    output_dir = DATA_DIR / "reauth_jobs" / job_id
    if output_format == "sub2api":
        path = output_dir / "reauth-sub2api.json"
        mimetype = "application/json"
        filename = f"reauth-{job_id[:8]}-sub2api.json"
    elif output_format == "cpa":
        path = output_dir / "reauth-cpa.zip"
        mimetype = "application/zip"
        filename = f"reauth-{job_id[:8]}-cpa.zip"
    elif output_format == "card-sub2api":
        path = output_dir / "card-sub2api.json"
        mimetype = "application/json"
        filename = f"card-{job_id[:8]}-sub2api.json"
    elif output_format == "card-cpa":
        path = output_dir / "card-cpa.zip"
        mimetype = "application/zip"
        filename = f"card-{job_id[:8]}-cpa.zip"
    else:
        return api_error("下载格式只支持 cpa、sub2api、2fa、card-cpa、card-sub2api 或 card-2fa", 400, "FORMAT_INVALID")
    if not path.is_file():
        return api_error("重新授权结果文件不存在", 404, "DOWNLOAD_NOT_FOUND")
    return send_file(path, mimetype=mimetype, as_attachment=True, download_name=filename)


@bp.route("/admin/password", methods=["GET", "POST"])
@login_required
def change_password():
    return serve_admin_frontend()


@bp.get("/admin")
@bp.get("/admin/dashboard")
@login_required
def dashboard():
    return serve_admin_frontend()


@bp.get("/admin/tasks")
@login_required
def tasks():
    return serve_admin_frontend()


@bp.route("/admin/files", methods=["GET"])
@login_required
def files():
    return serve_admin_frontend()


@bp.post("/admin/files/upload")
@login_required
def upload_files():
    user = current_user()
    requested_owner_id = request_owner_id(request.form)
    try:
        owner_id = require_write_owner(user, requested_owner_id)
    except BusinessError as exc:
        flash(str(exc), "error")
        return redirect(url_for("main.files", **current_pool_scope(user)))
    business_type = request_business_type(request.form)
    group_tag = request_group_tag(request.form)
    files = [item for item in request.files.getlist("files") if item and item.filename]
    if not files:
        flash("请选择要上传的 JSON 文件", "error")
        return redirect(url_for("main.files", owner_id=owner_id, business_type=business_type, group_tag=group_tag))
    job_id = uuid4().hex
    temp_dir = DATA_DIR / "upload_jobs" / job_id
    temp_dir.mkdir(parents=True, exist_ok=True)
    saved_files = []
    try:
        for index, item in enumerate(files):
            path = temp_dir / f"{index}.json"
            item.save(path)
            saved_files.append({"filename": item.filename, "path": str(path)})
    except Exception as exc:
        shutil.rmtree(temp_dir, ignore_errors=True)
        flash(f"上传临时文件保存失败：{exc}", "error")
        return redirect(url_for("main.files", owner_id=owner_id, business_type=business_type, group_tag=group_tag))

    user = current_user()
    initial_workers = task_workers(db())
    register_job({
        "id": job_id,
        "kind": "upload",
        "user_id": user.id,
        "status": "queued",
        "phase": "等待上传",
        "processed": 0,
        "total": len(saved_files),
        "success": 0,
        "failure": 0,
        "overwrite": 0,
        "business_type": business_type,
        "group_tag": group_tag,
        "workers": initial_workers,
        "current_file": "-",
        "events": [],
        "return_url": url_for("main.files", owner_id=owner_id, business_type=business_type, group_tag=group_tag),
    })
    Thread(
        target=run_upload_job,
        args=(job_id, saved_files, owner_id, business_type, group_tag, user.id, user.username, client_ip()),
        daemon=True,
    ).start()
    return redirect(url_for("main.upload_progress", job_id=job_id))


@bp.get("/admin/files/uploads/<int:batch_id>")
@login_required
def upload_detail(batch_id: int):
    return redirect("/admin/files")


@bp.get("/admin/files/uploads/progress/<job_id>")
@login_required
def upload_progress(job_id: str):
    return redirect("/admin/files")


@bp.get("/admin/files/uploads/progress/<job_id>.json")
@login_required
def upload_progress_json(job_id: str):
    job = job_payload(job_id, "upload")
    if not job or job.get("kind") != "upload" or job.get("user_id") != current_user().id:
        return jsonify({"status": "missing", "error": "上传任务不存在或已过期"}), 404
    return jsonify(job)


@bp.get("/admin/files/uploads/<int:batch_id>/failures.csv")
@login_required
def upload_failures_csv(batch_id: int):
    user = current_user()
    batch = db().query(UploadBatch).filter(UploadBatch.id == batch_id).first()
    if not batch:
        abort(404)
    if not user.is_admin and batch.owner_id != user.id:
        abort(403)
    rows = db().query(UploadResult).filter(UploadResult.batch_id == batch_id, UploadResult.status == "FAILURE").all()
    lines = ["filename,email,message\r\n"]
    for row in rows:
        lines.append(",".join([
            '"' + row.filename.replace('"', '""') + '"',
            '"' + (row.email or "").replace('"', '""') + '"',
            '"' + row.message.replace('"', '""') + '"',
        ]) + "\r\n")
    return Response("".join(lines), mimetype="text/csv; charset=utf-8", headers={"Content-Disposition": f"attachment; filename=upload-{batch.id}-failures.csv"})


@bp.get("/admin/files/<int:file_id>/download")
@login_required
def download_file(file_id: int):
    user = current_user()
    owner_id = request_owner_id(request.args)
    business_type = request_business_type(request.args)
    group_tag = request_group_tag(request.args)
    session_db = db()
    query = session_db.query(FileRecord).filter(FileRecord.id == file_id)
    if owner_id is not None:
        query = query.filter(FileRecord.uploaded_by == owner_id)
    query = query.filter(FileRecord.business_type == business_type, FileRecord.group_tag == group_tag)
    record = one_or_404(query)
    log_audit("DOWNLOAD_FILE", "file_record", record.id)
    try:
        content = zip_for_files(session_db, [record])
    except BusinessError as exc:
        flash(str(exc), "error")
        return redirect(url_for("main.files", owner_id=owner_id, business_type=business_type, group_tag=group_tag))
    return send_file(BytesIO(content), mimetype="application/zip", as_attachment=True, download_name=f"{record.email_name}.zip")


@bp.get("/admin/files/<int:file_id>")
@login_required
def file_detail(file_id: int):
    return serve_admin_frontend()


@bp.get("/admin/files/download")
@login_required
def download_filtered_files():
    user = current_user()
    owner_id = request_owner_id(request.args)
    business_type = request_business_type(request.args)
    group_tag = request_group_tag(request.args)
    day = parse_day(request.args.get("date"))
    session_db = db()
    query = session_db.query(FileRecord).options(joinedload(FileRecord.bound_cdkey)).order_by(FileRecord.upload_time.desc(), FileRecord.id.desc())
    query = file_filters(
        query,
        request.args.get("filename"),
        request.args.get("cdkey_code"),
        request.args.get("extract_status"),
        request.args.get("live_status"),
        day,
        owner_id,
        business_type,
        group_tag,
        request.args.get("extraction_no"),
    )
    files = query.all()
    if not files:
        flash("当前筛选条件下没有可下载文件", "error")
        return redirect(url_for("main.files", **compact_params(
            owner_id=owner_id,
            business_type=business_type,
            group_tag=group_tag,
            filename=request.args.get("filename"),
            cdkey_code=request.args.get("cdkey_code"),
            extract_status=request.args.get("extract_status"),
            live_status=request.args.get("live_status"),
            date=request.args.get("date"),
        )))
    log_audit("DOWNLOAD_FILTERED_FILES_ZIP", "file_record", None, f"count={len(files)}, owner_id={owner_id}, business={business_type}, tag={group_tag}")
    try:
        content = zip_for_files(session_db, files)
    except BusinessError as exc:
        flash(str(exc), "error")
        return redirect(url_for("main.files", **compact_params(
            owner_id=owner_id,
            business_type=business_type,
            group_tag=group_tag,
            filename=request.args.get("filename"),
            cdkey_code=request.args.get("cdkey_code"),
            extract_status=request.args.get("extract_status"),
            live_status=request.args.get("live_status"),
            date=request.args.get("date"),
        )))
    filename = f"files-{datetime.now():%Y%m%d%H%M%S}-{len(files)}.zip"
    return send_file(BytesIO(content), mimetype="application/zip", as_attachment=True, download_name=filename)


@bp.post("/admin/files/delete")
@login_required
def delete_files():
    user = current_user()
    session_db = db()
    owner_id = request_owner_id(request.form)
    business_type = request_business_type(request.form)
    group_tag = request_group_tag(request.form)
    day = parse_day(request.form.get("date"))
    mode = request.form.get("delete_mode", "selected")
    redirect_params = compact_params(
        owner_id=owner_id,
        business_type=business_type,
        group_tag=group_tag,
        filename=request.form.get("filename"),
        cdkey_code=request.form.get("cdkey_code"),
        extract_status=request.form.get("extract_status"),
        live_status=request.form.get("live_status"),
        extraction_no=request.form.get("extraction_no"),
        date=request.form.get("date"),
    )

    if mode == "filtered":
        if request.form.get("confirm_text", "").strip() != FILTER_DELETE_CONFIRM_TEXT:
            flash("删除筛选结果需要二次确认", "error")
            return redirect(url_for("main.files", **redirect_params))
        query = session_db.query(FileRecord.id, FileRecord.status)
        query = file_filters(
            query,
            request.form.get("filename"),
            request.form.get("cdkey_code"),
            request.form.get("extract_status"),
            request.form.get("live_status"),
            day,
            owner_id,
            business_type,
            group_tag,
            request.form.get("extraction_no"),
        )
    else:
        ids = [int(item) for item in request.form.getlist("selected_ids") if item.isdigit()]
        if not ids:
            flash("请选择要删除的文件", "error")
            return redirect(url_for("main.files", **redirect_params))
        query = session_db.query(FileRecord.id, FileRecord.status).filter(FileRecord.id.in_(ids))
        if owner_id is not None:
            query = query.filter(FileRecord.uploaded_by == owner_id)
        query = query.filter(FileRecord.business_type == business_type, FileRecord.group_tag == group_tag)

    rows = query.all()
    file_ids = [row.id for row in rows]
    if not file_ids:
        flash("没有可删除的文件", "error")
        return redirect(url_for("main.files", **redirect_params))

    job_id = uuid4().hex
    initial_workers = task_workers(db())
    register_job({
        "id": job_id,
        "kind": "file_delete",
        "user_id": user.id,
        "status": "queued",
        "phase": "等待删除",
        "processed": 0,
        "total": len(file_ids),
        "deleted": 0,
        "failure": 0,
        "skipped": 0,
        "local_done": 0,
        "local_success": 0,
        "local_failure": 0,
        "business_type": business_type,
        "group_tag": group_tag,
        "workers": initial_workers,
        "current_file": "-",
        "events": [],
        "return_url": url_for("main.files", **redirect_params),
    })
    Thread(target=run_file_delete_job, args=(job_id, file_ids, owner_id, user.id, user.username, client_ip(), mode), daemon=True).start()
    return redirect(url_for("main.file_delete_progress", job_id=job_id))


@bp.get("/admin/files/delete/progress/<job_id>")
@login_required
def file_delete_progress(job_id: str):
    return redirect("/admin/files")


@bp.get("/admin/files/delete/progress/<job_id>.json")
@login_required
def file_delete_progress_json(job_id: str):
    job = job_payload(job_id, "file_delete")
    if not job or job.get("kind") != "file_delete" or job.get("user_id") != current_user().id:
        return jsonify({"status": "missing", "error": "删除任务不存在或已过期"}), 404
    return jsonify(job)


@bp.post("/admin/files/recover-checking")
@login_required
def recover_checking_files():
    user = current_user()
    session_db = db()
    owner_id = request_owner_id(request.form)
    business_type = request_business_type(request.form)
    group_tag = request_group_tag(request.form)
    day = parse_day(request.form.get("date"))
    mode = request.form.get("recover_mode", "selected")
    redirect_params = compact_params(
        owner_id=owner_id,
        business_type=business_type,
        group_tag=group_tag,
        filename=request.form.get("filename"),
        cdkey_code=request.form.get("cdkey_code"),
        extract_status=request.form.get("extract_status"),
        live_status=request.form.get("live_status"),
        extraction_no=request.form.get("extraction_no"),
        date=request.form.get("date"),
    )

    if mode == "filtered":
        query = session_db.query(FileRecord.id, FileRecord.status)
        query = file_filters(
            query,
            request.form.get("filename"),
            request.form.get("cdkey_code"),
            request.form.get("extract_status"),
            request.form.get("live_status"),
            day,
            owner_id,
            business_type,
            group_tag,
            request.form.get("extraction_no"),
        )
    else:
        ids = [int(item) for item in request.form.getlist("selected_ids") if item.isdigit()]
        if not ids:
            flash("请选择要恢复的文件", "error")
            return redirect(url_for("main.files", **redirect_params))
        query = session_db.query(FileRecord.id, FileRecord.status).filter(FileRecord.id.in_(ids))
        if owner_id is not None:
            query = query.filter(FileRecord.uploaded_by == owner_id)
        query = query.filter(FileRecord.business_type == business_type, FileRecord.group_tag == group_tag)

    rows = query.all()
    recover_ids = [row.id for row in rows if row.status == "CHECKING"]
    protected_ids = active_protected_checking_file_ids()
    blocked_ids = [item for item in recover_ids if item in protected_ids]
    recover_ids = [item for item in recover_ids if item not in protected_ids]
    if recover_ids:
        session_db.query(FileRecord).filter(FileRecord.id.in_(recover_ids), FileRecord.status == "CHECKING").update(
            {"status": "AVAILABLE", "bound_cdkey_id": None, "bound_at": None},
            synchronize_session=False,
        )
        session_db.commit()
    log_audit(
        "RECOVER_CHECKING_FILES",
        "file_record",
        None,
        f"mode={mode}, count={len(recover_ids)}, blocked_active={len(blocked_ids)}, owner_id={owner_id}, business={business_type}, tag={group_tag}",
    )
    skipped = len(rows) - len(recover_ids) - len(blocked_ids)
    message = f"已恢复 {len(recover_ids)} 个提取测活中的文件为未提取"
    if skipped:
        message += f"，跳过 {skipped} 个非提取测活中文件"
    if blocked_ids:
        message += f"，另有 {len(blocked_ids)} 个仍被活动任务占用，未恢复"
    flash(message, "success" if recover_ids else "error")
    return redirect(url_for("main.files", **redirect_params))


@bp.post("/admin/files/live-check")
@login_required
def live_check_files():
    user = current_user()
    owner_id = request_owner_id(request.form)
    business_type = request_business_type(request.form)
    group_tag = request_group_tag(request.form)
    day = parse_day(request.form.get("date"))
    mode = request.form.get("check_mode", "selected")
    redirect_params = compact_params(
        owner_id=owner_id,
        business_type=business_type,
        group_tag=group_tag,
        filename=request.form.get("filename"),
        cdkey_code=request.form.get("cdkey_code"),
        extract_status=request.form.get("extract_status"),
        live_status=request.form.get("live_status"),
        extraction_no=request.form.get("extraction_no"),
        date=request.form.get("date"),
    )
    if mode == "filtered":
        query = db().query(FileRecord.id)
        query = file_filters(
            query,
            request.form.get("filename"),
            request.form.get("cdkey_code"),
            request.form.get("extract_status"),
            request.form.get("live_status"),
            day,
            owner_id,
            business_type,
            group_tag,
            request.form.get("extraction_no"),
        )
        ids = [row.id for row in query.order_by(FileRecord.upload_time.desc(), FileRecord.id.desc()).all()]
    else:
        ids = [int(item) for item in request.form.getlist("selected_ids") if item.isdigit()]
    if not ids:
        flash("没有可测活的文件", "error")
        return redirect(url_for("main.files", **redirect_params))
    job_id = uuid4().hex
    return_url = url_for("main.files", **redirect_params)
    initial_workers = task_workers(db())
    register_job({
        "id": job_id,
        "kind": "file_live_check",
        "user_id": user.id,
        "owner_id": owner_id,
        "mode": mode,
        "status": "queued",
        "phase": "等待开始",
        "checked": 0,
        "alive": 0,
        "dead": 0,
        "skipped": 0,
        "needed": len(ids),
        "workers": initial_workers,
        "latest_quota": "暂无",
        "latest_rt_ms": None,
        "health_status": "等待测活",
        "business_type": business_type,
        "group_tag": group_tag,
        "file_ids": ids,
        "events": [],
        "return_url": return_url,
    })
    Thread(target=run_file_live_check_job, args=(job_id, ids, owner_id, user.id, user.username, client_ip()), daemon=True).start()
    return redirect(url_for("main.file_live_check_progress", job_id=job_id))


@bp.get("/admin/files/live-check/<job_id>")
@login_required
def file_live_check_progress(job_id: str):
    return redirect("/admin/files")


@bp.get("/admin/files/live-check/<job_id>.json")
@login_required
def file_live_check_progress_json(job_id: str):
    job = job_payload(job_id, "file_live_check")
    if not job or job.get("kind") != "file_live_check" or job.get("user_id") != current_user().id:
        return jsonify({"status": "missing", "error": "测活任务不存在或已过期"}), 404
    return jsonify(job)


@bp.route("/admin/cdkeys", methods=["GET"])
@login_required
def cdkeys():
    return serve_admin_frontend()


@bp.route("/admin/cdkeys/create", methods=["GET", "POST"])
@login_required
def create_cdkeys():
    return redirect("/admin/cdkeys")


@bp.post("/admin/cdkeys/delete-by-codes")
@login_required
def delete_cdkeys_by_codes():
    user = current_user()
    session_db = db()
    owner_id = request_owner_id(request.form)
    business_type = request_business_type(request.form)
    group_tag = request_group_tag(request.form)
    redirect_params = compact_params(
        owner_id=owner_id,
        business_type=business_type,
        group_tag=group_tag,
        status=request.form.get("status"),
        batch_no=request.form.get("batch_no"),
        code=request.form.get("code"),
        date=request.form.get("date"),
    )
    codes = parse_text_codes(request.form.get("codes"))
    if not codes:
        flash("请输入要删除的卡密", "error")
        return redirect(url_for("main.cdkeys", **redirect_params))
    query = session_db.query(Cdkey.id).join(CdkeyBatch).filter(Cdkey.code.in_(codes))
    if owner_id is not None:
        query = query.filter(CdkeyBatch.created_by == owner_id)
    query = query.filter(CdkeyBatch.business_type == business_type, CdkeyBatch.group_tag == group_tag)
    cdkey_ids = [row.id for row in query.all()]
    if not cdkey_ids:
        flash("未找到匹配的卡密", "error")
        return redirect(url_for("main.cdkeys", **redirect_params))
    result = delete_cdkeys_with_bound_files(session_db, cdkey_ids, workers=task_workers(session_db))
    delete_failed = int(result["delete_failed"])
    if delete_failed:
        flash(f"账号字段删除失败 {delete_failed} 个，已取消删除卡密", "error")
        return redirect(url_for("main.cdkeys", **redirect_params))
    cdkey_codes = list(result["cdkey_codes"])
    deleted_files = int(result["deleted_files"])
    log_audit(
        "DELETE_CDKEYS_BY_CODES",
        "卡密",
        cdkey_target_text(cdkey_codes),
        f"input_count={len(codes)}, matched={len(cdkey_ids)}, removed_files={deleted_files}, owner_id={owner_id}, business={business_type}, tag={group_tag}",
    )
    flash(f"已删除 {len(cdkey_ids)} 张卡密，清理绑定文件 {deleted_files} 个", "success")
    return redirect(url_for("main.cdkeys", **redirect_params))


@bp.get("/admin/cdkeys/batches/<int:batch_id>")
@login_required
def batch_detail(batch_id: int):
    return redirect("/admin/cdkeys")


@bp.get("/admin/cdkeys/<int:cdkey_id>")
@login_required
def cdkey_detail(cdkey_id: int):
    return serve_admin_frontend()


@bp.get("/admin/cdkeys/<int:cdkey_id>/download")
@login_required
def admin_cdkey_download(cdkey_id: int):
    user = current_user()
    owner_id = request_owner_id(request.args)
    business_type = request_business_type(request.args)
    group_tag = request_group_tag(request.args)
    query = db().query(Cdkey).join(CdkeyBatch).filter(Cdkey.id == cdkey_id)
    if owner_id is not None:
        query = query.filter(CdkeyBatch.created_by == owner_id)
    query = query.filter(CdkeyBatch.business_type == business_type, CdkeyBatch.group_tag == group_tag)
    cdkey = one_or_404(query)
    files = bound_files(db(), [cdkey.id])
    log_audit("DOWNLOAD_CDKEY_ZIP", "卡密", cdkey.code)
    try:
        content = zip_for_files(db(), files)
    except BusinessError as exc:
        flash(str(exc), "error")
        return redirect(url_for("main.cdkey_detail", cdkey_id=cdkey.id, owner_id=owner_id, business_type=business_type, group_tag=group_tag))
    return send_file(BytesIO(content), mimetype="application/zip", as_attachment=True, download_name=f"{cdkey.code}.zip")


@bp.get("/admin/cdkeys/export")
@login_required
def export_cdkeys():
    user = current_user()
    owner_id = request_owner_id(request.args)
    business_type = request_business_type(request.args)
    group_tag = request_group_tag(request.args)
    day = parse_day(request.args.get("date"))
    query = db().query(Cdkey).options(joinedload(Cdkey.batch)).order_by(Cdkey.id.asc())
    query = cdkey_filters(query, request.args.get("status"), request.args.get("batch_no"), request.args.get("code"), day, owner_id, business_type, group_tag, request.args.get("extraction_no"))
    log_audit("EXPORT_CDKEYS", "卡密", "筛选结果", f"owner_id={owner_id}, date={day}, business={business_type}, tag={group_tag}")
    return send_file(BytesIO(cdkeys_csv(query.limit(10000).all())), mimetype="text/csv", as_attachment=True, download_name="cdkeys.csv")


@bp.post("/admin/cdkeys/over-issue")
@login_required
def over_issue():
    user = current_user()
    requested_owner_id = request_owner_id(request.form)
    try:
        owner_id = require_write_owner(user, requested_owner_id)
    except BusinessError as exc:
        flash(str(exc), "error")
        return redirect(url_for("main.cdkeys", **current_pool_scope(user)))
    business_type = request_business_type(request.form)
    group_tag = request_group_tag(request.form)
    value = set_configured_over_issue_files(
        db(),
        owner_id,
        business_type,
        max(0, parse_int(request.form.get("over_issue_files"), 0)),
    )
    log_audit("UPDATE_OVER_ISSUE", "admin_user", owner_id, f"business={business_type}, value={value}")
    flash("超发额度已更新", "success")
    return redirect(url_for("main.cdkeys", owner_id=owner_id, business_type=business_type, group_tag=group_tag))


@bp.post("/admin/cdkeys/delete")
@login_required
def delete_cdkeys():
    user = current_user()
    session_db = db()
    owner_id = request_owner_id(request.form)
    business_type = request_business_type(request.form)
    group_tag = request_group_tag(request.form)
    day = parse_day(request.form.get("date"))
    mode = request.form.get("delete_mode", "selected")
    redirect_params = compact_params(
        owner_id=owner_id,
        business_type=business_type,
        group_tag=group_tag,
        status=request.form.get("status"),
        batch_no=request.form.get("batch_no"),
        code=request.form.get("code"),
        extraction_no=request.form.get("extraction_no"),
        date=request.form.get("date"),
    )

    if mode == "filtered":
        if request.form.get("confirm_text", "").strip() != FILTER_DELETE_CONFIRM_TEXT:
            flash("删除筛选结果需要二次确认", "error")
            return redirect(url_for("main.cdkeys", **redirect_params))
        query = session_db.query(Cdkey.id)
        query = cdkey_filters(
            query,
            request.form.get("status"),
            request.form.get("batch_no"),
            request.form.get("code"),
            day,
            owner_id,
            business_type,
            group_tag,
            request.form.get("extraction_no"),
        )
    else:
        ids = [int(item) for item in request.form.getlist("selected_ids") if item.isdigit()]
        if not ids:
            flash("请选择要删除的卡密", "error")
            return redirect(url_for("main.cdkeys", **redirect_params))
        query = session_db.query(Cdkey.id).join(CdkeyBatch).filter(Cdkey.id.in_(ids))
        if owner_id is not None:
            query = query.filter(CdkeyBatch.created_by == owner_id)
        query = query.filter(CdkeyBatch.business_type == business_type, CdkeyBatch.group_tag == group_tag)

    cdkey_ids = [row.id for row in query.all()]
    cdkey_codes = []
    if cdkey_ids:
        result = delete_cdkeys_with_bound_files(session_db, cdkey_ids, workers=task_workers(session_db))
        cdkey_codes = list(result["cdkey_codes"])
        delete_failed = int(result["delete_failed"])
        if delete_failed:
            flash(f"账号字段删除失败 {delete_failed} 个，已取消删除卡密", "error")
            return redirect(url_for("main.cdkeys", **redirect_params))
        deleted_files = int(result["deleted_files"])
    else:
        delete_failed = 0
        deleted_files = 0
    log_audit("DELETE_CDKEYS", "卡密", cdkey_target_text(cdkey_codes), f"mode={mode}, count={len(cdkey_ids)}, removed_files={deleted_files}, delete_failed={delete_failed}, owner_id={owner_id}, business={business_type}, tag={group_tag}")
    flash(f"已删除 {len(cdkey_ids)} 张卡密，清理绑定文件 {deleted_files} 个", "success" if cdkey_ids else "error")
    return redirect(url_for("main.cdkeys", **redirect_params))


@bp.route("/admin/users", methods=["GET", "POST"])
@login_required
@admin_required
def users():
    return serve_admin_frontend()


@bp.post("/admin/users/<int:user_id>/password")
@login_required
@admin_required
def user_password(user_id: int):
    user = db().get(AdminUser, user_id) or abort(404)
    password = request.form.get("password", "")
    policy_error = password_policy_error(password, user.username)
    if policy_error:
        flash(policy_error, "error")
    else:
        user.password_hash = generate_password_hash(password)
        user.login_password = None
        bump_session_version(user)
        db().commit()
        log_audit("CHANGE_USER_PASSWORD", "admin_user", user.id)
        flash("密码已更新", "success")
    return redirect(url_for("main.users"))


@bp.post("/admin/users/<int:user_id>/username")
@login_required
@admin_required
def user_username(user_id: int):
    user = db().get(AdminUser, user_id) or abort(404)
    username = request.form.get("username", "").strip()
    if not username:
        flash("用户名不能为空", "error")
    elif db().query(AdminUser).filter(AdminUser.username == username, AdminUser.id != user.id).first():
        flash("用户名已存在", "error")
    else:
        old_username = user.username
        user.username = username
        bump_session_version(user)
        db().commit()
        log_audit("CHANGE_USER_USERNAME", "admin_user", user.id, f"{old_username} -> {username}")
        if current_user() and current_user().id == user.id:
            session.clear()
            flash("用户名已更新，请重新登录", "success")
            return redirect(url_for("main.login"))
        flash("用户名已更新", "success")
    return redirect(url_for("main.users"))


@bp.post("/admin/users/<int:user_id>/toggle")
@login_required
@admin_required
def user_toggle(user_id: int):
    user = db().get(AdminUser, user_id) or abort(404)
    if user.id == current_user().id:
        flash("不能停用当前账号", "error")
    else:
        user.enabled = not user.enabled
        db().commit()
        log_audit("TOGGLE_USER", "admin_user", user.id, f"enabled={user.enabled}")
        flash("用户状态已更新", "success")
    return redirect(url_for("main.users"))


@bp.post("/admin/users/<int:user_id>/delete")
@login_required
@admin_required
def user_delete(user_id: int):
    user = db().get(AdminUser, user_id) or abort(404)
    if user.id == current_user().id:
        flash("不能删除当前登录账号", "error")
        return redirect(url_for("main.users"))

    session_db = db()
    bound_files = session_db.query(FileRecord.id).filter(FileRecord.uploaded_by == user.id).count()
    bound_cdkey_batches = session_db.query(CdkeyBatch.id).filter(CdkeyBatch.created_by == user.id).count()
    upload_batches = session_db.query(UploadBatch.id).filter(
        (UploadBatch.owner_id == user.id) | (UploadBatch.uploaded_by == user.id)
    ).count()
    audit_logs = session_db.query(AuditLog.id).filter(AuditLog.user_id == user.id).count()
    if bound_files or bound_cdkey_batches or upload_batches or audit_logs:
        flash("该用户仍有关联数据，暂不支持直接删除；请先清空文件、卡密、上传记录和审计关联后再处理。", "error")
        return redirect(url_for("main.users"))

    username = user.username
    session_db.delete(user)
    session_db.commit()
    log_audit("DELETE_USER", "admin_user", username)
    flash(f"已删除用户 {username}", "success")
    return redirect(url_for("main.users"))


@bp.route("/admin/settings", methods=["GET", "POST"])
@login_required
@admin_required
def settings():
    return serve_admin_frontend()


@bp.get("/query")
def query_index():
    return serve_admin_frontend()


@bp.get("/query/stock")
def query_stock():
    return jsonify(public_inventory())


@bp.post("/query/access")
def query_access():
    return redirect("/query")


@bp.get("/query/progress/<job_id>")
def query_progress(job_id: str):
    return serve_admin_frontend()


@bp.get("/query/progress/<job_id>.json")
def query_progress_json(job_id: str):
    if not authorize_query_job(job_id):
        return jsonify({"status": "missing", "error": "请先输入卡密"}), 403
    job = job_payload(job_id, allow_public=True)
    if not job:
        return jsonify({"status": "missing", "error": "测活任务不存在或已过期"}), 404
    if job.get("status") == "done" and job.get("cdkey_ids"):
        sync_extracted_files_from_db(job_id, job.get("cdkey_ids") or [], job.get("live_check", True))
        with JOBS_LOCK:
            job = dict(EXTRACTION_JOBS.get(job_id) or job)
            if job.get("events"):
                job["events"] = list(job["events"])
        scoped_ids = scoped_query_cdkey_ids(job)
        ids = scoped_ids if scoped_ids is not None else query_job_cdkey_ids(job)
        session.permanent = True
        session["query_cdkey_ids"] = ids
        session["query_job_id"] = job_id
        session[QUERY_ACCESS_JOB_SESSION_KEY] = job_id
        session.pop("query_pending_job_id", None)
    return jsonify(public_query_job_payload(job))


@bp.get("/query/result")
def query_result():
    return serve_admin_frontend()


@bp.get("/query/files/download")
def query_download():
    ids, _job = authorized_query_result_ids(request.args.get("job_id") or session.get("query_job_id"))
    if not ids:
        return api_error("请先输入卡密", 403, "FORBIDDEN") if request.args.get("job_id") else redirect(url_for("main.query_index"))
    cdkeys = db().query(Cdkey).filter(Cdkey.id.in_(ids)).all()
    files = bound_files(db(), ids)
    filename = f"{datetime.now():%Y%m%d%H%M%S}-{len(files)}files.zip"
    log_audit("QUERY_DOWNLOAD", "卡密", cdkey_target_text([item.code for item in cdkeys]), f"files={len(files)}")
    try:
        content = zip_for_files(db(), files)
    except BusinessError as exc:
        if request.args.get("job_id"):
            return api_error(str(exc), 409, "DOWNLOAD_FAILED")
        flash(str(exc), "error")
        return redirect(url_for("main.query_result"))
    return send_file(BytesIO(content), mimetype="application/zip", as_attachment=True, download_name=filename)


@bp.get("/query/files/download-2fa")
def query_two_factor_download():
    from .two_factor import two_factor_txt

    ids, _job = authorized_query_result_ids(request.args.get("job_id") or session.get("query_job_id"))
    if not ids:
        return api_error("请先输入卡密", 403, "FORBIDDEN")
    files = bound_files(db(), ids)
    try:
        content = two_factor_txt(files)
    except BusinessError as exc:
        return api_error(str(exc), 409, "TOTP_NOT_READY")
    response = send_file(BytesIO(content), mimetype="text/plain", as_attachment=True, download_name="accounts-2fa.txt")
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.get("/query/files/download-sub")
def query_sub_download():
    ids, _job = authorized_query_result_ids(request.args.get("job_id") or session.get("query_job_id"))
    if not ids:
        return api_error("请先输入卡密", 403, "FORBIDDEN") if request.args.get("job_id") else redirect(url_for("main.query_index"))
    cdkeys = db().query(Cdkey).filter(Cdkey.id.in_(ids)).all()
    files = bound_files(db(), ids)
    filename = f"{datetime.now():%Y%m%d%H%M%S}-{len(files)}files-sub2api.json"
    log_audit("QUERY_DOWNLOAD_SUB", "卡密", cdkey_target_text([item.code for item in cdkeys]), f"files={len(files)}")
    try:
        content = sub2api_json_for_files(db(), files)
    except BusinessError as exc:
        if request.args.get("job_id"):
            return api_error(str(exc), 409, "DOWNLOAD_FAILED")
        flash(str(exc), "error")
        return redirect(url_for("main.query_result"))
    return send_file(BytesIO(content), mimetype="application/json", as_attachment=True, download_name=filename)


@bp.get("/admin/audit")
@login_required
@admin_required
def audit_logs():
    return serve_admin_frontend()
