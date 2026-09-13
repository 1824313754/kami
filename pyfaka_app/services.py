import csv
import io
import json
import re
import secrets
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from typing import Callable, Iterable

from sqlalchemy import func, inspect, or_
from sqlalchemy.orm import Session, joinedload, selectinload

from .auth_store import (
    DEFAULT_LIVE_CHECK_TIMEOUT,
    DEFAULT_LIVE_CHECK_USER_AGENT,
    LocalLiveCheckConfig,
    check_auth_payload,
)
from .database import SessionLocal
from .live_check import LiveCheckResult
from .models import AdminUser, AppSetting, Cdkey, CdkeyBatch, FileRecord, FileRecordPayload, UploadBatch, UploadResult

REQUIRED_PAYLOAD_KEYS = {
    "id_token",
    "access_token",
    "refresh_token",
    "account_id",
    "last_refresh",
    "email",
    "type",
    "expired",
}
PAYLOAD_FIELD_NAMES = (
    "id_token",
    "access_token",
    "refresh_token",
    "account_id",
    "last_refresh",
    "email",
    "type",
    "expired",
)
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
DEFAULT_LIVE_CHECK_WORKERS = 50
DEFAULT_UNSHIPPABLE_HTTP_STATUSES = (401,)
DEFAULT_BUSINESS_TYPE = "free"
DEFAULT_GROUP_TAG = "default"
DEFAULT_BUSINESS_TYPE_OPTIONS = (
    {"key": "free", "label": "Free", "code": "FREE", "show_in_query": True},
    {"key": "plus", "label": "Plus", "code": "PLUS", "show_in_query": True},
    {"key": "team", "label": "Team", "code": "TEAM", "show_in_query": True},
)
BUSINESS_TYPES = tuple(item["key"] for item in DEFAULT_BUSINESS_TYPE_OPTIONS)
BUSINESS_CODE_MAP = {item["key"]: item["code"] for item in DEFAULT_BUSINESS_TYPE_OPTIONS}
BUSINESS_NAME_MAP = {value: key for key, value in BUSINESS_CODE_MAP.items()}
BUSINESS_TYPE_KEY_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
BUSINESS_TYPE_CODE_RE = re.compile(r"^[A-Z][A-Z0-9]{0,15}$")
_BUSINESS_TYPE_OPTIONS_CACHE: list[dict] | None = None


class BusinessError(Exception):
    pass


class TaskAbortError(BusinessError):
    pass


ProgressCallback = Callable[[dict], None]
LIVE_CHECK_TIMEOUT_KEY = "live_check_timeout"
LIVE_CHECK_USER_AGENT_KEY = "live_check_user_agent"
UNSHIPPABLE_HTTP_STATUSES_KEY = "unshippable_http_status"
TASK_WORKERS_KEY = "task_workers"
QUERY_TOTP_ENABLED_KEY = "query_totp_enabled"
EXTRACT_CLEANUP_TIME_KEY = "extract_cleanup_time"
BUSINESS_TYPES_SETTING_KEY = "business_types"
SQL_IN_CHUNK_SIZE = 500


def chunk_list(values: list[int], size: int = SQL_IN_CHUNK_SIZE):
    for index in range(0, len(values), size):
        yield values[index:index + size]


def default_business_type_options() -> list[dict]:
    return [
        {
            "key": item["key"],
            "label": item["label"],
            "code": item["code"],
            "enabled": True,
            "show_in_query": bool(item["show_in_query"]),
            "locked": True,
        }
        for item in DEFAULT_BUSINESS_TYPE_OPTIONS
    ]


def bool_setting(value, default: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


def normalize_business_type_options(value, strict: bool = False) -> list[dict]:
    raw_options = value.get("items") if isinstance(value, dict) else value
    if not isinstance(raw_options, list):
        if strict:
            raise BusinessError("业务类型配置格式不正确")
        return default_business_type_options()

    options: list[dict] = []
    keys: set[str] = set()
    codes: set[str] = set()
    for index, raw in enumerate(raw_options):
        if not isinstance(raw, dict):
            if strict:
                raise BusinessError("业务类型配置格式不正确")
            continue
        code = str(raw.get("code") or raw.get("label") or raw.get("key") or "").strip().upper()
        key = str(raw.get("key") or code.lower()).strip().lower()
        label = str(raw.get("label") or code).strip()[:64] or code
        if not BUSINESS_TYPE_KEY_RE.match(key):
            if strict:
                raise BusinessError("业务类型 key 只能使用小写字母、数字、中横线或下划线，并且必须以字母开头")
            continue
        if not code:
            code = re.sub(r"[^A-Z0-9]", "", key.upper())
        if not BUSINESS_TYPE_CODE_RE.match(code):
            if strict:
                raise BusinessError("卡密编码只能使用大写字母和数字，并且必须以字母开头")
            continue
        if key in keys:
            if strict:
                raise BusinessError(f"业务类型 key 重复：{key}")
            continue
        if code in codes or (code in BUSINESS_NAME_MAP and BUSINESS_NAME_MAP[code] != key):
            if strict:
                raise BusinessError(f"卡密编码重复：{code}")
            continue
        keys.add(key)
        codes.add(code)
        options.append({
            "key": key,
            "label": label,
            "code": code,
            "enabled": bool_setting(raw.get("enabled"), True),
            "show_in_query": bool_setting(raw.get("show_in_query"), True),
            "locked": bool_setting(raw.get("locked"), key in BUSINESS_TYPES),
        })

    if not options:
        if strict:
            raise BusinessError("至少保留一个业务类型")
        return default_business_type_options()
    if strict and not any(item["enabled"] for item in options):
        raise BusinessError("至少启用一个业务类型")
    return options


def parse_business_type_options_text(value: str | None) -> list[dict]:
    text = str(value or "").strip()
    if not text:
        return default_business_type_options()
    try:
        payload = json.loads(text)
    except ValueError:
        return default_business_type_options()
    return normalize_business_type_options(payload)


def business_type_options(include_disabled: bool = True) -> list[dict]:
    global _BUSINESS_TYPE_OPTIONS_CACHE
    if _BUSINESS_TYPE_OPTIONS_CACHE is None:
        session_db = SessionLocal()
        try:
            _BUSINESS_TYPE_OPTIONS_CACHE = parse_business_type_options_text(
                get_setting(session_db, BUSINESS_TYPES_SETTING_KEY, "")
            )
        finally:
            session_db.close()
    options = [dict(item) for item in _BUSINESS_TYPE_OPTIONS_CACHE]
    if not include_disabled:
        options = [item for item in options if item.get("enabled")]
    return options


def query_business_type_options() -> list[dict]:
    return [item for item in business_type_options(False) if item.get("show_in_query")]


def business_type_keys(include_legacy: bool = True) -> tuple[str, ...]:
    keys = [item["key"] for item in business_type_options()]
    if include_legacy:
        for key in BUSINESS_TYPES:
            if key not in keys:
                keys.append(key)
    return tuple(keys)


def active_business_type_keys() -> tuple[str, ...]:
    keys = [item["key"] for item in business_type_options(False)]
    return tuple(keys or [DEFAULT_BUSINESS_TYPE])


def default_active_business_type() -> str:
    active_keys = active_business_type_keys()
    return DEFAULT_BUSINESS_TYPE if DEFAULT_BUSINESS_TYPE in active_keys else active_keys[0]


def normalize_active_business_type(value: str | None) -> str:
    text = str(value or "").strip().lower()
    active_keys = active_business_type_keys()
    return text if text in active_keys else default_active_business_type()


def business_type_code_map() -> dict[str, str]:
    mapping = dict(BUSINESS_CODE_MAP)
    for item in business_type_options():
        mapping[item["key"]] = item["code"]
    return mapping


def business_type_code_name_map() -> dict[str, str]:
    mapping = dict(BUSINESS_NAME_MAP)
    for item in business_type_options():
        mapping[item["code"]] = item["key"]
    return mapping


def business_type_options_json(options: list[dict]) -> str:
    return json.dumps(normalize_business_type_options(options, strict=True), ensure_ascii=False)


def business_type_options_json_for_update(options: list[dict], existing_options: list[dict]) -> str:
    existing_by_key = {item["key"]: item for item in existing_options}
    next_options = normalize_business_type_options(options, strict=True)
    for item in next_options:
        existing = existing_by_key.get(item["key"])
        if existing and item["code"] != existing["code"]:
            raise BusinessError(f"业务类型已创建，不能修改卡密编码：{existing['code']}")
        if existing:
            item["locked"] = True
    return json.dumps(next_options, ensure_ascii=False)


def today_range(day: date | None) -> tuple[datetime, datetime]:
    effective = day or date.today()
    start = datetime.combine(effective, time.min)
    return start, start + timedelta(days=1)


def parse_payload(stream) -> tuple[dict, int]:
    raw = stream.read()
    try:
        payload = json.loads(raw.decode("utf-8-sig"))
    except Exception as exc:
        raise BusinessError("JSON 格式不正确") from exc
    if not isinstance(payload, dict):
        raise BusinessError("JSON 格式不正确")
    missing_keys = REQUIRED_PAYLOAD_KEYS - set(payload.keys())
    if missing_keys:
        raise BusinessError("JSON 缺少必要字段：" + "、".join(sorted(missing_keys)))
    if not str(payload.get("email", "")).strip():
        raise BusinessError("邮箱不能为空")
    return payload, len(raw)


def parse_upload_payloads(stream) -> list[tuple[dict, int]]:
    raw = stream.read()
    try:
        document = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, UnicodeError) as exc:
        raise BusinessError("JSON 格式不正确") from exc
    if not isinstance(document, dict) or "accounts" not in document:
        return [parse_payload(io.BytesIO(raw))]
    accounts = document["accounts"]
    if not isinstance(accounts, list) or not accounts:
        raise BusinessError("sub2api accounts 必须是非空账号列表")
    payloads = []
    for index, account in enumerate(accounts, 1):
        prefix = f"sub2api 第 {index} 个账号："
        if not isinstance(account, dict) or account.get("platform") != "openai" or account.get("type") != "oauth":
            raise BusinessError(prefix + "只支持 openai 平台的 oauth 账号")
        credentials = account.get("credentials")
        if not isinstance(credentials, dict):
            raise BusinessError(prefix + "credentials 必须是 JSON 对象")
        extra = account.get("extra") or {}
        if not isinstance(extra, dict):
            raise BusinessError(prefix + "extra 必须是 JSON 对象")
        email = str(credentials.get("email") or extra.get("email") or account.get("name") or "").strip()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+", email):
            raise BusinessError(prefix + "缺少有效账号邮箱")
        for field in ("access_token", "refresh_token"):
            if not isinstance(credentials.get(field), str) or not credentials[field].strip():
                raise BusinessError(prefix + f"缺少有效 {field}")
        expired = credentials.get("expired") or ""
        expires_at = credentials.get("expires_at") or account.get("expires_at")
        if not expired and expires_at is not None:
            try:
                expired = datetime.fromtimestamp(int(expires_at), timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            except (ValueError, TypeError, OverflowError, OSError) as exc:
                raise BusinessError(prefix + "expires_at 必须是有效的 Unix 秒时间戳") from exc
        payload = {
            "id_token": str(credentials.get("id_token") or ""),
            "access_token": credentials["access_token"],
            "refresh_token": credentials["refresh_token"],
            "account_id": str(credentials.get("chatgpt_account_id") or credentials.get("account_id") or ""),
            "last_refresh": str(credentials.get("last_refresh") or extra.get("last_refresh") or ""),
            "email": email,
            "type": "oauth",
            "expired": str(expired),
        }
        payloads.append((payload, len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))))
    return payloads


def safe_name(value: str) -> str:
    return "".join("_" if ch in '\\/:*?"<>|' else ch for ch in value)


def normalize_business_type(value: str | None) -> str:
    text = str(value or "").strip().lower()
    return text if text in business_type_keys() else DEFAULT_BUSINESS_TYPE


def normalize_group_tag(value: str | None) -> str:
    text = str(value or "").strip()
    return text[:64] or DEFAULT_GROUP_TAG


def business_code(value: str | None) -> str:
    codes = business_type_code_map()
    return codes.get(normalize_business_type(value), BUSINESS_CODE_MAP[DEFAULT_BUSINESS_TYPE])


def upload_display_name(value: str) -> str:
    text = str(value or "").replace("\\", "/").strip("/")
    return text.rsplit("/", 1)[-1] if text else ""


def quota_remaining_label(quota: dict | None) -> str:
    if not quota:
        return "暂无"
    used_text = quota.get("x-codex-primary-used-percent")
    try:
        used = int(float(str(used_text)))
    except (TypeError, ValueError):
        return "暂无"
    remaining = max(0, 100 - used)
    return f"{remaining}%"


def quota_display_text(value) -> str:
    text = str(value or "").strip()
    if not text:
        return "暂无"
    match = re.search(r"(\d+)\s*%", text)
    if match:
        return f"{int(match.group(1))}%"
    return text


def live_check_message(result: LiveCheckResult) -> str:
    message = (result.message or "").strip()
    if result.http_status is not None and message:
        message = f"HTTP {result.http_status} {message}"
    elif result.http_status is not None:
        message = f"HTTP {result.http_status}"
    return message[:500] or "暂无"


def normalize_unshippable_http_statuses(value, strict: bool = False) -> tuple[int, ...]:
    raw_values = value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raw_values = []
        else:
            try:
                raw_values = json.loads(text)
            except ValueError:
                raw_values = text
    if not isinstance(raw_values, (list, tuple, set)):
        raw_values = [raw_values]

    statuses: list[int] = []
    for raw in raw_values:
        try:
            status = int(raw)
        except (TypeError, ValueError):
            if strict:
                raise BusinessError("不可出库状态码必须是 100 到 599 之间的整数")
            return DEFAULT_UNSHIPPABLE_HTTP_STATUSES
        if not 100 <= status <= 599:
            if strict:
                raise BusinessError("不可出库状态码必须是 100 到 599 之间的整数")
            return DEFAULT_UNSHIPPABLE_HTTP_STATUSES
        if status not in statuses:
            statuses.append(status)
    if not statuses:
        if strict:
            raise BusinessError("请至少选择一个不可出库状态码")
        return DEFAULT_UNSHIPPABLE_HTTP_STATUSES
    return tuple(statuses)


def is_live_check_alive(
    result: LiveCheckResult,
    unshippable_http_statuses: tuple[int, ...] = DEFAULT_UNSHIPPABLE_HTTP_STATUSES,
) -> bool:
    return result.alive and result.http_status == 200 and result.http_status not in unshippable_http_statuses


def is_definite_dead_account(
    result: LiveCheckResult,
    unshippable_http_statuses: tuple[int, ...] = DEFAULT_UNSHIPPABLE_HTTP_STATUSES,
) -> bool:
    return result.http_status in unshippable_http_statuses


def live_check_candidate_limit(workers: int, remaining_needed: int) -> int:
    remaining_needed = max(1, int(remaining_needed or 1))
    workers = max(1, int(workers or DEFAULT_LIVE_CHECK_WORKERS))
    if remaining_needed >= workers:
        return workers
    buffer_count = max(1, (remaining_needed + 1) // 2)
    return min(workers, remaining_needed + buffer_count)


def retry_note(result: LiveCheckResult) -> LiveCheckResult:
    message = (result.message or "").strip()
    if "已重试" not in message:
        message = f"{message or '测活未通过'}（已重试）"
    return LiveCheckResult(
        result.alive,
        result.http_status,
        message,
        result.token_refreshed,
        result.updated_auth,
        result.quota,
        result.rt_ms,
    )


def check_auth_item_with_retry(
    config,
    item: dict,
    unshippable_http_statuses: tuple[int, ...] = DEFAULT_UNSHIPPABLE_HTTP_STATUSES,
) -> LiveCheckResult:
    try:
        result = check_auth_payload(config, item)
    except Exception:
        result = LiveCheckResult(False, None, "测活请求异常", False)
    if is_live_check_alive(result, unshippable_http_statuses) or is_definite_dead_account(result, unshippable_http_statuses):
        return result
    try:
        return retry_note(check_auth_payload(config, item))
    except Exception as exc:
        return LiveCheckResult(False, None, f"{exc}（已重试）", False)


def get_setting(db: Session, key: str, default: str = "") -> str:
    item = db.get(AppSetting, key)
    return str(item.value or "") if item else default


def set_setting(db: Session, key: str, value: str | None) -> AppSetting:
    global _BUSINESS_TYPE_OPTIONS_CACHE
    item = db.get(AppSetting, key)
    if not item:
        item = AppSetting(key=key)
        db.add(item)
    item.value = value or ""
    db.commit()
    if key == BUSINESS_TYPES_SETTING_KEY:
        _BUSINESS_TYPE_OPTIONS_CACHE = parse_business_type_options_text(item.value)
    return item


def live_check_config(db: Session) -> LocalLiveCheckConfig:
    timeout = max(1, parse_setting_int(get_setting(db, LIVE_CHECK_TIMEOUT_KEY, str(DEFAULT_LIVE_CHECK_TIMEOUT)), DEFAULT_LIVE_CHECK_TIMEOUT))
    user_agent = get_setting(db, LIVE_CHECK_USER_AGENT_KEY, DEFAULT_LIVE_CHECK_USER_AGENT).strip() or DEFAULT_LIVE_CHECK_USER_AGENT
    return LocalLiveCheckConfig(timeout=timeout, user_agent=user_agent)


def unshippable_http_statuses(db: Session) -> tuple[int, ...]:
    value = get_setting(db, UNSHIPPABLE_HTTP_STATUSES_KEY, json.dumps(DEFAULT_UNSHIPPABLE_HTTP_STATUSES))
    return normalize_unshippable_http_statuses(value)


def parse_setting_int(value: str, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def worker_setting(db: Session, key: str, default: int = DEFAULT_LIVE_CHECK_WORKERS) -> int:
    value = parse_setting_int(get_setting(db, key, str(default)), default)
    return max(1, min(200, value))


def task_workers(db: Session) -> int:
    return worker_setting(db, TASK_WORKERS_KEY)


def query_totp_enabled(db: Session) -> bool:
    return get_setting(db, QUERY_TOTP_ENABLED_KEY, "1").strip().lower() in {"1", "true", "yes", "on"}


def normalize_cleanup_time_text(value: str | None, default: str = "12:00") -> str:
    text = str(value or "").strip()
    match = re.match(r"^(\d{1,2}):(\d{1,2})$", text)
    if not match:
        return default
    hour = int(match.group(1))
    minute = int(match.group(2))
    if hour < 0 or hour > 23 or minute < 0 or minute > 59:
        return default
    return f"{hour:02d}:{minute:02d}"


def cleanup_schedule_time(db: Session, default: str = "12:00") -> str:
    return normalize_cleanup_time_text(get_setting(db, EXTRACT_CLEANUP_TIME_KEY, default), default)


def payload_to_db_fields(payload: dict, existing_reauth_info_raw: str = "") -> dict[str, str]:
    fields = {name: str(payload.get(name) or "") for name in PAYLOAD_FIELD_NAMES}
    fields["reauth_info"] = existing_reauth_info_raw
    return fields


def payload_from_db_fields(
    payload: FileRecordPayload | None,
    include_reauth: bool = False,
) -> dict:
    if not payload:
        return {}
    result = {name: getattr(payload, name) or "" for name in PAYLOAD_FIELD_NAMES}
    if include_reauth:
        raw_reauth_info = getattr(payload, "reauth_info", "") or ""
        try:
            reauth_info = json.loads(raw_reauth_info)
        except (TypeError, ValueError):
            reauth_info = {}
        if isinstance(reauth_info, dict):
            result["reauth_info"] = reauth_info
    return result


def payload_for_record(
    record: FileRecord,
    include_reauth: bool = False,
) -> dict:
    return payload_from_db_fields(getattr(record, "payload", None), include_reauth)


def loaded_payload_for_record(record: FileRecord, include_reauth: bool = False) -> dict:
    if "payload" in inspect(record).unloaded:
        return {}
    return payload_for_record(record, include_reauth)


def payloads_for_records(
    db: Session,
    records: list[FileRecord],
    include_reauth: bool = False,
) -> dict[int, dict]:
    payloads: dict[int, dict] = {}
    missing_ids: list[int] = []
    for record in records:
        if not getattr(record, "id", None):
            continue
        record_id = int(record.id)
        payload = loaded_payload_for_record(record, include_reauth)
        if payload:
            payloads[record_id] = payload
        else:
            missing_ids.append(record_id)
    if missing_ids:
        for payload in db.query(FileRecordPayload).filter(FileRecordPayload.file_record_id.in_(missing_ids)).all():
            item = payload_from_db_fields(payload, include_reauth)
            if item:
                payloads[int(payload.file_record_id)] = item
    return payloads


def live_check_candidates(db: Session, records: list[FileRecord]) -> tuple[LocalLiveCheckConfig, dict[int, dict], dict[int, LiveCheckResult]]:
    config = live_check_config(db)
    jobs: dict[int, dict] = {}
    errors: dict[int, LiveCheckResult] = {}
    payloads = payloads_for_records(db, records)
    for record in records:
        payload = payloads.get(record.id)
        if not payload:
            errors[record.id] = LiveCheckResult(False, None, "账号字段内容不存在", False)
            continue
        jobs[record.id] = payload
    return config, jobs, errors


def delete_cdkeys_with_bound_files(
    db: Session,
    cdkey_ids: list[int],
    workers: int = DEFAULT_LIVE_CHECK_WORKERS,
) -> dict[str, int | list[str]]:
    unique_ids = list(dict.fromkeys(int(item) for item in cdkey_ids if item))
    if not unique_ids:
        return {
            "deleted_cdkeys": 0,
            "deleted_files": 0,
            "delete_failed": 0,
            "cdkey_codes": [],
        }

    cdkey_codes = [row.code for row in db.query(Cdkey.code).filter(Cdkey.id.in_(unique_ids)).all()]
    bound_records = db.query(FileRecord).filter(FileRecord.bound_cdkey_id.in_(unique_ids)).all()
    try:
        bound_record_ids = [record.id for record in bound_records]
        if bound_records:
            db.query(UploadResult).filter(UploadResult.record_id.in_(bound_record_ids)).update(
                {UploadResult.record_id: None},
                synchronize_session=False,
            )
            db.query(FileRecordPayload).filter(FileRecordPayload.file_record_id.in_(bound_record_ids)).delete(synchronize_session=False)
            db.query(FileRecord).filter(FileRecord.id.in_(bound_record_ids)).delete(synchronize_session=False)
        db.query(Cdkey).filter(Cdkey.id.in_(unique_ids)).delete(synchronize_session=False)
        db.commit()
    except Exception:
        db.rollback()
        raise
    return {
        "deleted_cdkeys": len(unique_ids),
        "deleted_files": len(bound_records),
        "delete_failed": 0,
        "cdkey_codes": cdkey_codes,
    }


@dataclass(frozen=True)
class PendingUpload:
    filename: str
    payload: dict
    size: int
    email: str
    normalized: str


def owner_scope(user: AdminUser, requested_owner_id: int | None) -> int | None:
    if user.is_admin:
        return requested_owner_id
    return user.id


def writable_owner_id(user: AdminUser, requested_owner_id: int | None) -> int:
    if user.is_admin and requested_owner_id:
        return requested_owner_id
    return user.id


def count_files(db: Session, owner_id: int | None, status: str | None = None) -> int:
    query = db.query(func.count(FileRecord.id))
    if owner_id is not None:
        query = query.filter(FileRecord.uploaded_by == owner_id)
    if status:
        query = query.filter(FileRecord.status == status)
    return int(query.scalar() or 0)


def count_scoped_files(
    db: Session,
    owner_id: int | None,
    business_type: str,
    group_tag: str,
    status: str | None = None,
) -> int:
    query = db.query(func.count(FileRecord.id))
    if owner_id is not None:
        query = query.filter(FileRecord.uploaded_by == owner_id)
    query = query.filter(
        FileRecord.business_type == normalize_business_type(business_type),
        FileRecord.group_tag == normalize_group_tag(group_tag),
    )
    if status:
        query = query.filter(FileRecord.status == status)
    return int(query.scalar() or 0)


def count_cdkeys(db: Session, owner_id: int | None, status: str | None = None) -> int:
    query = db.query(func.count(Cdkey.id)).join(CdkeyBatch)
    if owner_id is not None:
        query = query.filter(CdkeyBatch.created_by == owner_id)
    if status:
        query = query.filter(Cdkey.extract_status == status)
    return int(query.scalar() or 0)


def count_scoped_cdkeys(
    db: Session,
    owner_id: int | None,
    business_type: str,
    group_tag: str,
    status: str | None = None,
) -> int:
    query = db.query(func.count(Cdkey.id)).join(CdkeyBatch)
    if owner_id is not None:
        query = query.filter(CdkeyBatch.created_by == owner_id)
    query = query.filter(
        CdkeyBatch.business_type == normalize_business_type(business_type),
        CdkeyBatch.group_tag == normalize_group_tag(group_tag),
    )
    if status:
        query = query.filter(Cdkey.extract_status == status)
    return int(query.scalar() or 0)


def sum_cdkey_files(db: Session, owner_id: int | None, status: str | None = None) -> int:
    query = db.query(func.coalesce(func.sum(Cdkey.files_per_key), 0)).join(CdkeyBatch)
    if owner_id is not None:
        query = query.filter(CdkeyBatch.created_by == owner_id)
    if status:
        query = query.filter(Cdkey.extract_status == status)
    return int(query.scalar() or 0)


def sum_scoped_cdkey_files(
    db: Session,
    owner_id: int | None,
    business_type: str,
    group_tag: str,
    status: str | None = None,
) -> int:
    query = db.query(func.coalesce(func.sum(Cdkey.files_per_key), 0)).join(CdkeyBatch)
    if owner_id is not None:
        query = query.filter(CdkeyBatch.created_by == owner_id)
    query = query.filter(
        CdkeyBatch.business_type == normalize_business_type(business_type),
        CdkeyBatch.group_tag == normalize_group_tag(group_tag),
    )
    if status:
        query = query.filter(Cdkey.extract_status == status)
    return int(query.scalar() or 0)


def configured_over_issue_files(db: Session, owner: AdminUser, business_type: str) -> int:
    key = f"over_issue:{owner.id}:{normalize_business_type(business_type)}"
    value = get_setting(db, key, "").strip()
    if value:
        return max(0, parse_setting_int(value, 0))
    return max(0, owner.over_issue_files or 0)


def set_configured_over_issue_files(db: Session, owner_id: int, business_type: str, value: int) -> int:
    configured = max(0, int(value or 0))
    key = f"over_issue:{owner_id}:{normalize_business_type(business_type)}"
    set_setting(db, key, str(configured))
    return configured


def used_over_issue_files_for_business(db: Session, owner_id: int, business_type: str) -> int:
    business_type = normalize_business_type(business_type)
    available_by_group = {
        str(group_tag): int(count or 0)
        for group_tag, count in (
            db.query(FileRecord.group_tag, func.count(FileRecord.id))
            .filter(
                FileRecord.uploaded_by == owner_id,
                FileRecord.business_type == business_type,
                FileRecord.status == "AVAILABLE",
            )
            .group_by(FileRecord.group_tag)
            .all()
        )
    }
    reserved_by_group = {
        str(group_tag): int(count or 0)
        for group_tag, count in (
            db.query(CdkeyBatch.group_tag, func.coalesce(func.sum(Cdkey.files_per_key), 0))
            .join(Cdkey)
            .filter(
                CdkeyBatch.created_by == owner_id,
                CdkeyBatch.business_type == business_type,
                Cdkey.extract_status == "PENDING",
            )
            .group_by(CdkeyBatch.group_tag)
            .all()
        )
    }
    groups = set(available_by_group) | set(reserved_by_group)
    return sum(max(0, reserved_by_group.get(group, 0) - available_by_group.get(group, 0)) for group in groups)


@dataclass(frozen=True)
class Capacity:
    available_files: int
    reserved_files: int
    remaining_capacity: int
    configured_over_issue_files: int
    used_over_issue_files: int
    remaining_over_issue_files: int
    total_bindable_files: int


@dataclass(frozen=True)
class ScopeInfo:
    business_type: str
    group_tag: str


@dataclass(frozen=True)
class LiveCheckSummary:
    total: int
    normal: int
    error: int
    skipped: int


@dataclass(frozen=True)
class UploadItemResult:
    filename: str
    email: str | None
    status: str
    message: str
    record_id: int | None = None


@dataclass(frozen=True)
class UploadSummary:
    total_count: int
    success_count: int
    failure_count: int
    overwrite_count: int
    results: list[UploadItemResult]


@dataclass(frozen=True)
class CdkeyImportSummary:
    batches: list[CdkeyBatch]
    imported_count: int
    duplicate_input_count: int
    existing_count: int


def parse_cdkey_code_scope(code: str) -> tuple[int, str]:
    text = str(code or "").strip().upper()
    code_name_map = business_type_code_name_map()
    business_code_re = "|".join(re.escape(item) for item in sorted(code_name_map, key=len, reverse=True))
    match = re.match(rf"^(\d+)({business_code_re})-\d{{8}}-[{CODE_ALPHABET}]{{20}}$", text) if business_code_re else None
    if not match:
        raise BusinessError(f"卡密格式不正确：{code}")
    files_per_key = int(match.group(1))
    if files_per_key < 1 or files_per_key > 1000:
        raise BusinessError(f"卡密文件数不合法：{code}")
    return files_per_key, code_name_map[match.group(2)]


def capacity_for_owner(db: Session, owner_id: int, business_type: str = DEFAULT_BUSINESS_TYPE, group_tag: str = DEFAULT_GROUP_TAG) -> Capacity:
    owner = db.get(AdminUser, owner_id)
    if not owner:
        raise BusinessError("用户不存在")
    business_type = normalize_business_type(business_type)
    group_tag = normalize_group_tag(group_tag)
    available = count_scoped_files(db, owner_id, business_type, group_tag, "AVAILABLE")
    reserved = sum_scoped_cdkey_files(db, owner_id, business_type, group_tag, "PENDING")
    remaining = max(0, available - reserved)
    configured = configured_over_issue_files(db, owner, business_type)
    used_over = used_over_issue_files_for_business(db, owner_id, business_type)
    remaining_over = max(0, configured - used_over)
    return Capacity(available, reserved, remaining, configured, used_over, remaining_over, remaining + remaining_over)


def generate_code(prefix: str, key_date: date) -> str:
    random_part = "".join(secrets.choice(CODE_ALPHABET) for _ in range(20))
    return f"{prefix}-{key_date:%Y%m%d}-{random_part}"


def create_cdkey_batch(
    db: Session,
    owner_id: int,
    total_count: int,
    files_per_key: int,
    remark: str | None,
    business_type: str = DEFAULT_BUSINESS_TYPE,
    group_tag: str = DEFAULT_GROUP_TAG,
) -> CdkeyBatch:
    if total_count < 1 or total_count > 10000:
        raise BusinessError("生成数量必须在 1 到 10000 之间")
    if files_per_key < 1 or files_per_key > 1000:
        raise BusinessError("每张卡密文件数必须在 1 到 1000 之间")
    business_type = normalize_business_type(business_type)
    group_tag = normalize_group_tag(group_tag)
    requested = total_count * files_per_key
    cap = capacity_for_owner(db, owner_id, business_type, group_tag)
    if requested > cap.total_bindable_files:
        raise BusinessError("当前库存不足，超发额度不足")
    current = date.today()
    prefix = f"{files_per_key}{business_code(business_type)}"
    batch = CdkeyBatch(
        batch_no=f"BATCH-{current:%Y%m%d}-{secrets.token_hex(4)}",
        prefix=prefix,
        key_date=f"{current:%Y%m%d}",
        total_count=total_count,
        files_per_key=files_per_key,
        business_type=business_type,
        group_tag=group_tag,
        remark=(remark or "").strip() or None,
        created_by=owner_id,
    )
    db.add(batch)
    db.flush()
    for _ in range(total_count):
        code = None
        for _retry in range(10):
            candidate = generate_code(prefix, current)
            if not db.query(Cdkey).filter_by(code=candidate).first():
                code = candidate
                break
        if not code:
            raise BusinessError("卡密碰撞次数过多，请重试")
        db.add(Cdkey(batch_id=batch.id, code=code, files_per_key=files_per_key, extract_status="PENDING"))
    db.commit()
    return batch


def import_cdkey_batch(
    db: Session,
    owner_id: int,
    codes: Iterable[str],
    remark: str | None = None,
) -> CdkeyImportSummary:
    normalized_codes = [str(code or "").strip().upper() for code in codes if str(code or "").strip()]
    if not normalized_codes:
        raise BusinessError("请输入要导入的卡密")
    unique_codes = list(dict.fromkeys(normalized_codes))
    if len(unique_codes) > 10000:
        raise BusinessError("单次最多导入 10000 张卡密")
    duplicate_input_count = len(normalized_codes) - len(unique_codes)
    if not db.get(AdminUser, owner_id):
        raise BusinessError("用户不存在")

    existing_codes: set[str] = set()
    for index in range(0, len(unique_codes), 500):
        chunk = unique_codes[index:index + 500]
        existing_codes.update(code for (code,) in db.query(Cdkey.code).filter(Cdkey.code.in_(chunk)).all())
    import_codes = [code for code in unique_codes if code not in existing_codes]

    code_scopes: dict[str, tuple[int, str]] = {}
    for code in import_codes:
        files_per_key, business_type = parse_cdkey_code_scope(code)
        code_scopes[code] = (files_per_key, business_type)

    grouped: dict[tuple[int, str], list[str]] = {}
    for code in import_codes:
        files_per_key, business_type = code_scopes[code]
        grouped.setdefault((files_per_key, business_type), []).append(code)

    current = date.today()
    batches: list[CdkeyBatch] = []
    try:
        for (files_per_key, business_type), group_codes in grouped.items():
            prefix = f"{files_per_key}{business_code(business_type)}"
            batch = CdkeyBatch(
                batch_no=f"IMPORT-{current:%Y%m%d}-{secrets.token_hex(4)}",
                prefix=prefix,
                key_date=f"{current:%Y%m%d}",
                total_count=len(group_codes),
                files_per_key=files_per_key,
                business_type=business_type,
                group_tag=DEFAULT_GROUP_TAG,
                remark=(remark or "导入卡密").strip() or None,
                created_by=owner_id,
            )
            db.add(batch)
            db.flush()
            db.add_all([
                Cdkey(batch_id=batch.id, code=code, files_per_key=files_per_key, extract_status="PENDING")
                for code in group_codes
            ])
            batches.append(batch)
        db.commit()
    except Exception:
        db.rollback()
        raise
    return CdkeyImportSummary(
        batches=batches,
        imported_count=len(import_codes),
        duplicate_input_count=duplicate_input_count,
        existing_count=len(existing_codes),
    )


def existing_upload_records(
    db: Session,
    owner_id: int,
    business_type: str,
    group_tag: str,
    normalized_emails: list[str],
) -> dict[str, FileRecord]:
    records: dict[str, FileRecord] = {}
    for index in range(0, len(normalized_emails), 500):
        chunk = normalized_emails[index:index + 500]
        for record in (
            db.query(FileRecord)
            .options(selectinload(FileRecord.payload))
            .filter(
                FileRecord.uploaded_by == owner_id,
                FileRecord.business_type == business_type,
                FileRecord.group_tag == group_tag,
                func.lower(FileRecord.email_name).in_(chunk),
            )
            .all()
        ):
            records[str(record.email_name or "").strip().lower()] = record
    return records


def upload_payload_files(
    db: Session,
    files: Iterable,
    owner_id: int,
    business_type: str = DEFAULT_BUSINESS_TYPE,
    group_tag: str = DEFAULT_GROUP_TAG,
    progress_callback: ProgressCallback | None = None,
    workers: int = DEFAULT_LIVE_CHECK_WORKERS,
    abort_check: Callable[[], None] | None = None,
) -> UploadSummary:
    business_type = normalize_business_type(business_type)
    group_tag = normalize_group_tag(group_tag)
    results: list[UploadItemResult] = []
    pending: list[PendingUpload] = []
    seen: set[str] = set()
    has_error = False
    file_items = [item for item in files if item and item.filename]
    candidates = []
    for item in file_items:
        if abort_check:
            abort_check()
        filename = upload_display_name(item.filename)
        try:
            payloads = parse_upload_payloads(item.stream)
            for index, (payload, size) in enumerate(payloads, 1):
                display_name = f"{filename} [账号 {index}]" if len(payloads) > 1 else filename
                candidates.append((display_name, payload, size))
        except BusinessError as exc:
            results.append(UploadItemResult(filename=filename, email=None, status="FAILURE", message=str(exc)))
    if progress_callback:
        progress_callback({"event": "upload_start", "total": len(candidates) + len(results), "workers": workers})
        for index, result in enumerate(results, 1):
            progress_callback({"event": "upload_item_done", "filename": result.filename, "email": None, "status": "FAILURE", "message": result.message, "success": 0, "failure": index, "overwrite": 0})
    has_error = bool(results)
    for filename, payload, size in candidates:
        if abort_check:
            abort_check()
        try:
            email = str(payload["email"]).strip()
            normalized = email.lower()
            if normalized in seen:
                raise BusinessError("邮箱重复，本次上传中已存在同邮箱文件")
            seen.add(normalized)
            pending.append(PendingUpload(filename, payload, size, email, normalized))
        except BusinessError as exc:
            has_error = True
            results.append(UploadItemResult(filename=filename, email=None, status="FAILURE", message=str(exc)))
            if progress_callback:
                progress_callback({"event": "upload_item_done", "filename": filename, "email": None, "status": "FAILURE", "message": str(exc), "success": 0, "failure": len(results), "overwrite": 0})

    if abort_check:
        abort_check()
    existing_records = existing_upload_records(
        db,
        owner_id,
        business_type,
        group_tag,
        [item.normalized for item in pending],
    ) if pending else {}

    if abort_check:
        abort_check()
    writable_items: list[tuple[PendingUpload, FileRecord | None, bool]] = []
    for item in pending:
        if abort_check:
            abort_check()
        record = existing_records.get(item.normalized)
        overwritten = record is not None
        if record and record.status == "BOUND":
            has_error = True
            results.append(UploadItemResult(filename=item.filename, email=None, status="FAILURE", message="同邮箱文件已绑定卡密，不能覆盖"))
            if progress_callback:
                progress_callback({"event": "upload_item_done", "filename": item.filename, "email": None, "status": "FAILURE", "message": "同邮箱文件已绑定卡密，不能覆盖", "success": 0, "failure": len(results), "overwrite": 0})
            continue
        writable_items.append((item, record, overwritten))

    if abort_check:
        abort_check()
    if has_error:
        for item, _record, _overwritten in writable_items:
            results.append(UploadItemResult(
                filename=item.filename,
                email=item.email,
                status="FAILURE",
                message="整批上传失败，已取消入库",
            ))
            if progress_callback:
                progress_callback({
                    "event": "upload_item_done",
                    "filename": item.filename,
                    "email": item.email,
                    "status": "FAILURE",
                    "message": "整批上传失败，已取消入库",
                    "success": 0,
                    "failure": len(results),
                    "overwrite": 0,
                })
        db.rollback()
        return UploadSummary(
            total_count=len(results),
            success_count=0,
            failure_count=len(results),
            overwrite_count=0,
            results=results,
        )

    upload_time = datetime.now()
    new_entries: list[tuple[PendingUpload, FileRecord, bool]] = []
    payload_rows: list[FileRecordPayload] = []
    written_records: dict[str, FileRecord] = {}
    for item, record, overwritten in writable_items:
        if abort_check:
            abort_check()
        if not record:
            record = FileRecord(uploaded_by=owner_id)
            new_entries.append((item, record, overwritten))
        record.original_filename = f"{safe_name(item.email)}.json"
        record.email_name = item.email
        record.storage_path = "__payload__"
        record.file_size = item.size
        record.file_ext = "json"
        record.business_type = business_type
        record.group_tag = group_tag
        record.upload_time = upload_time
        record.status = "AVAILABLE"
        record.bound_cdkey_id = None
        record.bound_at = None
        if record.id and record.payload:
            for name, value in payload_to_db_fields(item.payload, record.payload.reauth_info).items():
                setattr(record.payload, name, value)
        elif record.id:
            payload_rows.append(FileRecordPayload(file_record_id=record.id, **payload_to_db_fields(item.payload)))
        written_records[item.normalized] = record

    if abort_check:
        abort_check()
    if new_entries:
        db.add_all([record for _item, record, _overwritten in new_entries])
        db.flush()
        for item, record, _overwritten in new_entries:
            payload_rows.append(FileRecordPayload(file_record_id=record.id, **payload_to_db_fields(item.payload)))
    if abort_check:
        abort_check()
    if payload_rows:
        db.add_all(payload_rows)
    db.flush()

    if abort_check:
        abort_check()
    success = 0
    overwrites = 0
    for item, _record, overwritten in writable_items:
        if abort_check:
            abort_check()
        record = written_records[item.normalized]
        success += 1
        if overwritten:
            overwrites += 1
        results.append(UploadItemResult(
            filename=item.filename,
            email=item.email,
            status="SUCCESS",
            message="已覆盖同邮箱未绑定文件" if overwritten else "上传成功",
            record_id=record.id,
        ))
        if progress_callback:
            progress_callback({
                "event": "upload_item_done",
                "filename": item.filename,
                "email": item.email,
                "status": "SUCCESS",
                "message": "已覆盖同邮箱未绑定文件" if overwritten else "上传成功",
                "success": success,
                "failure": len(results) - success,
                "overwrite": overwrites,
                "registered_at": item.payload.get("last_refresh") or record.upload_time,
                "live_checked_at": record.live_checked_at,
                "quota": quota_display_text(record.live_quota),
                "http_status": record.live_http_status,
            })
    return UploadSummary(
        total_count=len(results),
        success_count=success,
        failure_count=len(results) - success,
        overwrite_count=overwrites,
        results=results,
    )


def save_upload_batch(
    db: Session,
    summary: UploadSummary,
    owner_id: int,
    uploaded_by: int | None,
    business_type: str = DEFAULT_BUSINESS_TYPE,
    group_tag: str = DEFAULT_GROUP_TAG,
) -> UploadBatch:
    business_type = normalize_business_type(business_type)
    group_tag = normalize_group_tag(group_tag)
    batch = UploadBatch(
        owner_id=owner_id,
        uploaded_by=uploaded_by,
        business_type=business_type,
        group_tag=group_tag,
        total_count=summary.total_count,
        success_count=summary.success_count,
        failure_count=summary.failure_count,
        overwrite_count=summary.overwrite_count,
    )
    db.add(batch)
    db.flush()
    for item in summary.results:
        db.add(UploadResult(
            batch_id=batch.id,
            filename=item.filename,
            email=item.email,
            status=item.status,
            message=item.message,
            record_id=item.record_id,
        ))
    return batch


def claim_available_file_ids(
    db: Session,
    owner_id: int | None,
    business_type: str,
    group_tag: str,
    excluded_ids: set[int],
    limit: int,
) -> list[int]:
    business_type = normalize_business_type(business_type)
    group_tag = normalize_group_tag(group_tag)
    claimed_ids: list[int] = []
    seen_ids: set[int] = set()
    while len(claimed_ids) < limit:
        query = (
            db.query(FileRecord.id)
            .filter(
                FileRecord.status == "AVAILABLE",
                FileRecord.uploaded_by == owner_id,
                FileRecord.business_type == business_type,
                FileRecord.group_tag == group_tag,
            )
            .order_by(FileRecord.upload_time.asc(), FileRecord.id.asc())
        )
        ignored_ids = excluded_ids | seen_ids | set(claimed_ids)
        if ignored_ids:
            query = query.filter(~FileRecord.id.in_(ignored_ids))
        candidate_ids = [row[0] for row in query.limit(max((limit - len(claimed_ids)) * 2, 1)).all()]
        if not candidate_ids:
            break
        seen_ids.update(candidate_ids)
        for record_id in candidate_ids:
            updated = (
                db.query(FileRecord)
                .filter(FileRecord.id == record_id, FileRecord.status == "AVAILABLE")
                .update({"status": "CHECKING"}, synchronize_session=False)
            )
            if updated:
                claimed_ids.append(record_id)
                if len(claimed_ids) >= limit:
                    break
        db.commit()
    return claimed_ids


def lock_cdkey_for_extraction(db: Session, cdkey: Cdkey) -> bool:
    if cdkey.extract_status == "EXTRACTED":
        return False
    if cdkey.extract_status == "CHECKING":
        raise BusinessError(f"卡密正在提取中：{cdkey.code}")
    updated = (
        db.query(Cdkey)
        .filter(Cdkey.id == cdkey.id, Cdkey.extract_status == "PENDING")
        .update({"extract_status": "CHECKING"}, synchronize_session=False)
    )
    db.commit()
    if updated:
        cdkey.extract_status = "CHECKING"
        return True
    db.refresh(cdkey)
    if cdkey.extract_status == "EXTRACTED":
        return False
    raise BusinessError(f"卡密正在提取中：{cdkey.code}")


def lock_cdkeys_for_extraction(db: Session, cdkeys: list[Cdkey]) -> set[int]:
    locked_ids: set[int] = set()
    for cdkey in cdkeys:
        if cdkey.extract_status == "EXTRACTED":
            continue
        if cdkey.extract_status == "CHECKING":
            raise BusinessError(f"卡密正在提取中：{cdkey.code}")
        updated = (
            db.query(Cdkey)
            .filter(Cdkey.id == cdkey.id, Cdkey.extract_status == "PENDING")
            .update({"extract_status": "CHECKING"}, synchronize_session=False)
        )
        if updated:
            locked_ids.add(cdkey.id)
        else:
            db.refresh(cdkey)
            if cdkey.extract_status == "EXTRACTED":
                continue
            raise BusinessError(f"卡密正在提取中：{cdkey.code}")
    db.commit()
    return locked_ids


def restore_checking_cdkeys(db: Session, cdkey_ids: set[int]) -> None:
    if not cdkey_ids:
        return
    db.query(Cdkey).filter(Cdkey.id.in_(cdkey_ids), Cdkey.extract_status == "CHECKING").update(
        {"extract_status": "PENDING"},
        synchronize_session=False,
    )


def bind_cdkeys_without_live_check(
    db: Session,
    cdkeys: list[Cdkey],
    ip: str,
    extraction_no: str | None = None,
    progress_callback: ProgressCallback | None = None,
    abort_check: Callable[[], None] | None = None,
) -> None:
    groups: dict[tuple[int | None, str, str], list[Cdkey]] = {}
    for cdkey in cdkeys:
        key = (
            cdkey.batch.created_by,
            normalize_business_type(cdkey.batch.business_type),
            normalize_group_tag(cdkey.batch.group_tag),
        )
        groups.setdefault(key, []).append(cdkey)
    total_needed = sum(item.files_per_key for item in cdkeys)
    bound_total = 0
    all_claimed_ids: set[int] = set()
    bound_files_payload: list[dict[str, str]] = []
    try:
        for (owner_id, business_type, group_tag), group_cdkeys in groups.items():
            if abort_check:
                abort_check()
            group_needed = sum(item.files_per_key for item in group_cdkeys)
            claimed_ids = claim_available_file_ids(db, owner_id, business_type, group_tag, set(), group_needed)
            all_claimed_ids.update(claimed_ids)
            if progress_callback and claimed_ids:
                progress_callback({"event": "claimed_without_live_check", "claimed_file_ids": claimed_ids})
            if len(claimed_ids) < group_needed:
                if all_claimed_ids:
                    db.query(FileRecord).filter(FileRecord.id.in_(all_claimed_ids), FileRecord.status == "CHECKING").update(
                        {"status": "AVAILABLE"},
                        synchronize_session=False,
                    )
                    db.commit()
                raise BusinessError(f"当前可用文件数不足：需要 {total_needed} 个，已锁定 {bound_total} 个")
            records = (
                db.query(FileRecord)
                .filter(FileRecord.id.in_(claimed_ids), FileRecord.status == "CHECKING")
                .order_by(FileRecord.upload_time.asc(), FileRecord.id.asc())
                .all()
            )
            if abort_check:
                abort_check()
            bound_at = datetime.now()
            cursor = 0
            for cdkey in group_cdkeys:
                assigned_records = records[cursor:cursor + cdkey.files_per_key]
                cursor += cdkey.files_per_key
                for record in assigned_records:
                    record.status = "BOUND"
                    record.bound_cdkey_id = cdkey.id
                    record.bound_at = bound_at
                    record.extraction_no = extraction_no
                    record.live_status = None
                    record.live_message = "未测活出库，无质保"
                    bound_files_payload.append({
                        "email": record.email_name,
                        "quota": "未测活",
                        "quota_period": "未测活",
                        "plan_type": "未测活",
                        "status": "已出库",
                        "extracted_at": bound_at.strftime("%Y-%m-%d %H:%M:%S"),
                    })
                cdkey.extract_status = "EXTRACTED"
                cdkey.extraction_no = extraction_no
                cdkey.extracted_at = bound_at
                cdkey.first_extract_ip = ip
                bound_total += len(assigned_records)
            db.commit()
    except Exception:
        if all_claimed_ids:
            db.query(FileRecord).filter(FileRecord.id.in_(all_claimed_ids), FileRecord.status == "CHECKING").update(
                {"status": "AVAILABLE"},
                synchronize_session=False,
            )
            db.commit()
        raise
    if progress_callback:
        progress_callback({"event": "bound_without_live_check", "bound": bound_total, "needed": total_needed, "files": bound_files_payload})


def access_cdkey(db: Session, code: str, ip: str, progress_callback: ProgressCallback | None = None, live_check_workers: int = DEFAULT_LIVE_CHECK_WORKERS) -> Cdkey:
    cdkey = db.query(Cdkey).options(joinedload(Cdkey.batch)).filter(Cdkey.code == code.strip()).first()
    if not cdkey:
        raise BusinessError("卡密无效或不可用")
    if cdkey.extract_status == "EXTRACTED":
        if progress_callback:
            progress_callback({"event": "existing", "code": cdkey.code, "needed": cdkey.files_per_key})
        return cdkey
    locked_cdkey = lock_cdkey_for_extraction(db, cdkey)
    if not locked_cdkey:
        return cdkey
    live_records: list[FileRecord] = []
    tested_ids: set[int] = set()
    claimed_ids: set[int] = set()
    dead_count = 0
    checked_count = 0
    dead_http_statuses = unshippable_http_statuses(db)
    workers = max(1, int(live_check_workers or DEFAULT_LIVE_CHECK_WORKERS))
    if progress_callback:
        progress_callback({"event": "start_code", "code": cdkey.code, "needed": cdkey.files_per_key, "workers": workers})
    try:
        while len(live_records) < cdkey.files_per_key:
            remaining_needed = max(cdkey.files_per_key - len(live_records), 1)
            candidate_ids = claim_available_file_ids(
                db,
                cdkey.batch.created_by,
                cdkey.batch.business_type,
                cdkey.batch.group_tag,
                tested_ids,
                live_check_candidate_limit(workers, remaining_needed),
            )
            if not candidate_ids:
                for record in live_records:
                    record.status = "AVAILABLE"
                    record.bound_cdkey_id = None
                    record.bound_at = None
                db.commit()
                raise BusinessError(f"当前可提取活号不足，已找到 {len(live_records)} 个，不可出库 {dead_count} 个")
            candidates = (
                db.query(FileRecord)
                .filter(FileRecord.id.in_(candidate_ids), FileRecord.status == "CHECKING")
                .order_by(FileRecord.upload_time.asc(), FileRecord.id.asc())
                .all()
            )
            claimed_ids.update(record.id for record in candidates)
            if not candidates:
                continue

            record_by_id = {record.id: record for record in candidates}
            if progress_callback:
                progress_callback({"event": "batch", "candidate_count": len(candidates), "checked": checked_count, "alive": len(live_records), "dead": dead_count})
            config, live_jobs, live_errors = live_check_candidates(db, candidates)
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {
                    pool.submit(check_auth_item_with_retry, config, item, dead_http_statuses): record_id
                    for record_id, item in live_jobs.items()
                }
                for record_id, result in live_errors.items():
                    futures[pool.submit(lambda value: value, result)] = record_id
                for future in as_completed(futures):
                    record_id = futures[future]
                    record = record_by_id[record_id]
                    checked_count += 1
                    tested_ids.add(record.id)
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = LiveCheckResult(False, None, str(exc), False)
                    record.live_status = "NORMAL" if is_live_check_alive(result, dead_http_statuses) else "ERROR"
                    record.live_quota = quota_remaining_label(result.quota)
                    record.live_rt_ms = result.rt_ms
                    record.live_http_status = result.http_status
                    record.live_checked_at = datetime.now()
                    record.live_message = live_check_message(result)
                    alive = is_live_check_alive(result, dead_http_statuses)
                    definite_dead = is_definite_dead_account(result, dead_http_statuses)
                    if alive and len(live_records) < cdkey.files_per_key:
                        live_records.append(record)
                        outcome = "alive"
                    elif alive:
                        record.status = "AVAILABLE"
                        record.bound_cdkey_id = None
                        record.bound_at = None
                        outcome = "alive_spare"
                    else:
                        record.status = "DEAD" if definite_dead else "AVAILABLE"
                        record.bound_cdkey_id = None
                        record.bound_at = None
                        if definite_dead:
                            dead_count += 1
                            outcome = "dead"
                        else:
                            outcome = "unavailable"
                    if progress_callback:
                        progress_callback({
                            "event": "checked",
                            "outcome": outcome,
                            "email": record.email_name,
                            "registered_at": record.payload.last_refresh if record.payload else record.upload_time,
                            "checked": checked_count,
                            "alive": len(live_records),
                            "dead": dead_count,
                            "needed": cdkey.files_per_key,
                            "http_status": result.http_status,
                            "message": result.message,
                            "quota": result.quota,
                            "rt_ms": result.rt_ms,
                        })
            db.flush()
            if progress_callback:
                progress_callback({"event": "batch_done", "checked": checked_count, "alive": len(live_records), "dead": dead_count})
            if len(live_records) >= cdkey.files_per_key:
                break
            db.commit()
        bound_at = datetime.now()
        for record in live_records:
            record.status = "BOUND"
            record.bound_cdkey_id = cdkey.id
            record.bound_at = bound_at
        cdkey.extract_status = "EXTRACTED"
        cdkey.extracted_at = bound_at
        cdkey.first_extract_ip = ip
        db.commit()
        if progress_callback:
            progress_callback({"event": "bound", "code": cdkey.code, "bound": len(live_records), "checked": checked_count, "dead": dead_count})
        return cdkey
    except Exception:
        if claimed_ids:
            db.query(FileRecord).filter(FileRecord.id.in_(claimed_ids), FileRecord.status == "CHECKING").update(
                {"status": "AVAILABLE"},
                synchronize_session=False,
            )
        restore_checking_cdkeys(db, {cdkey.id})
        db.commit()
        raise


def access_cdkeys_bulk(
    db: Session,
    codes: list[str],
    ip: str,
    progress_callback: ProgressCallback | None = None,
    live_check_workers: int = DEFAULT_LIVE_CHECK_WORKERS,
    live_check: bool = True,
    extraction_no: str | None = None,
    abort_check: Callable[[], None] | None = None,
) -> list[Cdkey]:
    normalized_codes = [code.strip() for code in codes if code and code.strip()]
    if not normalized_codes:
        raise BusinessError("请输入卡密")

    rows = (
        db.query(Cdkey)
        .options(joinedload(Cdkey.batch))
        .filter(Cdkey.code.in_(normalized_codes))
        .all()
    )
    by_code = {item.code: item for item in rows}
    ordered_cdkeys: list[Cdkey] = []
    for code in normalized_codes:
        cdkey = by_code.get(code)
        if not cdkey:
            raise BusinessError(f"卡密无效或不可用：{code}")
        ordered_cdkeys.append(cdkey)

    locked_cdkey_ids = lock_cdkeys_for_extraction(db, ordered_cdkeys)
    ordered_ids = [item.id for item in ordered_cdkeys]
    refreshed_rows = (
        db.query(Cdkey)
        .options(joinedload(Cdkey.batch))
        .filter(Cdkey.id.in_(ordered_ids))
        .all()
    )
    refreshed_by_id = {item.id: item for item in refreshed_rows}
    ordered_cdkeys = [refreshed_by_id[item_id] for item_id in ordered_ids if item_id in refreshed_by_id]

    workers = max(1, int(live_check_workers or DEFAULT_LIVE_CHECK_WORKERS))
    pending_cdkeys = [item for item in ordered_cdkeys if item.id in locked_cdkey_ids and item.extract_status == "CHECKING"]
    existing_count = len(ordered_cdkeys) - len(pending_cdkeys)
    total_needed = sum(item.files_per_key for item in pending_cdkeys)
    if progress_callback:
        progress_callback({
            "event": "start_bulk",
            "code_count": len(ordered_cdkeys),
            "existing_count": existing_count,
            "needed": total_needed,
            "workers": workers,
            "live_check": live_check,
            "locked_cdkey_ids": list(locked_cdkey_ids),
        })
    if abort_check:
        abort_check()
    if not pending_cdkeys:
        return ordered_cdkeys
    if not live_check:
        try:
            bind_cdkeys_without_live_check(db, pending_cdkeys, ip, extraction_no, progress_callback, abort_check=abort_check)
        except Exception:
            restore_checking_cdkeys(db, locked_cdkey_ids)
            db.commit()
            raise
        return ordered_cdkeys

    groups: dict[tuple[int | None, str, str], list[Cdkey]] = {}
    for cdkey in pending_cdkeys:
        key = (
            cdkey.batch.created_by,
            normalize_business_type(cdkey.batch.business_type),
            normalize_group_tag(cdkey.batch.group_tag),
        )
        groups.setdefault(key, []).append(cdkey)

    checked_total = 0
    alive_total = 0
    dead_total = 0
    dead_http_statuses = unshippable_http_statuses(db)
    all_claimed_ids: set[int] = set()
    try:
        for (owner_id, business_type, group_tag), group_cdkeys in groups.items():
            if abort_check:
                abort_check()
            group_needed = sum(item.files_per_key for item in group_cdkeys)
            group_live_records: list[FileRecord] = []
            tested_ids: set[int] = set()
            if progress_callback:
                progress_callback({
                    "event": "owner_group",
                    "code_count": len(group_cdkeys),
                    "needed": total_needed,
                    "group_needed": group_needed,
                    "checked": checked_total,
                    "alive": alive_total,
                    "dead": dead_total,
                })

            while len(group_live_records) < group_needed:
                if abort_check:
                    abort_check()
                remaining_needed = group_needed - len(group_live_records)
                candidate_ids = claim_available_file_ids(
                    db,
                    owner_id,
                    business_type,
                    group_tag,
                    tested_ids,
                    live_check_candidate_limit(workers, remaining_needed),
                )
                if not candidate_ids:
                    for record in group_live_records:
                        record.status = "AVAILABLE"
                        record.bound_cdkey_id = None
                        record.bound_at = None
                    db.commit()
                    raise BusinessError(f"当前可提取活号不足，目标 {total_needed} 个，已找到 {alive_total} 个，不可出库 {dead_total} 个")

                all_claimed_ids.update(candidate_ids)
                candidates = (
                    db.query(FileRecord)
                    .filter(FileRecord.id.in_(candidate_ids), FileRecord.status == "CHECKING")
                    .order_by(FileRecord.upload_time.asc(), FileRecord.id.asc())
                    .all()
                )
                if not candidates:
                    continue

                record_by_id = {record.id: record for record in candidates}
                if progress_callback:
                    progress_callback({
                        "event": "batch",
                        "candidate_count": len(candidates),
                        "checked": checked_total,
                        "alive": alive_total,
                        "dead": dead_total,
                        "claimed_file_ids": [record.id for record in candidates],
                    })
                if abort_check:
                    abort_check()

                config, live_jobs, live_errors = live_check_candidates(db, candidates)
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = {
                        pool.submit(check_auth_item_with_retry, config, item, dead_http_statuses): record_id
                        for record_id, item in live_jobs.items()
                    }
                    for record_id, result in live_errors.items():
                        futures[pool.submit(lambda value: value, result)] = record_id
                    for future in as_completed(futures):
                        record_id = futures[future]
                        record = record_by_id[record_id]
                        checked_total += 1
                        tested_ids.add(record.id)
                        try:
                            result = future.result()
                        except Exception as exc:
                            result = LiveCheckResult(False, None, str(exc), False)
                        record.live_status = "NORMAL" if is_live_check_alive(result, dead_http_statuses) else "ERROR"
                        record.live_quota = quota_remaining_label(result.quota)
                        record.live_rt_ms = result.rt_ms
                        record.live_http_status = result.http_status
                        record.live_checked_at = datetime.now()
                        record.live_message = live_check_message(result)
                        alive = is_live_check_alive(result, dead_http_statuses)
                        definite_dead = is_definite_dead_account(result, dead_http_statuses)
                        if alive and len(group_live_records) < group_needed:
                            group_live_records.append(record)
                            alive_total += 1
                            outcome = "alive"
                        elif alive:
                            record.status = "AVAILABLE"
                            record.bound_cdkey_id = None
                            record.bound_at = None
                            outcome = "alive_spare"
                        else:
                            record.status = "DEAD" if definite_dead else "AVAILABLE"
                            record.bound_cdkey_id = None
                            record.bound_at = None
                            if definite_dead:
                                dead_total += 1
                                outcome = "dead"
                            else:
                                outcome = "unavailable"
                        if progress_callback:
                            progress_callback({
                                "event": "checked",
                                "outcome": outcome,
                                "email": record.email_name,
                                "registered_at": record.payload.last_refresh if record.payload else record.upload_time,
                                "checked": checked_total,
                                "alive": alive_total,
                                "dead": dead_total,
                                "needed": total_needed,
                                "http_status": result.http_status,
                                "message": result.message,
                                "quota": result.quota,
                                "rt_ms": result.rt_ms,
                            })
                        if abort_check:
                            abort_check()
                db.commit()
                if abort_check:
                    abort_check()

            if abort_check:
                abort_check()
            bound_at = datetime.now()
            cursor = 0
            for cdkey in group_cdkeys:
                assigned_records = group_live_records[cursor:cursor + cdkey.files_per_key]
                cursor += cdkey.files_per_key
                for record in assigned_records:
                    record.status = "BOUND"
                    record.bound_cdkey_id = cdkey.id
                    record.bound_at = bound_at
                    record.extraction_no = extraction_no
                cdkey.extract_status = "EXTRACTED"
                cdkey.extraction_no = extraction_no
                cdkey.extracted_at = bound_at
                cdkey.first_extract_ip = ip
            db.commit()
            if progress_callback:
                progress_callback({"event": "bound", "code_count": len(group_cdkeys), "bound": len(group_live_records), "checked": checked_total, "alive": alive_total, "dead": dead_total})
        return ordered_cdkeys
    except Exception:
        if all_claimed_ids:
            db.query(FileRecord).filter(FileRecord.id.in_(all_claimed_ids), FileRecord.status == "CHECKING").update(
                {"status": "AVAILABLE"},
                synchronize_session=False,
            )
        restore_checking_cdkeys(db, locked_cdkey_ids)
        db.commit()
        raise


def admin_live_check_files(
    db: Session,
    file_ids: list[int],
    owner_id: int | None = None,
    workers: int = DEFAULT_LIVE_CHECK_WORKERS,
    progress_callback: ProgressCallback | None = None,
    abort_check: Callable[[], None] | None = None,
) -> LiveCheckSummary:
    unique_ids = list(dict.fromkeys(file_ids))
    if not unique_ids:
        raise BusinessError("请选择要测活的文件")
    records: list[FileRecord] = []
    for id_chunk in chunk_list(unique_ids):
        query = db.query(FileRecord).filter(FileRecord.id.in_(id_chunk))
        if owner_id is not None:
            query = query.filter(FileRecord.uploaded_by == owner_id)
        records.extend(query.all())
    if not records:
        raise BusinessError("没有可测活的文件")

    skipped = 0
    checked_count = 0
    locked_original_status: dict[int, str] = {}
    checkable_bound_ids: set[int] = set()
    if progress_callback:
        progress_callback({"event": "start_admin_file_check", "total": len(records), "workers": workers})
    if abort_check:
        abort_check()
    for record in records:
        if record.status == "CHECKING":
            skipped += 1
            checked_count += 1
            if progress_callback:
                registered_at = record.payload.last_refresh if record.payload else record.upload_time.strftime("%Y-%m-%d %H:%M:%S")
                progress_callback({
                    "event": "checked",
                    "outcome": "skipped",
                    "email": record.email_name,
                    "registered_at": registered_at,
                    "live_checked_at": record.live_checked_at.strftime("%Y-%m-%d %H:%M:%S") if record.live_checked_at else "",
                    "checked": checked_count,
                    "alive": 0,
                    "dead": 0,
                    "skipped": skipped,
                    "needed": len(records),
                    "http_status": None,
                    "quota": None,
                    "rt_ms": None,
                    "message": "文件正在测活中",
                })
            continue
        if record.status == "BOUND":
            checkable_bound_ids.add(record.id)
            continue
        locked_original_status[record.id] = record.status

    if locked_original_status:
        locked_count = 0
        for id_chunk in chunk_list(list(locked_original_status.keys())):
            locked_count += (
                db.query(FileRecord)
                .filter(FileRecord.id.in_(id_chunk), FileRecord.status != "CHECKING")
                .update({"status": "CHECKING"}, synchronize_session=False)
            )
        skipped += max(0, len(locked_original_status) - locked_count)
    db.commit()
    if abort_check:
        abort_check()

    candidate_ids = list(locked_original_status.keys()) + list(checkable_bound_ids)
    candidates: list[FileRecord] = []
    for id_chunk in chunk_list(candidate_ids):
        candidates.extend(db.query(FileRecord).filter(FileRecord.id.in_(id_chunk)).all())
    checkable_candidates = [
        record for record in candidates
        if record.id in checkable_bound_ids or record.status == "CHECKING"
    ]
    config, live_jobs, live_errors = live_check_candidates(db, checkable_candidates)
    dead_http_statuses = unshippable_http_statuses(db)
    normal = 0
    error = 0
    results: dict[int, LiveCheckResult] = {}
    if progress_callback:
        progress_callback({"event": "batch", "candidate_count": len(checkable_candidates), "checked": checked_count, "alive": normal, "dead": error, "skipped": skipped})
    if abort_check:
        abort_check()
    record_by_id = {record.id: record for record in candidates}
    with ThreadPoolExecutor(max_workers=max(1, int(workers or DEFAULT_LIVE_CHECK_WORKERS))) as pool:
        futures = {
            pool.submit(check_auth_item_with_retry, config, item, dead_http_statuses): record_id
            for record_id, item in live_jobs.items()
        }
        for record_id, result in live_errors.items():
            futures[pool.submit(lambda value: value, result)] = record_id
        for future in as_completed(futures):
            record_id = futures[future]
            try:
                results[record_id] = future.result()
            except Exception as exc:
                results[record_id] = LiveCheckResult(False, None, str(exc), False)
            result = results[record_id]
            checked_count += 1
            alive = is_live_check_alive(result, dead_http_statuses)
            if alive:
                normal += 1
                outcome = "alive"
            else:
                error += 1
                outcome = "dead"
            if progress_callback:
                record = record_by_id.get(record_id)
                registered_at = record.payload.last_refresh if record and record.payload else (record.upload_time.strftime("%Y-%m-%d %H:%M:%S") if record else "")
                progress_callback({
                    "event": "checked",
                    "outcome": outcome,
                    "email": record.email_name if record else "",
                    "registered_at": registered_at,
                    "live_checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "checked": checked_count,
                    "alive": normal,
                    "dead": error,
                    "skipped": skipped,
                    "needed": len(records),
                    "http_status": result.http_status,
                    "quota": result.quota,
                    "rt_ms": result.rt_ms,
                    "message": result.message,
                })
            if abort_check:
                abort_check()

    if abort_check:
        abort_check()
    for record_id, result in results.items():
        record = record_by_id[record_id]
        alive = is_live_check_alive(result, dead_http_statuses)
        record.live_status = "NORMAL" if alive else "ERROR"
        record.live_quota = quota_remaining_label(result.quota)
        record.live_rt_ms = result.rt_ms
        record.live_http_status = result.http_status
        record.live_checked_at = datetime.now()
        record.live_message = live_check_message(result)
        if alive:
            if record_id not in checkable_bound_ids:
                record.status = "AVAILABLE"
        else:
            if record_id not in checkable_bound_ids and is_definite_dead_account(result, dead_http_statuses):
                record.status = "DEAD"
            elif record_id not in checkable_bound_ids:
                record.status = locked_original_status.get(record_id, "AVAILABLE")
    db.commit()
    return LiveCheckSummary(total=len(records), normal=normal, error=error, skipped=skipped)


def live_check_record(record: FileRecord) -> LiveCheckResult:
    raise BusinessError("单文件测活必须通过批量测活入口执行")


def bound_files(db: Session, cdkey_ids: list[int]) -> list[FileRecord]:
    return (
        db.query(FileRecord)
        .options(selectinload(FileRecord.payload))
        .filter(FileRecord.bound_cdkey_id.in_(cdkey_ids))
        .order_by(FileRecord.bound_at.asc(), FileRecord.id.asc())
        .all()
    )


def zip_for_files(db: Session, files: list[FileRecord]) -> bytes:
    if not files:
        raise BusinessError("当前没有可下载文件")
    auth_payloads = payloads_for_records(db, files, include_reauth=True)
    missing_2fa = [record.email_name for record in files if not _payload_has_two_factor(auth_payloads.get(record.id))]
    if missing_2fa:
        raise BusinessError(f"以下账号未导入 2FA，禁止出库：{'、'.join(missing_2fa[:10])}")
    payloads = payloads_for_records(db, files)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for record in files:
            payload = payloads.get(record.id)
            if not payload:
                raise BusinessError(f"账号字段内容不存在：{record.email_name}")
            archive.writestr(f"{safe_name(record.email_name)}.json", json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"))
    return buffer.getvalue()


def dedupe_sub2api_name(name: str, used: dict[str, int]) -> str:
    current = used.get(name, 0) + 1
    used[name] = current
    if current == 1:
        return name
    return f"{name}-{current}"


def sub2api_json_for_payloads(items: list[tuple[str, dict]]) -> bytes:
    if not items:
        raise BusinessError("当前没有可下载文件")
    accounts: list[dict] = []
    used_names: dict[str, int] = {}
    for index, (record_name, payload) in enumerate(items, start=1):
        if not payload:
            raise BusinessError(f"账号字段内容不存在：{record_name}")
        base_name = str(payload.get("email") or payload.get("account_id") or record_name or f"acc-{index:03d}").strip()
        accounts.append({
            "name": dedupe_sub2api_name(base_name, used_names),
            "platform": "openai",
            "type": "oauth",
            "credentials": payload,
            "concurrency": 3,
            "priority": 50,
        })
    exported_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    content = {
        "type": "sub2api-data",
        "version": 1,
        "exported_at": exported_at,
        "proxies": [],
        "accounts": accounts,
    }
    return json.dumps(content, ensure_ascii=False, indent=2).encode("utf-8")


def sub2api_json_for_files(db: Session, files: list[FileRecord]) -> bytes:
    if not files:
        raise BusinessError("当前没有可下载文件")
    auth_payloads = payloads_for_records(db, files, include_reauth=True)
    missing_2fa = [record.email_name for record in files if not _payload_has_two_factor(auth_payloads.get(record.id))]
    if missing_2fa:
        raise BusinessError(f"以下账号未导入 2FA，禁止出库：{'、'.join(missing_2fa[:10])}")
    payloads = payloads_for_records(db, files)
    return sub2api_json_for_payloads([
        (record.email_name, payloads.get(record.id, {}))
        for record in files
    ])


def _payload_has_two_factor(payload: dict | None) -> bool:
    info = payload.get("reauth_info") if isinstance(payload, dict) else None
    return bool(isinstance(info, dict) and info.get("password") and info.get("totp_secret"))


def cleanup_expired_extracted_cdkeys(
    db: Session,
    expire_after_hours: int = 24,
    workers: int = DEFAULT_LIVE_CHECK_WORKERS,
) -> dict[str, int]:
    expire_after_hours = max(1, int(expire_after_hours or 24))
    threshold = datetime.now() - timedelta(hours=expire_after_hours)
    expired_ids = [
        row.id
        for row in db.query(Cdkey.id)
        .filter(Cdkey.extract_status == "EXTRACTED", Cdkey.extracted_at.is_not(None), Cdkey.extracted_at < threshold)
        .all()
    ]
    if not expired_ids:
        return {"deleted_cdkeys": 0, "deleted_files": 0, "delete_failed": 0}
    result = delete_cdkeys_with_bound_files(db, expired_ids, workers=workers)
    return {
        "deleted_cdkeys": int(result["deleted_cdkeys"]),
        "deleted_files": int(result["deleted_files"]),
        "delete_failed": int(result["delete_failed"]),
    }


def cdkeys_csv(cdkeys: list[Cdkey]) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["code", "status", "files_per_key", "batch_no", "extraction_no", "created_at", "extracted_at"])
    for item in cdkeys:
        writer.writerow([
            item.code,
            item.extract_status,
            item.files_per_key,
            item.batch.batch_no,
            item.extraction_no or "",
            item.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            item.extracted_at.strftime("%Y-%m-%d %H:%M:%S") if item.extracted_at else "",
        ])
    return buffer.getvalue().encode("utf-8-sig")


def file_filters(
    query,
    filename: str | None,
    cdkey_code: str | None,
    extract_status: str | None,
    live_status: str | None,
    day: date | None,
    owner_id: int | None,
    business_type: str | None = None,
    group_tag: str | None = None,
    extraction_no: str | None = None,
):
    if owner_id is not None:
        query = query.filter(FileRecord.uploaded_by == owner_id)
    if business_type:
        query = query.filter(FileRecord.business_type == normalize_business_type(business_type))
    if group_tag:
        query = query.filter(FileRecord.group_tag == normalize_group_tag(group_tag))
    if filename:
        keyword = f"%{filename.strip()}%"
        query = query.filter(or_(FileRecord.original_filename.like(keyword), FileRecord.email_name.like(keyword)))
    if extract_status:
        query = query.filter(FileRecord.status == extract_status)
    if live_status == "UNCHECKED":
        query = query.filter(FileRecord.live_status.is_(None))
    elif live_status:
        query = query.filter(FileRecord.live_status == live_status)
    if day:
        start, end = today_range(day)
        query = query.filter(FileRecord.upload_time >= start, FileRecord.upload_time < end)
    if cdkey_code:
        query = query.join(Cdkey, FileRecord.bound_cdkey_id == Cdkey.id).filter(Cdkey.code.like(f"%{cdkey_code.strip()}%"))
    if extraction_no:
        query = query.filter(FileRecord.extraction_no.like(f"%{extraction_no.strip()}%"))
    return query


def cdkey_filters(
    query,
    status: str | None,
    batch_no: str | None,
    code: str | None,
    day: date | None,
    owner_id: int | None,
    business_type: str | None = None,
    group_tag: str | None = None,
    extraction_no: str | None = None,
):
    query = query.join(CdkeyBatch)
    if owner_id is not None:
        query = query.filter(CdkeyBatch.created_by == owner_id)
    if business_type:
        query = query.filter(CdkeyBatch.business_type == normalize_business_type(business_type))
    if group_tag:
        query = query.filter(CdkeyBatch.group_tag == normalize_group_tag(group_tag))
    if status:
        query = query.filter(Cdkey.extract_status == status)
    if batch_no:
        query = query.filter(CdkeyBatch.batch_no.like(f"%{batch_no.strip()}%"))
    if code:
        query = query.filter(Cdkey.code.like(f"%{code.strip()}%"))
    if extraction_no:
        query = query.filter(Cdkey.extraction_no.like(f"%{extraction_no.strip()}%"))
    if day:
        start, end = today_range(day)
        query = query.filter(Cdkey.created_at >= start, Cdkey.created_at < end)
    return query
