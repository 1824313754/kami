import base64
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4

from .database import DATA_DIR
from .live_check import LiveCheckResult


DEFAULT_LIVE_CHECK_TIMEOUT = 10
DEFAULT_LIVE_CHECK_USER_AGENT = "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"
AUTH_FILES_DIR = DATA_DIR / "auth_files"
AUTH_DELETE_TRASH_DIR = DATA_DIR / "auth_files_deleted"


class LocalAuthError(Exception):
    pass


@dataclass(frozen=True)
class LocalLiveCheckConfig:
    timeout: int = DEFAULT_LIVE_CHECK_TIMEOUT
    user_agent: str = DEFAULT_LIVE_CHECK_USER_AGENT


def local_auth_relative_path(record_id: int) -> str:
    return f"auth_files/{int(record_id)}.json"


def resolve_local_auth_path(storage_path: str) -> Path:
    relative = str(storage_path or "").strip().replace("\\", "/").lstrip("/")
    if not relative:
        raise LocalAuthError("缺少本地文件路径")
    path = (DATA_DIR / relative).resolve()
    data_root = DATA_DIR.resolve()
    try:
        path.relative_to(data_root)
    except ValueError as exc:
        raise LocalAuthError("本地文件路径不在数据目录内") from exc
    return path


def write_local_payload(storage_path: str, payload: dict[str, Any]) -> int:
    path = resolve_local_auth_path(storage_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    content = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    temp_path.write_bytes(content)
    os.replace(temp_path, path)
    return len(content)


def read_local_payload(storage_path: str) -> dict[str, Any]:
    path = resolve_local_auth_path(storage_path)
    if not path.exists():
        raise LocalAuthError(f"本地文件不存在：{path.name}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        raise LocalAuthError(f"本地文件不是合法 JSON：{path.name}") from exc
    if not isinstance(payload, dict):
        raise LocalAuthError(f"本地文件不是 JSON 对象：{path.name}")
    return payload


def stage_local_payload_delete(storage_path: str) -> tuple[Path, Path] | None:
    path = resolve_local_auth_path(storage_path)
    if not path.exists():
        return None
    AUTH_DELETE_TRASH_DIR.mkdir(parents=True, exist_ok=True)
    trash_path = AUTH_DELETE_TRASH_DIR / f"{uuid4().hex}-{path.name}"
    os.replace(path, trash_path)
    return path, trash_path


def restore_staged_local_payloads(staged_files: list[tuple[Path, Path]]) -> None:
    for original_path, trash_path in reversed(staged_files):
        if not trash_path.exists():
            continue
        original_path.parent.mkdir(parents=True, exist_ok=True)
        os.replace(trash_path, original_path)


def finalize_staged_local_payloads(staged_files: list[tuple[Path, Path]]) -> None:
    for _original_path, trash_path in staged_files:
        if trash_path.exists():
            trash_path.unlink()


def jwt_payload(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return {}
    parts = value.split(".")
    if len(parts) < 2:
        return {}
    try:
        segment = parts[1] + "=" * (-len(parts[1]) % 4)
        decoded = base64.urlsafe_b64decode(segment.encode("ascii"))
        parsed = json.loads(decoded.decode("utf-8", errors="replace"))
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def payload_access_token(payload: dict[str, Any]) -> str:
    for key in ("access_token", "accessToken", "token"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, dict):
            nested = payload_access_token(value)
            if nested:
                return nested
    return ""


def extract_chatgpt_account_id(payload: dict[str, Any]) -> str | None:
    for source in (payload, payload.get("metadata"), payload.get("attributes")):
        if not isinstance(source, dict):
            continue
        for key in ("account_id", "accountId", "chatgpt_account_id", "chatgptAccountId"):
            value = source.get(key)
            if value:
                return str(value)
    for source in (payload, payload.get("metadata"), payload.get("attributes")):
        if not isinstance(source, dict):
            continue
        token_info = jwt_payload(source.get("id_token"))
        value = token_info.get("chatgpt_account_id") or token_info.get("chatgptAccountId")
        if value:
            return str(value)
        auth_payload = token_info.get("https://api.openai.com/auth")
        if isinstance(auth_payload, dict):
            nested = auth_payload.get("chatgpt_account_id") or auth_payload.get("chatgptAccountId")
            if nested:
                return str(nested)
    return None


def quota_from_usage_body(body: Any) -> dict[str, str | None]:
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            body = {}
    rate_limit = body.get("rate_limit") if isinstance(body, dict) else {}
    if not isinstance(rate_limit, dict):
        rate_limit = {}
    windows = [item for item in (rate_limit.get("primary_window"), rate_limit.get("secondary_window")) if isinstance(item, dict)]
    used = None
    reset_after = None
    limit_window = None
    if windows:
        selected_window = max(windows, key=lambda window: float(window.get("used_percent") or 0))
        if selected_window.get("used_percent") is not None:
            used = str(float(selected_window["used_percent"]))
        if selected_window.get("reset_after_seconds") is not None:
            reset_after = str(int(selected_window["reset_after_seconds"]))
        if selected_window.get("limit_window_seconds") is not None:
            limit_window = str(int(selected_window["limit_window_seconds"]))
    plan_type = body.get("plan_type") if isinstance(body, dict) else None
    return {
        "x-codex-primary-used-percent": used,
        "x-codex-primary-reset-after-seconds": reset_after,
        "x-codex-primary-limit-window-seconds": limit_window,
        "x-codex-plan-type": str(plan_type).strip() if plan_type else None,
    }


def response_message(status_code: int | None, body: Any) -> str:
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            body = {"message": body}
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict):
            message = str(error.get("message") or "").strip()
            if message:
                return message[:500]
        message = str(body.get("message") or "").strip()
        if message:
            return message[:500]
    if status_code == 200:
        return "正常"
    return f"请求返回 {status_code or '未知状态'}"


def parse_http_body(raw: bytes) -> Any:
    text = raw.decode("utf-8", errors="replace")
    if not text.strip():
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text[:500]


def check_auth_payload(config: LocalLiveCheckConfig, payload: dict[str, Any]) -> LiveCheckResult:
    access_token = payload_access_token(payload)
    if not access_token:
        return LiveCheckResult(False, None, "文件缺少 access_token", False)
    headers = {
        "Authorization": "Bearer " + access_token,
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Connection": "Keep-Alive",
        "User-Agent": config.user_agent,
    }
    account_id = extract_chatgpt_account_id(payload)
    if account_id:
        headers["Chatgpt-Account-Id"] = account_id
    request = Request("https://chatgpt.com/backend-api/wham/usage", headers=headers, method="GET")
    started = time.perf_counter()
    try:
        with urlopen(request, timeout=max(1, int(config.timeout or DEFAULT_LIVE_CHECK_TIMEOUT))) as response:
            body = parse_http_body(response.read())
            status_code = int(response.status)
    except HTTPError as exc:
        body = parse_http_body(exc.read())
        status_code = int(exc.code)
    except URLError as exc:
        rt_ms = int((time.perf_counter() - started) * 1000)
        return LiveCheckResult(False, None, f"请求失败：{exc.reason}", False, None, None, rt_ms)
    except Exception as exc:
        rt_ms = int((time.perf_counter() - started) * 1000)
        return LiveCheckResult(False, None, str(exc), False, None, None, rt_ms)
    rt_ms = int((time.perf_counter() - started) * 1000)
    quota = quota_from_usage_body(body)
    message = response_message(status_code, body)
    return LiveCheckResult(status_code == 200, status_code, message, False, None, quota, rt_ms)
