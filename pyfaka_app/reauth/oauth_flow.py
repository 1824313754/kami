from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .oauth_client import AuthFlow, Config
from .settings import ServiceSettings


CODEX_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
CODEX_TOKEN_URL = "https://auth.openai.com/oauth/token"


def _token_time(offset_seconds: int = 0) -> str:
    value = datetime.now(timezone.utc) + timedelta(seconds=max(0, offset_seconds))
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _refresh_access_token(session: Any, refresh_token: str) -> dict[str, str]:
    token = str(refresh_token or "").strip()
    if not token:
        raise RuntimeError("重新 OAuth 未返回 Refresh Token")
    try:
        response = session.post(
            CODEX_TOKEN_URL,
            data={
                "grant_type": "refresh_token",
                "client_id": CODEX_CLIENT_ID,
                "refresh_token": token,
            },
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            timeout=30,
        )
    except Exception as exc:
        detail = str(exc).replace(token, "[redacted]")[:200]
        raise RuntimeError(f"Codex AT 刷新请求失败: {detail}") from exc
    try:
        payload = response.json()
    except Exception:
        payload = {}
    if int(getattr(response, "status_code", 0) or 0) != 200:
        error = str(payload.get("error") or "token_refresh_failed") if isinstance(payload, dict) else "token_refresh_failed"
        description = str(payload.get("error_description") or "") if isinstance(payload, dict) else ""
        detail = f"{error}: {description}" if description else error
        raise RuntimeError(f"Codex AT 刷新失败 ({getattr(response, 'status_code', 0)}): {detail[:200]}")
    access_token = str(payload.get("access_token") or "")
    if not access_token:
        raise RuntimeError("Codex AT 刷新失败：未返回 access_token")
    try:
        expires_in = max(0, int(payload.get("expires_in") or 0))
    except (TypeError, ValueError):
        expires_in = 0
    return {
        "access_token": access_token,
        "refresh_token": str(payload.get("refresh_token") or "").strip() or token,
        "id_token": str(payload.get("id_token") or "").strip(),
        "last_refresh": _token_time(),
        "expired": _token_time(expires_in),
    }


def reauthorize_account(
    target_email: str,
    credential: dict[str, Any],
    settings: ServiceSettings,
    on_progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    def emit(message: str) -> None:
        if on_progress:
            on_progress(message)

    emit("开始重登授权")
    flow = AuthFlow(
        Config(proxy=settings.proxy or None),
        env_overrides={
            "OAUTH_REFRESH_ONLY": "1",
            "OAUTH_CODEX_RT_EXCHANGE": "1",
            "OAUTH_CODEX_CLIENT_ID": CODEX_CLIENT_ID,
        },
        allow_phone_verification=False,
    )
    emit("正在使用账号密码和 2FA 验证")
    auth = flow.run_totp_login(target_email, credential["password"], credential["totp_secret"])
    emit("OpenAI OAuth 授权完成，正在刷新 Codex 令牌")
    refreshed = _refresh_access_token(flow.session, auth.refresh_token)
    emit("Codex 令牌刷新成功，准备回写账号")
    completed_at = _token_time()
    return {
        "email": str(target_email or "").strip().lower(),
        "access_token": refreshed["access_token"],
        "refresh_token": refreshed["refresh_token"],
        "id_token": refreshed["id_token"] or auth.id_token,
        "session_token": auth.session_token,
        "device_id": auth.device_id,
        "csrf_token": auth.csrf_token,
        "cookie_header": auth.cookie_header,
        "fingerprint": dict(auth.fingerprint),
        "last_refresh": refreshed["last_refresh"],
        "expired": refreshed["expired"],
        "oauth_reauthorization": {"completed_at": completed_at, "count": 1},
    }
