"""
注册/登录流程 - 协议直连方式
完整链路:
  chatgpt_csrf -> chatgpt_signin_openai -> auth_oauth_init -> sentinel
  -> signup -> send_otp -> verify_otp -> create_account
  -> redirect_chain -> auth_session -> (optional) oauth_token_exchange
"""
import json
import base64
import hashlib
import logging
import os
import random
import re
import secrets
import subprocess
import time
import uuid
from datetime import datetime
from html.parser import HTMLParser
from typing import Optional, Any
from urllib.parse import urlparse, parse_qs, parse_qsl, urljoin, urlencode, urlunparse
try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover - Python runtime without zoneinfo
    ZoneInfo = None

from .config import Config
from .fingerprint import generate_fingerprint
MailProvider = Any
from .http_client import create_http_session, USER_AGENT

logger = logging.getLogger(__name__)

_AUTH_STATSIG_CLIENT_KEY = "client-tN5GMyzpIPKXd3KNv7ANIfiqjRSvNNTTWbZdbdabF58"
_EMAIL_OTP_SESSION_COOKIE_NAMES = (
    "login_session",
    "hydra_redirect",
    "oai-client-auth-session",
    "auth-session-minimized",
    "auth-session-minimized-client-checksum",
    "auth_provider",
)
_AUTH_NETWORK_RETRY_DEFAULT_STATUS_CODES = frozenset({
    408,
    425,
    429,
    500,
    502,
    503,
    504,
})
_AUTH_NETWORK_RETRY_DEFAULT_ATTEMPTS = 3
_AUTH_NETWORK_RETRY_DEFAULT_BACKOFF_SECONDS = 2.0
_AUTH_NETWORK_RETRY_DEFAULT_BACKOFF_MULTIPLIER = 1.5


class _BootstrapInertScriptParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self._capturing = False
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag.lower() == "script" and dict(attrs).get("id") == "bootstrap-inert-script":
            self._capturing = True

    def handle_data(self, data: str) -> None:
        if self._capturing:
            self.parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._capturing:
            self._capturing = False


def _statsig_hash(value: str) -> int:
    result = 0
    for char in value:
        result = (result * 31 + ord(char)) & 0xFFFFFFFF
    return result


def _extract_auth_statsig_storage_keys(html: str) -> list[str]:
    parser = _BootstrapInertScriptParser()
    try:
        parser.feed(str(html or ""))
        bootstrap = json.loads("".join(parser.parts))
        identity = bootstrap["statsigClientInitData"]["identity"]
        device_id = str(identity.get("deviceId") or "").strip()
        stable_id = str(identity.get("oaicomStableId") or "").strip()
        surface_id = str(identity.get("sourceSurfaceStableId") or "").strip()
        session_id = str(identity.get("sessionLoggingId") or "").strip()
        if not all((device_id, stable_id, surface_id, session_id)):
            return []
    except (KeyError, TypeError, ValueError):
        return []

    custom_ids = (
        ("AuthSessionLoggingId", session_id),
        ("DeviceId", device_id),
        ("oaicom_stable_id", stable_id),
        ("source_surface_stable_id", surface_id),
        ("stableID", device_id),
        ("WebAnonymousCookieID", device_id),
    )
    user_key = (
        "uid:|cids:"
        + ",".join(f"{key}-{value}" for key, value in custom_ids)
        + f"|k:{_AUTH_STATSIG_CLIENT_KEY}"
    )
    sdk_hash = _statsig_hash(f"k:{_AUTH_STATSIG_CLIENT_KEY}")
    user_hash = _statsig_hash(user_key)
    return [
        f"statsig.cached.evaluations.{user_hash}",
        f"statsig.session_id.{sdk_hash}",
        "statsig.last_modified_time.evaluations",
        f"statsig.stable_id.{sdk_hash}",
    ]


class EmailOtpValidationError(RuntimeError):
    """Email OTP validation failed with an upstream HTTP status."""

    def __init__(self, status_code: int, body: str = ""):
        self.status_code = int(status_code)
        self.body = str(body or "")
        super().__init__(f"OTP 验证失败: {self.status_code} - {self.body[:260]}")


class EmailOtpResendError(RuntimeError):
    """Email OTP resend failed and the current auth flow must be abandoned."""

    def __init__(self, status_code: int, body: str = "", retry_after: str = ""):
        self.status_code = int(status_code)
        self.body = str(body or "")
        self.retry_after = str(retry_after or "")
        super().__init__(f"OTP 重发失败: {self.status_code} - {self.body[:260]}")


class PhoneVerificationRequired(RuntimeError):
    """The flow reached phone verification while phone verification is disabled."""


class AuthResult:
    """认证结果"""

    def __init__(self):
        self.email: str = ""
        self.password: str = ""
        self.session_token: str = ""
        self.access_token: str = ""
        self.device_id: str = ""
        self.csrf_token: str = ""
        self.id_token: str = ""
        self.refresh_token: str = ""
        self.web_access_token: str = ""
        self.cookie_header: str = ""
        self.fingerprint: dict[str, Any] = {}
        self.post_registration_conversation: dict[str, Any] = {}

    def is_valid(self) -> bool:
        return bool(self.access_token)

    def to_dict(self) -> dict:
        return {
            "email": self.email,
            "password": self.password,
            "session_token": self.session_token,
            "access_token": self.access_token,
            "device_id": self.device_id,
            "csrf_token": self.csrf_token,
            "id_token": self.id_token,
            "refresh_token": self.refresh_token,
            "web_access_token": self.web_access_token,
            "cookie_header": self.cookie_header,
            "fingerprint": dict(self.fingerprint),
            "post_registration_conversation": dict(self.post_registration_conversation),
        }


class AuthFlow:
    """注册/登录协议流"""

    def __init__(
        self,
        config: Config,
        sms_callback: Optional[Any] = None,
        env_overrides: Optional[dict[str, str]] = None,
        allow_phone_verification: bool = True,
    ):
        self.config = config
        self._env_overrides = {
            str(k): str(v) for k, v in (env_overrides or {}).items()
        }
        requested_timezone = (
            (self._env_value("SENTINEL_TIMEZONE", "") or "").strip()
            or (self._env_value("TZ", "") or "").strip()
        )
        self._fingerprint = generate_fingerprint(timezone=requested_timezone)
        self._timezone = (
            requested_timezone
            or str(self._fingerprint.get("timezone") or "").strip()
            or "America/New_York"
        )
        self._ua = self._fingerprint["user_agent"]
        self._impersonate_candidates = [self._fingerprint["impersonate"]] * 3
        self._impersonate_idx = 0
        self.session = create_http_session(
            proxy=config.proxy,
            impersonate=self._impersonate_candidates[self._impersonate_idx],
            user_agent=self._ua,
        )
        self._bind_session_fingerprint()
        self.result = AuthResult()
        self.result.fingerprint = dict(self._fingerprint)
        # 可选 SMS 接码控制器（sms_provider.PhoneCallbackController 实例）
        # 命中 add-phone 时自动租手机号 + 接 SMS 验证码，否则回退到环境变量路径
        self._sms_callback = sms_callback
        self._allow_phone_verification = bool(allow_phone_verification)
        self._http_trace_enabled = self._env_value("AUTH_HTTP_TRACE", "0").lower() in ("1", "true", "yes", "on")
        # signup() 会在分支里 set；run_protocol_login 命中已有账号路径会跳过 signup，
        # 导致 kickoff_otp_delivery 读未初始化属性 AttributeError。这里给个默认值。
        self._is_existing_account = False
        self._existing_email_verification_mode = ""
        self._existing_page_type = ""
        self._last_sentinel_token = ""
        self._last_sentinel_so_token = ""
        self._last_sentinel_flow = ""
        self._chatgpt_web_access_token = ""
        self._chatgpt_client_version = ""
        self._chatgpt_client_build_number = ""
        self._chatgpt_session_id = str(uuid.uuid4())
        self._registration_sentinel_time_origin_ms = 0.0
        self._registration_sentinel_performance_base_ms = 0.0
        self._registration_sentinel_monotonic_started = 0.0
        self._registration_sentinel_solver_state: Optional[dict[str, Any]] = None
        self._registration_sentinel_sdk: Any = None
        self._registration_sentinel_payload: dict[str, Any] = {}
        self._registration_sentinel_requirements: dict[str, Any] = {}
        self._registration_sentinel_challenge: dict[str, Any] = {}
        self._registration_sentinel_pending_flow = ""
        self._registration_sentinel_exchange_solved = False
        self._auth_local_storage_keys: list[str] = []
        self._manual_login_verifier = (self._env_value("LOGIN_VERIFIER", "") or "").strip()
        self._captured_login_verifier = ""
        self._oauth_client_secret = (self._env_value("OAUTH_CLIENT_SECRET", "") or "").strip()
        self._oauth_client_id = "YOUR_OPENAI_WEB_CLIENT_ID"
        self._oauth_redirect_uri = "https://chatgpt.com/api/auth/callback/openai"
        self._oauth_scope = ""
        self._oauth_state = ""
        self._oauth_auth_url = ""
        self._auth_oauth_final_url = ""
        self._auth_oauth_status_code = 0
        self._client_auth_session_dump: dict[str, Any] = {}
        self._client_auth_session_id: str = ""
        self._dump_login_verifier: str = ""
        self._codex_rt_attempted: bool = False
        self._trace_dump_enabled = self._env_value("AUTH_TRACE_DUMP", "0").lower() in ("1", "true", "yes", "on")
        self._trace_include_cookie = self._env_value("AUTH_TRACE_INCLUDE_COOKIE", "0").lower() in (
            "1", "true", "yes", "on"
        )
        self._trace_dump_path = ""
        if self._trace_dump_enabled:
            try:
                os.makedirs("outputs", exist_ok=True)
                ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                self._trace_dump_path = os.path.join("outputs", f"auth_trace_{ts}_{os.getpid()}.jsonl")
                logger.info(f"HTTP 明文抓包已启用: {self._trace_dump_path}")
            except Exception as e:
                logger.warning(f"初始化 HTTP 抓包文件失败: {e}")
                self._trace_dump_enabled = False
        self.registration_name = ""
        self.registration_birthdate = ""
        self._post_login_bootstrap_done = False
        logger.info(
            f"指纹: impersonate={self._fingerprint['impersonate']} "
            f"platform={self._fingerprint.get('navigator_platform', '-')} "
            f"screen={self._fingerprint['screen']} lang={self._fingerprint['lang']} "
            f"timezone={self._timezone}"
        )

    def _build_chatgpt_cookie_header(self) -> str:
        """
        导出当前会话中的 chatgpt.com 相关 cookie。

        说明：
        - `/backend-api/payments/checkout` 的 modern/custom 入口不仅依赖
          `__Secure-next-auth.session-token`，还会校验若干同域 cookie
          （如 csrf / oai-sc / Cloudflare 相关 cookie 等）。
        - 因此这里不能只回传 session_token，需要尽量保留当前会话里已经拿到的
          `chatgpt.com` 域 cookie 集合。
        """
        cookie_pairs: list[tuple[str, str]] = []
        seen: set[str] = set()

        try:
            jar_iter = list(self.session.cookies)
        except Exception:
            jar_iter = []

        for cookie in jar_iter:
            try:
                name = (getattr(cookie, "name", "") or "").strip()
                value = getattr(cookie, "value", "") or ""
                domain = (getattr(cookie, "domain", "") or "").strip().lower()
            except Exception:
                continue
            if not name or not value:
                continue
            if domain and "chatgpt.com" not in domain:
                continue
            if name in seen:
                continue
            seen.add(name)
            cookie_pairs.append((name, value))

        # 兜底补齐关键 cookie，避免某些 cookiejar 迭代行为差异导致遗漏
        critical_names = [
            "__Secure-next-auth.session-token",
            "__Host-next-auth.csrf-token",
            "__Secure-next-auth.callback-url",
            "oai-did",
            "oai-sc",
            "cf_clearance",
            "__cf_bm",
            "_cfuvid",
            "__cflb",
            "__stripe_mid",
            "__stripe_sid",
            "oai-client-auth-info",
            "oai-gn",
            "oai-nav-state",
            "oai-hlib",
            "_account_is_fedramp",
            "oai_consent_analytics",
            "oai_consent_marketing",
            "oai-allow-ne",
            "_ga",
            "_ga_9SHBSK2D9J",
            "_gcl_au",
            "_fbp",
            "_puid",
            "_dd_s",
            "g_state",
        ]
        for name in critical_names:
            if name in seen:
                continue
            try:
                value = self.session.cookies.get(name, "")
            except Exception:
                value = ""
            if value:
                seen.add(name)
                cookie_pairs.append((name, value))

        return "; ".join(f"{name}={value}" for name, value in cookie_pairs if name and value)

    def _trace_http(self, step: str, resp, extra_request: dict | None = None):
        """可选 HTTP 细粒度追踪（用于协议调试）"""
        if (not self._http_trace_enabled and not self._trace_dump_enabled) or resp is None:
            return
        try:
            req = getattr(resp, "request", None)
            method = getattr(req, "method", "") if req else ""
            req_url = getattr(req, "url", "") if req else ""
            req_body = ""
            req_headers = {}
            if req is not None:
                raw_req_body = getattr(req, "body", None)
                if raw_req_body is None:
                    raw_req_body = getattr(req, "content", None)
                if raw_req_body is None:
                    raw_req_body = getattr(req, "data", None)
                if isinstance(raw_req_body, bytes):
                    req_body = raw_req_body.decode("utf-8", errors="replace")
                elif raw_req_body is not None:
                    req_body = str(raw_req_body)
                try:
                    req_headers = dict(getattr(req, "headers", {}) or {})
                except Exception:
                    req_headers = {}

            # 手动补充请求信息（curl_cffi 某些场景 request.body/headers 为空）
            if isinstance(extra_request, dict):
                if not method:
                    method = str(extra_request.get("method", "") or "")
                if not req_url:
                    req_url = str(extra_request.get("url", "") or "")
                if not req_body:
                    maybe_body = extra_request.get("body", "")
                    if isinstance(maybe_body, bytes):
                        req_body = maybe_body.decode("utf-8", errors="replace")
                    else:
                        req_body = str(maybe_body or "")
                extra_headers = extra_request.get("headers", {})
                if isinstance(extra_headers, dict):
                    merged = dict(req_headers or {})
                    merged.update(extra_headers)
                    req_headers = merged

            status = getattr(resp, "status_code", "N/A")
            final_url = str(getattr(resp, "url", "") or "")
            req_cookie = (req_headers.get("Cookie", "") or "")
            location = (resp.headers.get("Location", "") or "")[:180]
            req_id = (resp.headers.get("x-request-id", "") or "")[:120]
            ctype = (resp.headers.get("Content-Type", "") or "")[:120]
            # 尽量保留完整 Set-Cookie（某些关键 cookie 可能在后续片段）
            set_cookie_list: list[str] = []
            try:
                get_list = getattr(resp.headers, "get_list", None) or getattr(resp.headers, "getlist", None)
                if callable(get_list):
                    vals = get_list("Set-Cookie")
                    if isinstance(vals, list):
                        set_cookie_list = [str(x) for x in vals if x]
            except Exception:
                set_cookie_list = []
            if not set_cookie_list:
                one = (resp.headers.get("Set-Cookie", "") or "")
                if one:
                    set_cookie_list = [one]
            set_cookie_raw = " || ".join(set_cookie_list)
            set_cookie = set_cookie_raw[:260]
            body = (resp.text or "").replace("\n", " ").replace("\r", " ")
            body = body[:260]
            req_headers_lc = {(str(k).lower()): v for k, v in (req_headers or {}).items()}

            if self._http_trace_enabled:
                logger.info(
                    "[HTTP TRACE] %s | %s %s -> %s | url=%s | location=%s | req_id=%s | ctype=%s | set_cookie=%s | body=%s",
                    step,
                    method,
                    req_url[:180],
                    status,
                    final_url[:180],
                    location,
                    req_id,
                    ctype,
                    set_cookie,
                    body,
                )
                if self._trace_include_cookie and req_cookie:
                    logger.info("[HTTP TRACE] %s | req_cookie=%s", step, req_cookie[:360])

            # 从多处信息中抓取 login_verifier/code_verifier
            self._sniff_login_verifier(req_url, f"{step}:req_url")
            self._sniff_login_verifier(req_body, f"{step}:req_body")
            self._sniff_login_verifier(final_url, f"{step}:final_url")
            self._sniff_login_verifier(location, f"{step}:location")
            raw_text = resp.text or ""
            self._sniff_login_verifier(raw_text, f"{step}:resp_body")

            # 明文 HTTP 抓包落盘（jsonl）
            if self._trace_dump_enabled and self._trace_dump_path:
                try:
                    include_req_cookie = self._env_flag("AUTH_TRACE_INCLUDE_REQ_COOKIE", "0")
                    record = {
                        "ts": datetime.utcnow().isoformat() + "Z",
                        "step": step,
                        "request": {
                            "method": method,
                            "url": req_url,
                            "body": req_body[:120000],
                            "headers": {
                                "Content-Type": (req_headers_lc.get("content-type", "") or "")[:240],
                                "Accept": (req_headers_lc.get("accept", "") or "")[:240],
                                "Referer": (req_headers_lc.get("referer", "") or "")[:500],
                                "Origin": (req_headers_lc.get("origin", "") or "")[:120],
                                **(
                                    {
                                        "Cookie": (req_headers_lc.get("cookie", "") or "")[:6000],
                                    }
                                    if include_req_cookie
                                    else {}
                                ),
                            },
                        },
                        "response": {
                            "status_code": status,
                            "url": final_url,
                            "location": resp.headers.get("Location", ""),
                            "x_request_id": resp.headers.get("x-request-id", ""),
                            "content_type": resp.headers.get("Content-Type", ""),
                            "set_cookie": set_cookie_raw,
                            "set_cookie_list": set_cookie_list,
                            "body": raw_text[:120000],
                        },
                        "captured_login_verifier": self._captured_login_verifier,
                    }
                    if self._trace_include_cookie and req_cookie:
                        record["request"]["headers"]["Cookie"] = req_cookie[:8000]
                    with open(self._trace_dump_path, "a", encoding="utf-8") as fw:
                        fw.write(json.dumps(record, ensure_ascii=False) + "\n")
                except Exception as e:
                    logger.debug(f"HTTP 抓包写入失败: {e}")
        except Exception as e:
            logger.debug(f"HTTP trace 输出失败: {e}")

    def _sniff_login_verifier(self, text: str, source: str = ""):
        """从任意文本中提取 login_verifier/code_verifier。"""
        if not text:
            return
        try:
            patterns = [
                r"(?:login_verifier|code_verifier|verifier)=([A-Za-z0-9._~-]{8,})",
                r'"(?:login_verifier|code_verifier|verifier)"\s*:\s*"([^"]{8,})"',
            ]
            for p in patterns:
                m = re.search(p, text)
                if not m:
                    continue
                v = (m.group(1) or "").strip()
                if not v:
                    continue
                if v != self._captured_login_verifier:
                    self._captured_login_verifier = v
                    logger.info("捕获 login_verifier 来源=%s len=%s", source or "unknown", len(v))
                return
        except Exception:
            return

    @staticmethod
    def _walk_collect_str_fields(obj: Any, wanted_keys: set[str], out: dict[str, str], depth: int = 0, max_depth: int = 6):
        """递归收集目标字段（仅字符串值）。"""
        if depth > max_depth or obj is None:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                kk = (str(k) or "").strip().lower()
                if kk in wanted_keys and isinstance(v, str) and v.strip():
                    out[kk] = v.strip()
                AuthFlow._walk_collect_str_fields(v, wanted_keys, out, depth + 1, max_depth)
        elif isinstance(obj, list):
            for it in obj:
                AuthFlow._walk_collect_str_fields(it, wanted_keys, out, depth + 1, max_depth)

    def fetch_client_auth_session_dump(self, stage: str = "") -> dict:
        """
        尝试读取 auth.openai 的 client_auth_session_dump：
        - 可能包含 session_id / client_auth_session 的额外状态
        - 若出现 verifier/refresh 相关字段，自动注入当前流程
        """
        headers = self._common_headers("https://auth.openai.com/email-verification")
        headers["Accept"] = "application/json"
        try:
            resp = self.session.get(
                "https://auth.openai.com/api/accounts/client_auth_session_dump",
                headers=headers,
                timeout=30,
            )
            self._trace_http(f"client_auth_session_dump_{stage or 'default'}", resp)
        except Exception as e:
            logger.debug(f"client_auth_session_dump 请求异常({stage}): {e}")
            return {}

        if resp.status_code != 200:
            logger.info(
                "client_auth_session_dump(%s) 非 200: %s",
                stage or "default",
                resp.status_code,
            )
            return {}

        try:
            data = resp.json()
        except Exception:
            logger.warning(f"client_auth_session_dump({stage}) JSON 解析失败")
            return {}

        if not isinstance(data, dict):
            return {}

        self._client_auth_session_dump = data
        cas = data.get("client_auth_session", {}) if isinstance(data.get("client_auth_session"), dict) else {}

        sid = (data.get("session_id", "") or "").strip() or (cas.get("session_id", "") or "").strip()
        if sid:
            self._client_auth_session_id = sid

        # 同步 OAuth client_id（若 dump 给出更准确值）
        dump_client_id = (cas.get("openai_client_id", "") or data.get("openai_client_id", "") or "").strip()
        if dump_client_id:
            self._oauth_client_id = dump_client_id

        wanted = {
            "login_verifier", "code_verifier", "verifier", "pkce_verifier", "oauth_code_verifier",
            "refresh_token", "oauth_refresh_token", "access_token", "id_token",
        }
        found: dict[str, str] = {}
        self._walk_collect_str_fields(data, wanted, found)

        # verifier 候选
        for key in ("login_verifier", "code_verifier", "verifier", "pkce_verifier", "oauth_code_verifier"):
            v = (found.get(key, "") or "").strip()
            if v and len(v) >= 8:
                self._dump_login_verifier = v
                self._captured_login_verifier = v
                logger.info("client_auth_session_dump 捕获 verifier: key=%s len=%s", key, len(v))
                break

        # token 候选（极少见，但若有直接收下）
        refresh = (found.get("refresh_token", "") or found.get("oauth_refresh_token", "")).strip()
        if refresh:
            self.result.refresh_token = refresh
        acc = (found.get("access_token", "") or "").strip()
        if acc:
            self.result.access_token = acc
        idt = (found.get("id_token", "") or "").strip()
        if idt:
            self.result.id_token = idt

        logger.info(
            "client_auth_session_dump(%s) 成功: top_keys=%s cas_keys=%s session_id=%s refresh=%s verifier=%s",
            stage or "default",
            list(data.keys())[:12],
            list(cas.keys())[:18] if isinstance(cas, dict) else [],
            (self._client_auth_session_id[:24] if self._client_auth_session_id else ""),
            "有" if self.result.refresh_token else "无",
            "有" if self._dump_login_verifier else "无",
        )
        return data

    @staticmethod
    def _is_tls_error(exc: Exception) -> bool:
        msg = str(exc).lower()
        markers = ["curl: (35)", "tls connect error", "openssl_internal", "sslerror"]
        return any(m in msg for m in markers)

    @staticmethod
    def _is_retryable_network_error(exc: Exception) -> bool:
        if AuthFlow._is_tls_error(exc) or isinstance(
            exc,
            (TimeoutError, ConnectionError, OSError),
        ):
            return True
        message = str(exc or "").lower()
        return any(
            marker in message
            for marker in (
                "curl: (",
                "timed out",
                "timeout",
                "connection reset",
                "connection aborted",
                "connection refused",
                "recv failure",
                "could not resolve",
                "proxy error",
            )
        )

    @staticmethod
    def _auth_network_retry_settings() -> tuple[int, float, float, set[int]]:
        return (
            _AUTH_NETWORK_RETRY_DEFAULT_ATTEMPTS,
            _AUTH_NETWORK_RETRY_DEFAULT_BACKOFF_SECONDS,
            _AUTH_NETWORK_RETRY_DEFAULT_BACKOFF_MULTIPLIER,
            set(_AUTH_NETWORK_RETRY_DEFAULT_STATUS_CODES),
        )

    def _request_with_network_retry(
        self,
        method: str,
        url: str,
        *,
        max_attempts: int | None = None,
        retry_status_codes: set[int] | None = None,
        extra_retry_status_codes: set[int] | None = None,
        rebuild_on_tls: bool = False,
        tls_only: bool = False,
        label: str = "",
        **kwargs,
    ):
        """Retry bounded transport/status failures without rebuilding an OTP session."""
        configured_attempts, backoff_seconds, backoff_multiplier, configured_status_codes = (
            self._auth_network_retry_settings()
        )
        attempt_limit = max(
            1,
            configured_attempts if max_attempts is None else int(max_attempts),
        )
        status_codes = (
            configured_status_codes
            if retry_status_codes is None
            else {int(code) for code in retry_status_codes}
        )
        status_codes.update(int(code) for code in (extra_retry_status_codes or set()))
        request_label = str(label or "").strip()
        if not request_label:
            parsed_url = urlparse(url)
            request_label = f"{method.upper()} {parsed_url.netloc}{parsed_url.path}"
        last_error: Exception | None = None
        for attempt in range(1, attempt_limit + 1):
            try:
                request = getattr(self.session, method.lower())
                response = request(url, **kwargs)
            except Exception as exc:
                retryable = (
                    self._is_tls_error(exc)
                    if tls_only
                    else self._is_retryable_network_error(exc)
                )
                if not retryable or attempt >= attempt_limit:
                    raise
                last_error = exc
                if rebuild_on_tls and self._is_tls_error(exc):
                    try:
                        self._rotate_impersonate_session()
                    except Exception as rotate_error:
                        logger.warning("TLS 重建 Session 失败，继续复用当前 Session: %s", rotate_error)
                delay = backoff_seconds * (backoff_multiplier ** (attempt - 1))
                logger.warning(
                    "Auth 请求网络失败，准备重试：接口=%s 异常=%s 次数=%s/%s 等待=%.1fs",
                    request_label,
                    exc.__class__.__name__,
                    attempt,
                    attempt_limit,
                    delay,
                )
                if delay > 0:
                    time.sleep(delay)
                continue

            status_code = int(getattr(response, "status_code", 0) or 0)
            if status_code in status_codes and attempt < attempt_limit:
                delay = backoff_seconds * (backoff_multiplier ** (attempt - 1))
                logger.warning(
                    "Auth 请求临时状态，准备重试：接口=%s status=%s 次数=%s/%s 等待=%.1fs",
                    request_label,
                    status_code,
                    attempt,
                    attempt_limit,
                    delay,
                )
                if delay > 0:
                    time.sleep(delay)
                continue
            return response

        if last_error is not None:
            raise last_error
        raise RuntimeError(f"Auth 请求重试耗尽: {method.upper()} {url}")

    @staticmethod
    def _is_registration_disallowed_error(exc: Exception) -> bool:
        msg = str(exc).lower()
        return "registration_disallowed" in msg

    def _get_cookie_value_by_name(
        self,
        name: str,
        preferred_domains: tuple[str, ...] = (),
    ) -> str:
        """按 cookie 名称获取值，并可优先选择与目标 host 匹配的 domain。"""
        target = (name or "").strip()
        if not target:
            return ""
        structured_cookies = []
        try:
            cookie_store = self.session.cookies
            cookie_source = getattr(cookie_store, "jar", None)
            if cookie_source is None:
                cookie_source = cookie_store
            structured_cookies = [
                cookie
                for cookie in cookie_source
                if hasattr(cookie, "name")
                and (getattr(cookie, "name", "") or "").strip().lower() == target.lower()
            ]
        except Exception:
            structured_cookies = []
        if preferred_domains and structured_cookies:
            for preferred_domain in preferred_domains:
                host = (preferred_domain or "").strip().lower().lstrip(".")
                domain_matches = []
                for cookie in structured_cookies:
                    cookie_domain = (
                        (getattr(cookie, "domain", "") or "").strip().lower().lstrip(".")
                    )
                    if cookie_domain and (
                        host == cookie_domain or host.endswith(f".{cookie_domain}")
                    ):
                        domain_matches.append((len(cookie_domain), cookie))
                if domain_matches:
                    _, cookie = max(domain_matches, key=lambda item: item[0])
                    return (getattr(cookie, "value", "") or "").strip()
            return ""
        try:
            value = self.session.cookies.get(target, "")
            if value:
                return str(value).strip()
        except Exception:
            pass
        try:
            if structured_cookies:
                return (getattr(structured_cookies[0], "value", "") or "").strip()
        except Exception:
            pass
        return ""

    def _missing_email_otp_session_cookies(self) -> tuple[str, ...]:
        """Return auth-state cookies required by the email verification page."""
        return tuple(
            name
            for name in _EMAIL_OTP_SESSION_COOKIE_NAMES
            if not self._get_cookie_value_by_name(name, ("auth.openai.com", "openai.com"))
        )

    def _extract_login_challenge_from_cookie(self) -> str:
        """
        从 login_session cookie 中提取 login_challenge。
        login_session 的第一段通常是 base64url(JSON)。
        """
        raw = self._get_cookie_value_by_name("login_session")
        if not raw:
            return ""
        try:
            p0 = raw.split(".")[0]
            p0 += "=" * (-len(p0) % 4)
            payload = json.loads(base64.urlsafe_b64decode(p0.encode("utf-8")).decode("utf-8"))
            return (payload.get("login_challenge", "") or "").strip()
        except Exception:
            return ""

    @staticmethod
    def _extract_query_first(url: str, keys: list[str]) -> str:
        if not url:
            return ""
        try:
            qs = parse_qs(urlparse(url).query)
        except Exception:
            return ""
        for k in keys:
            val = qs.get(k, [None])[0]
            if val:
                return val
        return ""

    @staticmethod
    def _extract_page_type(resp_json: dict | None) -> str:
        if not isinstance(resp_json, dict):
            return ""
        page = resp_json.get("page", {})
        if not isinstance(page, dict):
            return ""
        return (page.get("type", "") or "").strip()

    @staticmethod
    def _extract_continue_url_from_step(resp_json: dict | None) -> str:
        """
        从 auth step 响应提取 continue_url：
        - 顶层 continue_url
        - page.type=external_url 时 payload.url
        """
        if not isinstance(resp_json, dict):
            return ""
        continue_url = (resp_json.get("continue_url", "") or "").strip()
        if continue_url:
            return continue_url
        page = resp_json.get("page", {})
        if not isinstance(page, dict):
            return ""
        if (page.get("type", "") or "").strip() != "external_url":
            return ""
        payload = page.get("payload", {})
        if not isinstance(payload, dict):
            return ""
        return (payload.get("url", "") or "").strip()

    def _env_value(self, name: str, default: str = "") -> str:
        if name in self._env_overrides:
            return self._env_overrides[name]
        return str(os.getenv(name, default))

    def _env_flag(self, name: str, default: str = "0") -> bool:
        return self._env_value(name, default).lower() in ("1", "true", "yes", "on")

    @staticmethod
    def _b64url_no_pad(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

    def _remember_oauth_params(self, auth_url: str):
        """从 authorize URL 记住 OAuth 参数，供后续 token exchange 使用。"""
        if not auth_url:
            return
        self._oauth_auth_url = auth_url
        try:
            qs = parse_qs(urlparse(auth_url).query)
            self._oauth_client_id = (qs.get("client_id", [self._oauth_client_id])[0] or self._oauth_client_id).strip()
            self._oauth_redirect_uri = (
                qs.get("redirect_uri", [self._oauth_redirect_uri])[0] or self._oauth_redirect_uri
            ).strip()
            self._oauth_scope = (qs.get("scope", [""])[0] or "").strip()
            self._oauth_state = (qs.get("state", [""])[0] or "").strip()
        except Exception:
            return

    def _build_pkce_pair(self, raw_bytes: int = 64) -> tuple[str, str]:
        """生成 (code_verifier, code_challenge)。"""
        verifier = self._b64url_no_pad(secrets.token_bytes(max(32, int(raw_bytes))))
        if len(verifier) < 43:
            verifier = (verifier + ("A" * 43))[:43]
        if len(verifier) > 128:
            verifier = verifier[:128]
        challenge = self._b64url_no_pad(hashlib.sha256(verifier.encode("utf-8")).digest())
        return verifier, challenge

    def _build_codex_authorize(self, prompt_override: Optional[str] = None) -> tuple[str, str, str, str, str]:
        """
        构建用于获取 refresh_token 的 Codex OAuth 授权 URL。
        参考 any-auto-register 的实现：独立 client_id + redirect_uri + 可控 PKCE。
        """
        client_id = (self._env_value("OAUTH_CODEX_CLIENT_ID", "") or "").strip() or "app_EMoamEEZ73f0CkXaXp7hrann"
        redirect_uri = (self._env_value("OAUTH_CODEX_REDIRECT_URI", "") or "").strip() or "http://localhost:1455/auth/callback"
        scope = (self._env_value("OAUTH_CODEX_SCOPE", "") or "").strip() or "openid email profile offline_access"
        state = self._b64url_no_pad(secrets.token_bytes(24))
        verifier, challenge = self._build_pkce_pair()
        prompt = (
            (self._env_value("OAUTH_CODEX_PROMPT", "login") or "").strip()
            if prompt_override is None
            else (prompt_override or "").strip()
        )
        params = {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "id_token_add_organizations": "true",
            "codex_cli_simplified_flow": "true",
        }
        if prompt:
            params["prompt"] = prompt
        auth_url = f"https://auth.openai.com/oauth/authorize?{urlencode(params)}"
        return auth_url, state, verifier, redirect_uri, client_id

    @staticmethod
    def _callback_has_code(url: str, redirect_uri: str) -> bool:
        if not url:
            return False
        try:
            cb_base = (redirect_uri or "").split("?", 1)[0].rstrip("/")
            target = url.split("?", 1)[0].rstrip("/")
            if cb_base and target == cb_base:
                qs = parse_qs(urlparse(url).query)
                return bool((qs.get("code", [""])[0] or "").strip())
        except Exception:
            return False
        return False

    def _follow_authorize_for_callback(self, start_url: str, redirect_uri: str, trace_prefix: str) -> tuple[str, str]:
        """
        跟随 auth.openai.com 授权链路，捕获 callback（不消费 callback）。
        返回 (callback_url, final_url)。
        """
        current = start_url
        callback_url = ""
        chose_account = False  # /choose-an-account 每条链路只选一次，防 200/同 URL 循环
        for i in range(12):
            if self._callback_has_code(current, redirect_uri):
                callback_url = current
                break
            resp = self.session.get(
                current,
                headers=self._navigation_headers("https://chatgpt.com/", current),
                timeout=30,
                allow_redirects=False,
            )
            self._trace_http(f"{trace_prefix}_hop_{i+1}", resp)

            # workspace/consent 页面 200 时，主动选择 workspace，拿下一跳 continue_url
            if resp.status_code == 200:
                is_workspace_like = (
                    ("/workspace" in current)
                    or ("/sign-in-with-chatgpt/" in current)
                    or ("/consent" in current)
                )
                if is_workspace_like:
                    workspace_id = self._extract_workspace_id() or self._extract_workspace_id_from_html(resp.text or "")
                    if workspace_id:
                        next_url = self._workspace_select(workspace_id)
                        if next_url:
                            if next_url.startswith("/"):
                                next_url = urljoin("https://auth.openai.com", next_url)
                            current = next_url
                            continue

                # /choose-an-account：OpenAI 已登录多账号的选择页（react-router SSR）。
                # HTML 里 streamController.enqueue 注入 unified_sessions[].id (us_*) 和
                # authsess_*。protocol 端要主动选第一个 us_*，否则 codex callback 拿不到。
                if "/choose-an-account" in current and not chose_account:
                    chose_account = True
                    next_url = self._choose_account_select(resp.text or "", current)
                    if next_url:
                        if next_url.startswith("/"):
                            next_url = urljoin("https://auth.openai.com", next_url)
                        current = next_url
                        continue

            if resp.status_code not in (301, 302, 303, 307, 308):
                break
            loc = (resp.headers.get("Location", "") or "").strip()
            if not loc:
                break
            if loc.startswith("/"):
                loc = urljoin(current, loc)
            if self._callback_has_code(loc, redirect_uri):
                callback_url = loc
                current = loc
                break
            current = loc
        return callback_url, current

    @staticmethod
    def _drop_query_keys(url: str, drop_keys: set[str]) -> str:
        if not url:
            return ""
        try:
            parsed = urlparse(url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
            kept = [(k, v) for (k, v) in params if (k or "").strip() not in drop_keys]
            return urlunparse(parsed._replace(query=urlencode(kept)))
        except Exception:
            return url

    def _exchange_codex_callback_code(
        self,
        callback_url: str,
        expected_state: str,
        verifier: str,
        redirect_uri: str,
        client_id: str,
    ) -> bool:
        qs = parse_qs(urlparse(callback_url).query)
        code = (qs.get("code", [""])[0] or "").strip()
        got_state = (qs.get("state", [""])[0] or "").strip()
        if not code:
            logger.warning("Codex callback 缺少 code")
            return False
        if expected_state and got_state and got_state != expected_state:
            logger.warning("Codex callback state 不匹配，期望=%s 实际=%s", expected_state[:20], got_state[:20])
            return False

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "Origin": "https://auth.openai.com",
            "Referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
        }
        headers.update(self._browser_request_headers(
            destination="empty",
            mode="cors",
            site="same-origin",
        ))
        form = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        }
        encoded_form = urlencode(form)
        resp = self.session.post(
            "https://auth.openai.com/oauth/token",
            headers=headers,
            data=encoded_form,
            timeout=30,
        )
        self._trace_http(
            "oauth_token_exchange_codex_pkce",
            resp,
            extra_request={
                "method": "POST",
                "url": "https://auth.openai.com/oauth/token",
                "body": encoded_form,
                "headers": headers,
            },
        )
        if resp.status_code != 200:
            logger.warning("Codex oauth/token 失败: %s - %s", resp.status_code, (resp.text or "")[:220])
            return False
        data = resp.json() if resp is not None else {}
        self.result.id_token = data.get("id_token", self.result.id_token)
        self.result.access_token = data.get("access_token", self.result.access_token)
        self.result.refresh_token = data.get("refresh_token", self.result.refresh_token)
        logger.info(
            "Codex OAuth 交换成功: access=%s refresh=%s",
            "有" if self.result.access_token else "无",
            "有" if self.result.refresh_token else "无",
        )
        return True

    def _codex_drive_login_from_log_in(self, mail_provider: Optional[MailProvider] = None) -> str:
        """
        当 Codex 授权回落到 /log-in 时，补走一次纯协议登录推进状态机。
        返回可继续跟随的 continue_url（若无则返回空字符串）。
        """
        email = (self.result.email or "").strip()
        if not email:
            logger.warning("Codex 登录推进缺少 email")
            return ""
        password = (self.result.password or "").strip() or self._default_password_from_email(email)
        self.result.password = password

        device_id = (self.result.device_id or "").strip() or self._get_cookie_value_by_name(
            "oai-did",
            ("auth.openai.com", "openai.com", "chatgpt.com"),
        )
        if not device_id:
            device_id = str(uuid.uuid4())
            self.result.device_id = device_id

        sentinel = self.get_sentinel_token(device_id)
        step = self.authorize_continue(
            email=email,
            sentinel_token=sentinel,
            screen_hint="login",
            referer="https://auth.openai.com/log-in",
            trace_step="authorize_continue_login_codex",
        )
        page_type = self._extract_page_type(step)
        continue_url = self._normalize_continue_url(self._extract_continue_url_from_step(step))

        if page_type == "login_password" or "/log-in/password" in continue_url:
            step = self.login_password_verify(password)
            page_type = self._extract_page_type(step)
            continue_url = self._normalize_continue_url(self._extract_continue_url_from_step(step))

        if getattr(self, "_totp_secret", ""):
            step = self._complete_totp_login_step(step)
            page_type = self._extract_page_type(step)
            continue_url = self._normalize_continue_url(self._extract_continue_url_from_step(step))

        need_otp = (page_type == "email_otp_verification") or ("/email-verification" in (continue_url or ""))
        if need_otp:
            if mail_provider is None:
                logger.warning("Codex 登录推进需要 OTP，但未提供 mail_provider")
                return continue_url or ""
            try:
                otp_timeout = max(30, int(self._env_value("OTP_TIMEOUT", "60")))
            except Exception:
                otp_timeout = 180
            otp_sent_at = time.time()
            if not self.kickoff_otp_delivery("codex_login_need_otp"):
                self.send_otp()
            otp_code = mail_provider.wait_for_otp(
                email,
                timeout=otp_timeout,
                issued_after=otp_sent_at,
            )
            otp_resp = self.verify_otp(otp_code)
            continue_url = self._normalize_continue_url(self._extract_continue_url_from_step(otp_resp))

        # add-phone 分支（可选）：
        # 仅在配置了手机号与验证码获取方式时尝试自动推进
        if self._is_add_phone_state(page_type="", continue_url=continue_url):
            next_url = self._handle_add_phone_verification(continue_url=continue_url)
            if next_url:
                continue_url = self._normalize_continue_url(next_url)

        return continue_url or ""

    @staticmethod
    def _is_add_phone_state(page_type: str = "", continue_url: str = "") -> bool:
        pt = (page_type or "").strip().lower()
        cu = (continue_url or "").strip().lower()
        return (pt == "add_phone") or ("add-phone" in cu)

    def _phone_headers(self, referer: str) -> dict:
        headers = self._common_headers(referer)
        headers["Accept"] = "application/json"
        headers["Content-Type"] = "application/json"
        headers["Origin"] = "https://auth.openai.com"
        device_id = (self.result.device_id or "").strip() or self._get_cookie_value_by_name(
            "oai-did",
            ("auth.openai.com", "openai.com", "chatgpt.com"),
        )
        if device_id:
            headers["oai-device-id"] = device_id
        return headers

    def _add_phone_send(self, phone_number: str) -> dict:
        headers = self._phone_headers("https://auth.openai.com/add-phone")
        try:
            resp = self._request_with_tls_retry(
                "POST",
                "https://auth.openai.com/api/accounts/add-phone/send",
                headers=headers,
                json={"phone_number": phone_number},
                timeout=30,
            )
        except Exception as e:
            logger.warning("[add-phone] 网络异常: %s (phone=%s)", e, phone_number)
            raise
        self._trace_http("add_phone_send", resp)

        if resp.status_code != 200:
            # 解析 error.message（如果有的话）
            try:
                data = resp.json()
                msg = data.get("error", {}).get("message", "")
                code = data.get("error", {}).get("code", "")
            except Exception:
                msg = resp.text[:150]
                code = ""
            # 抛异常时只带 message（不带完整 JSON），让上层日志更简洁
            raise RuntimeError(msg or f"HTTP {resp.status_code}")

        try:
            return resp.json() if resp is not None else {}
        except Exception:
            return {}

    def _phone_otp_resend(self) -> bool:
        headers = self._phone_headers("https://auth.openai.com/phone-verification")
        resp = self._request_with_tls_retry(
            "POST",
            "https://auth.openai.com/api/accounts/phone-otp/resend",
            headers=headers,
            timeout=30,
        )
        self._trace_http("phone_otp_resend", resp)
        return resp.status_code == 200

    def _phone_otp_validate(self, code: str) -> dict:
        headers = self._phone_headers("https://auth.openai.com/phone-verification")
        resp = self._request_with_tls_retry(
            "POST",
            "https://auth.openai.com/api/accounts/phone-otp/validate",
            headers=headers,
            json={"code": code},
            timeout=30,
        )
        self._trace_http("phone_otp_validate", resp)
        if resp.status_code != 200:
            raise RuntimeError(f"phone-otp/validate 失败: {resp.status_code} - {(resp.text or '')[:220]}")
        try:
            return resp.json() if resp is not None else {}
        except Exception:
            return {}

    @staticmethod
    def _extract_otp6(text: str) -> str:
        if not text:
            return ""
        m = re.search(r"(?<!\d)(\d{6})(?!\d)", text)
        return (m.group(1) if m else "").strip()

    def _read_phone_otp_from_cmd(self) -> str:
        """
        从环境变量 OPENAI_PHONE_OTP_CMD 指定的命令读取手机验证码（stdout）。
        命令输出中只要出现 6 位数字即视为命中。
        """
        cmd = (os.getenv("OPENAI_PHONE_OTP_CMD", "") or "").strip()
        if not cmd:
            return ""
        try:
            out = subprocess.check_output(cmd, shell=True, text=True, timeout=20)
            return self._extract_otp6(out or "")
        except Exception:
            return ""

    def _wait_phone_otp(self, timeout: int = 180) -> str:
        static_otp = self._extract_otp6(os.getenv("OPENAI_PHONE_OTP", "") or "")
        if static_otp:
            return static_otp

        deadline = time.time() + max(20, int(timeout))
        while time.time() < deadline:
            code = self._read_phone_otp_from_cmd()
            if code:
                return code
            time.sleep(4)
        raise TimeoutError(f"等待手机 OTP 超时 ({timeout}s)")

    def _handle_add_phone_verification(self, continue_url: str = "") -> str:
        """
        处理 add-phone 验证分支：
        - 优先使用 self._sms_callback（SMS 接码 controller，自动租号 + 接码）
        - 回退到环境变量路径：OPENAI_PHONE_NUMBER + OPENAI_PHONE_OTP_CMD/OPENAI_PHONE_OTP
        """
        if not self._allow_phone_verification:
            raise PhoneVerificationRequired("已关闭手机验证，当前流程要求绑定手机号")
        if self._sms_callback is not None:
            try:
                return self._handle_add_phone_via_sms(continue_url)
            except Exception as e:
                logger.warning("SMS 接码流程失败，回退环境变量路径: %s", e)
                try:
                    self._sms_callback.cleanup()
                except Exception:
                    pass
        return self._handle_add_phone_via_env(continue_url)

    def _handle_add_phone_via_sms(self, continue_url: str = "") -> str:
        """走 SMS 接码 controller：租号 → add-phone/send → 等 SMS → validate。

        支持平台：SmsBower（smsbower.page）。
        单号窗口 80s（每 20s × 3 触发一次 OpenAI 端 resend）；失败自动 cancel + 换新号。
        最多换号次数默认 3，主人可在 WebUI / 环境变量 OPENAI_PHONE_MAX_ATTEMPTS 自定义。
        """
        ctrl = self._sms_callback
        try:
            ctrl.set_resend_callback(self._phone_otp_resend)
        except Exception:
            pass

        # 用 try/finally 保证即使 for 循环抛异常，也能 release lock + 最后一次 cleanup
        try:
            return self._do_sms_loop(ctrl)
        finally:
            # 无论成败都释放 lock + cleanup 最后一个号（如果有）
            try:
                ctrl.cleanup()
            except Exception:
                pass
            try:
                ctrl._release_lock()
            except Exception:
                pass

    def _do_sms_loop(self, ctrl) -> str:
        """SMS 接码循环逻辑（for 0..max_attempts）。"""
        # provider 信息（目前只支持 SmsBower）
        provider_key = (getattr(ctrl, "provider_key", "") or "").lower()

        # 优先从 controller.config 读（前端配置） → 环境变量兜底 → 用默认
        ctrl_cfg = getattr(ctrl, "config", None) or {}

        def _read_int(cfg_key: str, env_key: str, default: str, min_v: int = 1) -> int:
            raw = (str(ctrl_cfg.get(cfg_key) or "")).strip()
            if not raw:
                raw = os.getenv(env_key, default)
            try:
                return max(min_v, int(raw))
            except Exception:
                return int(default)

        # 单号等待窗口（秒）：默认 80 = 20×3 + 20 缓冲
        per_phone_timeout = max(40, _read_int(
            "sms_per_phone_timeout", "OPENAI_PHONE_OTP_TIMEOUT", "80", min_v=40
        ))
        # 最多换几个号（默认 3）
        max_phone_attempts = _read_int(
            "sms_max_phone_attempts", "OPENAI_PHONE_MAX_ATTEMPTS", "3"
        )
        # 单号内 code validate 失败后的重试次数（如果还有时间）
        max_code_retries_per_phone = _read_int(
            "sms_code_retries_per_phone", "OPENAI_PHONE_OTP_CODE_RETRIES", "2"
        )

        logger.info(
            "[sms] 配置: provider=%s 单号窗口=%ds 最多换号=%d 单号内验证重试=%d",
            provider_key, per_phone_timeout, max_phone_attempts, max_code_retries_per_phone,
        )

        # OpenAI "号已被使用 / 不允许" 类错误关键字
        _PHONE_REJECTED_PATTERNS = (
            "phone_number_already_in_use", "already_in_use", "already_taken",
            "phone_already_verified", "already_verified",
            "disallowed_phone", "invalid_phone_number", "phone_number_invalid",
            "blocked_phone", "phone_number_blocked",
            "suspicious behavior from phone",  # OpenAI 风控：号段可疑
        )
        def _is_phone_rejected(s: str) -> bool:
            sl = (s or "").lower()
            return any(p in sl for p in _PHONE_REJECTED_PATTERNS)

        last_err: Optional[Exception] = None

        for phone_attempt in range(1, max_phone_attempts + 1):
            logger.info("[sms] 🔁 第 %d/%d 个号尝试...", phone_attempt, max_phone_attempts)

            # 阶段 1：租号（第 2+ 个号会自动租新号，SmsBower cache 已被前一次 cleanup 清掉）
            try:
                phone = ctrl.get_phone()
            except Exception as e:
                last_err = e
                logger.warning("[sms] 第 %d 个号租号失败: %s", phone_attempt, e)
                continue
            if not phone:
                last_err = RuntimeError("SMS 接码 controller 未返回手机号")
                continue

            # 阶段 2：通知 OpenAI 发码到这个号
            send_resp = None
            try:
                logger.info("[sms] 📤 准备 POST add-phone/send (phone=%s) ...", phone)
                send_resp = self._add_phone_send(phone)
                logger.info("[sms] ✅ POST add-phone/send 成功 (phone=%s)", phone)
            except Exception as e:
                err_text = str(e)
                if "too many phone verification" in err_text.lower() \
                        or "phone_verification_rate_limit" in err_text.lower():
                    logger.warning(
                        "⚠️ OpenAI 频控: 这个 outlook 号/IP 已累积太多 add-phone 请求，"
                        "建议换 outlook 号或换代理 IP 后重试。本次放弃 add-phone（session_token 仍可保留）"
                    )
                    ctrl.mark_send_failed(err_text)
                    last_err = e
                    break
                if _is_phone_rejected(err_text):
                    logger.warning("[sms] 号 %s 被 OpenAI 拒（已用过/不允许）: %s",
                                   phone, err_text[:200])
                    ctrl.mark_send_failed(err_text)
                    last_err = e
                    continue
                # 其它未识别错误 → 也打详细日志但不视为"号码问题"
                logger.warning("[sms] 号 %s POST add-phone/send 失败（未识别错误）: %s",
                               phone, err_text[:300])
                ctrl.mark_send_failed(err_text)
                last_err = e
                continue

            send_page_type = self._extract_page_type(send_resp)
            send_continue = self._normalize_continue_url(self._extract_continue_url_from_step(send_resp))
            if send_page_type not in ("phone_otp_verification", "external_url") \
                    and "phone-verification" not in (send_continue or ""):
                logger.warning(
                    "add-phone/send 未进入手机验证码页: page=%s continue=%s",
                    send_page_type or "(empty)",
                    (send_continue or "")[:180],
                )
                ctrl.mark_send_failed("did not enter phone-verification page")
                last_err = RuntimeError(f"add-phone/send 未进入 phone-verification: page={send_page_type}")
                continue

            ctrl.mark_send_succeeded()

            # 阶段 3：等 SMS code（SmsBower 内部会按 20s × 3 调 OpenAI resend）
            phone_start = time.time()
            seen_codes: set[str] = set()
            code_attempt = 0
            phone_used = False

            while time.time() - phone_start < per_phone_timeout and code_attempt < max_code_retries_per_phone:
                remaining = per_phone_timeout - (time.time() - phone_start)
                if remaining < 10:
                    break
                code_attempt += 1
                logger.info(
                    "[sms] 号 %s 第 %d/%d 次等 SMS (剩余 %ds)",
                    phone, code_attempt, max_code_retries_per_phone, int(remaining),
                )
                code = ctrl.get_code(timeout=int(remaining))
                if not code:
                    break  # 超时换号
                if code in seen_codes:
                    logger.warning("[sms] 收到重复 code=%s，跳过", code)
                    continue
                seen_codes.add(code)
                phone_used = True

                try:
                    validate_resp = self._phone_otp_validate(code)
                    next_url = self._normalize_continue_url(
                        self._extract_continue_url_from_step(validate_resp)
                    )
                    logger.info("[sms] ✅ phone-otp/validate 通过 (phone=%s code=%s) next=%s",
                                phone, code, (next_url or "")[:160])
                    ctrl.report_success()
                    return next_url or continue_url or ""
                except Exception as e:
                    last_err = e
                    err_text = str(e)
                    logger.warning("[sms] validate 失败 (phone=%s code=%s): %s",
                                   phone, code, err_text[:200])
                    ctrl.mark_code_failed(err_text)
                    # 继续 while 循环等下一条 code（同号）

            # 单号窗口结束：cancel 这个号
            logger.warning("[sms] 号 %s 已用尽 %ds 窗口", phone, per_phone_timeout)
            try:
                ctrl.cleanup()
            except Exception:
                pass
            # cleanup 清掉 controller.activation，下一轮 get_phone 会租新号

        # 所有号都失败
        if last_err:
            raise last_err
        raise RuntimeError(f"SMS 接码 {max_phone_attempts} 个号均失败")

    def _handle_add_phone_via_env(self, continue_url: str = "") -> str:
        """
        处理 add-phone 验证分支（环境变量路径，旧用法）：
        - 需要通过环境变量提供号码与验证码来源：
          - OPENAI_PHONE_NUMBER=+1...
          - OPENAI_PHONE_OTP_CMD='...返回短信内容...' 或 OPENAI_PHONE_OTP=123456
        """
        phone_raw = (os.getenv("OPENAI_PHONE_NUMBER", "") or "").strip()
        phone_candidates = [x.strip() for x in phone_raw.split(",") if x.strip()]
        if not phone_candidates:
            logger.warning("命中 add-phone，但未配置 SMS 接码 / OPENAI_PHONE_NUMBER，无法继续推进")
            return continue_url or ""

        try:
            otp_timeout = max(30, int(os.getenv("OPENAI_PHONE_OTP_TIMEOUT", "180")))
        except Exception:
            otp_timeout = 180

        last_err = ""
        for idx, phone in enumerate(phone_candidates, 1):
            try:
                logger.info("add-phone 尝试号码 %s/%s: %s", idx, len(phone_candidates), phone)
                send_resp = self._add_phone_send(phone)
                send_page_type = self._extract_page_type(send_resp)
                send_continue = self._normalize_continue_url(self._extract_continue_url_from_step(send_resp))
                if send_page_type not in ("phone_otp_verification", "external_url") and "phone-verification" not in (send_continue or ""):
                    logger.warning(
                        "add-phone/send 未进入手机验证码页: page=%s continue=%s",
                        send_page_type or "(empty)",
                        (send_continue or "")[:180],
                    )
                    continue

                phone_code = self._wait_phone_otp(timeout=otp_timeout)
                validate_resp = self._phone_otp_validate(phone_code)
                next_url = self._normalize_continue_url(self._extract_continue_url_from_step(validate_resp))
                logger.info("add-phone 验证通过，next=%s", (next_url or "")[:180])
                return next_url or continue_url or ""
            except Exception as e:
                last_err = str(e)
                logger.warning("add-phone 号码 %s 失败: %s", phone, e)
                try:
                    self._phone_otp_resend()
                except Exception:
                    pass

        if last_err:
            logger.warning("add-phone 阶段未成功: %s", last_err)
        return continue_url or ""

    def _codex_refresh_retry_after_add_phone(
        self,
        auth_url: str,
        redirect_uri: str,
        attempts: int = 3,
        sleep_seconds: float = 1.2,
    ) -> tuple[str, str]:
        """
        当命中 add-phone 时，按“刷新重试”策略重复发起 authorize，
        期望命中不需要 add-phone 的分支并直接拿 callback code。
        """
        callback_url = ""
        final_url = ""
        start_url = self._drop_query_keys(auth_url, {"prompt"}) or auth_url
        rounds = max(1, int(attempts))
        wait_s = max(0.0, float(sleep_seconds))

        for i in range(rounds):
            callback_url, final_url = self._follow_authorize_for_callback(
                start_url,
                redirect_uri,
                f"codex_add_phone_refresh_retry_{i+1}",
            )
            if callback_url:
                return callback_url, final_url
            if i < rounds - 1 and wait_s > 0:
                time.sleep(wait_s)

        return callback_url, final_url

    def oauth_codex_rt_exchange(self, mail_provider: Optional[MailProvider] = None) -> bool:
        """
        纯协议方式获取 RT（参考 any-auto-register）：
        - 使用独立 Codex OAuth 参数重新授权（可控 PKCE）
        - 捕获 callback code（不消费）
        - 直接调 /oauth/token 交换 access_token + refresh_token
        """
        allow_retry = self._env_flag("OAUTH_CODEX_RT_ALLOW_RETRY", "0")
        if self._codex_rt_attempted and (not allow_retry):
            logger.info("Codex RT 本轮已尝试过，跳过重复尝试（可用 OAUTH_CODEX_RT_ALLOW_RETRY=1 强制重试）")
            return False
        self._codex_rt_attempted = True

        logger.info("尝试 Codex OAuth 直连换取 refresh_token ...")
        try:
            auth_url, state, verifier, redirect_uri, client_id = self._build_codex_authorize()
            self._oauth_auth_url = auth_url
            self._oauth_client_id = client_id
            self._oauth_redirect_uri = redirect_uri
            self._oauth_state = state
            self._manual_login_verifier = verifier
            self._captured_login_verifier = verifier
            callback_url, final_url = self._follow_authorize_for_callback(
                auth_url, redirect_uri, "codex_authorize"
            )

            # 若被打回 /log-in，补走一次协议登录，再继续授权链路
            if (not callback_url) and "/log-in" in (final_url or ""):
                logger.info("Codex 授权回落到 /log-in，尝试协议推进登录状态...")
                continue_url = ""
                try:
                    continue_url = self._codex_drive_login_from_log_in(mail_provider=mail_provider)
                except PhoneVerificationRequired:
                    raise
                except Exception as e:
                    logger.warning(f"Codex 登录推进失败，改走 no-prompt 兜底: {e}")
                if continue_url:
                    # 命中 add-phone 时，支持“刷新重试”策略（不立刻放弃）
                    if self._is_add_phone_state(page_type="", continue_url=continue_url) and self._env_flag(
                        "OAUTH_CODEX_ADD_PHONE_REFRESH_RETRY", "1"
                    ):
                        try:
                            retry_count = max(1, int(self._env_value("OAUTH_CODEX_ADD_PHONE_REFRESH_RETRY_COUNT", "3")))
                        except Exception:
                            retry_count = 3
                        try:
                            retry_sleep = max(0.0, float(self._env_value("OAUTH_CODEX_ADD_PHONE_REFRESH_SLEEP", "1.2")))
                        except Exception:
                            retry_sleep = 1.2
                        logger.info("命中 add-phone，执行 authorize 刷新重试: count=%s sleep=%.1fs", retry_count, retry_sleep)
                        callback_url, final_url = self._codex_refresh_retry_after_add_phone(
                            auth_url=auth_url,
                            redirect_uri=redirect_uri,
                            attempts=retry_count,
                            sleep_seconds=retry_sleep,
                        )
                    else:
                        callback_url, final_url = self._follow_authorize_for_callback(
                            continue_url,
                            redirect_uri,
                            "codex_post_login",
                        )

            # Codex authorize 直接被打到 /add-phone（不经过 /log-in）：
            # 如果配了 SMS 接码 controller，先把手机号绑了再重新 authorize
            if (not callback_url) and self._is_add_phone_state(page_type="", continue_url=final_url or ""):
                if not self._allow_phone_verification:
                    raise PhoneVerificationRequired("已关闭手机验证，Codex OAuth 要求绑定手机号")
                if self._sms_callback is not None:
                    logger.info("Codex 授权直接落到 /add-phone，尝试 SMS 接码绑号 ...")
                    try:
                        self._handle_add_phone_via_sms(continue_url=final_url)
                        # 绑号成功后重新 authorize 拿 callback code
                        callback_url, final_url = self._follow_authorize_for_callback(
                            auth_url, redirect_uri, "codex_authorize_after_add_phone"
                        )
                        if not callback_url:
                            no_prompt_url = self._drop_query_keys(auth_url, {"prompt"})
                            if no_prompt_url and no_prompt_url != auth_url:
                                callback_url, final_url = self._follow_authorize_for_callback(
                                    no_prompt_url,
                                    redirect_uri,
                                    "codex_authorize_noprompt_after_add_phone",
                                )
                    except Exception as e:
                        logger.warning(f"SMS 接码绑号失败: {e}")

            # 兜底：去掉 prompt=login 再发起一次授权
            if not callback_url:
                no_prompt_url = self._drop_query_keys(auth_url, {"prompt"})
                if no_prompt_url and no_prompt_url != auth_url:
                    callback_url, final_url = self._follow_authorize_for_callback(
                        no_prompt_url,
                        redirect_uri,
                        "codex_authorize_noprompt",
                    )

            if not callback_url:
                logger.warning("Codex OAuth 未捕获 callback code, final=%s", (final_url or "")[:180])
                return False
            return self._exchange_codex_callback_code(
                callback_url=callback_url,
                expected_state=state,
                verifier=verifier,
                redirect_uri=redirect_uri,
                client_id=client_id,
            )
        except PhoneVerificationRequired:
            if self.result.access_token:
                logger.warning(
                    "Codex OAuth 要求手机验证，但已取得 ChatGPT access token，跳过 RT 交换"
                )
                return False
            raise
        except Exception as e:
            logger.warning(f"Codex OAuth 交换异常: {e}")
            return False

    def _inject_pkce_into_auth_url(self, auth_url: str) -> str:
        """为 authorize URL 注入 PKCE 参数（可选）。"""
        if not auth_url:
            return auth_url
        if not self._env_flag("OAUTH_SECONDARY_PKCE", "0"):
            return auth_url

        try:
            parsed = urlparse(auth_url)
            params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            if params.get("code_challenge") and params.get("code_challenge_method"):
                return auth_url

            verifier, challenge = self._build_pkce_pair()
            params["code_challenge"] = challenge
            params["code_challenge_method"] = "S256"
            new_url = urlunparse(parsed._replace(query=urlencode(params)))
            # 若用户未手动指定 verifier，则自动注入本轮 verifier
            if not self._manual_login_verifier:
                self._manual_login_verifier = verifier
            logger.info(
                "已启用二次 PKCE 注入: verifier_len=%s challenge=%s...",
                len(verifier),
                challenge[:16],
            )
            return new_url
        except Exception as e:
            logger.warning(f"注入 PKCE 参数失败，回退原始 auth_url: {e}")
            return auth_url

    @staticmethod
    def _safe_b64url_decode_text(data: str) -> str:
        if not data:
            return ""
        try:
            s = data + "=" * (-len(data) % 4)
            return base64.urlsafe_b64decode(s.encode("utf-8")).decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _extract_hydra_redirect_values(self) -> list[str]:
        """从 hydra_redirect cookie 中提取可能的会话值。"""
        raw = self._get_cookie_value_by_name("hydra_redirect")
        if not raw:
            return []
        out: list[str] = []
        try:
            p0 = (raw.split(".", 1)[0] or "").strip()
            text = self._safe_b64url_decode_text(p0)
            if text:
                obj = json.loads(text)
                if isinstance(obj, dict):
                    for v in obj.values():
                        if isinstance(v, str) and v.strip():
                            vv = v.strip()
                            out.append(vv)
                            if "|" in vv:
                                out.extend([x for x in vv.split("|") if isinstance(x, str) and x.strip()])
        except Exception:
            return out
        return out

    def _collect_code_verifier_candidates(self, callback_url: str, continue_url: str) -> list[tuple[str, str]]:
        """收集 code_verifier 候选（来源 + 值）。"""
        raw_candidates: list[tuple[str, str]] = [
            ("query", self._extract_query_first(continue_url, ["login_verifier", "code_verifier", "verifier"])),
            ("query_callback", self._extract_query_first(callback_url, ["login_verifier", "code_verifier", "verifier"])),
            ("dump", self._dump_login_verifier),
            ("captured", self._captured_login_verifier),
            ("manual", self._manual_login_verifier),
            ("cookie_login_verifier", self._get_cookie_value_by_name("login_verifier")),
            ("cookie_code_verifier", self._get_cookie_value_by_name("code_verifier")),
            ("cookie_login_challenge", self._extract_login_challenge_from_cookie()),
            ("cookie_nextauth_state", self._get_cookie_value_by_name("__Secure-next-auth.state")),
        ]

        # hydra_redirect 中可能包含编码后的 csrf/session 串，作为实验候选
        for i, hv in enumerate(self._extract_hydra_redirect_values()):
            raw_candidates.append((f"hydra_{i}", hv))

        out: list[tuple[str, str]] = []
        seen: set[str] = set()

        max_len = max(128, int(self._env_value("OAUTH_MAX_VERIFIER_LEN", "4096")))
        for src, val in raw_candidates:
            v = (val or "").strip()
            if not v:
                continue
            if len(v) > max_len:
                v = v[:max_len]
            if v not in seen:
                seen.add(v)
                out.append((src, v))
            # PKCE 标准长度 43~128；对超长候选补一个截断版本
            if len(v) > 128:
                v128 = v[:128]
                if v128 not in seen:
                    seen.add(v128)
                    out.append((f"{src}_trunc128", v128))

        return out

    def _rotate_impersonate_session(self) -> bool:
        """使用同一 TLS/UA profile 重建 Session 后重试。"""
        if self._impersonate_idx >= len(self._impersonate_candidates) - 1:
            return False
        self._impersonate_idx += 1
        imp = self._impersonate_candidates[self._impersonate_idx]
        logger.warning(f"TLS 异常，使用同一指纹重建 Session: impersonate={imp}")
        self.session = create_http_session(
            proxy=self.config.proxy, impersonate=imp, user_agent=self._ua,
        )
        self._bind_session_fingerprint()
        return True

    def _bind_session_fingerprint(self) -> None:
        setattr(self.session, "_plus_register_fingerprint", dict(self._fingerprint))


    @staticmethod
    def _is_retryable_tls_connect_error(exc: Exception) -> bool:
        msg = str(exc).lower()
        return "curl: (35)" in msg and (
            "tls connect error" in msg
            or "ssl connect error" in msg
            or "openssl_internal" in msg
        )

    def _request_with_tls_retry(self, method: str, url: str, **kwargs):
        """Retry TLS-connect failures with a rebuilt Session using the same profile."""
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                request = getattr(self.session, method.lower())
                return request(url, **kwargs)
            except Exception as exc:
                if not self._is_retryable_tls_connect_error(exc):
                    raise
                last_error = exc
                if attempt >= 2 or not self._rotate_impersonate_session():
                    break
        raise RuntimeError(
            f"TLS 握手失败: {method.upper()} {url} 重建同一 TLS 指纹后仍失败: "
            f"{last_error}"
        ) from last_error

    def _common_headers(self, referer: str = "https://chatgpt.com/") -> dict:
        """
        构造通用请求头。

        关键点：
        - Origin 必须与 Referer 同源（尤其 auth.openai.com 的状态机接口），
          否则容易触发 invalid_state / 风控分支。
        - 在 auth.openai.com 域下，尽量补充 oai-device-id，提升状态机连续性。
        """
        origin = "https://chatgpt.com"
        try:
            parsed = urlparse(referer or "")
            if parsed.scheme and parsed.netloc:
                origin = f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            pass

        fp = self._fingerprint
        headers = {
            "Accept": "application/json",
            "Referer": referer,
            "Origin": origin,
        }
        headers.update(self._browser_request_headers(
            destination="empty",
            mode="cors",
            site="same-origin",
        ))
        if fp.get("sec_ch_ua"):
            headers["sec-ch-ua"] = fp["sec_ch_ua"]
            headers["sec-ch-ua-mobile"] = fp.get("sec_ch_ua_mobile") or "?0"
            headers["sec-ch-ua-platform"] = fp["sec_ch_ua_platform"]

        # auth.openai.com 侧请求补设备标识（若可得）
        try:
            host = (urlparse(origin).netloc or "").lower()
        except Exception:
            host = ""
        if "auth.openai.com" in host:
            device_id = (self.result.device_id or "").strip() or self._get_cookie_value_by_name(
                "oai-did",
                ("auth.openai.com", "openai.com", "chatgpt.com"),
            )
            if device_id:
                headers["oai-device-id"] = device_id

        return headers

    def _client_hint_headers(self) -> dict:
        fp = self._fingerprint
        if not fp.get("sec_ch_ua"):
            return {}
        return {
            "sec-ch-ua": fp["sec_ch_ua"],
            "sec-ch-ua-mobile": fp.get("sec_ch_ua_mobile") or "?0",
            "sec-ch-ua-platform": fp["sec_ch_ua_platform"],
        }

    def _navigation_headers(self, referer: str, target_url: str = "") -> dict:
        headers = {
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                if self._is_safari_profile()
                else (
                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
                    "image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
                )
            ),
            "Referer": referer,
            "Upgrade-Insecure-Requests": "1",
        }
        headers.update(self._browser_request_headers(
            destination="document",
            mode="navigate",
            site=self._navigation_site(referer, target_url or referer),
            user_activated=True,
        ))
        headers.update(self._client_hint_headers())
        return headers

    def _oauth_navigation_headers(self, referer: str, target_url: str = "") -> dict:
        navigation = self._navigation_headers(referer, target_url)
        return {
            key: navigation[key]
            for key in ("Accept", "Referer", "Upgrade-Insecure-Requests", "User-Agent")
        }

    def _chatgpt_bootstrap_headers(
        self,
        referer: str,
        *,
        accept: str = "*/*",
        content_type: str | None = None,
        origin: str = "",
    ) -> dict:
        headers = {
            "Accept": accept,
            "Referer": referer,
        }
        if content_type is not None:
            headers["Content-Type"] = content_type
        if origin:
            headers["Origin"] = origin
        headers.update(self._browser_request_headers(
            destination="empty",
            mode="cors",
            site="same-origin",
        ))
        headers.update(self._client_hint_headers())
        return headers

    def _auth_resend_headers(self, referer: str = "https://auth.openai.com/email-verification") -> dict:
        headers = {
            "Accept": "*/*",
            "Origin": "https://auth.openai.com",
            "Referer": referer,
        }
        if hasattr(self.session, "default_headers"):
            # curl_cffi otherwise adds application/x-www-form-urlencoded to an empty POST;
            # email-otp/resend accepts the capture's bodyless request without Content-Type.
            headers["Content-Type"] = None
        headers.update(self._browser_request_headers(
            destination="empty",
            mode="cors",
            site="same-origin",
        ))
        headers.update(self._client_hint_headers())
        return headers

    def _auth_json_headers(self, referer: str) -> dict:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": "https://auth.openai.com",
            "Referer": referer,
            "x-access-flow-invocation-id": str(uuid.uuid4()),
        }
        headers.update(self._browser_request_headers(
            destination="empty",
            mode="cors",
            site="same-origin",
        ))
        headers.update(self._client_hint_headers())
        return headers

    def _is_safari_profile(self) -> bool:
        return bool(
            "Safari/" in self._ua
            and not re.search(
                r"(?:Chrome|Chromium|CriOS|Edg|OPR|Electron)/",
                self._ua,
                re.IGNORECASE,
            )
        )

    def _supports_fetch_metadata(self) -> bool:
        if not self._is_safari_profile():
            return True
        match = re.search(r"Version/(\d+)(?:\.(\d+))?", self._ua)
        if not match:
            return False
        version = int(match.group(1)), int(match.group(2) or 0)
        return version >= (16, 4)

    def _browser_request_headers(
        self,
        *,
        destination: str,
        mode: str,
        site: str,
        user_activated: bool = False,
    ) -> dict:
        headers = {
            "User-Agent": self._ua,
            "Accept-Language": self._fingerprint["lang_full"],
        }
        if self._supports_fetch_metadata():
            headers.update({
                "Sec-Fetch-Dest": destination,
                "Sec-Fetch-Mode": mode,
                "Sec-Fetch-Site": site,
            })
            if user_activated:
                headers["Sec-Fetch-User"] = "?1"
        return headers

    @staticmethod
    def _navigation_site(referer: str, target_url: str) -> str:
        try:
            source = urlparse(referer)
            target = urlparse(target_url)
            if (
                source.scheme.lower() == target.scheme.lower()
                and source.netloc.lower() == target.netloc.lower()
            ):
                return "same-origin"
        except Exception:
            pass
        return "cross-site"

    def _chatgpt_backend_headers(
        self,
        referer: str = "https://chatgpt.com/",
        *,
        target_path: str = "",
        target_route: str = "",
        access_token: str = "",
        include_account_id: bool = False,
        origin: str = "",
        content_type: str | None = None,
        integrity_observation: str = "",
    ) -> dict:
        headers = {
            "Accept": "*/*",
            "Referer": referer,
        }
        headers.update(self._browser_request_headers(
            destination="empty",
            mode="cors",
            site="same-origin",
        ))
        if origin:
            headers["Origin"] = origin
        if content_type is not None:
            headers["Content-Type"] = content_type
        web_access_token = (access_token or self._chatgpt_web_access_token or "").strip()
        if web_access_token:
            headers["Authorization"] = f"Bearer {web_access_token}"
        device_id = self._ensure_device_id()
        if device_id:
            headers["OAI-Device-Id"] = device_id
        language = (self._fingerprint.get("lang", "") or "").strip()
        if language:
            headers["OAI-Language"] = language
        if self._chatgpt_session_id:
            headers["OAI-Session-Id"] = self._chatgpt_session_id
        if self._chatgpt_client_version:
            headers["OAI-Client-Version"] = self._chatgpt_client_version
        if self._chatgpt_client_build_number:
            headers["OAI-Client-Build-Number"] = self._chatgpt_client_build_number
        if target_path:
            headers["X-OpenAI-Target-Path"] = target_path
            headers["X-OpenAI-Target-Route"] = target_route or target_path
        headers["X-OAI-IS-Client-Observation"] = (
            integrity_observation or self._chatgpt_integrity_observation()
        )
        if include_account_id and web_access_token:
            account_id = self._chatgpt_account_id_from_token(web_access_token)
            if account_id:
                headers["ChatGPT-Account-ID"] = account_id
        headers.update(self._client_hint_headers())
        return headers

    def _remember_chatgpt_client_metadata(self, html_text: str) -> None:
        text = str(html_text or "")
        build_match = re.search(r'data-build=["\']([^"\']+)["\']', text)
        seq_match = re.search(r'data-seq=["\']([^"\']+)["\']', text)
        if build_match:
            self._chatgpt_client_version = (build_match.group(1) or "").strip()
        if seq_match:
            self._chatgpt_client_build_number = (seq_match.group(1) or "").strip()

    @staticmethod
    def _jwt_payload(token: str) -> dict:
        raw = str(token or "").strip()
        if raw.count(".") < 2:
            return {}
        try:
            segment = raw.split(".", 2)[1]
            segment += "=" * (-len(segment) % 4)
            value = json.loads(base64.urlsafe_b64decode(segment.encode("ascii")).decode("utf-8"))
            return value if isinstance(value, dict) else {}
        except Exception:
            return {}

    @classmethod
    def _chatgpt_account_id_from_token(cls, token: str) -> str:
        payload = cls._jwt_payload(token)
        auth = payload.get("https://api.openai.com/auth", {}) if isinstance(payload, dict) else {}
        if not isinstance(auth, dict):
            return ""
        return str(auth.get("chatgpt_account_id") or auth.get("user_id") or "").strip()

    def _chatgpt_integrity_observation(self) -> str:
        try:
            state = (self._get_cookie_value_by_name("__Secure-oai-is") or "").strip()
        except Exception:
            return "v1.r.r"
        if not state:
            return "v1.r.m"
        match = re.fullmatch(
            r"ois1\.[A-Za-z0-9_-]+\.([A-Za-z0-9_-]{16})\.[A-Za-z0-9_-]+",
            state,
        )
        return f"v1.r.p.{match.group(1)}" if match else "v1.r.i"

    def _browser_datetime(self) -> datetime:
        if ZoneInfo is not None:
            try:
                return datetime.now(ZoneInfo(self._timezone))
            except Exception:
                pass
        return datetime.now().astimezone()

    def _browser_timezone_offset_min(self) -> int:
        offset = self._browser_datetime().utcoffset()
        if offset is None:
            return 0
        return int(-(offset.total_seconds() // 60))

    def _post_login_capture_bootstrap(self, web_access_token: str = "") -> bool:
        """按 docs/新链路.json 补注册完成后的非阻断账号初始化请求。"""
        if self._post_login_bootstrap_done:
            return True
        web_access_token = (web_access_token or self._chatgpt_web_access_token or "").strip()
        if not web_access_token:
            logger.warning("未获取 fresh ChatGPT Web access token，跳过全部 backend bootstrap 请求")
            return False

        logger.info("执行注册后 ChatGPT bootstrap 请求...")
        bootstrap_observation = self._chatgpt_integrity_observation()
        try:
            try:
                resp = self.session.get(
                    "https://chatgpt.com/backend-api/user_granular_consent",
                    headers=self._chatgpt_backend_headers(
                        target_path="/backend-api/user_granular_consent",
                        access_token=web_access_token,
                        include_account_id=True,
                        integrity_observation=bootstrap_observation,
                    ),
                    timeout=30,
                )
                self._trace_http("chatgpt_user_granular_consent", resp)
                if resp.status_code != 200:
                    logger.warning(
                        f"user_granular_consent 非 200: {resp.status_code} - {(resp.text or '')[:180]}"
                    )
            except Exception as e:
                logger.warning(f"user_granular_consent 请求异常: {e}")

            resp = self.session.get(
                "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27",
                params={"timezone_offset_min": self._browser_timezone_offset_min()},
                headers=self._chatgpt_backend_headers(
                    target_path="/backend-api/accounts/check/v4-2023-04-27",
                    target_route="/backend-api/accounts/check/{version}",
                    access_token=web_access_token,
                    include_account_id=True,
                    integrity_observation=bootstrap_observation,
                ),
                timeout=30,
            )
            self._trace_http("chatgpt_accounts_check", resp)
            if resp.status_code != 200:
                logger.warning(f"accounts/check 非 200: {resp.status_code} - {(resp.text or '')[:180]}")

            try:
                resp = self.session.get(
                    "https://chatgpt.com/backend-api/accounts/optimized/check",
                    headers=self._chatgpt_backend_headers(
                        target_path="/backend-api/accounts/optimized/check",
                        access_token=web_access_token,
                        include_account_id=True,
                        integrity_observation=bootstrap_observation,
                    ),
                    timeout=30,
                )
                self._trace_http("chatgpt_accounts_optimized_check", resp)
                if resp.status_code != 200:
                    logger.warning(f"accounts/optimized/check 非 200: {resp.status_code} - {(resp.text or '')[:180]}")
            except Exception as e:
                logger.warning(f"accounts/optimized/check 请求异常: {e}")

            try:
                resp = self.session.get(
                    "https://chatgpt.com/backend-api/me",
                    headers=self._chatgpt_backend_headers(
                        target_path="/backend-api/me",
                        access_token=web_access_token,
                        include_account_id=True,
                        integrity_observation=bootstrap_observation,
                    ),
                    timeout=30,
                )
                self._trace_http("chatgpt_backend_me", resp)
                if resp.status_code != 200:
                    logger.warning(f"backend-api/me 非 200: {resp.status_code} - {(resp.text or '')[:180]}")
            except Exception as e:
                logger.warning(f"backend-api/me 请求异常: {e}")

            try:
                resp = self.session.post(
                    "https://chatgpt.com/backend-api/accounts/backfill_workspace_owner_domains",
                    headers=self._chatgpt_backend_headers(
                        target_path="/backend-api/accounts/backfill_workspace_owner_domains",
                        access_token=web_access_token,
                        include_account_id=True,
                        origin="https://chatgpt.com",
                        integrity_observation=bootstrap_observation,
                    ),
                    timeout=30,
                )
                self._trace_http("chatgpt_backfill_workspace_owner_domains", resp)
                if resp.status_code != 200:
                    logger.warning(
                        f"backfill_workspace_owner_domains 非 200: {resp.status_code} - {(resp.text or '')[:180]}"
                    )
            except Exception as e:
                logger.warning(f"backfill_workspace_owner_domains 请求异常: {e}")

        except Exception as e:
            logger.warning(f"accounts/check 请求异常: {e}")
        self._post_login_bootstrap_done = True
        return self._post_login_bootstrap_done

    def _ensure_device_id(self) -> str:
        device_id = (self.result.device_id or "").strip()
        if not device_id:
            device_id = self._get_cookie_value_by_name("oai-did", ("chatgpt.com",))
        if not device_id:
            device_id = str(uuid.uuid4())
        self.result.device_id = device_id
        try:
            if not self._get_cookie_value_by_name("oai-did", ("chatgpt.com",)):
                self.session.cookies.set("oai-did", device_id, domain="chatgpt.com", path="/")
        except Exception:
            pass
        return device_id

    @staticmethod
    def _split_screen(screen: str) -> tuple[int, int]:
        try:
            width, height = str(screen or "").lower().split("x", 1)
            return max(1, int(width)), max(1, int(height))
        except Exception:
            return 1512, 982

    @staticmethod
    def _split_languages(lang_full: str, lang: str) -> list[str]:
        values: list[str] = []
        for item in str(lang_full or lang or "en-US").split(","):
            code = item.split(";", 1)[0].strip()
            if code and code not in values:
                values.append(code)
        return values or [lang or "en-US"]

    def _sentinel_runtime_fingerprint(self, flow: str = "oauth_create_account") -> dict[str, Any]:
        width, height = self._split_screen(self._fingerprint.get("screen", "1512x982"))
        lang = self._fingerprint.get("lang", "en-US")
        lang_full = self._fingerprint.get("lang_full", "en-US,en;q=0.9")
        performance_now = random.uniform(3000, 25000)
        navigator_platform = self._fingerprint.get("navigator_platform", "MacIntel")
        fingerprint_seed = self._fingerprint.get("fingerprint_seed")
        return {
            "flow": flow,
            "browser_profile": (
                self._fingerprint.get("browser_profile")
                or ("safari" if self._is_safari_profile() else "chrome")
            ),
            "device_id": self._ensure_device_id(),
            "fingerprint_seed": (
                fingerprint_seed if fingerprint_seed is not None else self._ensure_device_id()
            ),
            "host_page_url": (
                "https://auth.openai.com/create-account/password"
                if flow == "username_password_create"
                else "https://auth.openai.com/about-you"
            ),
            "user_agent": self._ua,
            "accept_language": lang_full,
            "language": lang,
            "languages": self._split_languages(lang_full, lang),
            "screen_width": width,
            "screen_height": height,
            "hardware_concurrency": int(
                self._fingerprint.get("hardware_concurrency") or 16
            ),
            "device_memory": int(self._fingerprint.get("device_memory") or 8),
            "js_heap_size_limit": 4294705152,
            "performance_now": performance_now,
            "time_origin": time.time() * 1000 - performance_now,
            "navigator_platform": navigator_platform,
            "navigator_vendor": self._fingerprint.get(
                "navigator_vendor", "Apple Computer, Inc."
            ),
            "max_touch_points": int(self._fingerprint.get("max_touch_points") or 0),
            "sec_ch_ua": self._fingerprint.get("sec_ch_ua", ""),
            "sec_ch_ua_mobile": self._fingerprint.get("sec_ch_ua_mobile", ""),
            "sec_ch_ua_platform": self._fingerprint.get("sec_ch_ua_platform", ""),
            "sec_ch_ua_full_version": self._fingerprint.get("sec_ch_ua_full_version", ""),
            "sec_ch_ua_full_version_list": self._fingerprint.get(
                "sec_ch_ua_full_version_list", ""
            ),
            "sec_ch_ua_platform_version": self._fingerprint.get(
                "sec_ch_ua_platform_version", ""
            ),
            "sec_ch_ua_arch": self._fingerprint.get("sec_ch_ua_arch", ""),
            "sec_ch_ua_bitness": self._fingerprint.get("sec_ch_ua_bitness", ""),
            "gpu_vendor": self._fingerprint.get("gpu_vendor", "Apple Inc."),
            "gpu_renderer": self._fingerprint.get("gpu_renderer", "Apple GPU"),
            "device_pixel_ratio": self._fingerprint.get("device_pixel_ratio", 2),
            "color_depth": int(self._fingerprint.get("color_depth") or 24),
            "canvas_noise": self._fingerprint.get("canvas_noise", 0),
            "audio_noise": self._fingerprint.get("audio_noise", 0),
            "webrtc_policy": self._fingerprint.get("webrtc_policy", "block"),
            "timezone": self._timezone,
            "timezone_offset": self._fingerprint.get("timezone_offset"),
            "is_mac": navigator_platform == "MacIntel",
            "local_storage_keys": list(getattr(self, "_auth_local_storage_keys", [])),
        }

    def _build_sentinel_solver_payload(self, flow: str, host_page_url: str = "") -> dict[str, Any]:
        from . import sentinel_quickjs

        runtime_fingerprint = self._sentinel_runtime_fingerprint(flow)
        if flow in ("email_otp_validate", "oauth_create_account") and self._registration_sentinel_time_origin_ms > 0:
            runtime_fingerprint["time_origin"] = self._registration_sentinel_time_origin_ms
            elapsed_ms = max(
                0.0,
                (time.monotonic() - self._registration_sentinel_monotonic_started) * 1000,
            )
            runtime_fingerprint["performance_now"] = (
                self._registration_sentinel_performance_base_ms + elapsed_ms
            )
        payload = sentinel_quickjs._build_runtime_payload(
            device_id=self._ensure_device_id(),
            flow=flow,
            user_agent=self._ua,
            screen=self._fingerprint.get("screen", ""),
            lang=self._fingerprint.get("lang", ""),
            lang_full=self._fingerprint.get("lang_full", ""),
            runtime_fingerprint=runtime_fingerprint,
        )
        if host_page_url:
            payload["host_page_url"] = host_page_url
        return payload

    def _clear_sentinel_tokens(self) -> None:
        self._last_sentinel_token = ""
        self._last_sentinel_so_token = ""
        self._last_sentinel_flow = ""

    @staticmethod
    def _validate_registration_sentinel_requirements(
        sentinel_quickjs: Any,
        requirements: dict,
    ) -> tuple[str, str]:
        request_p = str((requirements or {}).get("request_p") or "").strip()
        sid = str((requirements or {}).get("sid") or "").strip()
        if not request_p or not sid:
            raise RuntimeError("Sentinel requirements 响应不完整")
        error_prefix = "gAAAAAC" + str(
            getattr(sentinel_quickjs, "SENTINEL_SDK_ERROR_PREFIX", "")
        )
        if error_prefix != "gAAAAAC" and request_p.startswith(error_prefix):
            raise RuntimeError("Sentinel requirements proof 包含 SDK 错误")
        return request_p, sid

    def _close_registration_sentinel_exchange(self) -> None:
        state = self._registration_sentinel_solver_state
        self._registration_sentinel_solver_state = None
        self._registration_sentinel_sdk = None
        self._registration_sentinel_payload = {}
        self._registration_sentinel_requirements = {}
        self._registration_sentinel_challenge = {}
        self._registration_sentinel_pending_flow = ""
        self._registration_sentinel_exchange_solved = False
        if state is not None:
            try:
                from . import sentinel_quickjs
                sentinel_quickjs._close_solver_state(state)
            except Exception as exc:
                logger.warning("关闭注册 Sentinel 求解进程失败: %s", exc)
    def _prefetch_registration_sentinel(self, flow: str) -> None:
        """预取当前 flow 的 requirements/challenge，最终 proof 延后生成。"""
        self._clear_sentinel_tokens()
        from . import sentinel_quickjs

        timeout_ms = 45000
        payload = self._build_sentinel_solver_payload(flow)
        accept_language = str(payload.get("accept_language") or "en-US,en;q=0.9")
        if (
            self._registration_sentinel_solver_state is not None
            and self._registration_sentinel_sdk is not None
            and self._registration_sentinel_exchange_solved
        ):
            try:
                requirements = sentinel_quickjs._run_quickjs_action(
                    action="transition_flow",
                    sdk_file=self._registration_sentinel_sdk.file,
                    solver_script=sentinel_quickjs._solver_script_path(),
                    payload=payload,
                    timeout_ms=timeout_ms,
                    solver_state=self._registration_sentinel_solver_state,
                )
                request_p, _ = self._validate_registration_sentinel_requirements(
                    sentinel_quickjs,
                    requirements,
                )
                challenge = sentinel_quickjs._fetch_sentinel_challenge(
                    self.session,
                    device_id=self.result.device_id,
                    flow=flow,
                    request_p=request_p,
                    frame_url=self._registration_sentinel_sdk.frame_url,
                    timeout_ms=timeout_ms,
                    accept_language=accept_language,
                    user_agent=self._ua,
                    runtime_fingerprint=payload,
                )
                if not str((challenge or {}).get("token") or "").strip():
                    raise RuntimeError("Sentinel challenge token 为空")
                self._registration_sentinel_payload = payload
                self._registration_sentinel_requirements = requirements
                self._registration_sentinel_challenge = challenge
                self._registration_sentinel_pending_flow = flow
                self._registration_sentinel_exchange_solved = False
                logger.info("Sentinel 同会话 challenge 预取完成: flow=%s", flow)
                return
            except Exception:
                self._close_registration_sentinel_exchange()
                raise

        self._close_registration_sentinel_exchange()
        solver_state: dict[str, Any] = {}
        sdk = sentinel_quickjs._bundled_sentinel_sdk()
        try:
            sentinel_quickjs._apply_sdk_metadata(payload, sdk)
            requirements = sentinel_quickjs._run_quickjs_action(
                action="requirements",
                sdk_file=sdk.file,
                solver_script=sentinel_quickjs._solver_script_path(),
                payload=payload,
                timeout_ms=timeout_ms,
                solver_state=solver_state,
            )
            request_p, _ = self._validate_registration_sentinel_requirements(
                sentinel_quickjs,
                requirements,
            )
            challenge = sentinel_quickjs._fetch_sentinel_challenge(
                self.session,
                device_id=self.result.device_id,
                flow=flow,
                request_p=request_p,
                frame_url=sdk.frame_url,
                timeout_ms=timeout_ms,
                accept_language=accept_language,
                user_agent=self._ua,
                runtime_fingerprint=payload,
            )
            if not str((challenge or {}).get("token") or "").strip():
                raise RuntimeError("Sentinel challenge token 为空")
            self._registration_sentinel_solver_state = solver_state
            self._registration_sentinel_sdk = sdk
            self._registration_sentinel_payload = payload
            self._registration_sentinel_requirements = requirements
            self._registration_sentinel_challenge = challenge
            self._registration_sentinel_pending_flow = flow
            self._registration_sentinel_exchange_solved = False
            logger.info("Sentinel challenge 预取完成: flow=%s", flow)
        except Exception:
            sentinel_quickjs._close_solver_state(solver_state)
            self._clear_sentinel_tokens()
            raise

    def _finalize_registration_sentinel(
        self,
        flow: str,
        *,
        keep_exchange: bool = False,
        behavior_input: Optional[dict[str, str]] = None,
    ) -> tuple[str, str]:
        """在业务请求提交前，用已预取 challenge 生成最终双 token。"""
        if (
            self._registration_sentinel_pending_flow != flow
            or self._registration_sentinel_solver_state is None
            or self._registration_sentinel_sdk is None
        ):
            raise RuntimeError(f"Sentinel flow 尚未预取: {flow}")
        from . import sentinel_quickjs

        state = self._registration_sentinel_solver_state
        sdk = self._registration_sentinel_sdk
        payload = self._registration_sentinel_payload
        requirements = self._registration_sentinel_requirements
        challenge = self._registration_sentinel_challenge
        completed = False
        try:
            request_p, sid = self._validate_registration_sentinel_requirements(
                sentinel_quickjs,
                requirements,
            )
            solved = sentinel_quickjs._run_quickjs_action(
                action="solve",
                sdk_file=sdk.file,
                solver_script=sentinel_quickjs._solver_script_path(),
                payload={
                    **payload,
                    **(behavior_input or {}),
                    "request_p": request_p,
                    "sid": sid,
                    "runtime_state": requirements.get("runtime_state") or {},
                    "challenge": challenge,
                },
                timeout_ms=45000,
                solver_state=state,
            )
            tokens = sentinel_quickjs._validate_solved_tokens(
                solved=solved,
                challenge=challenge,
                device_id=self.result.device_id,
                flow=flow,
            )
            self._last_sentinel_token = str(tokens.get("sentinel_token") or "").strip()
            self._last_sentinel_so_token = str(tokens.get("so_token") or "").strip()
            if not self._last_sentinel_token or not self._last_sentinel_so_token:
                raise RuntimeError("Sentinel/SO token 为空")
            self._last_sentinel_flow = flow
            self._registration_sentinel_exchange_solved = True
            completed = True
            logger.info("Sentinel 双 token 提交前求解完成: flow=%s", flow)
            return self._last_sentinel_token, self._last_sentinel_so_token
        except Exception:
            self._clear_sentinel_tokens()
            raise
        finally:
            if not (completed and keep_exchange):
                self._close_registration_sentinel_exchange()

    def _prepare_registration_sentinel(
        self,
        flow: str,
        *,
        behavior_input: Optional[dict[str, str]] = None,
    ) -> tuple[str, str]:
        self._prefetch_registration_sentinel(flow)
        return self._finalize_registration_sentinel(
            flow,
            behavior_input=behavior_input,
        )

    def _close_registration_sentinel(self) -> None:
        self._close_registration_sentinel_exchange()
        self._clear_sentinel_tokens()
        self._registration_sentinel_time_origin_ms = 0.0
        self._registration_sentinel_performance_base_ms = 0.0
        self._registration_sentinel_monotonic_started = 0.0

    # ── Step 1: 检查代理连通性 ──
    def check_proxy(self) -> bool:
        logger.info("检查网络连通性...")
        try:
            resp = self.session.get("https://cloudflare.com/cdn-cgi/trace", timeout=15)
            if resp.status_code == 200:
                loc = re.search(r"loc=(\w+)", resp.text)
                ip = re.search(r"ip=([^\n]+)", resp.text)
                logger.info(f"网络正常 - IP: {ip.group(1) if ip else 'N/A'}, "
                            f"地区: {loc.group(1) if loc else 'N/A'}")
            else:
                logger.warning(f"网络探测异常: cloudflare trace {resp.status_code}")

            # 关键链路探测: chatgpt csrf
            csrf_headers = self._common_headers("https://chatgpt.com/auth/login")
            csrf_resp = self.session.get(
                "https://chatgpt.com/api/auth/csrf",
                headers=csrf_headers,
                timeout=20,
            )
            if csrf_resp.status_code == 200:
                logger.info("chatgpt csrf 连通正常")
                return True

            logger.warning(f"chatgpt csrf 连通异常: {csrf_resp.status_code}")
            return False
        except Exception as e:
            logger.error(f"网络检查失败: {e}")
        return False

    # ── Step 2: 获取 CSRF Token ──
    def get_csrf_token(self) -> str:
        logger.info("[1/10] 获取 CSRF Token...")
        login_headers = self._navigation_headers(
            "https://chatgpt.com/",
            "https://chatgpt.com/auth/login",
        )
        providers_headers = self._chatgpt_bootstrap_headers(
            "https://chatgpt.com/auth/login",
            accept="*/*",
            content_type="application/json",
        )
        csrf_headers = self._chatgpt_bootstrap_headers(
            "https://chatgpt.com/auth/login",
            accept="*/*",
            content_type="application/json",
        )
        try:
            login_resp = self._request_with_network_retry(
                "GET",
                "https://chatgpt.com/auth/login",
                headers=login_headers,
                timeout=30,
                extra_retry_status_codes={403},
                rebuild_on_tls=True,
                label="chatgpt_auth_login",
            )
            self._trace_http("chatgpt_auth_login", login_resp)
            self._remember_chatgpt_client_metadata(login_resp.text or "")
        except Exception as e:
            logger.warning(f"访问 /auth/login 失败，继续 CSRF: {e}")

        providers_resp = self._request_with_network_retry(
            "GET",
            "https://chatgpt.com/api/auth/providers",
            headers=providers_headers,
            timeout=30,
            extra_retry_status_codes={403},
            rebuild_on_tls=True,
            label="chatgpt_auth_providers",
        )
        self._trace_http("chatgpt_auth_providers", providers_resp)
        providers_resp.raise_for_status()

        try:
            # Cloudflare 可能在短时间内多次请求后返回 403，次数由 network_retry 决定。
            resp = self._request_with_network_retry(
                "GET",
                "https://chatgpt.com/api/auth/csrf",
                headers=csrf_headers,
                timeout=30,
                extra_retry_status_codes={403},
                rebuild_on_tls=True,
                label="chatgpt_csrf",
            )
        except Exception as e:
            if self._is_tls_error(e):
                raise RuntimeError(
                    "chatgpt.com TLS 握手失败，当前网络无法建立到 /api/auth/csrf 的 HTTPS 连接。"
                    "请切换可直连 chatgpt.com 的网络或在界面中配置可用代理后重试。"
                ) from e
            raise
        resp.raise_for_status()

        self._trace_http("chatgpt_csrf", resp)
        csrf = resp.json().get("csrfToken", "")
        if not csrf:
            raise RuntimeError("CSRF Token 获取失败")
        self.result.csrf_token = csrf
        logger.info(f"CSRF Token: {csrf[:20]}...")
        return csrf

    # ── Step 3: 获取 auth URL ──
    def get_auth_url(
        self,
        csrf_token: str,
        email: str = "",
        device_id: str = "",
        *,
        include_passkey_capabilities: bool = True,
    ) -> str:
        logger.info("[2/10] 获取 OpenAI 授权地址...")
        email = (email or self.result.email or "").strip()
        device_id = (device_id or self._ensure_device_id()).strip()
        auth_session_logging_id = self._get_cookie_value_by_name("oai-asli", ("chatgpt.com",))
        if not auth_session_logging_id:
            auth_session_logging_id = str(uuid.uuid4())
            try:
                self.session.cookies.set(
                    "oai-asli",
                    auth_session_logging_id,
                    domain="chatgpt.com",
                    path="/",
                )
            except Exception:
                pass
        headers = self._chatgpt_bootstrap_headers(
            "https://chatgpt.com/auth/login",
            accept="*/*",
            content_type="application/x-www-form-urlencoded",
            origin="https://chatgpt.com",
        )
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        params = [
            ("prompt", "login"),
            ("ext-oai-did", device_id),
            ("auth_session_logging_id", auth_session_logging_id),
            ("screen_hint", "login_or_signup"),
            ("login_hint", email),
        ]
        if include_passkey_capabilities:
            params.insert(1, ("ext-passkey-client-capabilities", "01111"))
        resp = self._request_with_network_retry(
            "POST",
            "https://chatgpt.com/api/auth/signin/openai",
            headers=headers,
            params=params,
            data=[
                ("callbackUrl", "/"),
                ("csrfToken", csrf_token),
                ("json", "true"),
            ],
            timeout=30,
            extra_retry_status_codes={403},
            rebuild_on_tls=False,
            label="chatgpt_signin_openai",
        )
        resp.raise_for_status()
        self._trace_http("chatgpt_signin_openai", resp)
        auth_url = resp.json().get("url", "")
        if not auth_url:
            raise RuntimeError("Auth URL 获取失败")
        # 记住 OAuth 参数，并根据开关可选注入 PKCE
        self._remember_oauth_params(auth_url)
        auth_url = self._inject_pkce_into_auth_url(auth_url)
        self._remember_oauth_params(auth_url)
        logger.info(f"Auth URL: {auth_url[:80]}...")
        return auth_url

    # ── Step 4: OAuth 初始化 & 获取 device_id ──
    def auth_oauth_init(self, auth_url: str, *, preload_sentinel: bool = False) -> str:
        logger.info("[3/10] OAuth 初始化...")
        headers = self._oauth_navigation_headers("https://chatgpt.com/", auth_url)
        navigation_time_origin_ms = time.time() * 1000 if preload_sentinel else 0.0
        navigation_monotonic_started = time.monotonic() if preload_sentinel else 0.0
        request_options = (
            {"default_headers": False}
            if hasattr(self.session, "default_headers")
            else {}
        )
        resp = self._request_with_network_retry(
            "GET",
            auth_url,
            headers=headers,
            timeout=30,
            allow_redirects=True,
            retry_status_codes={403},
            rebuild_on_tls=False,
            tls_only=True,
            label="auth_oauth_init",
            **request_options,
        )
        self._trace_http("auth_oauth_init", resp)
        self._auth_oauth_status_code = int(getattr(resp, "status_code", 0) or 0)
        self._auth_oauth_final_url = str(getattr(resp, "url", "") or "").strip()
        self._auth_local_storage_keys = _extract_auth_statsig_storage_keys(resp.text)

        device_id = (self.result.device_id or "").strip()
        if not device_id:
            device_id = self._extract_query_first(auth_url, ["device_id", "ext-oai-did"])
        if not device_id:
            device_id = self._get_cookie_value_by_name(
                "oai-did",
                ("auth.openai.com", "openai.com", "chatgpt.com"),
            )

        # fallback: 从 HTML 提取
        if not device_id:
            m = re.search(r'oai-did["\s:=]+([a-f0-9-]{36})', resp.text)
            if m:
                device_id = m.group(1)

        if not device_id:
            device_id = str(uuid.uuid4())
            logger.warning(f"未从响应中获取 device_id，使用生成值: {device_id}")

        self.result.device_id = device_id
        if preload_sentinel:
            self._registration_sentinel_performance_base_ms = 0.0
            self._registration_sentinel_monotonic_started = navigation_monotonic_started
            self._registration_sentinel_time_origin_ms = navigation_time_origin_ms
        logger.info(f"Device ID: {device_id}")
        return device_id

    # ── Step 5: 获取 Sentinel Token ──
    def get_sentinel_token(self, device_id: str) -> str:
        logger.info("[4/10] 获取 Sentinel Token (PoW)...")
        from .sentinel import get_sentinel_token
        token = get_sentinel_token(
            self.session,
            device_id=device_id,
            flow="authorize_continue",
            user_agent=self._ua,
            sec_ch_ua=self._fingerprint["sec_ch_ua"],
            screen=self._fingerprint["screen"],
            lang=self._fingerprint["lang"],
            lang_full=self._fingerprint["lang_full"],
            runtime_fingerprint=self._sentinel_runtime_fingerprint("authorize_continue"),
        )
        self._last_sentinel_token = token or ""
        self._last_sentinel_so_token = ""
        self._last_sentinel_flow = "authorize_continue" if token else ""
        logger.info("Sentinel Token 获取成功")
        return token

    # ── Step 6: 提交注册邮箱 ──
    def authorize_continue(
        self,
        email: str,
        sentinel_token: str,
        screen_hint: str = "signup",
        referer: str = "https://auth.openai.com/create-account",
        trace_step: str = "",
    ) -> dict:
        """调用 /api/accounts/authorize/continue，返回 JSON。"""
        headers = self._common_headers(referer)
        headers["Content-Type"] = "application/json"
        if sentinel_token:
            headers["openai-sentinel-token"] = sentinel_token
        payload = {
            "username": {"value": email, "kind": "email"},
            "screen_hint": screen_hint,
        }
        resp = self.session.post(
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers=headers,
            json=payload,
            timeout=30,
        )
        self._trace_http(trace_step or f"authorize_continue_{screen_hint}", resp)
        if resp.status_code != 200:
            body = (resp.text or "")[:360]
            # 额外打日志：headers/req_id 帮排查是不是 IP 风控
            req_id = (resp.headers.get("x-request-id", "") or "")[:80]
            ct = (resp.headers.get("Content-Type", "") or "")[:60]
            logger.error(
                "authorize/continue 非 200: status=%s screen_hint=%s req_id=%s content_type=%s body=%r",
                resp.status_code, screen_hint, req_id, ct, body,
            )
            raise RuntimeError(
                f"authorize/continue 失败(screen_hint={screen_hint}): "
                f"HTTP {resp.status_code} req_id={req_id} body={body}"
            )
        try:
            return resp.json() if resp is not None else {}
        except Exception:
            return {}

    def signup(self, email: str, sentinel_token: str) -> bool:
        """提交注册邮箱。返回 True 表示走新注册流程，False 表示已有账号走 OTP 登录流程"""
        logger.info("[5/10] 提交注册邮箱...")
        data = self.authorize_continue(
            email=email,
            sentinel_token=sentinel_token,
            screen_hint="signup",
            referer="https://auth.openai.com/create-account",
            trace_step="authorize_continue_signup",
        )

        # 检测 page_type/continue_url，区分新账号与已有账号
        try:
            page = (data.get("page") or {}) if isinstance(data, dict) else {}
            page_type = (page.get("type") or "").strip()
            payload = (page.get("payload") or {}) if isinstance(page, dict) else {}
            continue_url = (data.get("continue_url") or "").strip()

            # 新账号标准分支
            if page_type == "create_account_password" or "/create-account/password" in continue_url:
                self._is_existing_account = False
                self._existing_email_verification_mode = ""
                self._existing_page_type = page_type
                logger.info("注册邮箱已提交")
                return True

            # 已有账号 OTP 分支
            if page_type == "email_otp_verification":
                self._existing_email_verification_mode = (payload.get("email_verification_mode", "") or "").strip()
                self._existing_page_type = page_type
                logger.info("检测到已有账号，切换到 OTP 登录流程")
                self._is_existing_account = True
                return False

            # 未知 page_type：通常是社交登录/风控分支，按已有账号处理，避免误进 register_password 导致 invalid_state
            self._existing_email_verification_mode = (payload.get("email_verification_mode", "") or "").strip()
            self._existing_page_type = page_type
            self._is_existing_account = True
            logger.warning(
                "authorize/continue 返回非标准注册页面: page_type=%s continue_url=%s，按已有账号流程处理",
                page_type or "(empty)",
                continue_url[:180] or "(empty)",
            )
            return False
        except Exception:
            # JSON 解析失败时保守按新注册处理
            self._is_existing_account = False
            self._existing_email_verification_mode = ""
            self._existing_page_type = ""
            logger.info("注册邮箱已提交")
            return True

    # ── Step 6.5: 注册密码 ──
    def register_password(self, email: str) -> dict:
        logger.info("[5.5/10] 注册密码...")
        # 按需求：密码默认使用注册邮箱，去掉 '@'
        # 例如: abc123@example.com -> abc123example.com
        password = self._default_password_from_email(email)
        self.result.password = password

        # 正常注册已经由 authorize 导航到密码页；旧登录回退路径仍需补这次导航。
        if (
            urlparse(self._auth_oauth_final_url).path.rstrip("/")
            != "/create-account/password"
        ):
            try:
                pw_page = self.session.get(
                    "https://auth.openai.com/create-account/password",
                    headers=self._navigation_headers(
                        "https://auth.openai.com/create-account",
                        "https://auth.openai.com/create-account/password",
                    ),
                    timeout=15,
                )
                logger.info(f"create-account/password 页面: {pw_page.status_code}")
            except Exception as e:
                logger.warning(f"访问 create-account/password 页面失败: {e}")

        # 注册前需要刷新 sentinel token，且 flow 必须为 username_password_create
        self._clear_sentinel_tokens()
        if self.result.device_id:
            try:
                from .sentinel import get_sentinel_token as _get_st
                token = _get_st(
                    self.session,
                    device_id=self.result.device_id,
                    flow="username_password_create",
                    user_agent=self._ua,
                    sec_ch_ua=self._fingerprint["sec_ch_ua"],
                    screen=self._fingerprint["screen"],
                    lang=self._fingerprint["lang"],
                    lang_full=self._fingerprint["lang_full"],
                    runtime_fingerprint=self._sentinel_runtime_fingerprint(
                        "username_password_create"
                    ),
                )
                self._last_sentinel_token = token or ""
                self._last_sentinel_so_token = ""
                self._last_sentinel_flow = "username_password_create" if token else ""
                logger.info("Sentinel Token 获取成功")
            except Exception as e:
                raise RuntimeError(f"密码注册 Sentinel 获取失败: {e}") from e
        if not self._last_sentinel_token:
            raise RuntimeError("密码注册 Sentinel Token 为空")

        headers = self._auth_json_headers("https://auth.openai.com/create-account/password")
        if self._last_sentinel_token:
            headers["openai-sentinel-token"] = self._last_sentinel_token
        try:
            resp = self.session.post(
                "https://auth.openai.com/api/accounts/user/register",
                headers=headers,
                json={"password": password, "username": email},
                timeout=30,
            )
        finally:
            self._clear_sentinel_tokens()
        self._trace_http("register_password", resp)
        if resp.status_code != 200:
            raise RuntimeError(f"密码注册失败: {resp.status_code} - {resp.text[:200]}")
        logger.info("密码注册成功")
        try:
            return resp.json()
        except Exception:
            return {}

    # ── Step 7: 发送 OTP ──
    def send_otp(
        self,
        referer: str = "https://auth.openai.com/create-account/password",
        target_url: str = "https://auth.openai.com/api/accounts/email-otp/send",
        *,
        document_navigation: bool = False,
    ):
        logger.info(f"[6/10] 发送 OTP (referer={referer.split('/')[-1]})...")
        headers = (
            self._oauth_navigation_headers(referer, target_url)
            if document_navigation
            else self._navigation_headers(referer, target_url)
        )
        if self._last_sentinel_token and not document_navigation:
            headers["openai-sentinel-token"] = self._last_sentinel_token
        request_options = (
            {"default_headers": False}
            if document_navigation and hasattr(self.session, "default_headers")
            else {}
        )
        resp = self.session.get(
            target_url,
            headers=headers,
            timeout=30,
            allow_redirects=True,
            **request_options,
        )
        self._trace_http("send_email_otp", resp)
        if resp.status_code != 200:
            raise RuntimeError(f"发送 OTP 失败: {resp.status_code} - {resp.text[:200]}")
        logger.info("OTP 已发送到邮箱")

    def send_passwordless_otp(self, referer: str = "https://auth.openai.com/create-account/password") -> bool:
        """
        走 passwordless 发码（create-account/password 页面可触发该路径）。
        """
        headers = self._auth_resend_headers(referer)
        resp = self.session.post(
            "https://auth.openai.com/api/accounts/passwordless/send-otp",
            headers=headers,
            timeout=30,
        )
        self._trace_http("send_passwordless_otp", resp)
        if resp.status_code == 200:
            logger.info("passwordless OTP 已发送")
            return True
        logger.warning(f"passwordless 发码失败: {resp.status_code} - {(resp.text or '')[:220]}")
        return False

    def resend_otp(self, referer: str = "https://auth.openai.com/email-verification") -> bool:
        """
        重发 OTP（适用于已有账号 passwordless/login_challenge）。
        返回 True 代表请求成功。
        """
        headers = self._auth_resend_headers(referer)
        resp = self.session.post(
            "https://auth.openai.com/api/accounts/email-otp/resend",
            headers=headers,
            timeout=30,
        )
        self._trace_http("resend_email_otp", resp)
        if resp.status_code == 200:
            logger.info("OTP 已重发")
            return True
        if resp.status_code == 429:
            raise EmailOtpResendError(
                resp.status_code,
                resp.text or "",
                resp.headers.get("Retry-After", "") if getattr(resp, "headers", None) else "",
            )
        logger.warning(f"重发 OTP 失败: {resp.status_code} - {(resp.text or '')[:200]}")
        return False

    def kickoff_otp_delivery(self, mode: str = "") -> bool:
        """
        统一发码策略, 根据 mode hint 区分"新注册" vs "已有账号" referer:

        - 新注册 (create-account/password 页面 state): passwordless/send-otp → email-otp/send
        - 已有账号 / passwordless_login / existing_*: send_otp(referer=email-verification) → resend_otp
          (绕开 passwordless/send-otp 在已有账号场景的 409 invalid_state)
        """
        mode_lc = (mode or "").strip().lower()
        is_existing = (
            "existing" in mode_lc
            or "passwordless_login" in mode_lc
            or "passwordless_signup" in mode_lc  # OpenAI 把 outlook 接码池都打这个 mode
            or self._is_existing_account
        )

        if is_existing:
            # 已有账号 passwordless_signup / passwordless_login: authorize/continue 已经在
            # OpenAI server 端 trigger 了发码 (state S, OTP X, 邮件 X 已在投递). 这里**只能 resend**
            # (复用同 challenge state, 复用同 OTP X 或派生新码但 state 不变). 不能调 send_otp,
            # 它会新建 challenge token 让 state 跳到 Y, 旧邮件 X 在 server 端立即失效 → IMAP 抓到 X
            # verify 时 wrong_email_otp_code.
            if self.resend_otp("https://auth.openai.com/email-verification"):
                return True
            # resend 失败兜底: send_otp 新建 challenge (旧 state 已坏, 不得不重启)
            logger.warning(f"已有账号 resend 失败, 兜底 send_otp 新建 challenge (邮件 X 将失效)")
            try:
                self.send_otp(referer="https://auth.openai.com/email-verification")
                return True
            except Exception as e:
                logger.warning(f"已有账号发码全 fail: {e}")
                return False

        # 新注册 (原顺序)
        if self.send_passwordless_otp("https://auth.openai.com/create-account/password"):
            return True
        if self.resend_otp("https://auth.openai.com/email-verification"):
            return True
        try:
            self.send_otp()
            return True
        except Exception as e:
            logger.warning(f"send_otp 兜底失败(mode={mode_lc or 'unknown'}): {e}")
            return False

    @staticmethod
    def _default_password_from_email(email: str) -> str:
        pwd = (email or "").replace("@", "")
        if len(pwd) < 8:
            pwd = f"{pwd}2026OpenAI"
        return pwd

    def login_password_verify(self, password: str) -> dict:
        """已有账号密码登录一步（/password/verify）。"""
        headers = self._common_headers("https://auth.openai.com/log-in/password")
        headers["Content-Type"] = "application/json"
        if self._last_sentinel_token:
            headers["openai-sentinel-token"] = self._last_sentinel_token
        resp = self.session.post(
            "https://auth.openai.com/api/accounts/password/verify",
            headers=headers,
            json={"password": password},
            timeout=30,
        )
        self._trace_http("login_password_verify", resp)
        if resp.status_code != 200:
            body = (resp.text or "")[:260]
            raise RuntimeError(f"密码登录失败: {resp.status_code} - {body}")
        try:
            return resp.json()
        except Exception:
            return {}

    # ── Step 8: 验证 OTP ──
    def verify_otp(
        self,
        otp_code: str,
        *,
        sentinel_token: str = "",
        sentinel_so_token: str = "",
    ) -> dict:
        logger.info("[7/10] 验证 OTP...")
        headers = self._auth_json_headers("https://auth.openai.com/email-verification")
        if sentinel_token:
            headers["openai-sentinel-token"] = sentinel_token
        if sentinel_so_token:
            headers["openai-sentinel-so-token"] = sentinel_so_token
        try:
            resp = self.session.post(
                "https://auth.openai.com/api/accounts/email-otp/validate",
                headers=headers,
                json={"code": otp_code},
                timeout=30,
            )
        finally:
            if sentinel_token or sentinel_so_token:
                self._clear_sentinel_tokens()
        self._trace_http("validate_email_otp", resp)
        if resp.status_code != 200:
            body = (resp.text or "")
            logger.warning(f"verify_otp FULL body ({resp.status_code}): {body[:2000]}")
            raise EmailOtpValidationError(resp.status_code, body)
        logger.info("OTP 验证成功")
        try:
            return resp.json()
        except Exception:
            return {}

    # ── Step 9: 创建账户 ──
    def create_account(self) -> str:
        logger.info("[8/10] 创建账户...")
        _FIRST = ["James", "John", "Robert", "Michael", "William", "David", "Richard",
                  "Joseph", "Thomas", "Charles", "Mary", "Patricia", "Jennifer", "Linda",
                  "Elizabeth", "Barbara", "Susan", "Jessica", "Sarah", "Karen"]
        _LAST = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
                 "Davis", "Rodriguez", "Martinez", "Wilson", "Anderson", "Taylor", "Thomas"]
        if not self.registration_name or not self.registration_birthdate:
            age = random.randint(21, 39)
            today = self._browser_datetime().date()
            self.registration_name = f"{random.choice(_FIRST)} {random.choice(_LAST)}"
            self.registration_birthdate = today.replace(year=today.year - age).isoformat()
        else:
            born = datetime.strptime(self.registration_birthdate, "%Y-%m-%d").date()
            today = self._browser_datetime().date()
            age = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
        if (
            self._last_sentinel_flow != "oauth_create_account"
            or not self._last_sentinel_token
            or not self._last_sentinel_so_token
        ):
            behavior_input = {
                "behavior_name": self.registration_name,
                "behavior_age": str(age),
            }
            if (
                self._registration_sentinel_pending_flow == "oauth_create_account"
                and self._registration_sentinel_solver_state is not None
                and self._registration_sentinel_sdk is not None
            ):
                self._finalize_registration_sentinel(
                    "oauth_create_account",
                    behavior_input=behavior_input,
                )
            else:
                self._prepare_registration_sentinel(
                    "oauth_create_account",
                    behavior_input=behavior_input,
                )
        sentinel_token = self._last_sentinel_token
        sentinel_so_token = self._last_sentinel_so_token
        # 抓包 create_account 使用独立的 oauth_create_account 主/SO 双 token。
        headers = self._auth_json_headers("https://auth.openai.com/about-you")
        headers["openai-sentinel-token"] = sentinel_token
        headers["openai-sentinel-so-token"] = sentinel_so_token
        try:
            resp = self.session.post(
                "https://auth.openai.com/api/accounts/create_account",
                headers=headers,
                json={
                    "name": self.registration_name,
                    "birthdate": self.registration_birthdate,
                },
                timeout=30,
            )
        finally:
            self._clear_sentinel_tokens()
        self._trace_http("create_account", resp)
        if resp.status_code != 200:
            body = (resp.text or "")[:500]
            logger.error("创建账户失败: http=%s body=%s", resp.status_code, body)
            raise RuntimeError(f"创建账户失败: {resp.status_code} - {body[:260]}")
        data = resp.json()
        continue_url = data.get("continue_url", "")
        self._sniff_login_verifier(continue_url, "create_account_continue_url")

        # 尝试 workspace select
        if not continue_url:
            workspace_id = self._extract_workspace_id()
            if workspace_id:
                continue_url = self._workspace_select(workspace_id)

        if not continue_url:
            raise RuntimeError("创建账户后未获取到 continue_url")

        logger.info("账户创建成功")
        return continue_url

    def _extract_workspace_id(self) -> str:
        """从 cookie 中提取 workspace_id"""
        try:
            auth_session = self.session.cookies.get("oai-client-auth-session", "")
            if auth_session:
                parts = auth_session.split(".")
                # 兼容不同 cookie 形态：workspace_id 可能在第 1 段/第 2 段，也可能在 workspaces[0].id
                for idx in range(min(2, len(parts))):
                    segment = (parts[idx] or "").strip()
                    if not segment:
                        continue
                    payload_b64 = segment + "=" * (-len(segment) % 4)
                    decoded = json.loads(base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8"))
                    if not isinstance(decoded, dict):
                        continue
                    wid = (decoded.get("workspace_id", "") or "").strip()
                    if wid:
                        return wid
                    workspaces = decoded.get("workspaces", [])
                    if isinstance(workspaces, list):
                        for it in workspaces:
                            if isinstance(it, dict):
                                wid = (it.get("id", "") or "").strip()
                                if wid:
                                    return wid
        except Exception:
            pass
        return ""

    def _workspace_select(self, workspace_id: str) -> str:
        logger.info("执行 workspace 选择...")
        headers = self._common_headers("https://auth.openai.com/sign-in-with-chatgpt/codex/consent")
        headers["Content-Type"] = "application/json"
        resp = self.session.post(
            "https://auth.openai.com/api/accounts/workspace/select",
            headers=headers,
            json={"workspace_id": workspace_id},
            timeout=30,
        )
        self._trace_http("workspace_select", resp)
        return resp.json().get("continue_url", "") if resp.status_code == 200 else ""

    def _choose_account_select(self, html_text: str, current_url: str) -> str:
        """处理 /choose-an-account 多账号选择页（react-router SSR）。

        HTML 里 streamController.enqueue 注入 `unified_sessions[].id` (us_*) 和
        `session_id` (authsess_*)。这里 regex 抽 us_*，按 react-router action 惯例
        POST 回 /choose-an-account，并 fallback 试几个候选 JSON endpoint。
        返回 next continue_url 或空串。
        """
        m = re.search(r"us_[A-Za-z0-9]{16,}", html_text or "")
        if not m:
            logger.warning("/choose-an-account HTML 里没找到 us_* session id, 跳过")
            return ""
        session_id = m.group(0)
        logger.info(f"/choose-an-account 选 session_id={session_id}")
        headers = self._common_headers("https://auth.openai.com/choose-an-account")
        headers["Origin"] = "https://auth.openai.com"

        # 真实 endpoint 从 nextStepHandler-*.js 反编译解出：
        #   const {path, method} = r.data.intent === "select"
        #     ? {path: "/session/select", method: "POST"}
        #     : {path: "/session/remove", method: "DELETE"};
        #   fetch(`${authapi_base}/session/select`, {method, body: JSON.stringify({session_id})})
        # 即 POST https://auth.openai.com/api/accounts/session/select JSON {session_id}
        # （intent 决定 path 不进 body；body 只有 session_id 一个字段）
        # 之前直接 POST /choose-an-account 会先经过 react-router action loader 再被
        # nextStepHandler 转发，但 server-side 那一段似乎对 CT/form 字段强敏感，500。
        # 直接命中底层 /api/accounts/session/select 绕开 react-router 层。
        candidates = [
            ("POST", "https://auth.openai.com/api/accounts/session/select",
             {"session_id": session_id}, "json"),
            # 兜底：万一上面被风控，回退到 react-router 路径 + zod schema 字段
            ("POST", "https://auth.openai.com/choose-an-account",
             {"intent": "select", "session_id": session_id}, "form"),
        ]
        for method, url, body, kind in candidates:
            try:
                h = dict(headers)
                if kind == "json":
                    h["Content-Type"] = "application/json"
                    h["Accept"] = "application/json"
                    resp = self.session.post(url, headers=h, json=body, timeout=30)
                else:
                    h["Content-Type"] = "application/x-www-form-urlencoded"
                    h["Accept"] = "application/json, text/html;q=0.9"
                    body_str = "&".join(f"{k}={v}" for k, v in body.items())
                    resp = self.session.post(url, headers=h, data=body_str, timeout=30)
                self._trace_http(f"choose_account_try_{kind}_{url.rsplit('/', 1)[-1][:30]}", resp)
                status = getattr(resp, "status_code", 0)
                snippet = (getattr(resp, "text", "") or "")[:240].replace("\n", " ")
                loc = (getattr(resp, "headers", {}) or {}).get("Location", "") or \
                      (getattr(resp, "headers", {}) or {}).get("location", "") or ""
                # print 到 stdout 让 webui SSE 能看到每个候选的具体结果
                print(
                    f"[choose-an-account] {method} {url} [{kind}] -> "
                    f"status={status} loc={loc[:120]} body={snippet}",
                    flush=True,
                )
                if status in (200, 201, 302, 303):
                    next_url = ""
                    try:
                        j = resp.json() if resp is not None else {}
                        next_url = j.get("continue_url", "") if isinstance(j, dict) else ""
                    except Exception:
                        pass
                    if not next_url and loc:
                        next_url = loc
                    if next_url:
                        logger.info(f"choose-an-account 选号成功 endpoint={url} next={next_url[:120]}")
                        return next_url
                    # 200 但没 continue_url：可能 set 了 cookie，直接让 caller 重 GET authorize
                    if status == 200:
                        logger.info(f"choose-an-account POST {url} 200 OK 无 continue_url，假定 cookie 已 set")
                        return current_url  # 让外层重 GET 一次，cookie 已被 server set
            except Exception as e:
                print(f"[choose-an-account] {method} {url} [{kind}] -> EXC {e}", flush=True)
                continue
        logger.warning("/choose-an-account 全部候选 endpoint 都失败")
        return ""

    def _normalize_continue_url(self, continue_url: str) -> str:
        """
        标准化 continue_url：
        1) 相对路径 -> 绝对路径
        2) workspace 页面 -> 调用 workspace/select 取下一跳
        """
        if not continue_url:
            return ""
        out = continue_url.strip()
        if out.startswith("/"):
            out = urljoin("https://auth.openai.com", out)
        if "/workspace" in out:
            workspace_id = self._extract_workspace_id() or self._extract_query_first(out, ["workspace_id", "id"])
            if workspace_id:
                logger.info("检测到 workspace 页面，尝试 workspace/select: workspace_id=%s", workspace_id)
                next_url = self._workspace_select(workspace_id)
                if next_url:
                    out = next_url
        return out

    @staticmethod
    def _extract_workspace_id_from_html(html_text: str) -> str:
        """从 workspace 页面 HTML 文本中提取 workspace_id（兜底）。"""
        if not html_text:
            return ""
        try:
            # 先把转义引号还原，便于正则匹配
            text = html_text.replace('\\"', '"')
            patterns = [
                r'workspaces".{0,1600}?"id","([0-9a-fA-F-]{36})"',
                r'"workspace_id"\s*:\s*"([0-9a-fA-F-]{36})"',
                r'"workspaceId"\s*:\s*"([0-9a-fA-F-]{36})"',
            ]
            for p in patterns:
                m = re.search(p, text, flags=re.DOTALL | re.IGNORECASE)
                if m:
                    return (m.group(1) or "").strip()
        except Exception:
            return ""
        return ""

    # ── Step 10: 跟踪重定向链 ──
    def follow_redirect_chain(self, start_url: str) -> tuple[str, str]:
        """手动跟踪重定向，返回 (callback_url, final_url)"""
        logger.info("[9/10] 跟踪重定向链...")
        current_url = start_url
        callback_url = ""
        max_hops = 12

        if "/api/auth/callback/openai" in current_url and "code=" in current_url:
            self._sniff_login_verifier(current_url, "redirect_direct_callback_url")
            logger.info("捕获直接 callback URL（未消费）")
            return current_url, current_url

        for i in range(max_hops):
            headers = self._navigation_headers("https://chatgpt.com/", current_url)
            resp = self.session.get(
                current_url, headers=headers, timeout=30, allow_redirects=False
            )
            self._trace_http(f"redirect_hop_{i+1}", resp)

            if "/api/auth/callback/openai" in current_url:
                callback_url = current_url
                self._sniff_login_verifier(current_url, f"redirect_hop_{i+1}_callback_url")

            # workspace 页面常见为 200，需要主动调 workspace/select 获取下一跳
            if "/workspace" in current_url and resp.status_code == 200:
                workspace_id = self._extract_workspace_id() or self._extract_workspace_id_from_html(resp.text or "")
                if workspace_id:
                    logger.info("workspace 页面提取到 workspace_id=%s，尝试继续授权", workspace_id)
                    next_url = self._workspace_select(workspace_id)
                    if next_url:
                        if next_url.startswith("/"):
                            next_url = urljoin("https://auth.openai.com", next_url)
                        current_url = next_url
                        continue

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if not location:
                    break
                if location.startswith("/"):
                    parsed = urlparse(current_url)
                    location = f"{parsed.scheme}://{parsed.netloc}{location}"
                # 关键：不要主动 GET callback，避免 code 被服务端回调消费
                if "/api/auth/callback/openai" in location and "code=" in location:
                    callback_url = location
                    current_url = location
                    self._sniff_login_verifier(location, f"redirect_hop_{i+1}_location_callback")
                    logger.info("捕获 callback URL（未消费）")
                    break
                current_url = location
                logger.debug(f"  重定向 {i + 1}: {current_url[:80]}...")
            else:
                break

        # 补一跳首页
        if (not callback_url) and (not current_url.rstrip("/").endswith("chatgpt.com")):
            self.session.get(
                "https://chatgpt.com/",
                headers=self._navigation_headers(current_url, "https://chatgpt.com/"),
                timeout=30,
            )

        logger.info(f"重定向链完成, callback: {'有' if callback_url else '无'}")
        return callback_url, current_url

    def _reauthorize_for_session(self, original_auth_url: str) -> str | None:
        """已有账号 OTP 验证后，重新发起 authorize 获取 callback URL"""
        logger.info("[9.5/10] 重新 authorize 获取 session ...")
        try:
            # 去掉 prompt=login 参数，利用已有的 auth session cookie
            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
            parsed = urlparse(original_auth_url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params.pop("prompt", None)
            # 重新构建 URL
            new_query = urlencode({k: v[0] for k, v in params.items()})
            authorize_url = urlunparse(parsed._replace(query=new_query))

            resp = self.session.get(
                authorize_url,
                headers=self._navigation_headers("https://auth.openai.com/", authorize_url),
                allow_redirects=False,
                timeout=15,
            )
            self._trace_http("reauthorize_start", resp)
            logger.info(f"reauthorize status={resp.status_code}")

            # 跟随 redirect chain 找到 callback URL
            current_url = resp.headers.get("Location", "")
            logger.info(f"reauthorize Location: {current_url[:150]}")
            if resp.status_code in (301, 302, 303, 307, 308) and current_url:
                for hop in range(10):
                    logger.debug(f"reauthorize redirect hop {hop+1}: {current_url[:100]}")
                    if "code=" in current_url and "state=" in current_url:
                        logger.info("reauthorize: 找到 callback URL")
                        return current_url
                    try:
                        hop_resp = self.session.get(
                            current_url,
                            headers=self._navigation_headers("https://auth.openai.com/", current_url),
                            allow_redirects=False,
                            timeout=15,
                        )
                        self._trace_http(f"reauthorize_hop_{hop+1}", hop_resp)
                        next_loc = hop_resp.headers.get("Location", "")
                        if hop_resp.status_code not in (301, 302, 303, 307, 308) or not next_loc:
                            # 检查最终 URL
                            final_url = str(getattr(hop_resp, 'url', current_url))
                            if "code=" in final_url:
                                return final_url
                            break
                        current_url = next_loc
                        if not current_url.startswith("http"):
                            from urllib.parse import urljoin
                            current_url = urljoin(authorize_url, current_url)
                    except Exception:
                        break
            logger.warning("reauthorize: 未能获取 callback URL")
            return None
        except Exception as e:
            logger.warning(f"reauthorize 失败: {e}")
            return None

    # ── Step 11: 获取 session ──
    def _extract_session_cookie(self) -> str:
        """多路兜底提取 __Secure-next-auth.session-token cookie。

        curl_cffi 在某些情况下按 domain 隔离 cookie，session.cookies.get(name) 拿不到，
        所以这里把所有 cookie 都遍历一遍，按名字精确匹配。
        """
        target = "__Secure-next-auth.session-token"
        # 路径1：直接 get
        try:
            v = self.session.cookies.get(target, "")
            if v:
                return v
        except Exception:
            pass
        # 路径2：遍历 jar
        try:
            for c in self.session.cookies:
                name = getattr(c, "name", "") if hasattr(c, "name") else str(c)
                if name == target:
                    val = getattr(c, "value", "") or ""
                    if val:
                        return val
        except Exception:
            pass
        # 路径3：用 _get_cookie_value_by_name（不挑 domain）
        try:
            return self._get_cookie_value_by_name(target)
        except Exception:
            return ""

    def _remember_chatgpt_access_token(self, response_text: str) -> str:
        text = str(response_text or "")
        for pattern in (
            r'"accessToken"\s*:\s*"([A-Za-z0-9._-]+)"',
            r'\\"accessToken\\"\s*:\s*\\"([A-Za-z0-9._-]+)\\"',
        ):
            match = re.search(pattern, text)
            if not match:
                continue
            access_token = str(match.group(1) or "").strip()
            if access_token:
                self._chatgpt_web_access_token = access_token
                self.result.web_access_token = access_token
                self.result.access_token = access_token
                return access_token
        return ""

    def get_auth_session(self) -> tuple[str, str]:
        """获取 session_token 和 access_token。

        session_token 三路兜底（按优先级）：
          1. cookie `__Secure-next-auth.session-token`（NextAuth 数据库 session 策略）
          2. JSON 响应里的 `sessionToken` 字段（NextAuth JWT session 策略，某些路径）
          3. 兼容大小写 / 下划线变体
        access_token 取 JSON 响应里的 `accessToken`。
        """
        logger.info("[10/10] 获取认证 Session...")
        headers = self._common_headers("https://chatgpt.com/")
        resp = self.session.get(
            "https://chatgpt.com/api/auth/session",
            headers=headers,
            timeout=30,
        )
        self._trace_http("chatgpt_auth_session", resp)
        resp.raise_for_status()

        try:
            sess_json = resp.json() if resp is not None else {}
        except Exception:
            sess_json = {}
        if not isinstance(sess_json, dict):
            sess_json = {}

        cookie_st = self._extract_session_cookie()
        json_st = (
            sess_json.get("sessionToken", "")
            or sess_json.get("session_token", "")
            or ""
        )
        session_token = cookie_st or json_st
        access_token = sess_json.get("accessToken", "") or sess_json.get("access_token", "") or ""
        self._chatgpt_web_access_token = access_token

        if session_token:
            self.result.session_token = session_token
        if access_token:
            self.result.web_access_token = access_token
            self.result.access_token = access_token
        self.result.cookie_header = self._build_chatgpt_cookie_header()

        logger.info(
            f"session_token: cookie={'有(len=%d)' % len(cookie_st) if cookie_st else '无'} "
            f"json={'有(len=%d)' % len(json_st) if json_st else '无'} "
            f"→ 最终={'有(len=%d)' % len(session_token) if session_token else '无'}; "
            f"access_token={'有(len=%d)' % len(access_token) if access_token else '无'}; "
            f"json_keys={list(sess_json.keys())[:10]}"
        )
        return session_token, access_token

    def _consume_callback_for_session(self, callback_url: str) -> bool:
        """主动 GET callback URL 让 chatgpt.com NextAuth 设 session cookie。

        协议层 follow_redirect_chain 故意不消费 callback（为后续 OAuth token exchange 留 code），
        但这导致 NextAuth 永远不会写 __Secure-next-auth.session-token cookie。
        在拿不到 session_token 时主动消费一次 callback：跟随到 chatgpt.com 主页，
        服务器会 Set-Cookie session-token。
        """
        if not callback_url or "code=" not in callback_url:
            return False
        try:
            current = callback_url
            request_options = (
                {"default_headers": False}
                if hasattr(self.session, "default_headers")
                else {}
            )
            for hop in range(8):
                resp = self.session.get(
                    current,
                    headers=self._oauth_navigation_headers("https://auth.openai.com/", current),
                    timeout=30,
                    allow_redirects=False,
                    **request_options,
                )
                self._trace_http(f"consume_callback_hop_{hop+1}", resp)
                if resp.status_code not in (301, 302, 303, 307, 308):
                    self._remember_chatgpt_client_metadata(resp.text or "")
                    self._remember_chatgpt_access_token(resp.text or "")
                    break
                loc = (resp.headers.get("Location", "") or "").strip()
                if not loc:
                    break
                if loc.startswith("/"):
                    loc = urljoin(current, loc)
                current = loc
                # 已到 chatgpt.com 主页就够
                parsed = urlparse(current)
                if "chatgpt.com" in (parsed.netloc or "") and "/api/auth/callback" not in current:
                    # 再 GET 一下主页，让 cookie 全部落地
                    try:
                        root_resp = self.session.get(
                            current,
                            headers=self._oauth_navigation_headers("https://auth.openai.com/", current),
                            timeout=20,
                            allow_redirects=True,
                            **request_options,
                        )
                        self._remember_chatgpt_client_metadata(root_resp.text or "")
                        self._remember_chatgpt_access_token(root_resp.text or "")
                    except Exception:
                        pass
                    break
            session_token = self._extract_session_cookie()
            if session_token:
                self.result.session_token = session_token
            self.result.cookie_header = self._build_chatgpt_cookie_header()
            return bool(session_token or self.result.access_token)
        except Exception as e:
            logger.warning(f"消费 callback 失败: {e}")
            return False

    # ── 可选: OAuth Token 交换 ──
    def oauth_token_exchange(self, callback_url: str, continue_url: str) -> bool:
        """
        交换 OAuth token（尽力模式）：
        1) 尝试多来源 code_verifier（query/cookie/dump/hydra）
        2) 回退无 verifier
        """
        auth_code = self._extract_query_first(callback_url, ["code"]) or self._extract_query_first(continue_url, ["code"])

        if not auth_code:
            logger.info("缺少 auth_code，跳过 token 交换")
            return False

        verifier_candidates = self._collect_code_verifier_candidates(callback_url, continue_url)
        if not verifier_candidates:
            logger.info("当前未获取到可用 code_verifier，将先尝试无 verifier 交换")
        else:
            show = ", ".join([f"{src}:{len(v)}" for src, v in verifier_candidates[:8]])
            logger.info("code_verifier 候选数=%s 示例=%s", len(verifier_candidates), show)

        logger.info("执行 OAuth Token 交换...")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "Origin": "https://auth.openai.com",
            "Referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
        }
        headers.update(self._browser_request_headers(
            destination="empty",
            mode="cors",
            site="same-origin",
        ))
        base_form = {
            "grant_type": "authorization_code",
            "client_id": self._oauth_client_id or "YOUR_OPENAI_WEB_CLIENT_ID",
            "code": auth_code,
            "redirect_uri": self._oauth_redirect_uri or "https://chatgpt.com/api/auth/callback/openai",
        }
        logger.info(
            "Token 交换参数: client_id=%s redirect_uri=%s",
            base_form["client_id"],
            base_form["redirect_uri"],
        )

        candidates: list[tuple[str, dict]] = []
        if self._oauth_client_secret:
            d = dict(base_form)
            d["client_secret"] = self._oauth_client_secret
            candidates.append(("with_client_secret", d))

        try:
            max_verifier_try = max(1, int(self._env_value("OAUTH_MAX_VERIFIER_TRY", "18")))
        except Exception:
            max_verifier_try = 18

        for src, verifier in verifier_candidates[:max_verifier_try]:
            d = dict(base_form)
            d["code_verifier"] = verifier
            candidates.append((f"with_verifier_{src}", d))
            if self._oauth_client_secret:
                d2 = dict(d)
                d2["client_secret"] = self._oauth_client_secret
                candidates.append((f"with_verifier_{src}_and_client_secret", d2))

        # 一些服务端可能要求额外参数（实验候选）
        audience = self._extract_query_first(self._oauth_auth_url, ["audience"])
        if audience:
            d = dict(base_form)
            d["audience"] = audience
            candidates.append(("without_verifier_with_audience", d))
        if self._oauth_scope:
            d = dict(base_form)
            d["scope"] = self._oauth_scope
            candidates.append(("without_verifier_with_scope", d))

        candidates.append(("without_verifier", dict(base_form)))

        seen_fingerprints: set[str] = set()
        for mode, form in candidates:
            fp = json.dumps(form, sort_keys=True, ensure_ascii=False)
            if fp in seen_fingerprints:
                continue
            seen_fingerprints.add(fp)
            try:
                self._sniff_login_verifier(urlencode(form), f"oauth_token_exchange_{mode}:form")
            except Exception:
                pass
            encoded_form = urlencode(form)
            extra_request = {
                "method": "POST",
                "url": "https://auth.openai.com/oauth/token",
                "body": encoded_form,
                "headers": headers,
            }

            resp = self.session.post(
                "https://auth.openai.com/oauth/token",
                headers=headers,
                data=encoded_form,
                timeout=30,
            )
            self._trace_http(f"oauth_token_exchange_{mode}", resp, extra_request=extra_request)
            if resp.status_code == 200:
                data = resp.json()
                self.result.id_token = data.get("id_token", "")
                self.result.access_token = data.get("access_token", self.result.access_token)
                self.result.refresh_token = data.get("refresh_token", "")
                logger.info(
                    "Token 交换成功(mode=%s): refresh_token=%s",
                    mode,
                    "有" if self.result.refresh_token else "无",
                )
                return True

            body = (resp.text or "")[:240]
            logger.warning("Token 交换失败(mode=%s): status=%s body=%s", mode, resp.status_code, body)

        return False

    def oauth_secondary_authorize_exchange(self) -> bool:
        """
        二次授权实验：
        - 在当前已登录会话上，重新发起一条带 PKCE 的 authorize
        - 仅提取 callback code，不消费 callback
        - 再走 oauth/token 交换
        """
        logger.info("尝试二次 authorize + PKCE 换 refresh_token ...")
        try:
            csrf = self.get_csrf_token()
            auth_url = self.get_auth_url(csrf)
        except Exception as e:
            logger.warning(f"二次 authorize 初始化失败: {e}")
            return False

        try:
            verifier, challenge = self._build_pkce_pair()
            parsed = urlparse(auth_url)
            params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            params["code_challenge"] = challenge
            params["code_challenge_method"] = "S256"
            if not params.get("state"):
                params["state"] = self._b64url_no_pad(os.urandom(16))
            sec_url = urlunparse(parsed._replace(query=urlencode(params)))

            self._manual_login_verifier = verifier
            self._captured_login_verifier = verifier
            self._remember_oauth_params(sec_url)

            current = sec_url
            callback_url = ""
            max_hops = 10
            for i in range(max_hops):
                resp = self.session.get(
                    current,
                    headers=self._navigation_headers("https://chatgpt.com/", current),
                    timeout=30,
                    allow_redirects=False,
                )
                self._trace_http(f"secondary_authorize_hop_{i+1}", resp)

                loc = (resp.headers.get("Location", "") or "").strip()
                if loc and loc.startswith("/"):
                    loc = urljoin(current, loc)

                if loc and "/api/auth/callback/openai" in loc and "code=" in loc:
                    callback_url = loc
                    break
                if resp.status_code not in (301, 302, 303, 307, 308) or not loc:
                    break
                current = loc

            if not callback_url:
                logger.warning("二次 authorize 未捕获 callback code")
                return False

            ok = self.oauth_token_exchange(callback_url, callback_url)
            logger.info("二次 authorize 交换结果: %s", "成功" if ok else "失败")
            return ok
        except Exception as e:
            logger.warning(f"二次 authorize 交换异常: {e}")
            return False

    def _send_post_registration_prompt(self) -> None:
        """Send one best-effort conversation without changing registration success."""
        try:
            from .conversation import (
                conversation_result_payload,
                configured_conversation_enabled,
                configured_conversation_prompts,
                send_random_prompt,
            )
            if not configured_conversation_enabled():
                self.result.post_registration_conversation = conversation_result_payload(
                    status="skipped",
                    error="注册后对话已关闭",
                )
                return

            web_access_token = str(
                getattr(self, "_chatgpt_web_access_token", "")
                or getattr(self.result, "web_access_token", "")
                or getattr(self.result, "access_token", "")
                or ""
            ).strip()
            if not web_access_token:
                self.result.post_registration_conversation = conversation_result_payload(
                    status="skipped",
                    error="缺少 ChatGPT Web access token",
                )
                logger.warning("注册后随机提问已跳过：缺少 ChatGPT Web access token")
                return
            result = send_random_prompt(
                session=self.session,
                access_token=web_access_token,
                device_id=self._ensure_device_id(),
                fingerprint=dict(getattr(self, "_fingerprint", {}) or {}),
                timezone=str(getattr(self, "_timezone", "") or ""),
                session_id=str(getattr(self, "_chatgpt_session_id", "") or ""),
                client_version=str(getattr(self, "_chatgpt_client_version", "") or ""),
                client_build_number=str(
                    getattr(self, "_chatgpt_client_build_number", "") or ""
                ),
                integrity_observation=self._chatgpt_integrity_observation,
                prompts=configured_conversation_prompts(),
            )
            self.result.post_registration_conversation = conversation_result_payload(result)
            answer_preview = re.sub(r"\s+", " ", result.answer).strip()[:80]
            logger.info(
                "注册后随机提问成功: conversation_id=%s prompt=%s 回答开头=%s",
                result.conversation_id,
                result.prompt,
                answer_preview or "(empty)",
            )
        except Exception as exc:
            from .conversation import conversation_result_payload

            self.result.post_registration_conversation = conversation_result_payload(
                status="failed",
                error=str(exc),
            )
            logger.warning("注册后随机提问失败，不影响注册结果: %s", exc)

    # ── 完整注册流程 ──
    def run_register(
        self,
        mail_provider: MailProvider,
        *,
        enable_oauth: bool = True,
        existing_account_relogin: bool = False,
    ) -> AuthResult:
        """执行完整注册流程"""
        email = mail_provider.create_mailbox()
        self.result.email = email
        direct_otp_since = 0.0

        # authorize 可能直接进入邮箱验证，也可能进入密码注册分支；两条路径在 OTP 校验处汇合。
        csrf_token = self.get_csrf_token()
        device_id = self._ensure_device_id()
        auth_url = self.get_auth_url(
            csrf_token,
            email,
            device_id,
            include_passkey_capabilities=not existing_account_relogin,
        )
        # authorize 导航会触发直接 OTP 首封邮件；前置 ChatGPT 请求不应扩大查码时间窗。
        direct_otp_since = time.time()
        self.auth_oauth_init(auth_url, preload_sentinel=True)
        try:
            try:
                otp_timeout = max(30, int(self._env_value("OTP_TIMEOUT", "60")))
            except Exception:
                otp_timeout = 180

            password_branch = (
                urlparse(self._auth_oauth_final_url).path.rstrip("/")
                == "/create-account/password"
            )
            email_otp_branch = (
                urlparse(self._auth_oauth_final_url).scheme.lower() == "https"
                and (urlparse(self._auth_oauth_final_url).hostname or "").lower()
                == "auth.openai.com"
                and urlparse(self._auth_oauth_final_url).path.rstrip("/").lower()
                == "/email-verification"
            )
            if existing_account_relogin:
                missing_cookies = self._missing_email_otp_session_cookies()
                status_code = int(getattr(self, "_auth_oauth_status_code", 200) or 0)
                if status_code != 200 or not email_otp_branch:
                    raise RuntimeError(
                        "已有账号重登未进入邮箱验证页面: "
                        f"status={status_code} final_url={self._auth_oauth_final_url or '(empty)'}"
                    )
                if missing_cookies:
                    raise RuntimeError(
                        "已有账号重登未建立邮箱验证码会话 Cookie: "
                        + ",".join(missing_cookies)
                    )
            if not password_branch and not email_otp_branch:
                raise RuntimeError(
                    "OAuth 初始化未进入支持的邮箱验证码页面: "
                    f"status={getattr(self, '_auth_oauth_status_code', 0)} "
                    f"final_url={self._auth_oauth_final_url or '(empty)'}"
                )
            if password_branch:
                logger.info("注册分支: username_password_create")
                register_step = self.register_password(email)
                method = str(register_step.get("method") or "").strip().upper()
                page_type = self._extract_page_type(register_step)
                send_url = self._normalize_continue_url(
                    self._extract_continue_url_from_step(register_step)
                )
                parsed_send_url = urlparse(send_url)
                if (
                    method != "GET"
                    or page_type != "email_otp_send"
                    or parsed_send_url.scheme != "https"
                    or parsed_send_url.netloc != "auth.openai.com"
                    or parsed_send_url.path != "/api/accounts/email-otp/send"
                ):
                    raise RuntimeError(
                        "密码注册未返回有效的 email-otp/send 下一步: "
                        f"method={method or '(empty)'} page_type={page_type or '(empty)'} "
                        f"continue_url={send_url or '(empty)'}"
                    )
                otp_sent_at = time.time()
                self.send_otp(
                    self._auth_oauth_final_url,
                    send_url,
                    document_navigation=True,
                )
                self._prefetch_registration_sentinel("email_otp_validate")
            else:
                logger.info("注册分支: direct_email_otp")
                self._prefetch_registration_sentinel("email_otp_validate")
                if existing_account_relogin:
                    logger.info("已有账号重登：使用 authorize 自动发送的首封验证码，查码耗尽后再重发")
                else:
                    logger.info("直接 OTP：使用 authorize 自动发送的首封验证码，查码耗尽后按邮箱配置重发")
                otp_sent_at = direct_otp_since

            otp_code = mail_provider.wait_for_otp(
                email,
                timeout=otp_timeout,
                issued_after=otp_sent_at,
            )
            email_sentinel_token, email_sentinel_so_token = self._finalize_registration_sentinel(
                "email_otp_validate",
                keep_exchange=True,
                behavior_input={"behavior_otp": otp_code},
            )
            otp_step = self.verify_otp(
                otp_code,
                sentinel_token=email_sentinel_token,
                sentinel_so_token=email_sentinel_so_token,
            )

            post_otp_page_type = self._extract_page_type(otp_step).strip().lower()
            post_otp_method = str(otp_step.get("method") or "").strip().upper()
            post_otp_continue_url = self._normalize_continue_url(
                self._extract_continue_url_from_step(otp_step)
            )
            post_otp_url = urlparse(post_otp_continue_url)
            post_otp_path = post_otp_url.path.rstrip("/").lower()
            expected_oauth_state = (self._oauth_state or "").strip()
            callback_state = (
                parse_qs(post_otp_url.query).get("state", [""])[0] or ""
            ).strip()
            callback_code = (
                parse_qs(post_otp_url.query).get("code", [""])[0] or ""
            ).strip()
            is_about_you_step = (
                post_otp_page_type == "about_you"
                and post_otp_method == "GET"
                and post_otp_url.scheme.lower() == "https"
                and (post_otp_url.hostname or "").lower() == "auth.openai.com"
                and post_otp_path == "/about-you"
            )
            is_chatgpt_callback = (
                post_otp_page_type == "external_url"
                and post_otp_method == "GET"
                and post_otp_url.scheme.lower() == "https"
                and (post_otp_url.hostname or "").lower() == "chatgpt.com"
                and post_otp_path == "/api/auth/callback/openai"
                and bool(callback_code)
                and bool(expected_oauth_state)
                and callback_state == expected_oauth_state
            )
            submitted_profile = False
            if is_about_you_step:
                logger.info("OTP 后分支: about_you -> 提交注册资料")
                self._prefetch_registration_sentinel("oauth_create_account")
                continue_url = self.create_account()
                submitted_profile = True
            elif is_chatgpt_callback:
                self._is_existing_account = True
                self._existing_page_type = post_otp_page_type
                continue_url = post_otp_continue_url
                logger.info("OTP 后分支: existing_account -> 直接跟踪登录 callback")
            elif (
                post_otp_page_type == "external_url"
                or post_otp_path == "/api/auth/callback/openai"
            ):
                raise RuntimeError(
                    "已有账号 OTP 验证后未返回有效的 ChatGPT callback: "
                    f"method={post_otp_method or '(empty)'} "
                    f"continue_url={post_otp_continue_url or '(empty)'}"
                )
            else:
                raise RuntimeError(
                    "OTP 验证后返回不支持的下一步: "
                    f"method={post_otp_method or '(empty)'} "
                    f"page_type={post_otp_page_type or '(empty)'} "
                    f"continue_url={post_otp_continue_url or '(empty)'}"
                )

            if continue_url:
                continue_url = self._normalize_continue_url(continue_url)
                callback_url, final_url = self.follow_redirect_chain(continue_url)
                if (not callback_url) and final_url and ("/workspace" in final_url):
                    normalized = self._normalize_continue_url(final_url)
                    if normalized and normalized != final_url:
                        callback_url, final_url = self.follow_redirect_chain(normalized)
            else:
                callback_url, final_url = None, None

            if not callback_url:
                raise RuntimeError("注册完成但未获取 ChatGPT callback")
            logger.info("消费 callback 并从 ChatGPT 首页提取 access_token ...")
            self._consume_callback_for_session(callback_url)
            if not self.result.access_token:
                self.get_auth_session()
            if not self.result.access_token:
                raise RuntimeError("注册完成但未获取 access_token")

            if submitted_profile:
                self._send_post_registration_prompt()

            if enable_oauth:
                logger.info("注册后尝试授权已开启，继续 OAuth 换取 refresh_token ...")
                self.oauth_codex_rt_exchange(mail_provider=mail_provider)
                if self.result.refresh_token:
                    logger.info("注册流程完成，已获取 access_token 和 refresh_token")
                else:
                    logger.warning("注册流程完成，已获取 access_token，但未获取 refresh_token")
            else:
                logger.info("注册后尝试授权已关闭，保留 access_token 并跳过 refresh_token 交换")
            return self.result
        finally:
            self._close_registration_sentinel()

    # ── 纯协议已有账号登录流程（目标：拿 callback/session/refresh） ──
    def _complete_totp_login_step(self, step: dict) -> dict:
        from ..totp import totp_code

        page_type = self._extract_page_type(step)
        continue_url = self._extract_continue_url_from_step(step)
        if page_type == "email_otp_verification" or "/email-verification" in continue_url:
            raise RuntimeError("上游要求邮箱验证，2FA 登录未完成")
        if page_type != "mfa_challenge" and "/mfa-challenge" not in continue_url:
            return step
        payload = step.get("page", {}).get("payload") or {}
        factor_id = str(payload.get("factor_id") or "").strip()
        if not factor_id:
            state = step.get("oai-client-auth-session") or {}
            factors = state.get("mfa_factors") or payload.get("factors")
            if not factors:
                dump = self.fetch_client_auth_session_dump("totp")
                factors = (dump.get("client_auth_session") or {}).get("mfa_factors") or []
            factor = next((item for item in factors if item.get("factor_type") == "totp"), None)
            factor_id = factor.get("id") if factor else ""
        if not factor_id:
            raise RuntimeError("账号未返回可用的 2FA 验证方式")
        headers = self._auth_json_headers("https://auth.openai.com/mfa-challenge/" + factor_id)
        response = self.session.post(
            "https://auth.openai.com/api/accounts/mfa/issue_challenge",
            headers=headers,
            json={"id": factor_id, "type": "totp", "force_fresh_challenge": False},
            timeout=30,
        )
        if response.status_code != 200:
            error = response.json().get("error", {})
            reason = "rate_limit_exceeded" if isinstance(error, dict) and error.get("code") == "rate_limit_exceeded" else "challenge_failed"
            raise RuntimeError(f"2FA {reason} ({response.status_code})")
        response = self.session.post(
            "https://auth.openai.com/api/accounts/mfa/verify",
            headers=headers,
            json={"id": factor_id, "type": "totp", "code": totp_code(self._totp_secret)["code"]},
            timeout=30,
        )
        if response.status_code != 200:
            try:
                error = response.json().get("error", {})
            except (ValueError, AttributeError):
                error = {}
            reason = "rate_limit_exceeded" if isinstance(error, dict) and error.get("code") == "rate_limit_exceeded" else "verification_failed"
            raise EmailOtpValidationError(response.status_code, f"2FA {reason}")
        result = response.json()
        if self._extract_page_type(result) == "mfa_challenge":
            raise RuntimeError("2FA 验证未通过，请检查密钥和服务器时间")
        return result

    def run_totp_login(self, email: str, password: str, secret: str) -> AuthResult:
        from ..totp import normalize_secret

        self._totp_secret = normalize_secret(secret)
        self.result.email = email.strip()
        self.result.password = password
        csrf = self.get_csrf_token()
        auth_url = self.get_auth_url(csrf)
        device_id = self.auth_oauth_init(auth_url)
        step = self.authorize_continue(
            email=self.result.email,
            sentinel_token=self.get_sentinel_token(device_id),
            screen_hint="login",
            referer="https://auth.openai.com/log-in",
            trace_step="authorize_continue_totp",
        )
        if self._extract_page_type(step) == "login_password" or "/log-in/password" in self._extract_continue_url_from_step(step):
            step = self.login_password_verify(password)
        step = self._complete_totp_login_step(step)
        continue_url = self._normalize_continue_url(self._extract_continue_url_from_step(step))
        if self._is_add_phone_state(self._extract_page_type(step), continue_url):
            raise RuntimeError("OAuth 要求 phone 验证")
        if not continue_url:
            raise RuntimeError("2FA 登录未返回后续授权地址")
        self.oauth_token_exchange(continue_url, continue_url)
        callback_url, _final_url = self.follow_redirect_chain(continue_url)
        if not self.result.refresh_token:
            self.oauth_token_exchange(callback_url or "", continue_url)
        if not self.result.refresh_token:
            self.oauth_codex_rt_exchange()
        if not self.result.refresh_token:
            raise RuntimeError("重新 OAuth 未返回 Refresh Token")
        return self.result

    def run_protocol_login(self, mail_provider: MailProvider, email: str, password: str = "") -> AuthResult:
        """
        纯协议登录（不创建随机邮箱）：
        - 适配 passwordless / login_password 两类已有账号入口
        - 可配合 OAUTH_EXCHANGE_BEFORE_CALLBACK / OAUTH_REFRESH_ONLY 尝试优先拿 refresh_token
        """
        if not (email or "").strip():
            raise RuntimeError("run_protocol_login 缺少邮箱")

        if not self.check_proxy():
            logger.warning("网络预检查未通过，继续尝试登录链路以获取精确错误...")

        # run_protocol_login 的语义即"登录已有账号"（docstring 明写）。kickoff_otp_delivery
        # 依据 _is_existing_account 选 resend vs send_passwordless_otp 分支；落到 send
        # 分支会把 server-side state 弄坏 → 之后 IMAP 抓到的 OTP X 已失效 → verify 401
        # wrong_email_otp_code。这里入口统一 set True，覆盖 passwordless 这类 page_type
        # 不在 ("login_password","email_otp_verification") 集合的情况；signup() 回退
        # 路径会基于 OpenAI 真实响应再次覆盖（True/False），无副作用。
        self._is_existing_account = True

        email = email.strip()
        self.result.email = email
        login_password = (password or "").strip() or self._default_password_from_email(email)
        self.result.password = login_password

        csrf_token = self.get_csrf_token()
        auth_url = self.get_auth_url(csrf_token)
        device_id = self.auth_oauth_init(auth_url)
        sentinel = self.get_sentinel_token(device_id)

        continue_url = ""
        try:
            otp_timeout = max(30, int(self._env_value("OTP_TIMEOUT", "60")))
        except Exception:
            otp_timeout = 180

        page_type = ""
        mode = ""
        prefer_login_screen_first = str(
            self._env_value("LOCALAUTH_EXISTING_LOGIN_USE_LOGIN_HINT", "1")
        ).lower() in ("1", "true", "yes", "on")

        if prefer_login_screen_first:
            try:
                logger.info("已有账号协议登录：优先走 login screen_hint 探测 password/otp 分支")
                login_step = self.authorize_continue(
                    email=email,
                    sentinel_token=sentinel,
                    screen_hint="login",
                    referer="https://auth.openai.com/log-in",
                    trace_step="authorize_continue_login_protocol",
                )
                page_type = (self._extract_page_type(login_step) or "").lower()
                continue_url = self._normalize_continue_url(
                    self._extract_continue_url_from_step(login_step)
                )
                page = (login_step.get("page") or {}) if isinstance(login_step, dict) else {}
                payload = (page.get("payload") or {}) if isinstance(page, dict) else {}
                mode = (payload.get("email_verification_mode", "") or "").lower()
                self._existing_page_type = page_type
                self._existing_email_verification_mode = mode

                if page_type == "login_password" or "/log-in/password" in (continue_url or ""):
                    logger.info("登录分支: login_password -> password/verify")
                    # 命中已有账号 password 路径：标记之，让 kickoff_otp_delivery 走 resend
                    # 分支（避免 send_passwordless_otp 把 state 弄坏 → wrong_email_otp_code）
                    self._is_existing_account = True
                    login_resp = self.login_password_verify(login_password)
                    page_type = (self._extract_page_type(login_resp) or "").lower()
                    continue_url = self._normalize_continue_url(
                        self._extract_continue_url_from_step(login_resp)
                    )
                elif page_type == "email_otp_verification" or "/email-verification" in (continue_url or ""):
                    logger.info("登录分支: email_otp_verification")
                    # 同上：authorize/continue 已 trigger 发码，kickoff_otp_delivery 必须只 resend。
                    self._is_existing_account = True
                else:
                    logger.info(
                        "login screen_hint 未直接命中已有账号完成态: page_type=%s continue_url=%s",
                        page_type or "(empty)",
                        (continue_url or "")[:180] or "(empty)",
                    )
            except Exception as e:
                logger.warning(f"login screen_hint 探测失败，回退 signup 探测: {e}")
                continue_url = ""
                page_type = ""
                mode = ""

        if not continue_url and page_type not in ("login_password", "email_otp_verification"):
            is_new = self.signup(email, sentinel)
            if is_new:
                raise RuntimeError("目标邮箱未识别为已有账号，已停止重新 OAuth")
            else:
                page_type = (self._existing_page_type or "").lower()
                mode = (self._existing_email_verification_mode or "").lower()
        else:
            page_type = (page_type or self._existing_page_type or "").lower()
            mode = (mode or self._existing_email_verification_mode or "").lower()

        if not continue_url or "/email-verification" in continue_url:
            # 仍需 OTP：优先 resend 获取新码
            otp_sent_at = time.time()
            resend_ok = self.kickoff_otp_delivery("protocol_need_otp")
            if not resend_ok and mode not in ("passwordless_signup", "passwordless_login"):
                self.send_otp()
                otp_sent_at = time.time()

            otp_code = mail_provider.wait_for_otp(
                email,
                timeout=otp_timeout,
                issued_after=otp_sent_at,
            )
            try:
                otp_resp = self.verify_otp(otp_code)
                self.fetch_client_auth_session_dump("post_verify_otp_protocol")
            except RuntimeError as e:
                if any(code in str(e) for code in ("401", "409")):
                    logger.warning(f"OTP 首次验证失败，重发重试: {e}")
                    otp_sent_at = time.time()
                    if not self.kickoff_otp_delivery("protocol_verify_retry"):
                        self.send_otp()
                    otp_code = mail_provider.wait_for_otp(
                        email,
                        timeout=otp_timeout,
                        issued_after=otp_sent_at,
                    )
                    otp_resp = self.verify_otp(otp_code)
                    self.fetch_client_auth_session_dump("post_verify_otp_retry_protocol")
                else:
                    raise
            continue_url = self._extract_continue_url_from_step(otp_resp)
            continue_url = self._normalize_continue_url(continue_url)
            if self._is_add_phone_state(page_type=self._extract_page_type(otp_resp), continue_url=continue_url):
                continue_url = self._normalize_continue_url(
                    self._handle_add_phone_verification(continue_url=continue_url)
                )

        continue_url = self._normalize_continue_url(continue_url)
        # 某些边缘态 OTP 后未返回 callback，回退 reauthorize
        if not continue_url:
            continue_url = self._reauthorize_for_session(auth_url) or ""

        refresh_only_mode = self._env_flag("OAUTH_REFRESH_ONLY", "0")
        callback_url = ""
        if continue_url:
            continue_url = self._normalize_continue_url(continue_url)
            if (not self.result.refresh_token) and self._env_flag("OAUTH_CODEX_RT_BEFORE_CALLBACK", "0"):
                self.oauth_codex_rt_exchange(mail_provider=mail_provider)
            pre_exchange_default = "1" if refresh_only_mode else "0"
            pre_exchange = self._env_flag("OAUTH_EXCHANGE_BEFORE_CALLBACK", pre_exchange_default)
            if pre_exchange:
                self.oauth_token_exchange(continue_url, continue_url)
            callback_url, final_url = self.follow_redirect_chain(continue_url)
            if (not callback_url) and final_url and ("/workspace" in final_url):
                normalized = self._normalize_continue_url(final_url)
                if normalized and normalized != final_url:
                    callback_url, final_url = self.follow_redirect_chain(normalized)

        if not refresh_only_mode:
            if callback_url:
                self._consume_callback_for_session(callback_url)
            _, web_access_token = self.get_auth_session()
            self._post_login_capture_bootstrap(web_access_token)

        if callback_url or continue_url:
            self.fetch_client_auth_session_dump("pre_oauth_exchange_protocol")
            self.oauth_token_exchange(callback_url or "", continue_url or "")
            if (not self.result.refresh_token) and self._env_flag("OAUTH_CODEX_RT_EXCHANGE", "1"):
                self.oauth_codex_rt_exchange(mail_provider=mail_provider)
            if (not self.result.refresh_token) and self._env_flag("OAUTH_SECONDARY_AUTHORIZE_EXCHANGE", "0"):
                self.oauth_secondary_authorize_exchange()

        if refresh_only_mode:
            if not (self.result.refresh_token or self.result.access_token):
                raise RuntimeError("协议登录完成，但未拿到 refresh_token/access_token")
        elif not self.result.is_valid():
            raise RuntimeError("协议登录完成，但未拿到有效 session/access token")

        logger.info("纯协议登录流程完成")
        return self.result

    # ── 从已有凭证初始化 ──
    def from_existing_credentials(
        self, session_token: str, access_token: str, device_id: str
    ) -> AuthResult:
        """使用已有凭证（跳过注册）"""
        self.result.device_id = device_id or str(uuid.uuid4())
        self.session.cookies.set("oai-did", self.result.device_id, domain=".chatgpt.com")
        detected_email = ""

        # 如果有 session_token, 用它刷新 access_token (旧 access_token 可能已过期)
        if session_token:
            self.session.cookies.set(
                "__Secure-next-auth.session-token",
                session_token,
                domain=".chatgpt.com",
            )
            logger.info("使用 session_token 刷新 access_token...")
            try:
                headers = self._common_headers("https://chatgpt.com/")
                resp = self.session.get(
                    "https://chatgpt.com/api/auth/session",
                    headers=headers,
                    timeout=30,
                )
                session_data = resp.json() if resp is not None else {}
                new_access_token = session_data.get("accessToken", "")
                user_obj = session_data.get("user", {}) if isinstance(session_data, dict) else {}
                if isinstance(user_obj, dict):
                    detected_email = detected_email or (user_obj.get("email", "") or "")
                new_session_token = self.session.cookies.get("__Secure-next-auth.session-token", "")
                if new_access_token:
                    access_token = new_access_token
                    logger.info("access_token 刷新成功")
                else:
                    logger.warning(f"access_token 刷新失败 (status={resp.status_code}), 使用原 token")
                if new_session_token:
                    session_token = new_session_token
            except Exception as e:
                logger.warning(f"刷新 access_token 失败: {e}, 使用原 token")
        elif access_token:
            # 没有 session_token, 尝试通过 access_token 获取
            logger.info("未提供 session_token, 尝试通过 access_token 获取...")
            try:
                headers = self._common_headers("https://chatgpt.com/")
                headers["Authorization"] = f"Bearer {access_token}"
                resp = self.session.get(
                    "https://chatgpt.com/api/auth/session",
                    headers=headers,
                    timeout=30,
                )
                session_data = resp.json() if resp is not None else {}
                user_obj = session_data.get("user", {}) if isinstance(session_data, dict) else {}
                if isinstance(user_obj, dict):
                    detected_email = detected_email or (user_obj.get("email", "") or "")
                session_token = self.session.cookies.get("__Secure-next-auth.session-token", "")
                if session_token:
                    logger.info("通过 access_token 获取 session_token 成功")
                else:
                    logger.warning("未能获取 session_token, 可能需要手动提供")
            except Exception as e:
                logger.warning(f"获取 session_token 失败: {e}")

        self.result.access_token = access_token
        self.result.session_token = session_token
        if session_token:
            self.session.cookies.set(
                "__Secure-next-auth.session-token",
                session_token,
                domain=".chatgpt.com",
            )
        self.result.cookie_header = self._build_chatgpt_cookie_header()

        # 回填 email（skip-register 模式下常用于账单 email）
        if not detected_email and access_token and access_token.count(".") >= 2:
            try:
                payload_b64 = access_token.split(".")[1]
                payload_b64 += "=" * (-len(payload_b64) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8"))
                prof = payload.get("https://api.openai.com/profile", {}) if isinstance(payload, dict) else {}
                if isinstance(prof, dict):
                    detected_email = detected_email or (prof.get("email", "") or "")
            except Exception:
                pass
        self.result.email = detected_email or ""
        logger.info("使用已有凭证初始化完成")
        return self.result

