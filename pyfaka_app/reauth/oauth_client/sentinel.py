"""OpenAI Sentinel token entry points.

The public helpers execute the captured Sentinel SDK and fail closed when the
SDK, challenge, Turnstile, or session-observer calculation fails. The older
pure-Python generator functions remain only for direct compatibility and unit
testing; registration no longer falls back to them automatically.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import random
import time
import uuid
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


SENTINEL_REQ_URL = "https://sentinel.openai.com/backend-api/sentinel/req"
SENTINEL_REFERER = "https://sentinel.openai.com/backend-api/sentinel/frame.html"
SENTINEL_SDK_URL = "https://sentinel.openai.com/sentinel/20260810913b/sdk.js"

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36"
)
DEFAULT_SEC_CH_UA = (
    '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"'
)


class SentinelTokenGenerator:
    """Sentinel Token 纯 Python 生成器。

    - 不依赖 Node / JS。
    - `t` 字段固定空串；上游接口（`/sentinel/req`）的返回会判定能否接受。
    """

    MAX_ATTEMPTS = 500000
    ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

    def __init__(
        self,
        device_id: str | None = None,
        user_agent: str | None = None,
        screen: str = "",
        lang: str = "",
        lang_full: str = "",
    ):
        self.device_id = device_id or str(uuid.uuid4())
        self.user_agent = user_agent or DEFAULT_UA
        self.screen = screen or "1920x1080"
        self.lang = lang or "en-US"
        self.lang_full = lang_full or "en-US,en"
        self.requirements_seed = str(random.random())
        self.sid = str(uuid.uuid4())

    @staticmethod
    def _fnv1a_32(text: str) -> str:
        h = 2166136261
        for ch in text:
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        h ^= h >> 16
        h = (h * 2246822507) & 0xFFFFFFFF
        h ^= h >> 13
        h = (h * 3266489909) & 0xFFFFFFFF
        h ^= h >> 16
        return format(h & 0xFFFFFFFF, "08x")

    def _get_config(self) -> list:
        now = datetime.now(timezone.utc)
        date_str = now.strftime("%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)")
        perf_now = random.uniform(1000, 50000)
        time_origin = time.time() * 1000 - perf_now
        nav_prop = random.choice([
            "vendorSub", "productSub", "vendor", "maxTouchPoints",
            "scheduling", "userActivation", "doNotTrack", "geolocation",
            "connection", "plugins", "mimeTypes", "pdfViewerEnabled",
            "webkitTemporaryStorage", "webkitPersistentStorage",
            "hardwareConcurrency", "cookieEnabled", "credentials",
            "mediaDevices", "permissions", "locks", "ink",
        ])
        return [
            self.screen,
            date_str,
            4294705152,
            random.random(),
            self.user_agent,
            SENTINEL_SDK_URL,
            None,
            None,
            self.lang,
            self.lang_full,
            random.random(),
            f"{nav_prop}−undefined",
            random.choice(["location", "implementation", "URL", "documentURI", "compatMode"]),
            random.choice(["Object", "Function", "Array", "Number", "parseFloat", "undefined"]),
            perf_now,
            self.sid,
            "",
            random.choice([4, 8, 12, 16]),
            time_origin,
        ]

    @staticmethod
    def _base64_encode(data) -> str:
        raw = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return base64.b64encode(raw).decode("ascii")

    def _run_check(self, start_time, seed, difficulty, config, nonce):
        config[3] = nonce
        config[9] = round((time.time() - start_time) * 1000)
        encoded = self._base64_encode(config)
        digest = self._fnv1a_32(seed + encoded)
        if digest[: len(difficulty)] <= difficulty:
            return encoded + "~S"
        return None

    def generate_token(self, seed: str | None = None, difficulty: str | None = None) -> str:
        seed = seed or self.requirements_seed
        difficulty = difficulty or "0"
        start_time = time.time()
        config = self._get_config()
        for nonce in range(self.MAX_ATTEMPTS):
            value = self._run_check(start_time, seed, difficulty, config, nonce)
            if value:
                return "gAAAAAB" + value
        return "gAAAAAB" + self.ERROR_PREFIX + self._base64_encode(str(None))

    def generate_requirements_token(self) -> str:
        config = self._get_config()
        config[3] = 1
        config[9] = round(random.uniform(5, 50))
        return "gAAAAAC" + self._base64_encode(config)


def fetch_sentinel_challenge(
    session,
    device_id: str,
    flow: str = "authorize_continue",
    user_agent: str | None = None,
    sec_ch_ua: str | None = None,
    impersonate: str | None = None,
    request_p: str | None = None,
    screen: str = "",
    lang: str = "",
    lang_full: str = "",
) -> dict | None:
    """POST `/sentinel/req` 并返回响应 JSON。失败返回 None。"""
    generator = SentinelTokenGenerator(
        device_id=device_id, user_agent=user_agent,
        screen=screen, lang=lang, lang_full=lang_full,
    )
    req_body = {
        "p": str(request_p or "").strip() or generator.generate_requirements_token(),
        "id": device_id,
        "flow": flow,
    }
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Referer": SENTINEL_REFERER,
        "Origin": "https://sentinel.openai.com",
        "User-Agent": user_agent or DEFAULT_UA,
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
    }
    if sec_ch_ua:
        headers["sec-ch-ua"] = sec_ch_ua
        headers["sec-ch-ua-mobile"] = "?0"
        headers["sec-ch-ua-platform"] = '"Windows"'
    kwargs = {"data": json.dumps(req_body), "headers": headers, "timeout": 20}
    if impersonate:
        kwargs["impersonate"] = impersonate
    try:
        response = session.post(SENTINEL_REQ_URL, **kwargs)
        if response.status_code == 200:
            return response.json()
        logger.warning(f"Sentinel /req 非 200: {response.status_code}")
    except Exception as exc:
        logger.warning(f"Sentinel /req 异常: {exc}")
        return None
    return None


def build_sentinel_token(
    session,
    device_id: str,
    flow: str = "authorize_continue",
    user_agent: str | None = None,
    sec_ch_ua: str | None = None,
    impersonate: str | None = None,
    screen: str = "",
    lang: str = "",
    lang_full: str = "",
) -> str | None:
    """完整 Sentinel token：fetch challenge → 用 server-given seed/difficulty 解 PoW → 拼装。

    返回 JSON 字符串，失败返回 None。
    """
    challenge = fetch_sentinel_challenge(
        session,
        device_id,
        flow=flow,
        user_agent=user_agent,
        sec_ch_ua=sec_ch_ua,
        impersonate=impersonate,
        screen=screen,
        lang=lang,
        lang_full=lang_full,
    )
    if not challenge:
        return None

    c_value = str(challenge.get("token") or "").strip()
    if not c_value:
        logger.warning("Sentinel 响应缺 token 字段")
        return None

    generator = SentinelTokenGenerator(
        device_id=device_id, user_agent=user_agent,
        screen=screen, lang=lang, lang_full=lang_full,
    )
    pow_data = challenge.get("proofofwork") or {}
    if pow_data.get("required") and pow_data.get("seed"):
        p_value = generator.generate_token(
            seed=pow_data.get("seed"),
            difficulty=pow_data.get("difficulty", "0"),
        )
    else:
        p_value = generator.generate_requirements_token()

    payload = {
        "p": p_value,
        "t": "",
        "c": c_value,
        "id": device_id,
        "flow": flow,
    }
    return json.dumps(payload, separators=(",", ":"))


def get_sentinel_tokens(
    session,
    device_id: str,
    flow: str = "authorize_continue",
    user_agent: str = DEFAULT_UA,
    sec_ch_ua: str = "",
    screen: str = "",
    lang: str = "",
    lang_full: str = "",
    *,
    runtime_fingerprint: dict | None = None,
) -> dict[str, str]:
    """Return SDK-generated tokens or fail the current auth flow."""
    if os.environ.get("OPENAI_SENTINEL_DISABLE_QUICKJS"):
        raise RuntimeError("Sentinel SDK execution is disabled")

    from .sentinel_quickjs import get_sentinel_tokens_via_quickjs

    runtime_payload = dict(runtime_fingerprint or {})
    if sec_ch_ua:
        runtime_payload.setdefault("sec_ch_ua", sec_ch_ua)
    try:
        tokens = get_sentinel_tokens_via_quickjs(
            session,
            device_id=device_id,
            flow=flow,
            user_agent=user_agent,
            screen=screen,
            lang=lang,
            lang_full=lang_full,
            runtime_fingerprint=runtime_payload,
            log=lambda message: logger.info(message),
        )
    except Exception as exc:
        raise RuntimeError(f"Sentinel SDK token generation failed: {exc}") from exc
    if not tokens.get("sentinel_token"):
        raise RuntimeError("Sentinel SDK did not return a token")
    logger.info(
        "Sentinel Token assembled (SDK main=%s SO=%s)",
        len(tokens["sentinel_token"]),
        len(tokens.get("so_token") or ""),
    )
    return tokens


def get_sentinel_token(
    session,
    device_id: str,
    flow: str = "authorize_continue",
    user_agent: str = DEFAULT_UA,
    sec_ch_ua: str = "",
    screen: str = "",
    lang: str = "",
    lang_full: str = "",
    *,
    runtime_fingerprint: dict | None = None,
) -> str:
    return get_sentinel_tokens(
        session,
        device_id=device_id,
        flow=flow,
        user_agent=user_agent,
        sec_ch_ua=sec_ch_ua,
        screen=screen,
        lang=lang,
        lang_full=lang_full,
        runtime_fingerprint=runtime_fingerprint,
    )["sentinel_token"]
