"""Sentinel token generation through bundled SDK files and Node runtimes."""
from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import queue
import re
import secrets
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


SENTINEL_VERSION = "20260810913b"
SENTINEL_SDK_FILENAME = f"sentinel_sdk_{SENTINEL_VERSION}.js"
SENTINEL_SDK_URL = f"https://sentinel.openai.com/sentinel/{SENTINEL_VERSION}/sdk.js"
SENTINEL_REQ_URL = "https://sentinel.openai.com/backend-api/sentinel/req"
SENTINEL_SDK_ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"
CHATGPT_SENTINEL_ORIGIN = "https://chatgpt.com"
CHATGPT_SENTINEL_SDK_URL = (
    f"{CHATGPT_SENTINEL_ORIGIN}/sentinel/{SENTINEL_VERSION}/sdk.js"
)
CHATGPT_CHAT_REQUIREMENTS_PREPARE_URL = (
    f"{CHATGPT_SENTINEL_ORIGIN}/backend-api/sentinel/chat-requirements/prepare"
)
CHATGPT_CHAT_REQUIREMENTS_FINALIZE_URL = (
    f"{CHATGPT_SENTINEL_ORIGIN}/backend-api/sentinel/chat-requirements/finalize"
)


@dataclass(frozen=True)
class _BundledSentinelSdk:
    file: Path
    url: str
    version: str

    @property
    def frame_url(self) -> str:
        return f"https://sentinel.openai.com/backend-api/sentinel/frame.html?sv={self.version}"


def _resolve_node_binary() -> str:
    return (os.getenv("OPENAI_SENTINEL_NODE_PATH", "") or "").strip() or "node"


def _solver_script_path() -> Path:
    return Path(__file__).resolve().with_name("sentinel_solver.js")


def _bundled_sentinel_sdk(
    *,
    sdk_url: str = SENTINEL_SDK_URL,
) -> _BundledSentinelSdk:
    sdk_file = _solver_script_path().with_name(SENTINEL_SDK_FILENAME)
    if not sdk_file.is_file():
        raise RuntimeError(f"Bundled Sentinel SDK does not exist: {sdk_file}")
    return _BundledSentinelSdk(
        file=sdk_file,
        url=sdk_url,
        version=SENTINEL_VERSION,
    )


def _fingerprint_request_headers(runtime_fingerprint: Optional[dict]) -> dict[str, str]:
    profile = runtime_fingerprint if isinstance(runtime_fingerprint, dict) else {}
    headers: dict[str, str] = {}
    for header_name, field_name in (
        ("sec-ch-ua", "sec_ch_ua"),
        ("sec-ch-ua-mobile", "sec_ch_ua_mobile"),
        ("sec-ch-ua-platform", "sec_ch_ua_platform"),
    ):
        value = str(profile.get(field_name) or "").strip()
        if value:
            headers[header_name] = value
    return headers


def _safari_version(user_agent: str) -> tuple[int, int] | None:
    if "Safari/" not in user_agent or re.search(
        r"(?:Chrome|Chromium|CriOS|Edg|OPR|Electron)/",
        user_agent,
        re.IGNORECASE,
    ):
        return None
    match = re.search(r"Version/(\d+)(?:\.(\d+))?", user_agent)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2) or 0)


def _supports_fetch_metadata(user_agent: str) -> bool:
    safari_version = _safari_version(user_agent)
    return safari_version is None or safari_version >= (16, 4)


class _SentinelSolverSession:
    def __init__(
        self,
        *,
        sdk_file: Path,
        solver_script: Path,
        timezone_name: str = "",
    ):
        env = {**os.environ, "SENTINEL_SDK_FILE": str(sdk_file)}
        if timezone_name:
            env["TZ"] = timezone_name
        self._process = subprocess.Popen(
            [_resolve_node_binary(), str(solver_script), "--server"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
            env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
        )
        self._responses: queue.Queue[str | None] = queue.Queue()
        self._stderr_tail = ""
        self._next_id = 1
        self._closed = False
        self._request_lock = threading.Lock()
        self._stdout_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self._stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self._stdout_thread.start()
        self._stderr_thread.start()

    def _read_stdout(self) -> None:
        try:
            assert self._process.stdout is not None
            for line in self._process.stdout:
                self._responses.put(line)
        finally:
            self._responses.put(None)

    def _read_stderr(self) -> None:
        assert self._process.stderr is not None
        for line in self._process.stderr:
            self._stderr_tail = (self._stderr_tail + line)[-65536:]

    def request(self, action: str, payload: dict, timeout_ms: int) -> dict:
        with self._request_lock:
            if self._closed or self._process.poll() is not None:
                raise RuntimeError(
                    f"Sentinel solver is not running: {self._stderr_tail.strip() or 'no stderr'}"
                )
            message_id = self._next_id
            self._next_id += 1
            assert self._process.stdin is not None
            self._process.stdin.write(
                json.dumps(
                    {"id": message_id, "action": action, "payload": payload},
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            )
            self._process.stdin.flush()
            try:
                line = self._responses.get(timeout=max(10, timeout_ms / 1000 + 5))
            except queue.Empty as exc:
                self._abort()
                raise subprocess.TimeoutExpired("Sentinel solver", timeout_ms / 1000) from exc
            if line is None:
                raise RuntimeError(
                    f"Sentinel solver exited early: {self._stderr_tail.strip() or 'no stderr'}"
                )
            response = json.loads(line)
            if response.get("id") != message_id:
                raise RuntimeError("Sentinel solver response id mismatch")
            if not response.get("ok"):
                error = response.get("error") if isinstance(response.get("error"), dict) else {}
                code = str(error.get("code") or "SOLVER_ERROR")
                message = str(error.get("message") or "Sentinel solver failed")
                raise RuntimeError(f"{code}: {message}")
            result = response.get("result")
            if not isinstance(result, dict):
                raise RuntimeError("Sentinel solver result is not an object")
            return result

    def _abort(self) -> None:
        if self._process.poll() is None:
            self._process.kill()

    def close(self) -> None:
        with self._request_lock:
            if self._closed:
                return
            self._closed = True
            if self._process.poll() is None:
                try:
                    assert self._process.stdin is not None
                    self._process.stdin.write(
                        json.dumps(
                            {"id": self._next_id, "action": "shutdown", "payload": {}},
                            separators=(",", ":"),
                        )
                        + "\n"
                    )
                    self._process.stdin.flush()
                    self._process.wait(timeout=2)
                except Exception:
                    if self._process.poll() is None:
                        self._process.terminate()
                        try:
                            self._process.wait(timeout=1)
                        except subprocess.TimeoutExpired:
                            self._process.kill()
                            self._process.wait(timeout=1)
            self._stdout_thread.join(timeout=0.5)
            self._stderr_thread.join(timeout=0.5)
            for stream in (self._process.stdin, self._process.stdout, self._process.stderr):
                try:
                    if stream is not None:
                        stream.close()
                except Exception:
                    pass


def _run_quickjs_action(
    *,
    action: str,
    sdk_file: Path,
    solver_script: Path,
    payload: dict,
    timeout_ms: int,
    solver_state: Optional[dict[str, Any]] = None,
) -> dict:
    if solver_state is not None:
        solver = solver_state.get("session")
        if solver is None:
            solver = _SentinelSolverSession(
                sdk_file=sdk_file,
                solver_script=solver_script,
                timezone_name=str(payload.get("timezone") or ""),
            )
            solver_state["session"] = solver
        return solver.request(action, payload, timeout_ms)

    body = dict(payload)
    body["action"] = action
    process_env = {**os.environ, "SENTINEL_SDK_FILE": str(sdk_file)}
    timezone_name = str(payload.get("timezone") or "").strip()
    if timezone_name:
        process_env["TZ"] = timezone_name
    behavior_timeout_seconds = max(0, int(payload.get("behavior_duration_ms") or 0)) / 1000
    proc = subprocess.run(
        [_resolve_node_binary(), str(solver_script)],
        input=json.dumps(body, ensure_ascii=False),
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=max(10, int(timeout_ms / 1000) + behavior_timeout_seconds + 5),
        env=process_env,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Sentinel SDK execution failed: {(proc.stderr or proc.stdout or 'unknown').strip()[:300]}"
        )
    output = (proc.stdout or "").strip()
    if not output:
        raise RuntimeError("Sentinel SDK returned empty output")
    result = json.loads(output)
    if not isinstance(result, dict):
        raise RuntimeError("Sentinel SDK output is not an object")
    return result


def _close_solver_state(solver_state: dict[str, Any]) -> None:
    solver = solver_state.pop("session", None)
    if solver is not None:
        solver.close()


def _fetch_sentinel_challenge(
    session: Any,
    *,
    device_id: str,
    flow: str,
    request_p: str,
    frame_url: str,
    timeout_ms: int,
    accept_language: str = "zh-CN,zh;q=0.9",
    user_agent: str = "",
    runtime_fingerprint: Optional[dict] = None,
) -> dict:
    body = {"p": request_p, "id": device_id, "flow": flow}
    is_safari = _safari_version(user_agent) is not None
    headers = {
        "origin": "https://sentinel.openai.com",
        "referer": frame_url,
        "content-type": "text/plain;charset=UTF-8",
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br" if is_safari else "gzip, deflate, br, zstd",
        "accept-language": accept_language,
    }
    if user_agent:
        headers["user-agent"] = user_agent
    headers.update(_fingerprint_request_headers(runtime_fingerprint))
    if _supports_fetch_metadata(user_agent):
        headers.update({
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
        })
    response = session.post(
        SENTINEL_REQ_URL,
        data=json.dumps(body, separators=(",", ":")),
        headers=headers,
        timeout=max(10, int(timeout_ms / 1000)),
    )
    if getattr(response, "status_code", 0) != 200:
        response_headers = getattr(response, "headers", {}) or {}
        try:
            request_id = (
                response_headers.get("x-oai-request-id", "")
                or response_headers.get("X-OAI-Request-Id", "")
                or ""
            )
        except Exception:
            request_id = ""
        body_text = str(getattr(response, "text", "") or "")[:300]
        raise RuntimeError(
            f"/sentinel/req HTTP {getattr(response, 'status_code', 0)}"
            f" req_id={request_id or '-'} body={body_text}"
        )
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError("Sentinel challenge response is not an object")
    return payload


def _host_page_url(flow: str) -> str:
    return {
        "authorize_continue": "https://auth.openai.com/create-account",
        "email_authorize_continue": "https://auth.openai.com/log-in",
        "pending_authorize_continue": "https://auth.openai.com/log-in?usernameKind=phone_number",
        "username_password_create": "https://auth.openai.com/create-account/password",
        "password_verify": "https://auth.openai.com/log-in/password",
        "email_otp_validate": "https://auth.openai.com/email-verification",
        "oauth_create_account": "https://auth.openai.com/about-you",
        "chat_requirements": "https://chatgpt.com/",
    }.get(flow, "https://auth.openai.com/create-account")


def _build_runtime_payload(
    *,
    device_id: str,
    flow: str,
    user_agent: str,
    screen: str,
    lang: str,
    lang_full: str,
    runtime_fingerprint: Optional[dict],
) -> dict:
    try:
        screen_width, screen_height = [int(value) for value in screen.lower().split("x", 1)]
    except Exception:
        screen_width, screen_height = 1366, 768
    languages = [
        part.split(";", 1)[0].strip()
        for part in (lang_full or lang or "zh-CN,zh").split(",")
        if part.strip()
    ]
    performance_now = 3000.0 + (uuid.uuid4().int % 3_000_000) / 100.0
    payload: dict[str, Any] = {
        "user_agent": user_agent or "Mozilla/5.0",
        "accept_language": lang_full or lang or "zh-CN,zh;q=0.9",
        "language": lang or (languages[0] if languages else "zh-CN"),
        "languages": languages,
        "screen_width": screen_width,
        "screen_height": screen_height,
        "performance_now": performance_now,
        "time_origin": time.time() * 1000 - performance_now,
    }
    if runtime_fingerprint:
        payload.update(dict(runtime_fingerprint))

    effective_ua = str(payload.get("user_agent") or "Mozilla/5.0")
    is_mac = "Macintosh" in effective_ua
    payload.setdefault("navigator_platform", "MacIntel" if is_mac else "Win32")
    payload.setdefault("navigator_vendor", "Apple Computer, Inc." if is_mac else "Google Inc.")
    payload.setdefault("is_mac", is_mac)
    payload.setdefault("fingerprint_seed", device_id)
    payload.setdefault("hardware_concurrency", 8)
    payload.setdefault("device_memory", 8)
    payload.setdefault("device_pixel_ratio", 2 if is_mac else 1)
    payload.setdefault("color_depth", 24)
    payload.setdefault("behavior_duration_ms", secrets.randbelow(1001) + 1000)
    payload.update(
        {
            "device_id": device_id,
            "flow": flow,
            "host_page_url": _host_page_url(flow),
        }
    )
    return payload


def _apply_sdk_metadata(payload: dict, sdk: _BundledSentinelSdk) -> dict:
    payload.update(
        {
            "sdk_version": sdk.version,
            "sdk_url": sdk.url,
            "requirements_sdk_url": sdk.url,
            "enforcement_sdk_url": sdk.url,
        }
    )
    return payload


def _validate_solved_tokens(
    *,
    solved: dict,
    challenge: dict,
    device_id: str,
    flow: str,
) -> dict[str, str]:
    token = str(solved.get("token_json") or "").strip()
    if not token:
        raise RuntimeError("Sentinel solve did not return token_json")
    try:
        token_payload = json.loads(token)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Sentinel token_json is invalid") from exc
    if not isinstance(token_payload, dict) or not str(token_payload.get("p") or ""):
        raise RuntimeError("Sentinel token_json is incomplete")
    final_p = str(solved.get("final_p") or "").strip()
    token_p = str(token_payload.get("p") or "").strip()
    if not final_p or token_p != final_p:
        raise RuntimeError("Sentinel final proof mismatch")
    if token_p.startswith("gAAAAAB" + SENTINEL_SDK_ERROR_PREFIX):
        raise RuntimeError("Sentinel final proof contains an SDK error")
    if token_payload.get("t") != solved.get("t"):
        raise RuntimeError("Sentinel turnstile proof mismatch")
    expected_challenge = str(challenge.get("token") or "")
    if str(token_payload.get("c") or "") != expected_challenge:
        raise RuntimeError("Sentinel token challenge mismatch")
    if str(token_payload.get("id") or "") != device_id:
        raise RuntimeError("Sentinel token device_id mismatch")
    if str(token_payload.get("flow") or "") != flow:
        raise RuntimeError("Sentinel token flow mismatch")
    turnstile = challenge.get("turnstile") or {}
    if turnstile.get("required") and not turnstile.get("dx"):
        raise RuntimeError("Sentinel required turnstile program is missing")
    if (turnstile.get("required") or turnstile.get("dx")) and not token_payload.get("t"):
        raise RuntimeError("Sentinel turnstile proof is missing")
    if token_payload.get("t"):
        encoded_turnstile = str(token_payload["t"]).strip()
        try:
            decoded_turnstile = base64.b64decode(
                encoded_turnstile + "=" * (-len(encoded_turnstile) % 4),
                validate=True,
            ).lstrip()
        except (binascii.Error, ValueError) as exc:
            raise RuntimeError("Sentinel turnstile proof is not valid Base64") from exc
        if re.match(rb"^(?:\d+:\s*)?[A-Za-z]*Error\b", decoded_turnstile):
            raise RuntimeError("Sentinel turnstile proof contains an SDK error")

    so_token = str(solved.get("session_observer_token") or "").strip()
    so_config = challenge.get("so") or {}
    so_required = bool(so_config.get("required"))
    if so_required and (
        not str(so_config.get("collector_dx") or "").strip()
        or not str(so_config.get("snapshot_dx") or "").strip()
    ):
        raise RuntimeError("Sentinel required session-observer programs are missing")
    if so_required and not so_token:
        raise RuntimeError("Sentinel session-observer token is missing")
    if so_token and flow != "chat_requirements":
        try:
            so_payload = json.loads(so_token)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Sentinel session-observer token is invalid") from exc
        if not isinstance(so_payload, dict) or not str(so_payload.get("so") or "").strip():
            raise RuntimeError("Sentinel session-observer payload is incomplete")
        if str(so_payload.get("c") or "") != expected_challenge:
            raise RuntimeError("Sentinel session-observer challenge mismatch")
        if str(so_payload.get("id") or "") != device_id:
            raise RuntimeError("Sentinel session-observer device_id mismatch")
        if str(so_payload.get("flow") or "") != flow:
            raise RuntimeError("Sentinel session-observer flow mismatch")
        encoded_so = str(so_payload["so"]).strip()
        try:
            decoded_so = base64.b64decode(
                encoded_so + "=" * (-len(encoded_so) % 4),
                validate=True,
            ).lstrip()
        except (binascii.Error, ValueError) as exc:
            raise RuntimeError("Sentinel session-observer proof is not valid Base64") from exc
        if re.match(rb"^(?:\d+:\s*)?[A-Za-z]*Error\b", decoded_so):
            raise RuntimeError("Sentinel session-observer proof contains an SDK error")
    return {"sentinel_token": token, "so_token": so_token}


def get_sentinel_tokens_via_quickjs(
    session: Any,
    device_id: str,
    *,
    flow: str = "authorize_continue",
    user_agent: str = "",
    screen: str = "",
    lang: str = "",
    lang_full: str = "",
    runtime_fingerprint: Optional[dict] = None,
    timeout_ms: int = 45000,
    log: Optional[Callable[[str], None]] = None,
) -> dict[str, str]:
    """Generate tokens with the fixed bundled SDK and two Node processes."""
    log = log or (lambda message: logger.info(message))
    solver_script = _solver_script_path()
    if not solver_script.exists():
        raise RuntimeError(f"Sentinel solver does not exist: {solver_script}")

    did = str(device_id or uuid.uuid4())
    base_payload = _build_runtime_payload(
        device_id=did,
        flow=flow,
        user_agent=user_agent,
        screen=screen,
        lang=lang,
        lang_full=lang_full,
        runtime_fingerprint=runtime_fingerprint,
    )
    accept_language = str(
        base_payload.get("accept_language") or lang_full or lang or "zh-CN,zh;q=0.9"
    )
    sdk = _bundled_sentinel_sdk()
    try:
        _apply_sdk_metadata(base_payload, sdk)
        requirements = _run_quickjs_action(
            action="requirements",
            sdk_file=sdk.file,
            solver_script=solver_script,
            payload=base_payload,
            timeout_ms=timeout_ms,
        )
        request_p = str(requirements.get("request_p") or "").strip()
        sid = str(requirements.get("sid") or "").strip()
        if not request_p or not sid:
            raise RuntimeError("Sentinel requirements response is incomplete")
        if request_p.startswith("gAAAAAC" + SENTINEL_SDK_ERROR_PREFIX):
            raise RuntimeError("Sentinel requirements proof contains an SDK error")

        challenge = _fetch_sentinel_challenge(
            session,
            device_id=did,
            flow=flow,
            request_p=request_p,
            frame_url=sdk.frame_url,
            timeout_ms=timeout_ms,
            accept_language=accept_language,
            user_agent=str(base_payload.get("user_agent") or ""),
            runtime_fingerprint=base_payload,
        )
        if not str(challenge.get("token") or "").strip():
            raise RuntimeError("Sentinel challenge token is empty")

        solved = _run_quickjs_action(
            action="solve",
            sdk_file=sdk.file,
            solver_script=solver_script,
            payload={
                **base_payload,
                "request_p": request_p,
                "sid": sid,
                "runtime_state": requirements.get("runtime_state") or {},
                "challenge": challenge,
            },
            timeout_ms=timeout_ms,
        )
        tokens = _validate_solved_tokens(
            solved=solved,
            challenge=challenge,
            device_id=did,
            flow=flow,
        )
        log(
            "Sentinel SDK success "
            f"(token_len={len(tokens['sentinel_token'])} "
            f"so_len={len(tokens['so_token'])} c_len={len(str(challenge.get('token') or ''))})"
        )
        return tokens
    except Exception as exc:
        log(f"Sentinel SDK failed closed: {exc}")
        raise


def _json_object_response(response: Any, label: str) -> dict:
    status_code = int(getattr(response, "status_code", 0) or 0)
    if status_code != 200:
        body = str(getattr(response, "text", "") or "")[:300]
        raise RuntimeError(f"{label} HTTP {status_code}: {body}")
    try:
        payload = response.json()
    except Exception as exc:
        raise RuntimeError(f"{label} response is not JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"{label} response is not an object")
    return payload


def get_chat_requirements_tokens_via_quickjs(
    session: Any,
    device_id: str,
    *,
    headers_factory: Callable[[str], dict[str, str]],
    user_agent: str = "",
    screen: str = "",
    lang: str = "",
    lang_full: str = "",
    runtime_fingerprint: Optional[dict] = None,
    timeout_ms: int = 45000,
    log: Optional[Callable[[str], None]] = None,
) -> dict[str, Any]:
    """Complete ChatGPT's chat-requirements prepare/finalize exchange."""
    log = log or (lambda message: logger.info(message))
    solver_script = _solver_script_path()
    if not solver_script.exists():
        raise RuntimeError(f"Sentinel solver does not exist: {solver_script}")

    did = str(device_id or uuid.uuid4())
    base_payload = _build_runtime_payload(
        device_id=did,
        flow="chat_requirements",
        user_agent=user_agent,
        screen=screen,
        lang=lang,
        lang_full=lang_full,
        runtime_fingerprint=runtime_fingerprint,
    )
    timeout = max(10, int(timeout_ms / 1000))
    sdk = _bundled_sentinel_sdk(sdk_url=CHATGPT_SENTINEL_SDK_URL)
    solver_state: dict[str, Any] = {}
    try:
        _apply_sdk_metadata(base_payload, sdk)
        requirements = _run_quickjs_action(
            action="chat_requirements",
            sdk_file=sdk.file,
            solver_script=solver_script,
            payload=base_payload,
            timeout_ms=timeout_ms,
            solver_state=solver_state,
        )
        request_p = str(requirements.get("request_p") or "").strip()
        sid = str(requirements.get("sid") or "").strip()
        if not request_p:
            raise RuntimeError("Chat requirements proof is empty")
        if request_p.startswith("gAAAAAC" + SENTINEL_SDK_ERROR_PREFIX):
            raise RuntimeError("Chat requirements proof contains an SDK error")

        prepare_path = "/backend-api/sentinel/chat-requirements/prepare"
        prepare_response = session.post(
            CHATGPT_CHAT_REQUIREMENTS_PREPARE_URL,
            json={"p": request_p},
            headers=headers_factory(prepare_path),
            timeout=timeout,
        )
        challenge = _json_object_response(
            prepare_response,
            "Chat requirements prepare",
        )
        prepare_token = str(challenge.get("prepare_token") or "").strip()
        if not prepare_token:
            raise RuntimeError("Chat requirements prepare token is empty")

        solved = _run_quickjs_action(
            action="solve",
            sdk_file=sdk.file,
            solver_script=solver_script,
            payload={
                **base_payload,
                "request_p": request_p,
                "sid": sid,
                "challenge": challenge,
            },
            timeout_ms=timeout_ms,
            solver_state=solver_state,
        )
        proof_token = str(solved.get("final_p") or "").strip()
        turnstile_token = str(solved.get("t") or "").strip()
        if not proof_token:
            raise RuntimeError("Chat requirements proof token is empty")
        turnstile = challenge.get("turnstile") or {}
        if isinstance(turnstile, dict) and turnstile.get("required") and not turnstile_token:
            raise RuntimeError("Chat requirements turnstile token is empty")

        finalize_path = "/backend-api/sentinel/chat-requirements/finalize"
        finalize_response = session.post(
            CHATGPT_CHAT_REQUIREMENTS_FINALIZE_URL,
            json={
                "prepare_token": prepare_token,
                "proofofwork": proof_token,
                "turnstile": turnstile_token,
            },
            headers=headers_factory(finalize_path),
            timeout=timeout,
        )
        finalized = _json_object_response(
            finalize_response,
            "Chat requirements finalize",
        )
        requirements_token = str(finalized.get("token") or "").strip()
        if not requirements_token:
            raise RuntimeError("Chat requirements final token is empty")
        log(
            "Chat requirements SDK success "
            f"(requirements_len={len(requirements_token)} "
            f"proof_len={len(proof_token)} turnstile_len={len(turnstile_token)})"
        )
        return {
            "chat_requirements_token": requirements_token,
            "proof_token": proof_token,
            "turnstile_token": turnstile_token,
            "expire_after": finalized.get("expire_after"),
            "expire_at": finalized.get("expire_at"),
        }
    except Exception as exc:
        log(f"Chat requirements SDK failed closed: {exc}")
        raise
    finally:
        _close_solver_state(solver_state)


def get_sentinel_token_via_quickjs(
    session: Any,
    device_id: str,
    *,
    flow: str = "authorize_continue",
    runtime_fingerprint: Optional[dict] = None,
    timeout_ms: int = 45000,
    log: Optional[Callable[[str], None]] = None,
) -> str:
    tokens = get_sentinel_tokens_via_quickjs(
        session,
        device_id,
        flow=flow,
        runtime_fingerprint=runtime_fingerprint,
        timeout_ms=timeout_ms,
        log=log,
    )
    return tokens["sentinel_token"]
