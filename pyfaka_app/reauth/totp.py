import base64
import hashlib
import hmac
import re
import struct
import time


def normalize_secret(value: str) -> str:
    secret = str(value or "").strip().upper().rstrip("=")
    if not re.fullmatch(r"[A-Z2-7]+", secret):
        raise ValueError("2FA 密钥必须是有效的 Base32 字符串")
    try:
        decoded = base64.b32decode(secret + "=" * (-len(secret) % 8))
    except ValueError as exc:
        raise ValueError("2FA 密钥格式不正确") from exc
    if len(decoded) < 10:
        raise ValueError("2FA 密钥长度不足")
    return secret


def totp_code(secret: str, timestamp: float | None = None) -> dict:
    secret = normalize_secret(secret)
    now = int(time.time() if timestamp is None else timestamp)
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", now // 30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff
    return {"code": f"{number % 1000000:06d}", "expires_in": 30 - now % 30, "period": 30}
