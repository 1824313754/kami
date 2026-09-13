import json

from sqlalchemy import func
from sqlalchemy.orm import joinedload

from .models import FileRecord
from .reauth.totp import normalize_secret
from .services import BusinessError


def account_credentials(record) -> dict:
    raw = record.payload.reauth_info if record.payload else ""
    try:
        info = json.loads(raw or "{}")
    except ValueError:
        info = {}
    if not isinstance(info, dict):
        info = {}
    if not info.get("password") or not info.get("totp_secret"):
        raise BusinessError(f"账号 {record.email_name} 尚未导入 2FA")
    return info


def import_two_factor(db, text: str, owner_id: int, business_type: str, group_tag: str) -> dict:
    entries = {}
    for line_number, line in enumerate(text.lstrip("\ufeff").splitlines(), 1):
        if not line.strip():
            continue
        parts = line.strip().split("--")
        if len(parts) != 3 or not all(parts):
            raise BusinessError(f"第 {line_number} 行格式错误，应为邮箱--密码--2FA密钥")
        email, password, secret = parts
        email = email.strip().lower()
        if "@" not in email or any(char.isspace() for char in email):
            raise BusinessError(f"第 {line_number} 行邮箱格式错误")
        try:
            secret = normalize_secret(secret)
        except ValueError as exc:
            raise BusinessError(f"第 {line_number} 行：{exc}") from exc
        entries[email] = {"password": password, "totp_secret": secret}
    if not entries:
        raise BusinessError("请输入 2FA 数据")
    records = []
    emails = list(entries)
    for offset in range(0, len(emails), 500):
        records.extend(db.query(FileRecord).options(joinedload(FileRecord.payload)).filter(
            FileRecord.uploaded_by == owner_id,
            FileRecord.business_type == business_type,
            FileRecord.group_tag == group_tag,
            func.lower(FileRecord.email_name).in_(emails[offset:offset + 500]),
        ).all())
    matched = {record.email_name.lower() for record in records if record.payload}
    missing = [email for email in emails if email not in matched]
    for record in records:
        if not record.payload:
            continue
        try:
            old = json.loads(record.payload.reauth_info or "{}")
        except ValueError:
            old = {}
        info = dict(entries[record.email_name.lower()])
        if isinstance(old, dict):
            for key in ("oauth_blocked_reason", "oauth_blocked_at"):
                if old.get(key):
                    info[key] = old[key]
        record.payload.reauth_info = json.dumps(info, ensure_ascii=False, separators=(",", ":"))
    db.flush()
    return {"matched_accounts": len(matched), "updated_records": sum(bool(record.payload) for record in records), "skipped_accounts": len(missing)}


def two_factor_txt(files) -> bytes:
    lines = []
    seen = set()
    for record in files:
        email = record.email_name.strip().lower()
        if email in seen:
            continue
        info = account_credentials(record)
        lines.append(f"{email}--{info['password']}--{info['totp_secret']}")
        seen.add(email)
    if not lines:
        raise BusinessError("当前卡密没有可下载的 2FA 账号")
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")
