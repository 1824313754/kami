import base64
import hashlib
import hmac
import re

from cryptography.fernet import Fernet, InvalidToken
from werkzeug.security import check_password_hash, generate_password_hash

from .models import Cdkey

PASSWORD_FAILURE_LIMIT = 10


class CdkeyPasswordError(ValueError):
    def __init__(self, message, code, status):
        super().__init__(message)
        self.code = code
        self.status = status


def validate_cdkey_password(password):
    if not isinstance(password, str) or not re.fullmatch(r"(?=.*[A-Za-z])(?=.*[0-9])[A-Za-z0-9]{6,}", password):
        raise CdkeyPasswordError("提取密码至少 6 位，必须同时包含英文字母和数字", "PASSWORD_FORMAT", 400)


def password_cipher(secret_key):
    key = secret_key.encode("utf-8") if isinstance(secret_key, str) else secret_key
    derived = hmac.digest(key, b"pyfaka-cdkey-password-v1", hashlib.sha256)
    return Fernet(base64.urlsafe_b64encode(derived))


def decrypt_cdkey_password(ciphertext, secret_key):
    try:
        return password_cipher(secret_key).decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise CdkeyPasswordError("提取密码记录无法解密，请检查服务端密钥是否变更", "PASSWORD_DECRYPT_FAILED", 409) from exc


def verify_cdkey_password(db, cdkeys, password, *, secret_key, allow_setup=False):
    validate_cdkey_password(password)
    cards = sorted(cdkeys, key=lambda item: item.id)
    try:
        # Lock rows before checking. A no-op UPDATE also serializes SQLite
        # writers, where SELECT FOR UPDATE alone would not protect the counter.
        for card in cards:
            db.query(Cdkey).filter(Cdkey.id == card.id).update(
                {Cdkey.access_password_failures: Cdkey.access_password_failures, Cdkey.updated_at: Cdkey.updated_at},
                synchronize_session=False,
            )
            db.refresh(card, with_for_update=True)
        if any(card.access_admin_locked for card in cards):
            raise CdkeyPasswordError("卡密已被管理员锁定，请联系管理员解锁", "CDKEY_ADMIN_LOCKED", 423)
        if any(card.access_password_failures >= PASSWORD_FAILURE_LIMIT for card in cards):
            raise CdkeyPasswordError("卡密已锁定，请联系管理员解锁", "PASSWORD_LOCKED", 423)
        for card in cards:
            if card.access_password_hash:
                if not check_password_hash(card.access_password_hash, password):
                    card.access_password_failures += 1
                    locked = card.access_password_failures >= PASSWORD_FAILURE_LIMIT
                    db.commit()
                    if locked:
                        raise CdkeyPasswordError("卡密已锁定，请联系管理员解锁", "PASSWORD_LOCKED", 423)
                    raise CdkeyPasswordError("卡密或提取密码不正确", "PASSWORD_INCORRECT", 403)
            elif not allow_setup:
                raise CdkeyPasswordError("请先到卡密提取模块设置该卡密的提取密码", "PASSWORD_NOT_SET", 409)
        pending = [card for card in cards if not card.access_password_hash]
        if pending:
            password_hash = generate_password_hash(password)
            for card in pending:
                card.access_password_hash = password_hash
                card.access_password_ciphertext = password_cipher(secret_key).encrypt(password.encode("utf-8")).decode("ascii")
        versions = {str(card.id): card.access_password_version for card in cards}
        db.commit()
        return versions
    except Exception:
        db.rollback()
        raise
