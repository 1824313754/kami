"""Offline 2FA import, authorization, TXT export, and OAuth MFA regression checks."""
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

workspace = Path(tempfile.mkdtemp(prefix="pyfaka-two-factor-"))
os.environ["PYFAKA_DATABASE_URL"] = f"sqlite:///{(workspace / 'test.sqlite3').as_posix()}"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from flask import Flask
from sqlalchemy.orm import sessionmaker
from werkzeug.security import generate_password_hash
from pyfaka_app import routes
from pyfaka_app.database import Base, engine, SessionLocal
from pyfaka_app.models import AdminUser, AuditLog, Cdkey, CdkeyBatch, FileRecord, FileRecordPayload
from pyfaka_app.services import BusinessError, payload_to_db_fields, payload_for_record
from pyfaka_app.reauth.totp import normalize_secret, totp_code
from pyfaka_app.reauth.oauth_client.auth_flow import AuthFlow, AuthResult, EmailOtpValidationError
from pyfaka_app.two_factor import import_two_factor, two_factor_txt

SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # RFC 6238 public test vector
routes.DATA_DIR = workspace
routes.JOB_HISTORY_PATH = workspace / "task_history.json"


def expect_error(fn, text):
    try:
        fn()
    except (BusinessError, ValueError, RuntimeError) as exc:
        assert text in str(exc), str(exc)
    else:
        raise AssertionError("expected error: " + text)


def check_totp():
    for timestamp, expected in [(59, "287082"), (1111111109, "081804"), (1111111111, "050471"), (1234567890, "005924"), (2000000000, "279037"), (20000000000, "353130")]:
        assert totp_code(SECRET, timestamp)["code"] == expected
    assert totp_code(SECRET, 59)["expires_in"] == 1
    assert totp_code(SECRET, 60)["expires_in"] == 30
    assert normalize_secret(SECRET.lower()) == SECRET
    for invalid in ["", "bad-secret", "123456", "A", "AAAA"]:
        expect_error(lambda: normalize_secret(invalid), "2FA")


def check_mfa():
    flow = AuthFlow.__new__(AuthFlow)
    flow.result = AuthResult()
    flow._totp_secret = SECRET
    flow._auth_json_headers = lambda referer: {"Referer": referer}
    calls = []
    step = {"page": {"type": "mfa_challenge", "payload": {"factors": [{"id": "factor-test", "factor_type": "totp"}]}}, "continue_url": "https://auth.openai.com/mfa-challenge"}
    completed = {"page": {"type": "external_url", "payload": {"url": "https://auth.openai.com/consent"}}}

    def post(url, **kwargs):
        calls.append((url, kwargs["json"]))
        assert "mail" not in url
        assert kwargs["json"]["id"] == "factor-test" and kwargs["json"]["type"] == "totp"
        if url.endswith("/mfa/verify"):
            assert kwargs["json"]["code"] == "287082"
        return SimpleNamespace(status_code=200, json=lambda: completed)

    flow.session = SimpleNamespace(post=post)
    with patch("pyfaka_app.reauth.totp.time.time", return_value=59):
        assert flow._complete_totp_login_step(step) == completed
    assert [url.rsplit("/", 1)[-1] for url, _ in calls] == ["issue_challenge", "verify"]
    calls.clear()
    email_step = {"page": {"type": "email_otp_verification"}, "continue_url": "https://auth.openai.com/email-verification"}
    expect_error(lambda: flow._complete_totp_login_step(email_step), "邮箱验证")
    assert calls == []
    flow.fetch_client_auth_session_dump = lambda _: {"client_auth_session": {"mfa_factors": [{"id": "factor-test", "factor_type": "totp"}]}}
    with patch("pyfaka_app.reauth.totp.time.time", return_value=59):
        assert flow._complete_totp_login_step({"page": {"type": "mfa_challenge"}}) == completed
    # Upstream may identify the selected authenticator directly instead of listing factors.
    def unexpected_dump(_):
        raise AssertionError("factor_id must not require a session lookup")

    flow.fetch_client_auth_session_dump = unexpected_dump
    for payload in [
        {"factor_id": "factor-test"},
        {"factor_id": "factor-test", "factors": [{"id": "other-factor", "factor_type": "totp"}]},
    ]:
        calls.clear()
        with patch("pyfaka_app.reauth.totp.time.time", return_value=59):
            assert flow._complete_totp_login_step({"page": {"type": "mfa_challenge", "payload": payload}}) == completed
        assert [url.rsplit("/", 1)[-1] for url, _ in calls] == ["issue_challenge", "verify"]

    calls.clear()
    with patch("pyfaka_app.reauth.totp.time.time", return_value=59):
        assert flow._complete_totp_login_step({"page": {"type": "mfa_challenge"}, "oai-client-auth-session": {"mfa_factors": [{"id": "factor-test", "factor_type": "totp"}]}}) == completed
    flow.fetch_client_auth_session_dump = lambda _: {"client_auth_session": {}}
    calls.clear()
    expect_error(lambda: flow._complete_totp_login_step({"page": {"type": "mfa_challenge"}}), "2FA")
    assert calls == []
    flow.get_csrf_token = lambda: "csrf"
    flow.get_auth_url = lambda _: "https://auth.openai.com/authorize"
    flow.auth_oauth_init = lambda _: "device"
    flow.get_sentinel_token = lambda _: "sentinel"
    flow.authorize_continue = lambda **_: {"page": {"type": "login_password"}}
    passwords = []
    flow.login_password_verify = lambda value: passwords.append(value) or step
    flow.follow_redirect_chain = lambda _: ("http://localhost/callback?code=test", "")
    flow._normalize_continue_url = lambda value: value
    flow.oauth_token_exchange = lambda *_: setattr(flow.result, "refresh_token", "new-refresh")
    with patch("pyfaka_app.reauth.totp.time.time", return_value=59):
        result = flow.run_totp_login("USER@example.com", "account-password", SECRET)
    assert passwords == ["account-password"] and result.refresh_token == "new-refresh"
    # A rejected MFA code must never continue to token exchange.
    flow.session = SimpleNamespace(post=lambda url, **_: SimpleNamespace(status_code=403 if url.endswith("/verify") else 200))
    try:
        flow._complete_totp_login_step(step)
    except EmailOtpValidationError as exc:
        assert exc.status_code == 403
    else:
        raise AssertionError("rejected MFA was accepted")
    flow.session = SimpleNamespace(post=lambda url, **_: SimpleNamespace(status_code=429, json=lambda: {"error": {"code": "rate_limit_exceeded"}}))
    expect_error(lambda: flow._complete_totp_login_step(step), "rate_limit_exceeded")


def check_api_and_download():
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    owner = AdminUser(username="owner", password_hash=generate_password_hash("test-password"), cdkey_prefix="A", is_admin=False)
    other = AdminUser(username="other", password_hash="unused", cdkey_prefix="B", is_admin=False)
    db.add_all([owner, other])
    db.flush()
    batch = CdkeyBatch(batch_no="two-factor", prefix="A", key_date="20260912", total_count=2, files_per_key=1, created_by=owner.id)
    db.add(batch)
    db.flush()
    card = Cdkey(batch_id=batch.id, code="CARD-A", files_per_key=1, extract_status="DONE")
    other_card = Cdkey(batch_id=batch.id, code="CARD-B", files_per_key=1, extract_status="DONE")
    db.add_all([card, other_card])
    db.flush()

    def add(email, owner_id, card_id, group="default"):
        record = FileRecord(email_name=email, original_filename=email + ".json", uploaded_by=owner_id, business_type="free", group_tag=group, status="BOUND", bound_cdkey_id=card_id)
        record.payload = FileRecordPayload(**payload_to_db_fields({"email": email, "access_token": "unchanged", "refresh_token": "unchanged-refresh"}))
        db.add(record)
        db.flush()
        return record

    record = add("Mixed@Example.com", owner.id, card.id)
    second = add("second@example.com", owner.id, other_card.id)
    foreign = add("Mixed@Example.com", other.id, other_card.id)
    outside_group = add("Mixed@Example.com", owner.id, other_card.id, "other")
    db.commit()
    app = Flask(__name__)
    app.config.update(SECRET_KEY="test-session", TESTING=True)
    app.register_blueprint(routes.bp)
    client = app.test_client()
    request_payload = {"text": f"\ufeffMIXED@example.com--account-password--{SECRET.lower()}\r\n\r\nsecond@example.com--second-password--{SECRET}", "business_type": "free", "group_tag": "default", "owner_id": other.id}
    assert client.post("/api/admin/files/import-2fa", json=request_payload).status_code in {400, 401, 403}
    login = client.post("/api/admin/login", json={"username": "owner", "password": "test-password"})
    assert login.status_code == 200
    csrf = {"X-CSRF-Token": login.get_json()["session"]["csrf_token"]}
    assert client.post("/api/admin/files/import-2fa", json=request_payload).status_code == 400
    response = client.post("/api/admin/files/import-2fa", json=request_payload, headers=csrf)
    assert response.status_code == 200, response.get_json()
    assert response.get_json()["matched_accounts"] == 2
    db.expire_all()
    assert record.payload.access_token == "unchanged" and record.status == "BOUND" and record.bound_cdkey_id == card.id
    assert foreign.payload.reauth_info == "" and outside_group.payload.reauth_info == ""
    assert SECRET not in response.get_data(as_text=True) and "account-password" not in response.get_data(as_text=True)
    assert all(SECRET not in (log.detail or "") for log in db.query(AuditLog).all())
    original = record.payload.reauth_info
    for text, error in [
        (f"mixed@example.com--changed--{SECRET}\nmissing@example.com--p--{SECRET}", "未匹配"),
        (f"mixed@example.com--p--{SECRET}\nMIXED@example.com--p--{SECRET}", "重复"),
        ("mixed@example.com--p--invalid-key", "2FA"),
        ("mixed@example.com--p", "格式"),
    ]:
        failed = client.post("/api/admin/files/import-2fa", json={**request_payload, "text": text}, headers=csrf)
        if error in {"重复", "未匹配"}:
            assert failed.status_code == 200
        else:
            assert failed.status_code == 400 and error in failed.get_json()["error"]
        db.expire_all()
    assert "mixed@example.com--p--" in two_factor_txt([record]).decode()

    guest = app.test_client()
    job_id = "two-factor-query"
    routes.register_job({"id": job_id, "kind": "query_access", "status": "done", "cdkey_ids": [card.id, other_card.id], "events": []})
    with guest.session_transaction() as session:
        session[routes.QUERY_ACCESS_JOB_SESSION_KEY] = job_id
        session[routes.QUERY_ACCESS_TOKEN_SESSION_KEY] = "guest-token"
        session[routes.QUERY_ACCESS_CDKEY_IDS_SESSION_KEY] = [card.id]
    url = f"/query/files/download-2fa?job_id={job_id}&token=guest-token"
    assert app.test_client().get(url).status_code == 403
    assert guest.get(url.replace("guest-token", "wrong-token")).status_code == 403
    txt = guest.get(url)
    assert txt.status_code == 200, txt.get_data(as_text=True)
    assert txt.get_data(as_text=True) == f"mixed@example.com--account-password--{SECRET}\r\n"
    assert txt.headers["Cache-Control"] == "no-store"
    assert "attachment" in txt.headers["Content-Disposition"] and ".txt" in txt.headers["Content-Disposition"]
    assert "second-password" not in txt.get_data(as_text=True)
    record.payload.reauth_info = ""
    db.commit()
    missing = guest.get(url)
    assert missing.status_code == 409 and missing.get_json()["code"] == "TOTP_NOT_READY"
    record.payload.reauth_info = original
    db.commit()

    reauth_id = "two-factor-reauth"
    routes.register_job({"id": reauth_id, "kind": "query_reauth", "status": "done", "reauth_ready": True, "successful_file_ids": [record.id], "download_file_ids": [record.id, second.id], "events": []})
    with guest.session_transaction() as session:
        session[routes.QUERY_REAUTH_JOB_SESSION_KEY] = reauth_id
        session[routes.QUERY_REAUTH_TOKEN_SESSION_KEY] = "reauth-token"
    for kind, count in [("2fa", 1), ("card-2fa", 2)]:
        route = f"/api/query/reauth/{reauth_id}/download?format={kind}&token=reauth-token"
        assert app.test_client().get(route).status_code == 403
        result = guest.get(route)
        assert result.status_code == 200 and len(result.get_data(as_text=True).splitlines()) == count
    routes.update_job(reauth_id, source_job_id=job_id)
    scoped = guest.get(f"/api/query/reauth/{reauth_id}/download?format=card-2fa&token=guest-token")
    assert scoped.status_code == 200 and len(scoped.get_data(as_text=True).splitlines()) == 1
    assert "second-password" not in scoped.get_data(as_text=True)
    routes.QUERY_ATTEMPTS.clear()
    accounts = guest.post("/api/query/2fa/accounts", json={"code": card.code})
    assert accounts.status_code == 200 and accounts.get_json()["accounts"] == ["mixed@example.com"]
    with patch("pyfaka_app.reauth.totp.time.time", return_value=59):
        code = guest.post("/api/query/2fa/code", json={"code": card.code, "email": "MIXED@example.com"})
    assert code.status_code == 200 and code.get_json()["code"] == "287082"
    assert code.get_json()["password"] == "account-password"
    assert "second-password" not in code.get_data(as_text=True) and SECRET not in code.get_data(as_text=True)
    assert "account-password" not in accounts.get_data(as_text=True)
    rejected = guest.post("/api/query/2fa/code", json={"code": card.code, "email": "second@example.com"})
    assert rejected.status_code == 404 and "second-password" not in rejected.get_data(as_text=True)
    SessionLocal.remove()


if __name__ == "__main__":
    check_totp()
    check_mfa()
    check_api_and_download()
    print("2FA verification passed: RFC6238, MFA, import matching/atomicity/scope, guest TXT authorization, local codes")
