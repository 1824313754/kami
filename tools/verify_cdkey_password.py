"""Offline checks for card password binding, authorization, locks and unlocks."""
import json
import os
from pathlib import Path
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from threading import Barrier
from unittest.mock import patch

workspace = Path(tempfile.mkdtemp(prefix="pyfaka-card-password-"))
os.environ["PYFAKA_DATABASE_URL"] = f"sqlite:///{(workspace / 'test.sqlite3').as_posix()}"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from flask import Flask
from sqlalchemy import inspect
from sqlalchemy.orm import sessionmaker
from werkzeug.security import check_password_hash, generate_password_hash
from pyfaka_app import routes
from pyfaka_app.cdkey_password import CdkeyPasswordError, cdkey_access_deadline, cdkey_access_expired, decrypt_cdkey_password, verify_cdkey_password
from pyfaka_app.database import Base, SessionLocal, engine, ensure_sqlite_columns
from pyfaka_app.models import AdminUser, AuditLog, Cdkey, CdkeyBatch, FileRecord, FileRecordPayload
from pyfaka_app.services import access_cdkeys_bulk, cleanup_expired_extracted_cdkeys, payload_to_db_fields

routes.DATA_DIR = workspace
routes.JOB_HISTORY_PATH = workspace / "history.json"
routes.EXTRACTION_JOBS.clear()
factory = sessionmaker(bind=engine)
PASSWORD = "Test12"
WRONG = "Wrong1"


def expect_error(fn, code):
    try:
        fn()
    except CdkeyPasswordError as exc:
        assert exc.code == code, (exc.code, code)
    else:
        raise AssertionError("expected " + code)


def main():
    Base.metadata.create_all(engine)
    with factory() as db:
        batch = CdkeyBatch(batch_no="password", prefix="P", key_date="20261020", total_count=30, files_per_key=1)
        db.add(batch)
        db.flush()
        batch_id = batch.id
        db.add(Cdkey(batch_id=batch_id, code="LEGACY", files_per_key=1))
        db.commit()
    # Reproduce an old database, then run the actual additive migration twice.
    with engine.begin() as conn:
        conn.exec_driver_sql("ALTER TABLE cdkey_py DROP COLUMN access_password_hash")
        conn.exec_driver_sql("ALTER TABLE cdkey_py DROP COLUMN access_password_ciphertext")
        conn.exec_driver_sql("ALTER TABLE cdkey_py DROP COLUMN access_password_failures")
        conn.exec_driver_sql("ALTER TABLE cdkey_py DROP COLUMN access_unlocked_until")
        conn.exec_driver_sql("ALTER TABLE cdkey_py DROP COLUMN access_password_version")
        conn.exec_driver_sql("ALTER TABLE cdkey_py DROP COLUMN access_admin_locked")
    ensure_sqlite_columns()
    ensure_sqlite_columns()
    assert {"access_password_hash", "access_password_ciphertext", "access_password_failures", "access_unlocked_until"}.issubset({c["name"] for c in inspect(engine).get_columns("cdkey_py")})
    with factory() as db:
        legacy = db.query(Cdkey).filter_by(code="LEGACY").one()
        assert legacy.access_password_hash is None and legacy.access_password_failures == 0
        assert legacy.access_unlocked_until is None and legacy.access_password_version == 1
        assert not legacy.access_admin_locked

    def new_card(code, password=None):
        with factory() as db:
            card = Cdkey(batch_id=batch_id, code=code, files_per_key=1, extract_status="EXTRACTED",
                         access_password_hash=generate_password_hash(password) if password else None)
            db.add(card)
            db.commit()
            return card.id

    def verify(ids, password, setup=False):
        with factory() as db:
            cards = db.query(Cdkey).filter(Cdkey.id.in_(ids)).all()
            verify_cdkey_password(db, cards, password, secret_key="isolated-test", allow_setup=setup)

    card_id = new_card("CARD-A")
    for password in [None, "", "123456", "abcdef", "Ab123", "Ab123!45", "Ab12!3", "中文ab12", "abcd１２", " Ab123"]:
        expect_error(lambda: verify([card_id], password, True), "PASSWORD_FORMAT")
    for length in [7, 64, 256]:
        longer_password = "A1" + "b" * (length - 2)
        longer_id = new_card(f"LONG-{length}")
        verify([longer_id], longer_password, True)
        verify([longer_id], longer_password)
        with factory() as db:
            stored = db.get(Cdkey, longer_id)
            assert check_password_hash(stored.access_password_hash, longer_password)
            assert decrypt_cdkey_password(stored.access_password_ciphertext, "isolated-test") == longer_password
            if length == 256:
                assert len(stored.access_password_ciphertext) > 255, "long passwords must survive storage"
    expect_error(lambda: verify([card_id], PASSWORD), "PASSWORD_NOT_SET")
    verify([card_id], PASSWORD, True)
    with factory() as db:
        original_hash = db.get(Cdkey, card_id).access_password_hash
        assert original_hash != PASSWORD and check_password_hash(original_hash, PASSWORD)
        ciphertext = db.get(Cdkey, card_id).access_password_ciphertext
        assert ciphertext != PASSWORD and decrypt_cdkey_password(ciphertext, "isolated-test") == PASSWORD
        expect_error(lambda: decrypt_cdkey_password(ciphertext, "different-key"), "PASSWORD_DECRYPT_FAILED")
    verify([card_id], PASSWORD, True)
    expect_error(lambda: verify([card_id], WRONG, True), "PASSWORD_INCORRECT")
    verify([card_id], PASSWORD)
    with factory() as db:
        assert db.get(Cdkey, card_id).access_password_hash == original_hash
        assert db.get(Cdkey, card_id).access_password_failures == 1, "success must not erase cumulative failures"
    pending_id = new_card("PENDING")
    expect_error(lambda: verify([pending_id, card_id], WRONG, True), "PASSWORD_INCORRECT")
    with factory() as db:
        assert db.get(Cdkey, pending_id).access_password_hash is None, "batch must not partially bind"

    race_id = new_card("RACE")
    barrier = Barrier(2)

    def bind_race(password):
        with factory() as db:
            card = db.get(Cdkey, race_id)
            barrier.wait(timeout=10)
            try:
                verify_cdkey_password(db, [card], password, secret_key="isolated-test", allow_setup=True)
                return password
            except CdkeyPasswordError as exc:
                assert exc.code == "PASSWORD_INCORRECT"
                return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        winners = list(pool.map(bind_race, [PASSWORD, WRONG]))
    assert len([p for p in winners if p]) == 1, winners
    with factory() as db:
        assert check_password_hash(db.get(Cdkey, race_id).access_password_hash, next(p for p in winners if p))

    counter_id = new_card("CONCURRENT", PASSWORD)
    barrier = Barrier(12)

    def fail_race(_):
        barrier.wait(timeout=10)
        try:
            verify([counter_id], WRONG)
        except CdkeyPasswordError as exc:
            return exc.code
        raise AssertionError("wrong password accepted")

    with ThreadPoolExecutor(max_workers=12) as pool:
        outcomes = list(pool.map(fail_race, range(12)))
    assert outcomes.count("PASSWORD_INCORRECT") == 9 and outcomes.count("PASSWORD_LOCKED") == 3, outcomes
    with factory() as db:
        assert db.get(Cdkey, counter_id).access_password_failures == 10
    expect_error(lambda: verify([counter_id], PASSWORD), "PASSWORD_LOCKED")

    # First extraction time/IP are immutable on a normal repeated extraction.
    with factory() as db:
        timed = Cdkey(batch_id=batch_id, code="TIME-CARD", files_per_key=1)
        available = FileRecord(email_name="time@example.com", original_filename="time.json", status="AVAILABLE")
        available.payload = FileRecordPayload(**payload_to_db_fields({"email": "time@example.com"}))
        available.payload.reauth_info = json.dumps({"password": "account-secret", "totp_secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"})
        db.add_all([timed, available])
        db.commit()
        access_cdkeys_bulk(db, [timed.code], "192.0.2.1", live_check=False)
        db.refresh(timed)
        first_time = timed.extracted_at
        assert first_time is not None
        access_cdkeys_bulk(db, [timed.code], "192.0.2.2", live_check=False)
        db.refresh(timed)
        assert timed.extracted_at == first_time and timed.first_extract_ip == "192.0.2.1"

    other_id = new_card("CARD-B", "Other1")
    api_id = new_card("API-CARD")
    with factory() as db:
        for cid, email in [(api_id, "owned@example.com"), (other_id, "other@example.com")]:
            record = FileRecord(email_name=email, original_filename=email + ".json", status="BOUND", bound_cdkey_id=cid)
            record.payload = FileRecordPayload(**payload_to_db_fields({"email": email, "access_token": "test-access", "refresh_token": "test-refresh"}))
            record.payload.reauth_info = json.dumps({"password": "account-secret", "totp_secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"})
            db.add(record)
        admin = AdminUser(username="admin-test", password_hash=generate_password_hash("AdminTest123"), is_admin=True, cdkey_prefix="ADM")
        owner = AdminUser(username="owner-test", password_hash=generate_password_hash("OwnerTest123"), is_admin=False, cdkey_prefix="OWN")
        db.add_all([admin, owner])
        db.commit()

    app = Flask(__name__)
    app.config.update(SECRET_KEY="isolated-test", TESTING=True)
    app.register_blueprint(routes.bp)
    app.teardown_appcontext(lambda _error: SessionLocal.remove())
    client = app.test_client()
    endpoints = [
        ("/api/query/access", {"code": "API-CARD", "live_check": False}),
        ("/api/query/reauth", {"codes": "API-CARD"}),
        ("/api/query/2fa/accounts", {"code": "API-CARD"}),
        ("/api/query/2fa/code", {"code": "API-CARD", "email": "owned@example.com"}),
    ]
    for url, payload in endpoints:
        assert client.post(url, json=payload).status_code == 400
    for url, payload in endpoints[1:]:
        result = client.post(url, json={**payload, "password": PASSWORD})
        assert result.status_code == 409 and result.json["code"] == "PASSWORD_NOT_SET", result.json

    with patch.object(routes, "Thread") as thread:
        response = client.post(endpoints[0][0], json={**endpoints[0][1], "password": PASSWORD})
        assert response.status_code == 202, response.json
        assert thread.return_value.start.called
    job_id, token = response.json["job_id"], response.json["access_token"]
    routes.update_job(job_id, status="done", cdkey_ids=[api_id])
    with client.session_transaction() as session:
        assert PASSWORD not in str(dict(session)) and "scrypt:" not in str(dict(session))
    query = f"?job_id={job_id}&token={token}"
    urls = ["/api/query/result" + query, f"/api/query/jobs/{job_id}?token={token}", f"/query/progress/{job_id}.json?token={token}"]
    downloads = ["/query/files/" + kind + query for kind in ["download", "download-sub", "download-2fa"]]
    for url in downloads:
        for _ in range(2):
            response = client.get(url)
            assert response.status_code == 200, (url, response.get_data(as_text=True))
        assert app.test_client().get(url).status_code == 403

    legacy_client = app.test_client()
    with legacy_client.session_transaction() as session:
        session[routes.QUERY_ACCESS_JOB_SESSION_KEY] = job_id
        session[routes.QUERY_ACCESS_TOKEN_SESSION_KEY] = token
        session[routes.QUERY_ACCESS_CDKEY_IDS_SESSION_KEY] = [api_id]
        session["query_job_id"] = job_id
        session["query_cdkey_ids"] = [api_id]
    for url in urls + downloads + ["/api/query/result"]:
        assert legacy_client.get(url).status_code == 403, url
    with legacy_client.session_transaction() as session:
        session.pop(routes.QUERY_ACCESS_TOKEN_SESSION_KEY)
    assert legacy_client.get("/api/query/result").status_code == 403

    # Correct password reaches each protected function; another card's password does not.
    for url, payload in endpoints[1:]:
        with patch.object(routes, "Thread"):
            response = client.post(url, json={**payload, "password": PASSWORD})
        assert response.status_code in {200, 202}, (url, response.json)
        if url.endswith("reauth"):
            reauth_id, reauth_token = response.json["job_id"], response.json["access_token"]
    for url, payload in endpoints:
        response = client.post(url, json={**payload, "password": "Other1"})
        assert response.status_code == 403 and "account-secret" not in response.get_data(as_text=True), response.json
    routes.update_job(reauth_id, cdkey_ids=[api_id, other_id])
    response = client.post("/api/query/reauth", json={"codes": "API-CARD", "password": PASSWORD})
    assert response.status_code == 409 and response.json["code"] == "REAUTH_SCOPE_BUSY"
    routes.update_job(reauth_id, source_job_id=job_id)
    assert client.get(f"/api/query/jobs/{reauth_id}?token={token}").status_code == 403
    assert client.get("/api/query/result" + query).json["reauth_job"] is None
    routes.update_job(reauth_id, cdkey_ids=[api_id])
    # The registration race must apply the same full-card-set check as early reuse.
    shared_job = {"id": "shared-race", "kind": "query_reauth", "cdkey_ids": [api_id, other_id]}
    with patch.object(routes, "find_running_query_reauth_job_for_cdkeys", return_value=None), patch.object(routes, "register_job", return_value=shared_job):
        response = client.post("/api/query/reauth", json={"codes": "API-CARD", "password": PASSWORD})
        assert response.status_code == 409 and response.json["code"] == "REAUTH_SCOPE_BUSY"
    # Restore a valid reauth credential after the rejected racing registration.
    response = client.post("/api/query/reauth", json={"codes": "API-CARD", "password": PASSWORD})
    assert response.status_code == 202, response.json
    reauth_token = response.json["access_token"]
    routes.update_job(job_id, cdkey_ids=[api_id, other_id], codes=["API-CARD", "CARD-B"], phase="CARD-B", events=["other@example.com"])
    partial = client.get(f"/api/query/jobs/{job_id}?token={token}")
    assert partial.status_code == 200 and "CARD-B" not in partial.get_data(as_text=True)
    assert "other@example.com" not in partial.get_data(as_text=True)
    routes.update_job(job_id, cdkey_ids=[api_id], codes=["API-CARD"], events=[])

    # Complete the cumulative ten errors across all four APIs and different source IPs.
    for attempt in range(6):
        url, payload = endpoints[attempt % len(endpoints)]
        response = client.post(url, json={**payload, "password": WRONG}, environ_overrides={"REMOTE_ADDR": f"192.0.2.{attempt + 1}"})
        assert response.status_code == (423 if attempt == 5 else 403), response.json
    routes.QUERY_FAILURES.clear()  # Simulate losing process-local counters on restart.
    routes.QUERY_ATTEMPTS.clear()
    with factory() as db:
        assert db.get(Cdkey, api_id).access_password_failures == 10
        bound_hash = db.get(Cdkey, api_id).access_password_hash
    for url, payload in endpoints:
        response = client.post(url, json={**payload, "password": PASSWORD})
        assert response.status_code == 423, (url, response.json)
    for url in urls + downloads + [f"/api/query/jobs/{reauth_id}?token={reauth_token}", f"/api/query/reauth/{reauth_id}/download?token={reauth_token}"]:
        assert client.get(url).status_code == 403, url

    # Only a superadmin with CSRF protection can unlock; the original hash survives.
    unlock_url = f"/api/admin/cdkeys/{api_id}/unlock-password"
    assert app.test_client().post(unlock_url).status_code in {400, 401}
    owner_client = app.test_client()
    login = owner_client.post("/api/admin/login", json={"username": "owner-test", "password": "OwnerTest123"})
    assert login.status_code == 200, login.json
    assert owner_client.post(unlock_url, headers={"X-CSRF-Token": login.json["session"]["csrf_token"]}).status_code == 403
    admin_client = app.test_client()
    login = admin_client.post("/api/admin/login", json={"username": "admin-test", "password": "AdminTest123"})
    assert login.status_code == 200, login.json
    reveal_url = f"/api/admin/cdkeys/{api_id}/password"
    assert client.post(reveal_url).status_code in {400, 401}
    with owner_client.session_transaction() as session:
        owner_csrf = session["_csrf_token"]
    assert owner_client.post(reveal_url, headers={"X-CSRF-Token": owner_csrf}).status_code == 403
    assert admin_client.post(reveal_url).status_code == 400
    revealed = admin_client.post(reveal_url, headers={"X-CSRF-Token": login.json["session"]["csrf_token"]})
    assert revealed.status_code == 200 and revealed.json["password"] == PASSWORD, revealed.json
    assert revealed.headers["Cache-Control"] == "no-store"
    assert admin_client.post(unlock_url).status_code == 400
    response = admin_client.post(unlock_url, headers={"X-CSRF-Token": login.json["session"]["csrf_token"]})
    assert response.status_code == 200, response.json
    with factory() as db:
        card = db.get(Cdkey, api_id)
        assert card.access_password_failures == 0 and card.access_password_hash == bound_hash
        assert db.query(AuditLog).filter_by(action="UNLOCK_CDKEY_PASSWORD").count() == 1
        assert db.query(AuditLog).filter_by(action="VIEW_CDKEY_PASSWORD").count() == 1
        assert all(PASSWORD not in (log.detail or "") for log in db.query(AuditLog).all())
        with app.test_request_context():
            assert PASSWORD not in str(routes.cdkey_item_payload(card))
    response = client.post("/api/query/2fa/accounts", json={"code": "API-CARD", "password": PASSWORD})
    assert response.status_code == 200, response.json

    # Exactly 24 hours from first successful extraction, then fresh windows only
    # after an authenticated admin unlock. No wall-clock sleeps or real deletion.
    first_extracted = datetime.now().replace(microsecond=0) - timedelta(hours=23)
    first_deadline = first_extracted + timedelta(hours=24)
    with factory() as db:
        card = db.get(Cdkey, api_id)
        card.extracted_at = first_extracted
        ciphertext_before_expiry = card.access_password_ciphertext
        db.commit()
        assert cdkey_access_deadline(card) == first_deadline

    class TestClock(datetime):
        current = first_deadline - timedelta(microseconds=1)

        @classmethod
        def now(cls, tz=None):
            return cls.current.replace(tzinfo=tz) if tz else cls.current

    admin_headers = {"X-CSRF-Token": login.json["session"]["csrf_token"]}
    with patch("pyfaka_app.cdkey_password.datetime", TestClock), patch.object(routes, "datetime", TestClock):
        routes.QUERY_FAILURES.clear()
        routes.QUERY_ATTEMPTS.clear()
        before_expiry = client.post("/api/query/2fa/accounts", json={"code": "API-CARD", "password": PASSWORD})
        assert before_expiry.status_code == 200, before_expiry.json
        for url in downloads:
            assert client.get(url).status_code == 200, url
        with factory() as db:
            card = db.get(Cdkey, api_id)
            access_cdkeys_bulk(db, [card.code], "192.0.2.3", live_check=False)
            db.refresh(card)
            assert card.extracted_at == first_extracted and card.access_unlocked_until is None
            assert not cdkey_access_expired(card)
            assert not cdkey_access_expired(db.get(Cdkey, pending_id)), "unextracted cards do not expire"

        TestClock.current = first_deadline
        for url, payload in endpoints:
            response = client.post(url, json={**payload, "password": PASSWORD})
            assert response.status_code == 423 and response.json["code"] == "CDKEY_EXPIRED", response.json
        for url in urls + downloads + [f"/api/query/jobs/{reauth_id}?token={reauth_token}", f"/api/query/jobs/{reauth_id}?token={token}"]:
            assert client.get(url).status_code == 403, url
        for kind in ["cpa", "sub2api", "2fa", "card-cpa", "card-sub2api", "card-2fa"]:
            response = client.get(f"/api/query/reauth/{reauth_id}/download?format={kind}&token={reauth_token}")
            assert response.status_code == 403, kind
        assert client.post(f"/api/query/reauth/{reauth_id}/terminate?token={reauth_token}").status_code == 403
        with factory() as db:
            card = db.get(Cdkey, api_id)
            assert card.access_password_failures == 0, "expiry must not count as an incorrect password"
            records_before = db.query(FileRecord).filter_by(bound_cdkey_id=api_id).count()
            assert cleanup_expired_extracted_cdkeys(db) == {"deleted_cdkeys": 0, "deleted_files": 0, "delete_failed": 0}
            assert db.get(Cdkey, api_id) and db.query(FileRecord).filter_by(bound_cdkey_id=api_id).count() == records_before
            with app.test_request_context():
                state = routes.cdkey_item_payload(card)
                assert state["expiry_locked"] and state["access_locked"] and not state["password_locked"]
        assert owner_client.post(unlock_url, headers={"X-CSRF-Token": owner_csrf}).status_code == 403
        assert admin_client.post(unlock_url).status_code == 400
        TestClock.current = first_deadline + timedelta(hours=2)
        response = admin_client.post(unlock_url, headers=admin_headers)
        assert response.status_code == 200, response.json
        renewed_deadline = TestClock.current + timedelta(hours=24)
        with factory() as db:
            card = db.get(Cdkey, api_id)
            assert card.access_unlocked_until == renewed_deadline
            assert card.extracted_at == first_extracted and card.access_password_hash == bound_hash
            assert card.access_password_ciphertext == ciphertext_before_expiry
        # Reopening a DB session and clearing process counters must preserve the renewal.
        routes.QUERY_FAILURES.clear()
        routes.QUERY_ATTEMPTS.clear()
        for url in downloads:
            assert client.get(url).status_code == 200, url
        for url, payload in endpoints:
            with patch.object(routes, "Thread"):
                response = client.post(url, json={**payload, "password": PASSWORD})
            assert response.status_code in {200, 202}, (url, response.json)
            if url.endswith("access"):
                renewed_job, renewed_token = response.json["job_id"], response.json["access_token"]
                routes.update_job(renewed_job, status="done", cdkey_ids=[api_id])
            elif url.endswith("reauth"):
                reauth_token = response.json["access_token"]
        renewed_download = f"/query/files/download-2fa?job_id={renewed_job}&token={renewed_token}"
        TestClock.current = renewed_deadline - timedelta(microseconds=1)
        assert client.get(renewed_download).status_code == 200
        TestClock.current = renewed_deadline
        assert client.get(renewed_download).status_code == 403
        assert client.get(f"/api/query/jobs/{reauth_id}?token={reauth_token}").status_code == 403
        for url, payload in endpoints:
            response = client.post(url, json={**payload, "password": PASSWORD})
            assert response.status_code == 423 and response.json["code"] == "CDKEY_EXPIRED"
        # A second unlock renews again; password lockout is independent of the time grant.
        response = admin_client.post(unlock_url, headers=admin_headers)
        assert response.status_code == 200
        with factory() as db:
            card = db.get(Cdkey, api_id)
            assert card.access_unlocked_until == renewed_deadline + timedelta(hours=24)
            card.access_password_failures = 10
            db.commit()
        assert client.get(renewed_download).status_code == 403
        response = client.post("/api/query/2fa/accounts", json={"code": "API-CARD", "password": PASSWORD})
        assert response.status_code == 423 and response.json["code"] == "PASSWORD_LOCKED"
        assert admin_client.post(unlock_url, headers=admin_headers).status_code == 200
        assert client.get(renewed_download).status_code == 200

    # Changing a bound password revokes existing guest credentials, not the time grant.
    routes.QUERY_FAILURES.clear()
    routes.QUERY_ATTEMPTS.clear()
    change_url = f"/api/admin/cdkeys/{api_id}/change-password"
    new_password = "Changed12345"
    body = {"password": new_password}
    assert app.test_client().post(change_url, json=body).status_code in {400, 401}
    assert owner_client.post(change_url, json=body, headers={"X-CSRF-Token": owner_csrf}).status_code == 403
    assert admin_client.post(change_url, json=body).status_code == 400
    assert admin_client.post("/api/admin/cdkeys/999999/change-password", json=body, headers=admin_headers).status_code == 404
    assert admin_client.post(f"/api/admin/cdkeys/{pending_id}/change-password", json=body, headers=admin_headers).status_code == 409
    with factory() as db:
        card = db.get(Cdkey, api_id)
        card.access_password_failures = 2
        db.commit()
        before_change = (card.extracted_at, card.access_unlocked_until, card.access_password_failures)
        original_version = card.access_password_version
    for invalid in [None, "123456", "abcdef", "Ab123", "Ab123!45"]:
        response = admin_client.post(change_url, json={"password": invalid}, headers=admin_headers)
        assert response.status_code == 400 and response.json["code"] == "PASSWORD_FORMAT"
    with factory() as db:
        assert db.get(Cdkey, api_id).access_password_hash == bound_hash
        assert db.get(Cdkey, api_id).access_password_version == original_version
    assert client.get(renewed_download).status_code == 200
    assert client.get(f"/api/query/jobs/{reauth_id}?token={reauth_token}").status_code == 200
    # A separate card's valid credential must remain usable.
    other_client = app.test_client()
    with patch.object(routes, "Thread"):
        response = other_client.post("/api/query/access", json={"code": "CARD-B", "password": "Other1", "live_check": False})
    assert response.status_code == 202, response.json
    other_job, other_token = response.json["job_id"], response.json["access_token"]
    routes.update_job(other_job, status="done", cdkey_ids=[other_id])
    other_download = f"/query/files/download-2fa?job_id={other_job}&token={other_token}"
    assert other_client.get(other_download).status_code == 200
    response = admin_client.post(change_url, json=body, headers=admin_headers)
    assert response.status_code == 200, response.json
    with factory() as db:
        card = db.get(Cdkey, api_id)
        assert check_password_hash(card.access_password_hash, new_password)
        assert decrypt_cdkey_password(card.access_password_ciphertext, "isolated-test") == new_password
        assert card.access_password_version == original_version + 1
        assert (card.extracted_at, card.access_unlocked_until, card.access_password_failures) == before_change
        assert db.query(AuditLog).filter_by(action="CHANGE_CDKEY_PASSWORD").count() == 1
        assert all(new_password not in (log.detail or "") for log in db.query(AuditLog).all())
    revealed = admin_client.post(reveal_url, headers=admin_headers)
    assert revealed.json["password"] == new_password and revealed.headers["Cache-Control"] == "no-store"
    revoked_query = f"?job_id={renewed_job}&token={renewed_token}"
    revoked_urls = ["/api/query/result" + revoked_query, f"/api/query/jobs/{renewed_job}?token={renewed_token}",
                    f"/query/progress/{renewed_job}.json?token={renewed_token}",
                    f"/api/query/jobs/{reauth_id}?token={reauth_token}", f"/api/query/jobs/{reauth_id}?token={renewed_token}"]
    revoked_urls += ["/query/files/" + kind + revoked_query for kind in ["download", "download-sub", "download-2fa"]]
    revoked_urls += [f"/api/query/reauth/{reauth_id}/download?format={kind}&token={reauth_token}"
                     for kind in ["cpa", "sub2api", "2fa", "card-cpa", "card-sub2api", "card-2fa"]]
    for url in revoked_urls:
        assert client.get(url).status_code == 403, url
    assert client.post(f"/api/query/reauth/{reauth_id}/terminate?token={reauth_token}").status_code == 403
    assert other_client.get(other_download).status_code == 200
    # An otherwise valid session without a version is also rejected.
    with other_client.session_transaction() as session:
        session.pop(routes.QUERY_PASSWORD_VERSIONS_SESSION_KEY)
    assert other_client.get(other_download).status_code == 403
    for url, payload in endpoints:
        response = client.post(url, json={**payload, "password": PASSWORD})
        assert response.status_code == 403 and response.json["code"] == "PASSWORD_INCORRECT", response.json
    for url, payload in endpoints:
        with patch.object(routes, "Thread"):
            response = client.post(url, json={**payload, "password": new_password})
        assert response.status_code in {200, 202}, (url, response.json)
    # Capture the verified version before commit; a concurrent later password change
    # must not let credentials be issued with a version the user never verified.
    with factory() as db:
        verified_versions = verify_cdkey_password(db, [db.get(Cdkey, api_id)], new_password, secret_key="isolated-test")
    with factory() as db:
        card = db.get(Cdkey, api_id)
        card.access_password_failures = 10
        db.commit()
        locked_deadline = card.access_unlocked_until
    response = admin_client.post(change_url, json=body, headers=admin_headers)
    assert response.status_code == 200
    with factory() as db:
        card = db.get(Cdkey, api_id)
        assert card.access_password_failures == 10 and card.extracted_at == first_extracted
        assert card.access_unlocked_until == locked_deadline
        assert verified_versions[str(api_id)] != card.access_password_version
    response = client.post("/api/query/2fa/accounts", json={"code": "API-CARD", "password": new_password})
    assert response.status_code == 423 and response.json["code"] == "PASSWORD_LOCKED"
    assert admin_client.post(unlock_url, headers=admin_headers).status_code == 200
    with app.test_request_context():
        routes.g.query_verified_password_versions = verified_versions
        routes.issue_query_access("password-change-race", [api_id])
        assert not routes.query_cards_unlocked([api_id], routes.QUERY_PASSWORD_VERSIONS_SESSION_KEY)
    assert new_password not in routes.JOB_HISTORY_PATH.read_text(encoding="utf-8")


    # Admin locks are separate from password failures, persist, and revoke all guest access.
    routes.QUERY_FAILURES.clear()
    routes.QUERY_ATTEMPTS.clear()
    for url, payload in endpoints[:2]:
        with patch.object(routes, "Thread"):
            response = client.post(url, json={**payload, "password": new_password})
        assert response.status_code == 202, response.json
        if url.endswith("access"):
            lock_job, lock_token = response.json["job_id"], response.json["access_token"]
            routes.update_job(lock_job, status="done", cdkey_ids=[api_id])
        else:
            lock_reauth, lock_reauth_token = response.json["job_id"], response.json["access_token"]
    routes.update_job(lock_reauth, source_job_id=lock_job)
    lock_query = f"?job_id={lock_job}&token={lock_token}"
    lock_urls = ["/api/query/result" + lock_query, f"/api/query/jobs/{lock_job}?token={lock_token}",
                 f"/query/progress/{lock_job}.json?token={lock_token}",
                 f"/api/query/jobs/{lock_reauth}?token={lock_reauth_token}",
                 f"/api/query/jobs/{lock_reauth}?token={lock_token}"]
    lock_urls += ["/query/files/" + kind + lock_query for kind in ["download", "download-sub", "download-2fa"]]
    for url in lock_urls:
        assert client.get(url).status_code == 200, url
    lock_urls += [f"/api/query/reauth/{lock_reauth}/download?format={kind}&token={lock_reauth_token}"
                  for kind in ["cpa", "sub2api", "2fa", "card-cpa", "card-sub2api", "card-2fa"]]
    lock_url = f"/api/admin/cdkeys/{api_id}/lock"
    assert app.test_client().post(lock_url).status_code in {400, 401}
    assert owner_client.post(lock_url, headers={"X-CSRF-Token": owner_csrf}).status_code == 403
    assert admin_client.post(lock_url).status_code == 400
    assert admin_client.post("/api/admin/cdkeys/999999/lock", headers=admin_headers).status_code == 404
    with factory() as db:
        card = db.get(Cdkey, api_id)
        card.access_password_failures = 3
        db.commit()
        preserved = (card.extracted_at, card.access_unlocked_until, card.access_password_hash, card.access_password_ciphertext, card.access_password_failures)
        prelock_version = card.access_password_version
    assert admin_client.post(lock_url, headers=admin_headers).status_code == 200
    routes.QUERY_FAILURES.clear()
    routes.QUERY_ATTEMPTS.clear()
    with factory() as db:
        card = db.get(Cdkey, api_id)
        assert card.access_admin_locked and card.access_password_version == prelock_version + 1
        assert (card.extracted_at, card.access_unlocked_until, card.access_password_hash, card.access_password_ciphertext, card.access_password_failures) == preserved
        assert not db.get(Cdkey, other_id).access_admin_locked
        assert db.query(AuditLog).filter_by(action="LOCK_CDKEY", target_id=str(api_id)).count() == 1
        assert all(new_password not in (log.detail or "") for log in db.query(AuditLog).all())
        state = routes.cdkey_item_payload(card)
        assert state["admin_locked"] and state["access_locked"] and not state["password_locked"]
        assert state["password_failures"] == 3
    for url, payload in endpoints:
        with patch.object(routes, "Thread") as thread:
            response = client.post(url, json={**payload, "password": new_password})
        assert response.status_code == 423 and response.json["code"] == "CDKEY_ADMIN_LOCKED", response.json
        assert not thread.called, 'locked cards must not start work'
    for url in lock_urls:
        assert client.get(url).status_code == 403, url
    assert client.post(f"/api/query/reauth/{lock_reauth}/terminate?token={lock_reauth_token}").status_code == 403
    # Backend password maintenance remains available but does not bypass a manual lock.
    assert admin_client.post(reveal_url, headers=admin_headers).json["password"] == new_password
    assert admin_client.post(change_url, json={"password": new_password}, headers=admin_headers).status_code == 200
    with factory() as db:
        card = db.get(Cdkey, api_id)
        assert card.access_admin_locked and card.access_password_failures == 3
        assert (card.extracted_at, card.access_unlocked_until) == preserved[:2]
    response = client.post(endpoints[2][0], json={**endpoints[2][1], "password": new_password})
    assert response.status_code == 423 and response.json["code"] == "CDKEY_ADMIN_LOCKED"
    unlock_before = datetime.now()
    assert admin_client.post(unlock_url, headers=admin_headers).status_code == 200
    with factory() as db:
        card = db.get(Cdkey, api_id)
        assert not card.access_admin_locked and card.access_password_failures == 0
        assert card.extracted_at == first_extracted
        assert unlock_before + timedelta(hours=24) <= card.access_unlocked_until <= datetime.now() + timedelta(hours=24)
    for url in lock_urls:
        assert client.get(url).status_code == 403, 'unlock must not reactivate revoked credentials: ' + url
    for url, payload in endpoints:
        with patch.object(routes, "Thread"):
            response = client.post(url, json={**payload, "password": new_password})
        assert response.status_code in {200, 202}, response.json
    # An unextracted, unbound card can be locked before sale/first access.
    pending_lock = f"/api/admin/cdkeys/{pending_id}/lock"
    assert admin_client.post(pending_lock, headers=admin_headers).status_code == 200
    response = client.post("/api/query/access", json={"code": "PENDING", "password": PASSWORD, "live_check": False})
    assert response.status_code == 423 and response.json["code"] == "CDKEY_ADMIN_LOCKED"
    expect_error(lambda: verify([card_id, pending_id], PASSWORD, True), "CDKEY_ADMIN_LOCKED")
    with factory() as db:
        card = db.get(Cdkey, pending_id)
        assert card.access_password_hash is None and card.extracted_at is None
        assert card.access_password_failures == 0
    assert admin_client.post(f"/api/admin/cdkeys/{pending_id}/unlock-password", headers=admin_headers).status_code == 200
    with factory() as db:
        card = db.get(Cdkey, pending_id)
        assert not card.access_admin_locked and card.access_unlocked_until is None and card.extracted_at is None
    verify([pending_id], PASSWORD, True)
    # Lock/unlock without changing the password also permanently revokes prior credentials.
    with other_client.session_transaction() as session:
        session[routes.QUERY_PASSWORD_VERSIONS_SESSION_KEY] = {str(other_id): 1}
    assert other_client.get(other_download).status_code == 200
    assert admin_client.post(f"/api/admin/cdkeys/{other_id}/lock", headers=admin_headers).status_code == 200
    assert other_client.get(other_download).status_code == 403
    assert admin_client.post(f"/api/admin/cdkeys/{other_id}/unlock-password", headers=admin_headers).status_code == 200
    assert other_client.get(other_download).status_code == 403


    # Unknown cards across modules share the source budget; forged forwarding headers cannot reset it.
    routes.QUERY_FAILURES.clear()
    routes.QUERY_ATTEMPTS.clear()
    for attempt in range(10):
        url, payload = endpoints[attempt % len(endpoints)]
        unknown = {key: ("UNKNOWN" if key in {"code", "codes"} else value) for key, value in payload.items()}
        response = app.test_client().post(url, json={**unknown, "password": WRONG}, headers={"X-Forwarded-For": f"198.51.100.{attempt}"})
        assert response.status_code == (429 if attempt == 9 else 403), response.json
    response = client.post("/api/query/2fa/accounts", json={"code": "API-CARD", "password": PASSWORD})
    assert response.status_code == 429 and response.json["code"] == "PASSWORD_IP_LOCKED"
    with patch.dict(os.environ, {"PYFAKA_TRUSTED_PROXY_IPS": "127.0.0.1"}):
        with app.test_request_context(headers={"X-Forwarded-For": "fake, 192.0.2.10"}, environ_base={"REMOTE_ADDR": "127.0.0.1"}):
            assert routes.password_ip_key() == "cdkey-password-ip:192.0.2.10"
        with app.test_request_context(headers={"X-Forwarded-For": "192.0.2.10"}, environ_base={"REMOTE_ADDR": "198.51.100.1"}):
            assert routes.password_ip_key() == "cdkey-password-ip:198.51.100.1"
    assert PASSWORD not in routes.JOB_HISTORY_PATH.read_text(encoding="utf-8")
    print("PASS: migration; format; atomic first binding; cumulative concurrent locks; all APIs and downloads; legacy sessions; batch scope; admin unlock; shared IP guard; exact 24-hour expiry; renewable admin windows; no expiry deletion; admin password change and credential revocation; persistent admin locks and unlock windows")
    SessionLocal.remove()
    engine.dispose()


if __name__ == "__main__":
    main()
