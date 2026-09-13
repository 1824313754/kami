import os
import sys
import tempfile

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from flask import Flask
from werkzeug.security import generate_password_hash

workspace = tempfile.mkdtemp(prefix="pyfaka-business-rules-")
os.environ["PYFAKA_DATABASE_URL"] = f"sqlite:///{os.path.join(workspace, 'verify.sqlite3').replace(os.sep, '/')}"
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from pyfaka_app import routes, services
from pyfaka_app.auth_store import quota_from_usage_body
from pyfaka_app.live_check import LiveCheckResult
from pyfaka_app.database import Base, SessionLocal, engine as app_engine
from pyfaka_app.models import AdminUser, Cdkey, CdkeyBatch, FileRecord
from pyfaka_app.routes import bp, plan_type_label, quota_label, quota_period_label


def add_pending_cdkey(db, owner_id: int, business_type: str, group_tag: str, files: int) -> None:
    batch = CdkeyBatch(
        batch_no=f"{business_type}-{group_tag}",
        prefix="TEST",
        key_date="20260725",
        total_count=1,
        files_per_key=files,
        business_type=business_type,
        group_tag=group_tag,
        created_by=owner_id,
    )
    db.add(batch)
    db.flush()
    db.add(Cdkey(batch_id=batch.id, code=f"CODE-{business_type}-{group_tag}", files_per_key=files))


def add_available_file(db, owner_id: int, business_type: str, group_tag: str, index: int) -> None:
    db.add(FileRecord(
        original_filename=f"{business_type}-{group_tag}-{index}.json",
        email_name=f"{business_type}-{group_tag}-{index}@example.com",
        uploaded_by=owner_id,
        business_type=business_type,
        group_tag=group_tag,
    ))


def verify_over_issue_isolation() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    services._BUSINESS_TYPE_OPTIONS_CACHE = services.default_business_type_options()
    owner = AdminUser(
        username="tester",
        password_hash="unused",
        cdkey_prefix="T1",
        over_issue_files=7,
    )
    db.add(owner)
    db.commit()

    assert services.capacity_for_owner(db, owner.id, "free").configured_over_issue_files == 7
    services.set_configured_over_issue_files(db, owner.id, "free", 6)
    services.set_configured_over_issue_files(db, owner.id, "plus", 12)

    add_pending_cdkey(db, owner.id, "free", "default", 4)
    add_available_file(db, owner.id, "free", "default", 1)
    add_pending_cdkey(db, owner.id, "free", "other", 3)
    add_available_file(db, owner.id, "free", "other", 1)
    add_pending_cdkey(db, owner.id, "plus", "default", 3)
    db.commit()

    free = services.capacity_for_owner(db, owner.id, "free", "default")
    plus = services.capacity_for_owner(db, owner.id, "plus", "default")
    assert (free.configured_over_issue_files, free.used_over_issue_files, free.remaining_over_issue_files) == (6, 5, 1)
    assert (plus.configured_over_issue_files, plus.used_over_issue_files, plus.remaining_over_issue_files) == (12, 3, 9)
    db.close()


def verify_unshippable_status() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    assert services.unshippable_http_statuses(db) == (401,)
    services.set_setting(db, services.UNSHIPPABLE_HTTP_STATUSES_KEY, "403")
    assert services.unshippable_http_statuses(db) == (403,)
    services.set_setting(db, services.UNSHIPPABLE_HTTP_STATUSES_KEY, "[401, 403, 401]")
    assert services.unshippable_http_statuses(db) == (401, 403)
    services.set_setting(db, services.UNSHIPPABLE_HTTP_STATUSES_KEY, "invalid")
    assert services.unshippable_http_statuses(db) == (401,)
    db.close()

    assert services.is_definite_dead_account(LiveCheckResult(False, 401, "", False))
    assert not services.is_definite_dead_account(LiveCheckResult(False, 403, "", False))
    assert services.is_definite_dead_account(LiveCheckResult(False, 403, "", False), (401, 403))
    assert not services.is_live_check_alive(LiveCheckResult(True, 200, "", False), (200, 401))

    original = services.check_auth_payload
    calls = []

    def fake_check(_config, item):
        calls.append(item)
        return LiveCheckResult(False, 403, "forbidden", False)

    services.check_auth_payload = fake_check
    try:
        services.check_auth_item_with_retry(None, {}, (401, 403))
        assert len(calls) == 1
        calls.clear()
        services.check_auth_item_with_retry(None, {}, (401,))
        assert len(calls) == 2
    finally:
        services.check_auth_payload = original


def verify_live_check_metadata() -> None:
    quota = quota_from_usage_body({
        "plan_type": "plus",
        "rate_limit": {
            "primary_window": {
                "used_percent": 20,
                "reset_after_seconds": 300,
                "limit_window_seconds": 18000,
            },
            "secondary_window": {
                "used_percent": 70,
                "reset_after_seconds": 7200,
                "limit_window_seconds": 604800,
            },
        },
    })
    assert quota["x-codex-primary-used-percent"] == "70.0"
    assert quota["x-codex-primary-reset-after-seconds"] == "7200"
    assert quota["x-codex-primary-limit-window-seconds"] == "604800"
    assert quota_label(quota) == "30%"
    assert quota_period_label(quota) == "7天"
    assert plan_type_label(quota) == "Plus"

    primary_quota = quota_from_usage_body({
        "plan_type": "self_serve_business_usage_based",
        "rate_limit": {
            "primary_window": {"used_percent": 80, "limit_window_seconds": 18000},
            "secondary_window": {"used_percent": 10, "limit_window_seconds": 604800},
        },
    })
    assert quota_label(primary_quota) == "20%"
    assert quota_period_label(primary_quota) == "5小时"
    assert plan_type_label(primary_quota) == "self_serve_business_usage_based"
    assert services.retry_note(LiveCheckResult(False, 500, "retry", False, quota=quota)).quota == quota
    assert quota_period_label({}) == "暂无"
    assert plan_type_label({}) == "暂无"

    original_persist = routes.persist_job_snapshot_throttled
    routes.persist_job_snapshot_throttled = lambda *_args, **_kwargs: None
    try:
        live_job_id = "verify-live-metadata"
        routes.EXTRACTION_JOBS[live_job_id] = {"id": live_job_id, "result_rows": []}
        routes.file_live_check_progress_callback(live_job_id)({
            "event": "checked",
            "outcome": "alive",
            "email": "live@example.com",
            "registered_at": "2026-07-25T10:00:00Z",
            "live_checked_at": "2026-07-25 10:05:00",
            "checked": 1,
            "alive": 1,
            "dead": 0,
            "skipped": 0,
            "needed": 1,
            "http_status": 200,
            "quota": quota,
        })
        live_row = routes.EXTRACTION_JOBS[live_job_id]["result_rows"][0]
        assert live_row["quota_period"] == "7天"
        assert live_row["plan_type"] == "Plus"

        extraction_job_id = "verify-extraction-metadata"
        routes.EXTRACTION_JOBS[extraction_job_id] = {"id": extraction_job_id, "extracted_files": []}
        routes.extraction_progress_callback(extraction_job_id)({
            "event": "checked",
            "outcome": "alive",
            "email": "query@example.com",
            "registered_at": "2026-07-25T10:00:00Z",
            "checked": 1,
            "alive": 1,
            "dead": 0,
            "needed": 1,
            "http_status": 200,
            "quota": quota,
        })
        extracted = routes.EXTRACTION_JOBS[extraction_job_id]["extracted_files"][0]
        assert extracted["quota_period"] == "7天"
        assert extracted["plan_type"] == "Plus"
    finally:
        routes.persist_job_snapshot_throttled = original_persist
        routes.EXTRACTION_JOBS.pop("verify-live-metadata", None)
        routes.EXTRACTION_JOBS.pop("verify-extraction-metadata", None)


def verify_admin_api() -> None:
    Base.metadata.create_all(app_engine)
    db = SessionLocal()
    owner = AdminUser(
        username="api-admin",
        password_hash=generate_password_hash("StrongPass123"),
        cdkey_prefix="A1",
        over_issue_files=0,
        is_admin=True,
    )
    operator = AdminUser(
        username="api-operator",
        password_hash=generate_password_hash("StrongPass456"),
        cdkey_prefix="A2",
        over_issue_files=0,
        is_admin=False,
    )
    db.add_all([owner, operator])
    db.commit()
    owner_id = owner.id
    db.close()

    app = Flask(__name__)
    app.config.update(SECRET_KEY="verification-secret", TESTING=True)
    app.register_blueprint(bp)
    client = app.test_client()

    login = client.post("/api/admin/login", json={"username": "api-admin", "password": "StrongPass123"})
    assert login.status_code == 200
    csrf = login.get_json()["session"]["csrf_token"]
    headers = {"X-CSRF-Token": csrf}

    settings = client.get("/api/admin/settings")
    assert settings.get_json()["settings"]["unshippable_http_statuses"] == [401]
    assert settings.get_json()["settings"]["query_totp_enabled"] is True
    assert "export_microsoft_rt" not in settings.get_json()["settings"]
    invalid = client.post("/api/admin/settings", json={"unshippable_http_statuses": [99]}, headers=headers)
    assert invalid.status_code == 400
    invalid_text = client.post("/api/admin/settings", json={"unshippable_http_statuses": ["invalid"]}, headers=headers)
    assert invalid_text.status_code == 400
    empty = client.post("/api/admin/settings", json={"unshippable_http_statuses": []}, headers=headers)
    assert empty.status_code == 400
    saved = client.post(
        "/api/admin/settings",
        json={"unshippable_http_statuses": [401, 403, 401], "query_totp_enabled": True},
        headers=headers,
    )
    assert saved.status_code == 200
    assert saved.get_json()["settings"]["unshippable_http_statuses"] == [401, 403]
    assert saved.get_json()["settings"]["query_totp_enabled"] is True
    assert "export_microsoft_rt" not in saved.get_json()["settings"]

    guest_reauth_job_id = "verify-admin-guest-reauth"
    routes.register_job({
        "id": guest_reauth_job_id,
        "kind": "query_reauth",
        "status": "running",
        "user_id": None,
        "phase": "正在先测活卡密文件",
        "total": 2,
        "processed": 0,
        "workers": 5,
        "live_check_total": 2,
        "live_check_checked": 1,
        "live_check_result_rows": [{
            "email": "guest@example.com",
            "live_status": "正常",
            "registered_at": "2026-08-15 12:00:00",
            "live_checked_at": "2026-08-15 12:01:00",
            "quota": "80%",
            "quota_period": "7天",
            "plan_type": "Plus",
            "http_status": "200",
            "message": "HTTP 200 正常",
        }],
        "result_rows": [],
        "events": [],
    })
    try:
        jobs_response = client.get("/api/admin/jobs?kind=query_reauth")
        assert jobs_response.status_code == 200
        jobs = jobs_response.get_json()["items"]
        guest_job = next(item for item in jobs if item["id"] == guest_reauth_job_id)
        assert guest_job["workers"] == 5
        assert guest_job["live_check_result_rows"][0]["email"] == "guest@example.com"

        detail_response = client.get(f"/api/admin/jobs/{guest_reauth_job_id}")
        assert detail_response.status_code == 200
        assert detail_response.get_json()["job"]["kind"] == "query_reauth"

        terminate_response = client.post(f"/api/admin/jobs/{guest_reauth_job_id}/terminate", headers=headers)
        assert terminate_response.status_code == 200
        assert routes.EXTRACTION_JOBS[guest_reauth_job_id].get("cancel_requested") is True
        assert terminate_response.get_json()["job"]["cancel_requested"] is True

        operator_client = app.test_client()
        operator_login = operator_client.post(
            "/api/admin/login",
            json={"username": "api-operator", "password": "StrongPass456"},
        )
        assert operator_login.status_code == 200
        operator_csrf = operator_login.get_json()["session"]["csrf_token"]
        operator_jobs = operator_client.get("/api/admin/jobs?kind=query_reauth").get_json()["items"]
        assert all(item["id"] != guest_reauth_job_id for item in operator_jobs)
        assert operator_client.get(f"/api/admin/jobs/{guest_reauth_job_id}").status_code == 404
        assert operator_client.post(
            f"/api/admin/jobs/{guest_reauth_job_id}/terminate",
            headers={"X-CSRF-Token": operator_csrf},
        ).status_code == 404
    finally:
        routes.EXTRACTION_JOBS.pop(guest_reauth_job_id, None)

    for business_type, value in (("free", 4), ("plus", 9)):
        updated = client.post(
            "/api/admin/cdkeys/over-issue",
            json={
                "owner_id": owner_id,
                "business_type": business_type,
                "group_tag": "default",
                "over_issue_files": value,
            },
            headers=headers,
        )
        assert updated.status_code == 200
        assert updated.get_json()["capacity"]["configured_over_issue_files"] == value

    free = client.get(f"/api/admin/cdkeys?owner_id={owner_id}&business_type=free&group_tag=default")
    plus = client.get(f"/api/admin/cdkeys?owner_id={owner_id}&business_type=plus&group_tag=default")
    assert free.get_json()["capacity"]["configured_over_issue_files"] == 4
    assert plus.get_json()["capacity"]["configured_over_issue_files"] == 9


if __name__ == "__main__":
    verify_over_issue_isolation()
    verify_unshippable_status()
    verify_live_check_metadata()
    verify_admin_api()
    print("business rule verification passed")
