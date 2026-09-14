import json
import os
import sys
import tempfile
import time
from io import BytesIO
from pathlib import Path
from threading import Barrier, Lock, Thread
from types import SimpleNamespace
from zipfile import ZipFile

from flask import Flask

workspace = tempfile.mkdtemp(prefix="pyfaka-db-store-")
os.environ["PYFAKA_DATABASE_URL"] = f"sqlite:///{os.path.join(workspace, 'verify.sqlite3').replace(os.sep, '/')}"
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from pyfaka_app import routes
from pyfaka_app.database import DATA_DIR, SessionLocal, engine, ensure_sqlite_columns, init_db
from pyfaka_app.models import AdminUser, AuditLog, Cdkey, CdkeyBatch, FileRecord, FileRecordPayload
from pyfaka_app.two_factor import import_two_factor
from pyfaka_app.reauth.oauth_client.auth_flow import EmailOtpValidationError
from pyfaka_app.services import (
    QUERY_TOTP_ENABLED_KEY,
    delete_cdkeys_with_bound_files,
    payload_to_db_fields,
    set_setting,
    sub2api_json_for_files,
    upload_payload_files,
    zip_for_files,
)


def assert_true(value, label):
    if not value:
        raise AssertionError(label)


def auth_payload(email: str) -> dict:
    return {
        "id_token": "id",
        "access_token": "access",
        "refresh_token": "refresh",
        "account_id": "account",
        "last_refresh": "2026-06-19T12:00:00Z",
        "email": email,
        "type": "oauth",
        "expired": "2099-01-01T00:00:00Z",
        "client_id": "client",
        "device_id": "device",
        "password": "secret",
        "user_agent": "agent",
    }


def upload_item(filename: str, payload: dict) -> SimpleNamespace:
    return SimpleNamespace(
        filename=filename,
        stream=BytesIO(json.dumps(payload).encode("utf-8")),
    )


def main():
    scheduler_records = [
        {"id": 1, "source_key": "account-a@example.com"},
        {"id": 2, "source_key": "account-a@example.com"},
        {"id": 3, "source_key": "account-b@example.com"},
        {"id": 4, "source_key": "account-b@example.com"},
    ]
    scheduler_lock = Lock()
    scheduler_barrier = Barrier(2)
    active_by_source = {}
    max_active_by_source = {}
    active_total = 0
    max_active_total = 0

    def scheduler_process(item):
        nonlocal active_total, max_active_total
        source_key = item["source_key"]
        with scheduler_lock:
            active_by_source[source_key] = active_by_source.get(source_key, 0) + 1
            max_active_by_source[source_key] = max(
                max_active_by_source.get(source_key, 0), active_by_source[source_key]
            )
            active_total += 1
            max_active_total = max(max_active_total, active_total)
        try:
            if item["id"] in {1, 3}:
                scheduler_barrier.wait(timeout=2)
            time.sleep(0.01)
            return item["id"]
        finally:
            with scheduler_lock:
                active_by_source[source_key] -= 1
                active_total -= 1

    scheduler_results = [
        future.result()
        for _record, future in routes._source_serialized_reauth_futures(
            scheduler_records,
            2,
            scheduler_process,
            lambda: None,
        )
    ]
    assert_true(set(scheduler_results) == {1, 2, 3, 4}, "source scheduler should process every account")
    assert_true(
        all(value == 1 for value in max_active_by_source.values()),
        "source scheduler should serialize accounts from the same account",
    )
    assert_true(max_active_total == 2, "source scheduler should run different accounts concurrently")

    init_db()
    with engine.begin() as conn:
        conn.exec_driver_sql("DROP TABLE file_record_payload_py")
        conn.exec_driver_sql(
            "CREATE TABLE file_record_payload_py ("
            "file_record_id INTEGER NOT NULL PRIMARY KEY, "
            "id_token TEXT NOT NULL, access_token TEXT NOT NULL, refresh_token TEXT NOT NULL, "
            "account_id VARCHAR(255) NOT NULL, last_refresh VARCHAR(128) NOT NULL, "
            "email VARCHAR(255) NOT NULL, type VARCHAR(64) NOT NULL, expired VARCHAR(128) NOT NULL, "
            "FOREIGN KEY(file_record_id) REFERENCES file_record_py (id))"
        )
    ensure_sqlite_columns()
    with engine.connect() as conn:
        migrated_columns = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(file_record_payload_py)")}
    assert_true("microsoft_rt" not in migrated_columns, "SQLite payload table should not contain microsoft_rt")
    assert_true("mailinfo" in migrated_columns, "SQLite migration should add reauth_info to an old payload table")

    db = SessionLocal()
    try:
        owner = db.query(AdminUser).filter_by(is_admin=True).first()
        assert_true(owner is not None, "default admin should exist")

        failed_payload = auth_payload("bad@example.com")
        del failed_payload["refresh_token"]
        failed_summary = upload_payload_files(
            db,
            [
                upload_item("valid.json", auth_payload("valid@example.com")),
                upload_item("bad.json", failed_payload),
            ],
            owner.id,
        )
        assert_true(failed_summary.success_count == 0, "failed batch should have no success")
        assert_true(failed_summary.failure_count == 2, "failed batch should mark all files failed")
        assert_true(db.query(FileRecord).count() == 0, "failed batch should not create file records")
        assert_true(db.query(FileRecordPayload).count() == 0, "failed batch should not create payload rows")

        summary = upload_payload_files(
            db,
            [
                upload_item("input-a.json", auth_payload("test@example.com")),
                upload_item("input-b.json", auth_payload("batch@example.com")),
            ],
            owner.id,
        )
        assert_true(summary.success_count == 2, "batch upload should succeed")
        assert_true(db.query(FileRecord).count() == 2, "batch upload should create two file records")
        assert_true(db.query(FileRecordPayload).count() == 2, "batch upload should create two payload rows")
        record = db.query(FileRecord).filter_by(email_name="test@example.com").first()
        assert_true(record is not None, "file record should exist")
        assert_true(record.storage_path == "__payload__", "new upload should use database payload marker")
        assert_true(not (DATA_DIR / "auth_files" / f"{record.id}.json").exists(), "new upload should not write auth json file")
        import_two_factor(db, "test@example.com--account-secret--GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\nbatch@example.com--account-secret--GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", owner.id, "free", "default")
        db_payload = db.get(FileRecordPayload, record.id)
        assert_true(db_payload is not None, "payload row should exist")
        assert_true(db_payload.access_token == "access", "access token should be stored in database field")
        assert_true(not hasattr(db_payload, "microsoft_rt"), "microsoft_rt should not be mapped")
        assert_true(json.loads(db_payload.reauth_info)["password"] == "account-secret", "reauth_info should be stored for server-side reauthorization")
        assert_true(not hasattr(db_payload, "client_id"), "client_id should not be stored")
        assert_true(not hasattr(db_payload, "password"), "password should not be stored")
        assert_true(engine.hide_parameters is True, "database errors should hide payload parameters")
        db.commit()

        with engine.begin() as conn:
            conn.exec_driver_sql("ALTER TABLE file_record_payload_py ADD COLUMN client_id TEXT")
            conn.exec_driver_sql("ALTER TABLE file_record_payload_py ADD COLUMN password TEXT")
        ensure_sqlite_columns()
        db.expire_all()
        migrated_columns = {row[1] for row in db.connection().exec_driver_sql("PRAGMA table_info(file_record_payload_py)")}
        assert_true("client_id" not in migrated_columns, "legacy client_id should be removed during payload migration")
        assert_true("password" not in migrated_columns, "legacy password should be removed during payload migration")
        assert_true("microsoft_rt" not in migrated_columns, "legacy microsoft_rt should be removed during payload migration")
        db_payload = db.get(FileRecordPayload, record.id)
        assert_true(json.loads(db_payload.reauth_info)["totp_secret"] == "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "payload migration should preserve reauth_info")

        original_data_dir = routes.DATA_DIR
        original_persist = routes.persist_job_snapshot
        original_persist_throttled = routes.persist_job_snapshot_throttled
        routes.DATA_DIR = Path(workspace)
        routes.persist_job_snapshot = lambda *_args, **_kwargs: None
        routes.persist_job_snapshot_throttled = lambda *_args, **_kwargs: None

        def admin_download_export(suffix: str) -> dict:
            job_id = f"verify-download-{suffix}"
            routes.register_job({
                "id": job_id,
                "kind": "file_download",
                "user_id": owner.id,
                "status": "queued",
                "events": [],
            })
            try:
                worker = Thread(
                    target=routes.run_file_download_job,
                    args=(job_id, [record.id], owner.id, owner.id, owner.username, "127.0.0.1", "selected"),
                )
                worker.start()
                worker.join(10)
                assert_true(not worker.is_alive(), "admin download job should stop")
                job = routes.EXTRACTION_JOBS[job_id]
                assert_true(job["status"] == "done", f"admin download job should finish: {job.get('error')}")
                with ZipFile(job["download_path"]) as archive:
                    return json.loads(archive.read("test@example.com.json").decode("utf-8"))
            finally:
                routes.EXTRACTION_JOBS.pop(job_id, None)

        try:
            zipped = zip_for_files(db, [record])
            with ZipFile(BytesIO(zipped)) as archive:
                names = archive.namelist()
                assert_true(names == ["test@example.com.json"], "zip should contain account json")
                exported = json.loads(archive.read(names[0]).decode("utf-8"))
            assert_true(exported["refresh_token"] == "refresh", "download should rebuild json from database fields")
            assert_true(exported["type"] == "codex", "CPA export should use codex type")
            assert_true("client_id" not in exported, "client_id should not be exported")
            assert_true("device_id" not in exported, "device_id should not be exported")
            assert_true("password" not in exported, "password should not be exported")
            assert_true("user_agent" not in exported, "user_agent should not be exported")
            assert_true("reauth_info" not in exported, "CPA export should omit reauth_info")
            admin_exported = admin_download_export("default")
            assert_true(admin_exported["type"] == "codex", "admin CPA export should use codex type")
            assert_true("reauth_info" not in admin_exported, "admin ZIP should omit reauth_info")

            default_sub = json.loads(sub2api_json_for_files(db, [record]).decode("utf-8"))
            assert_true(default_sub["accounts"][0]["name"] == "test@example.com", "sub2api name should use email")
            assert_true("reauth_info" not in default_sub["accounts"][0]["credentials"], "sub2api should omit reauth_info")

            from pyfaka_app.reauth import oauth_flow

            original_reauthorize = oauth_flow.reauthorize_account
            original_admin_live_check = routes.admin_live_check_files
            live_check_target_id = record.id
            expected_live_check_ids = None
            def fake_reauthorize(target_email, credential, _settings, on_progress=None):
                assert credential["password"] == "account-secret"
                assert credential["totp_secret"] == "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
                if on_progress:
                    on_progress("OTP 第 1/3 轮第 1/3 次未找到新验证码")
                    on_progress("OTP 第 1/2 次 resend 已提交")
                    on_progress("OTP 第 2/3 轮第 1/3 次查码成功，验证码：654321")
                    on_progress("Codex 令牌刷新成功，准备回写账号")
                return {
                    "email": target_email,
                    "id_token": "id-reauthorized",
                    "access_token": "access-reauthorized",
                    "refresh_token": "refresh-reauthorized",
                    "last_refresh": "2026-08-14T12:00:00Z",
                    "expired": "2026-08-14T13:00:00Z",
                }

            def fake_admin_live_check(session_db, file_ids, _owner_id=None, _workers=1, progress_callback=None, abort_check=None):
                expected_ids = expected_live_check_ids or [record.id, db.query(FileRecord).filter_by(email_name="batch@example.com").first().id]
                assert_true(file_ids == expected_ids, "reauth live check should receive every card file")
                if progress_callback:
                    progress_callback({"event": "start_admin_file_check", "total": len(file_ids), "workers": _workers})
                alive = 0
                dead = 0
                quota = {
                    "x-codex-primary-used-percent": "25",
                    "x-codex-primary-limit-window-seconds": "604800",
                    "x-codex-plan-type": "plus",
                }
                for checked, file_id in enumerate(file_ids, start=1):
                    if abort_check:
                        abort_check()
                    checked_record = session_db.get(FileRecord, file_id)
                    checked_record.live_http_status = 401 if file_id == live_check_target_id else 200
                    if checked_record.live_http_status == 200:
                        alive += 1
                        outcome = "alive"
                    else:
                        dead += 1
                        outcome = "dead"
                    if progress_callback:
                        progress_callback({
                            "event": "checked",
                            "outcome": outcome,
                            "email": checked_record.email_name,
                            "checked": checked,
                            "alive": alive,
                            "dead": dead,
                            "skipped": 0,
                            "needed": len(file_ids),
                            "http_status": checked_record.live_http_status,
                            "quota": quota,
                            "live_checked_at": f"2026-08-15 12:00:0{checked}",
                            "message": f"HTTP {checked_record.live_http_status}",
                        })
                session_db.commit()
                return SimpleNamespace(total=len(file_ids), normal=alive, error=dead, skipped=0)

            oauth_flow.reauthorize_account = fake_reauthorize
            routes.admin_live_check_files = fake_admin_live_check
            reauth_job_id = "verify-query-reauth"
            routes.register_job({
                "id": reauth_job_id,
                "kind": "query_reauth",
                "status": "queued",
                "events": [],
            })
            try:
                batch_record = db.query(FileRecord).filter_by(email_name="batch@example.com").first()
                worker = Thread(
                    target=routes.run_query_reauth_job,
                    args=(reauth_job_id, [record.id], [record.id, batch_record.id], 1, "127.0.0.1"),
                )
                worker.start()
                worker.join(10)
                assert_true(not worker.is_alive(), "query reauth job should stop")
                reauth_job = routes.EXTRACTION_JOBS[reauth_job_id]
                assert_true(reauth_job["status"] == "done", f"query reauth should finish: {reauth_job.get('error')}")
                live_rows = {item["email"]: item for item in reauth_job["live_check_result_rows"]}
                assert_true(set(live_rows) == {"test@example.com", "batch@example.com"}, "reauth should retain every live-check result")
                assert_true(live_rows["test@example.com"]["live_status"] == "异常", "HTTP 401 should be visible as an abnormal live-check result")
                assert_true(live_rows["test@example.com"]["http_status"] == "401", "the 401 status should remain visible")
                assert_true(live_rows["batch@example.com"]["live_status"] == "正常", "HTTP 200 should be visible as a normal live-check result")
                assert_true(live_rows["batch@example.com"]["http_status"] == "200", "the 200 status should remain visible")
                assert_true(live_rows["test@example.com"]["reauth_required"] is True, "HTTP 401 accounts should be prioritized for reauth")
                assert_true(live_rows["test@example.com"]["reauth_status"] == "授权成功", "the account row should expose final reauth status")
                assert_true(live_rows["batch@example.com"]["reauth_status"] == "无需授权", "healthy accounts should remain visible without entering reauth")
                assert_true(
                    live_rows["test@example.com"]["quota"] == "75%"
                    and live_rows["test@example.com"]["quota_period"] == "7天"
                    and live_rows["test@example.com"]["plan_type"] == "Plus",
                    "reauth live-check rows should retain quota metadata",
                )
                assert_true(
                    [item["email"] for item in reauth_job["result_rows"]] == ["test@example.com"],
                    "only the freshly measured 401 account should enter OAuth",
                )
                event_text = json.dumps(reauth_job["events"], ensure_ascii=False)
                account_log_text = json.dumps(live_rows["test@example.com"]["progress_logs"], ensure_ascii=False)
                assert_true("登录前测活：异常，HTTP 401" in account_log_text, "the account row should retain its live-check result")
                assert_true("OTP 第 1/3 轮第 1/3 次未找到新验证码" in account_log_text, "the account row should retain OTP polling progress")
                assert_true("OTP 第 2/3 轮第 1/3 次查码成功，验证码：654321" in account_log_text, "the account row should expose the OTP code")
                assert_true("重登授权成功，令牌已回写原账号" in account_log_text, "the account row should retain the final writeback result")
                assert_true(live_rows["test@example.com"]["progress_log"] == "重登授权成功，令牌已回写原账号", "the account row should expose its latest log")
                assert_true(
                    all(secret not in event_text + account_log_text for secret in ("account-secret", "persisted-cookie", "persisted-sid", "persisted-jsession")),
                    "reauth progress must not expose account credentials",
                )
                assert_true(
                    len(routes.job_summary_payload({"events": [{"text": str(index)} for index in range(35)]})["events"]) == 30,
                    "admin task detail should expose the latest 30 task events",
                )
                complete_account_rows = [{"email": f"account-{index}@example.com"} for index in range(205)]
                assert_true(
                    len(routes.job_summary_payload({"kind": "query_reauth", "live_check_result_rows": complete_account_rows})["live_check_result_rows"]) == 205,
                    "admin reauth detail should retain every account row",
                )
                assert_true(
                    len(routes.normalize_job_for_storage({"kind": "query_reauth", "live_check_result_rows": complete_account_rows})["live_check_result_rows"]) == 205,
                    "persisted reauth history should retain every account row",
                )
                assert_true(
                    "AUTH_TOKEN_SECRET" not in routes._reauth_public_error(RuntimeError("AUTH_TOKEN_SECRET")),
                    "unknown OAuth errors should be redacted from public task output",
                )
                db.expire_all()
                refreshed_payload = db.get(FileRecordPayload, record.id)
                assert_true(refreshed_payload.access_token == "access-reauthorized", "reauth should overwrite the stored access token")
                assert_true(refreshed_payload.refresh_token == "refresh-reauthorized", "reauth should overwrite the stored refresh token")
                refreshed_reauth_info = json.loads(refreshed_payload.reauth_info)
                assert_true(refreshed_reauth_info["password"] == "account-secret", "reauth writeback should preserve reauth_info")
                assert_true(refreshed_reauth_info["totp_secret"] == "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "reauth should preserve the imported 2FA secret")
                with ZipFile(Path(workspace) / "reauth_jobs" / reauth_job_id / "reauth-cpa.zip") as archive:
                    reauth_export = json.loads(archive.read("test@example.com.json").decode("utf-8"))
                assert_true(reauth_export["access_token"] == "access-reauthorized", "reauth CPA should contain the refreshed token")
                assert_true(reauth_export["type"] == "codex", "reauth CPA should use codex type")
                assert_true("reauth_info" not in reauth_export, "reauth CPA should omit reauth_info")
                reauth_sub = json.loads((Path(workspace) / "reauth_jobs" / reauth_job_id / "reauth-sub2api.json").read_text(encoding="utf-8"))
                assert_true("reauth_info" not in reauth_sub["accounts"][0]["credentials"], "reauth sub2api should omit reauth_info")
                with ZipFile(Path(workspace) / "reauth_jobs" / reauth_job_id / "card-cpa.zip") as archive:
                    assert_true(set(archive.namelist()) == {"test@example.com.json", "batch@example.com.json"}, "card CPA should contain all bound files")
                    card_refreshed = json.loads(archive.read("test@example.com.json").decode("utf-8"))
                    card_unchanged = json.loads(archive.read("batch@example.com.json").decode("utf-8"))
                assert_true(card_refreshed["access_token"] == "access-reauthorized", "card CPA should contain the refreshed token")
                assert_true(card_unchanged["access_token"] == "access", "card CPA should preserve non-target account tokens")
                assert_true(
                    card_refreshed["type"] == "codex" and card_unchanged["type"] == "codex",
                    "card CPA should use codex type",
                )
                assert_true("reauth_info" not in card_refreshed and "reauth_info" not in card_unchanged, "card CPA should omit reauth_info")
                card_sub = json.loads((Path(workspace) / "reauth_jobs" / reauth_job_id / "card-sub2api.json").read_text(encoding="utf-8"))
                assert_true(len(card_sub["accounts"]) == 2, "card sub2api should contain all bound files")
                assert_true(all("reauth_info" not in item["credentials"] for item in card_sub["accounts"]), "card sub2api should omit reauth_info")

                deactivated_body = json.dumps({
                    "error": {
                        "message": "You do not have an account because it has been deleted or deactivated.",
                        "type": "invalid_request_error",
                        "code": "account_deactivated",
                    }
                })
                deactivated_error = EmailOtpValidationError(403, deactivated_body)
                assert_true(routes._reauth_public_error(deactivated_error) == "账户封禁", "account_deactivated should use the public banned-account reason")
                assert_true(
                    routes._reauth_public_error(EmailOtpValidationError(403, '{"error":{"code":"wrong_email_otp_code"}}')) == "账户封禁",
                    "every OTP validation 403 should permanently ban reauthorization",
                )
                assert_true(
                    routes._reauth_public_error(RuntimeError("普通上游请求失败: HTTP 403")) != "账户封禁",
                    "non-OTP 403 errors must not be classified as banned accounts",
                )
                assert_true(
                    routes._reauth_public_error(RuntimeError("2FA 验证失败")) == "2FA 验证失败，请检查密钥和服务器时间",
                    "2FA failures should use the public error message",
                )
                rate_limited_error = RuntimeError(
                    'authorize/continue 失败: {"error":{"code":"rate_limit_exceeded"}}'
                )
                assert_true(
                    routes._reauth_public_error(rate_limited_error) == "账户已被限流，5分钟后再重试",
                    "rate_limit_exceeded should use the public rate-limited reason",
                )
                assert_true(
                    routes._reauth_block_reason({
                        "reauth_info": {
                            "oauth_blocked_reason": "rate_limit_exceeded",
                            "oauth_blocked_at": "2020-01-01 00:00:00",
                        }
                    }) == "",
                    "an expired rate-limit marker should allow a later OAuth attempt",
                )

                blocked_job_id = "verify-query-reauth-account-deactivated"
                skipped_job_id = "verify-query-reauth-account-deactivated-skip"
                expected_live_check_ids = [record.id]

                def fake_deactivated_reauthorize(_target_email, _credential, _settings, on_progress=None):
                    if on_progress:
                        on_progress("OTP 第 1/3 轮第 1/3 次查码成功，验证码：123456")
                    raise EmailOtpValidationError(403, deactivated_body)

                oauth_flow.reauthorize_account = fake_deactivated_reauthorize
                routes.register_job({
                    "id": blocked_job_id,
                    "kind": "query_reauth",
                    "status": "queued",
                    "events": [],
                })
                blocked_worker = Thread(
                    target=routes.run_query_reauth_job,
                    args=(blocked_job_id, [record.id], [record.id], 1, "127.0.0.1"),
                )
                blocked_worker.start()
                blocked_worker.join(10)
                assert_true(not blocked_worker.is_alive(), "account-deactivated reauth job should stop")
                blocked_job = routes.EXTRACTION_JOBS[blocked_job_id]
                assert_true(blocked_job["status"] == "error", "an all-failed account-deactivated job should end as an error")
                assert_true(blocked_job["result_rows"][0]["reason"] == "账户封禁", "account-deactivated result row should be explicit")
                assert_true(blocked_job["live_check_result_rows"][0]["reauth_status"] == "授权失败", "account-deactivated row should show failed authorization")
                assert_true("重登授权失败：账户封禁" in blocked_job["live_check_result_rows"][0]["progress_log"], "account-deactivated account log should be explicit")
                db.expire_all()
                blocked_reauth_info_raw = db.get(FileRecordPayload, record.id).reauth_info
                blocked_reauth_info = json.loads(blocked_reauth_info_raw)
                assert_true(blocked_reauth_info["oauth_blocked_reason"] == "account_deactivated", "account-deactivated marker should persist")
                assert_true(bool(blocked_reauth_info.get("oauth_blocked_at")), "account-deactivated marker should retain its detection time")
                preserved_fields = payload_to_db_fields(auth_payload(record.email_name), blocked_reauth_info_raw)
                preserved_reauth_info = json.loads(preserved_fields["reauth_info"])
                assert_true(
                    preserved_reauth_info["oauth_blocked_reason"] == "account_deactivated",
                    "re-uploading the same account should preserve its OAuth block",
                )

                unexpected_oauth_calls = 0

                def should_not_reauthorize(*_args, **_kwargs):
                    nonlocal unexpected_oauth_calls
                    unexpected_oauth_calls += 1
                    raise AssertionError("a blocked account must not enter OAuth")

                oauth_flow.reauthorize_account = should_not_reauthorize
                routes.register_job({
                    "id": skipped_job_id,
                    "kind": "query_reauth",
                    "status": "queued",
                    "events": [],
                })
                skipped_worker = Thread(
                    target=routes.run_query_reauth_job,
                    args=(skipped_job_id, [record.id], [record.id], 1, "127.0.0.1"),
                )
                skipped_worker.start()
                skipped_worker.join(10)
                assert_true(not skipped_worker.is_alive(), "blocked-account skip job should stop")
                skipped_job = routes.EXTRACTION_JOBS[skipped_job_id]
                assert_true(unexpected_oauth_calls == 0, "blocked accounts should never enter a later OAuth flow")
                assert_true(
                    skipped_job["error"] == "当前卡密账号均为账户封禁，已跳过重登授权",
                    "an all-blocked job should explain why OAuth was skipped",
                )
                assert_true(
                    "账户封禁，已跳过重登授权" in skipped_job["live_check_result_rows"][0]["progress_log"],
                    "the later task should expose the banned-account skip in its account row",
                )
                rate_limited_skip_job_id = "verify-query-reauth-rate-limit-skip"
                db.expire_all()
                rate_reauth_info = json.loads(db.get(FileRecordPayload, record.id).reauth_info)
                rate_reauth_info["oauth_blocked_reason"] = "rate_limit_exceeded"
                rate_reauth_info["oauth_blocked_at"] = routes.full_clock_text()
                db.get(FileRecordPayload, record.id).reauth_info = json.dumps(rate_reauth_info, ensure_ascii=False)
                db.commit()
                routes.register_job({
                    "id": rate_limited_skip_job_id,
                    "kind": "query_reauth",
                    "status": "queued",
                    "events": [],
                })
                rate_limited_skip_worker = Thread(
                    target=routes.run_query_reauth_job,
                    args=(rate_limited_skip_job_id, [record.id], [record.id], 1, "127.0.0.1"),
                )
                rate_limited_skip_worker.start()
                rate_limited_skip_worker.join(10)
                assert_true(not rate_limited_skip_worker.is_alive(), "rate-limited skip job should stop")
                rate_limited_skip_job = routes.EXTRACTION_JOBS[rate_limited_skip_job_id]
                assert_true(
                    rate_limited_skip_job["error"] == "当前卡密账号均在限流冷却期，请5分钟后再重试",
                    "an all-rate-limited job should explain why OAuth was skipped",
                )
                assert_true(
                    "账户已被限流，5分钟后再重试，已跳过重登授权" in rate_limited_skip_job["live_check_result_rows"][0]["progress_log"],
                    "the later task should expose the rate-limited skip in its account row",
                )
                routes.EXTRACTION_JOBS.pop(blocked_job_id, None)
                routes.EXTRACTION_JOBS.pop(skipped_job_id, None)
                routes.EXTRACTION_JOBS.pop(rate_limited_skip_job_id, None)
                expected_live_check_ids = None
                oauth_flow.reauthorize_account = fake_reauthorize

                download_app = Flask(__name__)
                download_app.config.update(SECRET_KEY="verification-secret", TESTING=True)
                download_app.register_blueprint(routes.bp)
                download_client = download_app.test_client()
                download_token = "verification-reauth-token"
                with download_client.session_transaction() as guest_session:
                    guest_session[routes.QUERY_REAUTH_JOB_SESSION_KEY] = reauth_job_id
                    guest_session[routes.QUERY_REAUTH_TOKEN_SESSION_KEY] = download_token
                cpa_response = download_client.get(
                    f"/api/query/reauth/{reauth_job_id}/download?format=cpa&token={download_token}"
                )
                assert_true(cpa_response.status_code == 200, "guest should download this OAuth run as CPA ZIP")
                with ZipFile(BytesIO(cpa_response.data)) as archive:
                    assert_true(
                        archive.namelist() == ["test@example.com.json"],
                        "downloaded OAuth CPA should only contain this run's successful accounts",
                    )
                sub_response = download_client.get(
                    f"/api/query/reauth/{reauth_job_id}/download?format=sub2api&token={download_token}"
                )
                assert_true(sub_response.status_code == 200, "guest should download this OAuth run as sub2api JSON")
                downloaded_sub = json.loads(sub_response.data.decode("utf-8"))
                assert_true(
                    len(downloaded_sub["accounts"]) == 1
                    and downloaded_sub["accounts"][0]["name"] == "test@example.com",
                    "downloaded OAuth sub2api should only contain this run's successful accounts",
                )

                no_target_job_id = "verify-query-reauth-no-target"
                routes.register_job({
                    "id": no_target_job_id,
                    "kind": "query_reauth",
                    "status": "queued",
                    "events": [],
                })
                live_check_target_id = None
                try:
                    no_target_worker = Thread(
                        target=routes.run_query_reauth_job,
                        args=(no_target_job_id, [record.id, batch_record.id], [record.id, batch_record.id], 1, "127.0.0.1"),
                    )
                    no_target_worker.start()
                    no_target_worker.join(10)
                    assert_true(not no_target_worker.is_alive(), "reauth without a 401 target should stop")
                    no_target_job = routes.EXTRACTION_JOBS[no_target_job_id]
                    assert_true(no_target_job["status"] == "error", "reauth without a 401 target should fail before OAuth")
                    assert_true(no_target_job["error"] == "当前卡密没有检测到 401 账号", "reauth should report the fresh 401 result")
                    assert_true(
                        len(no_target_job["live_check_result_rows"]) == 2
                        and all(item["live_status"] == "正常" for item in no_target_job["live_check_result_rows"]),
                        "live-check results should remain visible when no account needs OAuth",
                    )
                finally:
                    live_check_target_id = record.id
                    routes.EXTRACTION_JOBS.pop(no_target_job_id, None)
            finally:
                oauth_flow.reauthorize_account = original_reauthorize
                routes.admin_live_check_files = original_admin_live_check
                routes.EXTRACTION_JOBS.pop(reauth_job_id, None)

            secret = "AUTH_TOKEN_SECRET"
            secret_path = Path(workspace) / "upload-error.json"
            secret_path.write_text("{}", encoding="utf-8")
            original_upload = routes.upload_payload_files

            def fail_upload(*_args, **_kwargs):
                raise RuntimeError(secret)

            routes.upload_payload_files = fail_upload
            error_job_id = "verify-upload-error-redaction"
            routes.register_job({"id": error_job_id, "kind": "upload", "status": "queued", "events": []})
            db.commit()
            try:
                worker = Thread(
                    target=routes.run_upload_job,
                    args=(
                        error_job_id,
                        [{"filename": secret_path.name, "path": str(secret_path)}],
                        owner.id,
                        "free",
                        "default",
                        owner.id,
                        owner.username,
                        "127.0.0.1",
                    ),
                )
                worker.start()
                worker.join(10)
                assert_true(not worker.is_alive(), "failed upload job should stop")
            finally:
                routes.upload_payload_files = original_upload
            error_job = routes.EXTRACTION_JOBS.pop(error_job_id)
            assert_true(secret not in json.dumps(error_job, ensure_ascii=False), "upload task errors should not expose token values")
            db.expire_all()
            failure_audit = db.query(AuditLog).filter_by(action="UPLOAD_FILES_FAILURE").order_by(AuditLog.id.desc()).first()
            assert_true(failure_audit is not None, "upload failure should create an audit row")
            assert_true(secret not in str(failure_audit.detail or ""), "upload audit should not expose token values")
            assert_true("error_type=RuntimeError" in str(failure_audit.detail or ""), "upload audit should retain the error type")
        finally:
            routes.DATA_DIR = original_data_dir
            routes.persist_job_snapshot = original_persist
            routes.persist_job_snapshot_throttled = original_persist_throttled

        overwrite_payload = auth_payload("test@example.com")
        overwrite_payload["access_token"] = "access-overwritten"
        overwrite_summary = upload_payload_files(db, [upload_item("overwrite.json", overwrite_payload)], owner.id)
        assert_true(overwrite_summary.success_count == 1, "overwrite upload should succeed")
        assert_true(overwrite_summary.overwrite_count == 1, "overwrite upload should be counted")
        assert_true(db.query(FileRecord).count() == 2, "overwrite should not create a new file record")
        db.refresh(db_payload)
        assert_true(db_payload.access_token == "access-overwritten", "overwrite should update payload row")

        batch = CdkeyBatch(
            batch_no="VERIFY-20260622",
            prefix="TEST",
            key_date="20260622",
            total_count=1,
            files_per_key=2,
            created_by=owner.id,
        )
        db.add(batch)
        db.flush()
        cdkey = Cdkey(batch_id=batch.id, code="TEST-20260622-ABCDEFGHJKLMNPQRST", files_per_key=2, extract_status="EXTRACTED")
        db.add(cdkey)
        db.flush()
        record_id = record.id
        batch_record = db.query(FileRecord).filter_by(email_name="batch@example.com").first()
        batch_record_id = batch_record.id
        record.status = "BOUND"
        record.bound_cdkey_id = cdkey.id
        record.live_http_status = 200
        batch_record.status = "BOUND"
        batch_record.bound_cdkey_id = cdkey.id
        batch_record.live_http_status = 200
        db.commit()

        original_read_job_history = routes.read_job_history
        routes.read_job_history = lambda: [{
            "id": "original-query-job",
            "kind": "query_access",
            "status": "done",
            "codes": [cdkey.code],
            "updated_at": "2026-08-15 12:00:00",
            "extracted_files": [
                {"email": record.email_name, "quota_period": "7天", "plan_type": "Plus"},
                {"email": batch_record.email_name, "quota_period": "7天", "plan_type": "Plus"},
            ],
        }]
        try:
            repeated_files = routes.extracted_files_for_cdkeys([cdkey.id], live_check=True)
            assert_true(
                all(item["quota_period"] == "7天" for item in repeated_files),
                "repeated extraction should preserve the original quota period",
            )
            assert_true(
                all(item["plan_type"] == "Plus" for item in repeated_files),
                "repeated extraction should preserve the original plan type",
            )
            unchecked_files = routes.extracted_files_for_cdkeys([cdkey.id], live_check=False)
            assert_true(
                all(item["quota_period"] == "未测活" and item["plan_type"] == "未测活" for item in unchecked_files),
                "unchecked repeated extraction should not reuse live-check metadata",
            )
        finally:
            routes.read_job_history = original_read_job_history

        app = Flask(__name__)
        app.config.update(SECRET_KEY="verification-secret", TESTING=True)
        app.register_blueprint(routes.bp)
        client = app.test_client()

        reused_reauth_job_id = "verify-query-reauth-reuse"
        routes.register_job({
            "id": reused_reauth_job_id,
            "kind": "query_reauth",
            "status": "running",
            "cdkey_ids": [cdkey.id],
            "total": 2,
            "events": [],
        })
        try:
            assert_true(
                routes.find_running_query_reauth_job_for_cdkeys([cdkey.id, 999]) is not None,
                "overlapping multi-card reauth submissions should find the existing job",
            )
            reused_response = client.post("/api/query/reauth", json={"codes": cdkey.code})
            reused_payload = reused_response.get_json()
            assert_true(reused_response.status_code == 202, "duplicate reauth submission should reuse the active task")
            assert_true(reused_payload["reused"] is True, "duplicate reauth response should identify the reused task")
            assert_true(reused_payload["job_id"] == reused_reauth_job_id, "duplicate reauth should return the active task id")
            assert_true(bool(reused_payload["access_token"]), "duplicate reauth should issue a task access token")
        finally:
            routes.update_job(reused_reauth_job_id, status="done", phase="验证完成", completed_at=routes.full_clock_text())
            routes.EXTRACTION_JOBS.pop(reused_reauth_job_id, None)

        routes.QUERY_ATTEMPTS.clear()
        set_setting(db, QUERY_TOTP_ENABLED_KEY, "0")
        assert_true(client.post("/api/query/2fa/accounts", json={"code": cdkey.code}).status_code == 403, "disabled 2FA lookup should reject access")
        set_setting(db, QUERY_TOTP_ENABLED_KEY, "1")
        accounts = client.post("/api/query/2fa/accounts", json={"code": cdkey.code})
        assert_true(accounts.get_json()["accounts"] == ["batch@example.com", "test@example.com"], "2FA should list only bound accounts")
        assert_true(client.post("/api/query/2fa/code", json={"code": cdkey.code, "email": "unbound@example.com"}).status_code == 404, "2FA should reject an unbound account")
        code_response = client.post("/api/query/2fa/code", json={"code": cdkey.code, "email": record.email_name})
        assert_true(code_response.status_code == 200, "2FA should generate a code locally")
        code_payload = code_response.get_json()
        assert_true(code_payload["password"] == "account-secret", "code API should return the selected account password")
        assert_true(set(code_payload) == {"ok", "email", "password", "code", "expires_in", "period", "refreshed_at"}, "code API should expose only the requested login fields and code timing")
        assert_true(len(code_payload["code"]) == 6 and code_payload["code"].isdigit(), "2FA should return six digits")
        assert_true(code_response.headers["Cache-Control"] == "no-store", "code must not be cached")
        assert_true(client.post("/api/query/2fa/code", json={"code": cdkey.code, "email": record.email_name}).status_code == 429, "code refresh should respect cooldown")

        original_thread = routes.Thread

        class DeferredThread:
            def __init__(self, *args, **kwargs):
                self.args = args
                self.kwargs = kwargs

            def start(self):
                return None

        routes.Thread = DeferredThread
        try:
            missing_response = client.post("/api/query/reauth", json={"codes": "MISSING-CARD"})
            assert_true(missing_response.status_code == 404, "unknown card should not start guest reauth")
            no_401_response = client.post("/api/query/reauth", json={"codes": cdkey.code})
            assert_true(no_401_response.status_code == 202, "guest reauth should start a fresh live check")
            no_401_payload = no_401_response.get_json()
            no_401_job_id = no_401_payload["job_id"]
            assert_true(routes.EXTRACTION_JOBS[no_401_job_id]["file_ids"] == [record.id, batch_record.id], "fresh reauth should measure every bound account")
            assert_true(no_401_payload["total"] == 2, "fresh reauth should report all files to be measured")
            assert_true(routes.EXTRACTION_JOBS[no_401_job_id]["workers"] == 10, "guest reauth should default to ten workers")
            routes.EXTRACTION_JOBS.pop(no_401_job_id, None)
            record.live_http_status = 401
            db.commit()
            response = client.post("/api/query/reauth", json={"codes": cdkey.code, "workers": 99})
            assert_true(response.status_code == 202, "guest should start reauth directly by card")
            response_payload = response.get_json()
            reauth_job_id = response_payload["job_id"]
            reauth_token = response_payload["access_token"]
            assert_true(routes.EXTRACTION_JOBS[reauth_job_id]["workers"] == 10, "guest reauth should cap workers at ten")
            assert_true(routes.EXTRACTION_JOBS[reauth_job_id]["codes"] == [cdkey.code], "guest reauth should retain the requested card")
            assert_true(routes.EXTRACTION_JOBS[reauth_job_id]["cdkey_ids"] == [cdkey.id], "guest reauth should resolve the requested card")
            assert_true(routes.EXTRACTION_JOBS[reauth_job_id]["file_ids"] == [record.id, batch_record.id], "guest reauth should measure every bound account before filtering")
            assert_true(routes.EXTRACTION_JOBS[reauth_job_id]["download_file_ids"] == [record.id, batch_record.id], "guest reauth should retain all card files for download")
            assert_true(response_payload["total"] == 2, "guest reauth should report the fresh live-check count")
            status_response = client.get(f"/api/query/jobs/{reauth_job_id}?token={reauth_token}")
            assert_true(status_response.status_code == 200, "authorized guest should read reauth progress")
            unauthorized = app.test_client().get(f"/api/query/jobs/{reauth_job_id}?token=wrong")
            assert_true(unauthorized.status_code == 403, "reauth progress should require its independent task token")
            unauthorized_stop = client.post(f"/api/query/reauth/{reauth_job_id}/terminate?token=wrong")
            assert_true(unauthorized_stop.status_code == 403, "guest reauth stop should reject an invalid task token")
            stop_response = client.post(f"/api/query/reauth/{reauth_job_id}/terminate?token={reauth_token}")
            assert_true(stop_response.status_code == 200, "authorized guest should stop an active reauth task")
            assert_true(
                routes.EXTRACTION_JOBS[reauth_job_id].get("cancel_requested") is True,
                "guest reauth stop should set the cooperative cancellation flag",
            )
            assert_true(
                stop_response.get_json()["job"].get("cancel_requested") is True,
                "guest should immediately see that the stop request is pending",
            )
        finally:
            routes.Thread = original_thread
            routes.EXTRACTION_JOBS.pop(locals().get("reauth_job_id", ""), None)

        result = delete_cdkeys_with_bound_files(db, [cdkey.id])
        assert_true(result["deleted_files"] == 2, "bound files should be deleted with cdkey")
        assert_true(db.get(FileRecordPayload, record_id) is None, "payload row should be deleted")
        assert_true(db.get(FileRecord, record_id) is None, "file record should be deleted")
        assert_true(db.get(FileRecordPayload, batch_record_id) is None, "second payload row should be deleted")
        assert_true(db.get(FileRecord, batch_record_id) is None, "second file record should be deleted")
        print(f"database auth store verification passed: {workspace}")
    finally:
        db.close()
        SessionLocal.remove()


if __name__ == "__main__":
    main()
