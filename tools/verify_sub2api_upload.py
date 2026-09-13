import copy
from io import BytesIO
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

workspace = tempfile.TemporaryDirectory(prefix="pyfaka-sub2api-")
os.environ["PYFAKA_DATABASE_URL"] = f"sqlite:///{(Path(workspace.name) / 'verify.sqlite3').as_posix()}"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from flask import Flask
from sqlalchemy.orm import close_all_sessions, sessionmaker
from werkzeug.security import generate_password_hash
from pyfaka_app import routes, services
from pyfaka_app.database import Base, engine, SessionLocal
from pyfaka_app.models import AdminUser, FileRecord, FileRecordPayload, UploadBatch


def item(payload, name="accounts.json"):
    return SimpleNamespace(filename=name, stream=BytesIO(json.dumps(payload).encode("utf-8")))


def document(count=13):
    return {"exported_at": "2026-09-12T00:52:28Z", "proxies": [], "accounts": [
        {"name": f"user-{index}@example.com", "platform": "openai", "type": "oauth",
         "credentials": {"email": f"user-{index}@example.com", "access_token": f"access-{index}", "refresh_token": f"refresh-{index}", "id_token": f"id-{index}", "account_id": f"user-id-{index}", "chatgpt_account_id": f"workspace-{index}", "expires_at": 1790038332},
         "extra": {"last_refresh": "2026-09-12T00:52:13Z"}}
        for index in range(count)
    ]}


def verify():
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    owner = AdminUser(username="sub2api-test", password_hash=generate_password_hash("verify-password"), cdkey_prefix="SUB", is_admin=False)
    db.add(owner)
    db.commit()
    owner_id = owner.id
    events = []
    summary = services.upload_payload_files(db, [item(document())], owner_id, progress_callback=events.append)
    assert (summary.total_count, summary.success_count, summary.failure_count) == (13, 13, 0)
    assert events[0]["total"] == 13 and len(events) == 14
    assert db.query(FileRecord).count() == 13
    record = db.query(FileRecord).filter_by(email_name="user-0@example.com").one()
    assert record.payload.account_id == "workspace-0"
    assert record.payload.expired == "2026-09-22T00:52:12Z"
    assert record.payload.last_refresh == "2026-09-12T00:52:13Z"
    assert record.original_filename == "user-0@example.com.json"
    assert all(row.filename.startswith("accounts.json [账号 ") for row in summary.results)
    record.payload.reauth_info = '{"password":"account-secret","totp_secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}'
    db.commit()
    original_2fa = record.payload.reauth_info
    changed = document(1)
    changed["accounts"][0]["credentials"]["access_token"] = "updated-access"
    overwritten = services.upload_payload_files(db, [item(changed)], owner_id)
    assert overwritten.overwrite_count == 1
    assert record.payload.access_token == "updated-access" and record.payload.reauth_info == original_2fa
    db.commit()
    count = db.query(FileRecord).count()
    bad_inputs = []
    malformed = document(2)
    del malformed["accounts"][1]["credentials"]["refresh_token"]
    bad_inputs.append((malformed, "第 2 个账号"))
    unsupported = document(1)
    unsupported["accounts"][0]["platform"] = "anthropic"
    bad_inputs.append((unsupported, "openai"))
    for value in [[], {}, None]:
        bad_inputs.append(({"accounts": value}, "非空账号列表"))
    duplicate = document(2)
    duplicate["accounts"][1]["credentials"]["email"] = "USER-0@example.com"
    bad_inputs.append((duplicate, "邮箱重复"))
    invalid_date = document(1)
    invalid_date["accounts"][0]["credentials"]["expires_at"] = "invalid"
    bad_inputs.append((invalid_date, "expires_at"))
    for payload, message in bad_inputs:
        failed = services.upload_payload_files(db, [item(payload)], owner_id)
        assert failed.success_count == 0 and any(message in row.message for row in failed.results)
        assert db.query(FileRecord).count() == count
        assert db.query(FileRecordPayload).filter_by(file_record_id=record.id).one().access_token == "updated-access"
    record.status = "BOUND"
    db.commit()
    failed = services.upload_payload_files(db, [item(document(14))], owner_id)
    assert failed.success_count == 0 and any("已绑定" in row.message for row in failed.results)
    assert db.query(FileRecord).count() == count
    record.status = "AVAILABLE"
    db.commit()
    exported = services.sub2api_json_for_files(db, [record])
    reimport = services.upload_payload_files(db, [SimpleNamespace(filename="roundtrip.json", stream=BytesIO(exported))], owner_id)
    assert reimport.success_count == 1 and record.payload.account_id == "workspace-0"
    assert record.payload.reauth_info == original_2fa
    db.rollback()
    plain = services.payload_for_record(record)
    plain["email"] = "plain@example.com"
    mixed = services.upload_payload_files(db, [item(document(1)), item(plain, "plain.json")], owner_id)
    assert mixed.success_count == 2
    db.rollback()
    mixed_duplicate = services.upload_payload_files(db, [item(document(1)), item(services.payload_for_record(record), "plain.json")], owner_id)
    assert mixed_duplicate.success_count == 0 and mixed_duplicate.failure_count == 2
    assert db.query(FileRecord).count() == count
    fallback = document(1)
    del fallback["accounts"][0]["credentials"]["email"]
    fallback["accounts"][0]["extra"]["email"] = "fallback@example.com"
    assert services.parse_upload_payloads(item(fallback).stream)[0][0]["email"] == "fallback@example.com"
    del fallback["accounts"][0]["extra"]["email"]
    assert services.parse_upload_payloads(item(fallback).stream)[0][0]["email"] == "user-0@example.com"
    assert services.parse_upload_payloads(BytesIO(b"\xef\xbb\xbf" + json.dumps(document(1)).encode()))[0][0]["email"] == "user-0@example.com"

    routes.DATA_DIR = Path(workspace.name)
    routes.JOB_HISTORY_PATH = Path(workspace.name) / "task_history.json"
    app = Flask(__name__)
    app.config.update(SECRET_KEY="sub2api-verification", TESTING=True)
    app.register_blueprint(routes.bp)
    client = app.test_client()
    login = client.post("/api/admin/login", json={"username": "sub2api-test", "password": "verify-password"})
    assert login.status_code == 200
    headers = {"X-CSRF-Token": login.get_json()["session"]["csrf_token"]}

    class ImmediateThread:
        def __init__(self, target, args, **_):
            self.target, self.args = target, args

        def start(self):
            self.target(*self.args)

    with patch.object(routes, "Thread", ImmediateThread):
        response = client.post("/api/admin/files/upload", data={"files": (item(document()).stream, "sub2api.json"), "business_type": "free", "group_tag": "api"}, headers=headers)
    assert response.status_code == 202
    job = routes.EXTRACTION_JOBS[response.get_json()["job_id"]]
    assert job["status"] == "done", job.get("error")
    assert (job["total"], job["processed"], job["success"]) == (13, 13, 13)
    db.expire_all()
    batch = db.query(UploadBatch).filter_by(id=job["batch_id"]).one()
    assert batch.total_count == 13
    assert db.query(FileRecord).filter_by(group_tag="api").count() == 13

    if len(sys.argv) > 1:
        sample_path = Path(sys.argv[1])
        with sample_path.open("rb") as stream:
            sample = services.upload_payload_files(db, [SimpleNamespace(filename=sample_path.name, stream=stream)], owner_id, group_tag="sample-only")
        assert sample.total_count == sample.success_count == 13 and sample.failure_count == 0
        rows = db.query(FileRecord).filter_by(group_tag="sample-only").all()
        originals = json.loads(sample_path.read_text(encoding="utf-8-sig"))["accounts"]
        source = {entry["credentials"]["email"].lower(): entry for entry in originals}
        for row in rows:
            credentials = source[row.email_name.lower()]["credentials"]
            assert row.payload.access_token == credentials["access_token"]
            assert row.payload.refresh_token == credentials["refresh_token"]
        db.rollback()
        print("SAMPLE PASS: 13 accounts parsed and imported in isolated database; tokens preserved")
    db.close()
    print("SUB2API PASS: mapping, 13-account progress, atomic errors, duplicates, bound protection, 2FA preservation, mixed JSON, API upload")


if __name__ == "__main__":
    try:
        verify()
    finally:
        SessionLocal.remove()
        close_all_sessions()
        engine.dispose()
        workspace.cleanup()
