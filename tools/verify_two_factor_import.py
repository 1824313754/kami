"""Offline API checks for unmatched 2FA imports, including zero matches."""
from unittest.mock import patch

from verify_two_factor_stock import fixture, SECRET
from flask import Flask
from werkzeug.security import generate_password_hash
from pyfaka_app import routes
from pyfaka_app.models import FileRecordPayload


def main():
    db, owner, missing, ready = fixture()
    owner.password_hash = generate_password_hash("test-password")
    db.commit()
    app = Flask(__name__)
    app.config.update(SECRET_KEY="test-key", TESTING=True)
    app.register_blueprint(routes.bp)
    client = app.test_client()
    with patch.object(routes, "db", return_value=db):
        login = client.post("/api/admin/login", json={"username": "owner", "password": "test-password"})
        assert login.status_code == 200
        headers = {"X-CSRF-Token": login.get_json()["session"]["csrf_token"]}

        def snapshot():
            return dict(db.query(FileRecordPayload.file_record_id, FileRecordPayload.reauth_info).all())

        def send(text, group="default"):
            return client.post("/api/admin/files/import-2fa", json={"text": text, "business_type": "free", "group_tag": group}, headers=headers)

        before = snapshot()
        absent = f"absent@example.com--test-password--{SECRET}"
        for text, skipped, group in [(absent, 1, "default"), (absent + "\n" + absent.replace("absent@", "another@"), 2, "default"), (absent, 1, "empty-pool")]:
            response = send(text, group)
            data = response.get_json()
            assert response.status_code == 200, f"all-unmatched import returned HTTP {response.status_code}"
            assert (data["matched_accounts"], data["updated_records"], data["skipped_accounts"]) == (0, 0, skipped)
            assert snapshot() == before
        matched = f"{missing[0].email_name.upper()}--new-password--{SECRET}"
        response = send(matched + "\n" + absent)
        data = response.get_json()
        assert response.status_code == 200
        assert (data["matched_accounts"], data["updated_records"], data["skipped_accounts"]) == (1, 1, 1)
        after = snapshot()
        assert {key for key in before if before[key] != after[key]} == {missing[0].id}
        for text in ["", "invalid-line", f"absent@example.com--p--invalid!", matched + "\ninvalid-line"]:
            assert send(text).status_code == 400
            assert snapshot() == after
    db.close()
    print("PASS: unmatched/empty-pool HTTP 200; skip counts; mixed import; no unintended writes; invalid input rejected")


if __name__ == "__main__":
    main()
