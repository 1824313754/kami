"""Offline inventory, issuance and extraction checks for mandatory 2FA."""
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["PYFAKA_DATABASE_URL"] = "sqlite:///:memory:"

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from pyfaka_app import services
from pyfaka_app.database import Base
from pyfaka_app.live_check import LiveCheckResult
from pyfaka_app.models import AdminUser, Cdkey, CdkeyBatch, FileRecord, FileRecordPayload
from pyfaka_app.two_factor import import_two_factor

SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
READY = json.dumps({"password": "test-password", "totp_secret": SECRET})


def fixture():
    services._BUSINESS_TYPE_OPTIONS_CACHE = services.default_business_type_options()
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    owner = AdminUser(username="owner", password_hash="unused", cdkey_prefix="T", over_issue_files=100)
    other = AdminUser(username="other", password_hash="unused", cdkey_prefix="U")
    db.add_all([owner, other])
    db.commit()

    def add(raw="", *, scope="default", business="free", user=None, status="AVAILABLE"):
        index = db.query(FileRecord).count()
        email = f"account-{index}@example.com"
        record = FileRecord(original_filename=f"{index}.json", email_name=email, uploaded_by=user or owner.id,
                            business_type=business, group_tag=scope, status=status)
        record.payload = FileRecordPayload(id_token="id", access_token="access", refresh_token="refresh",
                                           account_id="account", last_refresh="", email=email, type="oauth",
                                           expired="2099-01-01T00:00:00Z", reauth_info=raw)
        db.add(record)
        db.flush()
        return record

    # Put unready files first, including malformed legacy credentials.
    invalid = ["", "{}", "[]", "broken", json.dumps({"totp_secret": SECRET}),
               json.dumps({"password": "p"}), json.dumps({"password": "p", "totp_secret": "invalid!"})]
    missing = [add(invalid[i % len(invalid)]) for i in range(10)]
    ready = [add(READY) for _ in range(20)]
    add(READY, user=other.id)
    add(READY, scope="other")
    add(READY, business="plus")
    add(READY, status="BOUND")
    db.commit()
    return db, owner, missing, ready


def rejected(db, action):
    before = (db.query(Cdkey).count(), db.query(CdkeyBatch).count())
    try:
        action()
    except services.BusinessError as exc:
        assert "2FA" in str(exc), str(exc)
    else:
        raise AssertionError("insufficient 2FA inventory was accepted")
    assert (db.query(Cdkey).count(), db.query(CdkeyBatch).count()) == before


def check_generation():
    db, owner, missing, ready = fixture()
    cap = services.capacity_for_owner(db, owner.id)
    assert cap.available_files == 20, f"expected 20 eligible files, got {cap.available_files}"
    assert cap.total_bindable_files == 20, "over-issue must not bypass 2FA stock"
    rejected(db, lambda: services.create_cdkey_batch(db, owner.id, 21, 1, None))
    rejected(db, lambda: services.create_cdkey_batch(db, owner.id, 11, 2, None))
    batch = services.create_cdkey_batch(db, owner.id, 10, 2, None)
    assert len(batch.cdkeys) == 10
    assert services.capacity_for_owner(db, owner.id).total_bindable_files == 0
    rejected(db, lambda: services.create_cdkey_batch(db, owner.id, 1, 1, None))
    import_two_factor(db, f"{missing[0].email_name}--test-password--{SECRET}", owner.id, "free", "default")
    db.commit()
    assert services.capacity_for_owner(db, owner.id).total_bindable_files == 1
    services.create_cdkey_batch(db, owner.id, 1, 1, None)
    db.close()


def check_import():
    db, owner, missing, ready = fixture()
    codes = [f"1FREE-20260913-{'A' * 19}{services.CODE_ALPHABET[i]}" for i in range(21)]
    rejected(db, lambda: services.import_cdkey_batch(db, owner.id, codes))
    # Check every business before inserting any group.
    mixed = [codes[0], f"2PLUS-20260913-{'B' * 20}"]
    rejected(db, lambda: services.import_cdkey_batch(db, owner.id, mixed))
    result = services.import_cdkey_batch(db, owner.id, codes[:20])
    assert result.imported_count == 20
    assert services.capacity_for_owner(db, owner.id).total_bindable_files == 0
    assert services.import_cdkey_batch(db, owner.id, codes[:20]).imported_count == 0
    db.close()


def check_extraction(live, single=False):
    db, owner, missing, ready = fixture()
    batch = services.create_cdkey_batch(db, owner.id, 20, 1, None)
    cards = list(batch.cdkeys)
    checked = []

    def candidates(session, records):
        checked.extend(record.id for record in records)
        return None, {record.id: {} for record in records}, {}

    with patch.object(services, "live_check_candidates", side_effect=candidates), patch.object(
        services, "check_auth_item_with_retry", return_value=LiveCheckResult(True, 200, "ok", False)
    ):
        if single:
            for card in cards:
                services.access_cdkey(db, card.code, "127.0.0.1", live_check_workers=1)
        else:
            services.access_cdkeys_bulk(db, [card.code for card in cards], "127.0.0.1", live_check=live, live_check_workers=1)
    db.expire_all()
    assert all(record.status == "AVAILABLE" and record.bound_cdkey_id is None for record in missing)
    assert all(record.status == "BOUND" and record.bound_cdkey_id for record in ready)
    assert all(card.extract_status == "EXTRACTED" for card in cards)
    if live:
        assert set(checked) == {record.id for record in ready}
    assert services.capacity_for_owner(db, owner.id).total_bindable_files == 0
    db.close()


def main():
    check_generation()
    check_import()
    check_extraction(False)
    check_extraction(True)
    check_extraction(True, single=True)
    print("PASS: 30 files/20 with 2FA; generation/reservations; no over-issue; import atomicity; 3 extraction paths; scopes; later 2FA import")


if __name__ == "__main__":
    main()
