import os
import sys
import tempfile
from datetime import datetime


workspace = tempfile.mkdtemp(prefix="pyfaka-cleanup-verify-")
os.environ["PYFAKA_DATABASE_URL"] = f"sqlite:///{os.path.join(workspace, 'verify.sqlite3').replace(os.sep, '/')}"
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from pyfaka_app import app_timezone, cleanup_target_time
from pyfaka_app.database import SessionLocal, init_db
from pyfaka_app.services import (
    EXTRACT_CLEANUP_TIME_KEY,
    cleanup_schedule_time,
    normalize_cleanup_time_text,
    set_setting,
)


def assert_equal(actual, expected, label):
    if actual != expected:
        raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")


def main():
    init_db()
    db = SessionLocal()
    try:
        assert_equal(normalize_cleanup_time_text("12:00"), "12:00", "valid time")
        assert_equal(normalize_cleanup_time_text("7:5"), "07:05", "normalize time")
        assert_equal(normalize_cleanup_time_text("25:00"), "12:00", "invalid hour fallback")
        assert_equal(cleanup_schedule_time(db), "12:00", "default cleanup time")

        set_setting(db, EXTRACT_CLEANUP_TIME_KEY, "13:45")
        assert_equal(cleanup_schedule_time(db), "13:45", "saved cleanup time")

        tz = app_timezone()
        sample_now = datetime(2026, 6, 19, 10, 2, 3, tzinfo=tz)
        sample_target = cleanup_target_time(sample_now, "13:45")
        assert_equal(sample_target.hour, 13, "target hour")
        assert_equal(sample_target.minute, 45, "target minute")
        assert_equal(sample_target.second, 0, "target second")

        set_setting(db, EXTRACT_CLEANUP_TIME_KEY, "09:30")
        assert_equal(cleanup_schedule_time(db), "09:30", "hot reload cleanup time")
        print("cleanup scheduler verification passed")
    finally:
        db.close()
        SessionLocal.remove()


if __name__ == "__main__":
    main()
