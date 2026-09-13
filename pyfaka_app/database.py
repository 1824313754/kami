import os
from pathlib import Path

from sqlalchemy import create_engine, event, inspect
from sqlalchemy.orm import declarative_base, scoped_session, sessionmaker


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)

DATABASE_URL = os.environ.get(
    "PYFAKA_DATABASE_URL",
    f"sqlite:///{(DATA_DIR / 'fakaipingtai_py.sqlite3').as_posix()}",
)
DATABASE_URL = DATABASE_URL.strip() or f"sqlite:///{(DATA_DIR / 'fakaipingtai_py.sqlite3').as_posix()}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 30} if DATABASE_URL.startswith("sqlite") else {},
    hide_parameters=True,
    future=True,
)
SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True))
Base = declarative_base()


if DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def configure_sqlite(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()


def ensure_sqlite_columns() -> None:
    if not DATABASE_URL.startswith("sqlite"):
        inspector = inspect(engine)
        if "file_record_payload_py" in inspector.get_table_names():
            payload_columns = {column["name"] for column in inspector.get_columns("file_record_payload_py")}
            if "mailinfo" not in payload_columns:
                with engine.begin() as conn:
                    conn.exec_driver_sql("ALTER TABLE file_record_payload_py ADD COLUMN mailinfo TEXT NOT NULL")
        return
    additions = {
        "cdkey_batch_py": {
            "business_type": "VARCHAR(32) NOT NULL DEFAULT 'free'",
            "group_tag": "VARCHAR(64) NOT NULL DEFAULT 'default'",
        },
        "file_record_py": {
            "business_type": "VARCHAR(32) NOT NULL DEFAULT 'free'",
            "group_tag": "VARCHAR(64) NOT NULL DEFAULT 'default'",
            "extraction_no": "VARCHAR(64)",
            "live_status": "VARCHAR(16)",
            "live_quota": "VARCHAR(64)",
            "live_rt_ms": "INTEGER",
            "live_http_status": "INTEGER",
            "live_checked_at": "DATETIME",
            "live_message": "VARCHAR(500)",
        },
        "file_record_payload_py": {
            "mailinfo": "TEXT NOT NULL DEFAULT ''",
        },
        "cdkey_py": {
            "extraction_no": "VARCHAR(64)",
        },
        "admin_user_py": {
            "session_version": "INTEGER NOT NULL DEFAULT 1",
        },
        "upload_batch_py": {
            "business_type": "VARCHAR(32) NOT NULL DEFAULT 'free'",
            "group_tag": "VARCHAR(64) NOT NULL DEFAULT 'default'",
        },
    }
    with engine.begin() as conn:
        for table, columns in additions.items():
            existing = {row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})")}
            for name, ddl in columns.items():
                if name not in existing:
                    conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_file_record_py_extract_claim "
            "ON file_record_py (status, uploaded_by, business_type, group_tag, upload_time, id)"
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_file_record_py_bound_lookup "
            "ON file_record_py (bound_cdkey_id, bound_at, id)"
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_file_record_py_extraction_no "
            "ON file_record_py (extraction_no)"
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_cdkey_py_extraction_no "
            "ON cdkey_py (extraction_no)"
        )
        payload_columns = [row[1] for row in conn.exec_driver_sql("PRAGMA table_info(file_record_payload_py)")]
        if {"client_id", "password", "microsoft_rt"} & set(payload_columns):
            keep_columns = [
                "file_record_id",
                "id_token",
                "access_token",
                "refresh_token",
                "account_id",
                "last_refresh",
                "email",
                "type",
                "expired",
                "mailinfo",
            ]
            conn.exec_driver_sql("ALTER TABLE file_record_payload_py RENAME TO file_record_payload_py_old")
            Base.metadata.tables["file_record_payload_py"].create(bind=conn)
            old_columns = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(file_record_payload_py_old)")}
            copy_columns = [name for name in keep_columns if name in old_columns]
            column_sql = ", ".join(copy_columns)
            conn.exec_driver_sql(
                f"INSERT INTO file_record_payload_py ({column_sql}) "
                f"SELECT {column_sql} FROM file_record_payload_py_old"
            )
            conn.exec_driver_sql("DROP TABLE file_record_payload_py_old")


def init_db() -> None:
    from .models import AdminUser, AppSetting
    from werkzeug.security import check_password_hash, generate_password_hash

    Base.metadata.create_all(bind=engine)
    ensure_sqlite_columns()
    db = SessionLocal()
    try:
        default_username = os.environ.get("PYFAKA_ADMIN_USERNAME", "admin")
        default_password = os.environ.get("PYFAKA_ADMIN_PASSWORD", "change-me")
        admin = db.query(AdminUser).filter_by(username=default_username).first()
        existing_admin = db.query(AdminUser).filter_by(is_admin=True).first()
        if not admin and not existing_admin:
            prefix = "A1"
            if db.query(AdminUser).filter_by(cdkey_prefix=prefix).first():
                for index in range(2, 1000):
                    candidate = f"A{index}"
                    if not db.query(AdminUser).filter_by(cdkey_prefix=candidate).first():
                        prefix = candidate
                        break
            admin = AdminUser(
                username=default_username,
                password_hash=generate_password_hash(default_password),
                enabled=True,
                is_admin=True,
                login_password="must_change" if default_password == "change-me" else None,
                session_version=1,
                cdkey_prefix=prefix,
                over_issue_files=0,
            )
            db.add(admin)
            db.commit()
        elif admin and default_password == "change-me" and not admin.login_password and check_password_hash(admin.password_hash, default_password):
            admin.login_password = "must_change"
            db.commit()
        legacy_proxy = db.get(AppSetting, "live_check_proxy")
        if legacy_proxy:
            db.delete(legacy_proxy)
            db.commit()
        for legacy_key in ("upload_workers", "live_check_workers", "delete_workers"):
            legacy_setting = db.get(AppSetting, legacy_key)
            if legacy_setting:
                db.delete(legacy_setting)
        db.commit()
    finally:
        db.close()
