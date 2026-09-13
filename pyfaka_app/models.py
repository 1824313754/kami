from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, BigInteger
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def now() -> datetime:
    return datetime.now()


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now, nullable=False)


class AdminUser(Base, TimestampMixin):
    __tablename__ = "admin_user_py"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime)
    login_password: Mapped[str | None] = mapped_column(String(128))
    session_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    cdkey_prefix: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    over_issue_files: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class AppSetting(Base, TimestampMixin):
    __tablename__ = "app_setting_py"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str | None] = mapped_column(Text)


class CdkeyBatch(Base):
    __tablename__ = "cdkey_batch_py"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    batch_no: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    prefix: Mapped[str] = mapped_column(String(32), nullable=False)
    key_date: Mapped[str] = mapped_column(String(8), nullable=False)
    total_count: Mapped[int] = mapped_column(Integer, nullable=False)
    files_per_key: Mapped[int] = mapped_column(Integer, nullable=False)
    business_type: Mapped[str] = mapped_column(String(32), default="free", nullable=False, index=True)
    group_tag: Mapped[str] = mapped_column(String(64), default="default", nullable=False, index=True)
    remark: Mapped[str | None] = mapped_column(String(255))
    created_by: Mapped[int | None] = mapped_column(ForeignKey("admin_user_py.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now, nullable=False)

    owner = relationship("AdminUser")
    cdkeys = relationship("Cdkey", back_populates="batch", cascade="all, delete-orphan")


class Cdkey(Base, TimestampMixin):
    __tablename__ = "cdkey_py"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    batch_id: Mapped[int] = mapped_column(ForeignKey("cdkey_batch_py.id"), nullable=False)
    code: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    files_per_key: Mapped[int] = mapped_column(Integer, nullable=False)
    extract_status: Mapped[str] = mapped_column(String(16), default="PENDING", nullable=False, index=True)
    extraction_no: Mapped[str | None] = mapped_column(String(64), index=True)
    extracted_at: Mapped[datetime | None] = mapped_column(DateTime)
    first_extract_ip: Mapped[str | None] = mapped_column(String(64))

    batch = relationship("CdkeyBatch", back_populates="cdkeys")
    files = relationship("FileRecord", back_populates="bound_cdkey")


class FileRecord(Base, TimestampMixin):
    __tablename__ = "file_record_py"
    __table_args__ = (
        Index(
            "ix_file_record_py_extract_claim",
            "status",
            "uploaded_by",
            "business_type",
            "group_tag",
            "upload_time",
            "id",
        ),
        Index("ix_file_record_py_bound_lookup", "bound_cdkey_id", "bound_at", "id"),
    )

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    email_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    storage_path: Mapped[str] = mapped_column(String(512), default="__payload__", nullable=False)
    file_size: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    file_ext: Mapped[str] = mapped_column(String(32), default="json", nullable=False)
    business_type: Mapped[str] = mapped_column(String(32), default="free", nullable=False, index=True)
    group_tag: Mapped[str] = mapped_column(String(64), default="default", nullable=False, index=True)
    upload_time: Mapped[datetime] = mapped_column(DateTime, default=now, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), default="AVAILABLE", nullable=False, index=True)
    bound_cdkey_id: Mapped[int | None] = mapped_column(ForeignKey("cdkey_py.id"))
    bound_at: Mapped[datetime | None] = mapped_column(DateTime)
    extraction_no: Mapped[str | None] = mapped_column(String(64), index=True)
    uploaded_by: Mapped[int | None] = mapped_column(ForeignKey("admin_user_py.id"), index=True)
    live_status: Mapped[str | None] = mapped_column(String(16))
    live_quota: Mapped[str | None] = mapped_column(String(64))
    live_rt_ms: Mapped[int | None] = mapped_column(Integer)
    live_http_status: Mapped[int | None] = mapped_column(Integer)
    live_checked_at: Mapped[datetime | None] = mapped_column(DateTime)
    live_message: Mapped[str | None] = mapped_column(String(500))

    owner = relationship("AdminUser")
    bound_cdkey = relationship("Cdkey", back_populates="files")
    payload = relationship("FileRecordPayload", back_populates="file_record", uselist=False, cascade="all, delete-orphan")


class FileRecordPayload(Base):
    __tablename__ = "file_record_payload_py"

    file_record_id: Mapped[int] = mapped_column(ForeignKey("file_record_py.id"), primary_key=True)
    id_token: Mapped[str] = mapped_column(Text, nullable=False)
    access_token: Mapped[str] = mapped_column(Text, nullable=False)
    refresh_token: Mapped[str] = mapped_column(Text, nullable=False)
    account_id: Mapped[str] = mapped_column(String(255), nullable=False)
    last_refresh: Mapped[str] = mapped_column(String(128), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    expired: Mapped[str] = mapped_column(String(128), nullable=False)
    reauth_info: Mapped[str] = mapped_column("mailinfo", Text, default="", server_default="", nullable=False)

    file_record = relationship("FileRecord", back_populates="payload")


class AuditLog(Base):
    __tablename__ = "audit_log_py"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("admin_user_py.id"))
    username: Mapped[str | None] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_type: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(255))
    ip: Mapped[str | None] = mapped_column(String(64))
    detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now, nullable=False, index=True)

    user = relationship("AdminUser")


class UploadBatch(Base):
    __tablename__ = "upload_batch_py"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("admin_user_py.id"))
    uploaded_by: Mapped[int | None] = mapped_column(ForeignKey("admin_user_py.id"))
    business_type: Mapped[str] = mapped_column(String(32), default="free", nullable=False, index=True)
    group_tag: Mapped[str] = mapped_column(String(64), default="default", nullable=False, index=True)
    total_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    success_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failure_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    overwrite_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now, nullable=False, index=True)

    owner = relationship("AdminUser", foreign_keys=[owner_id])
    uploader = relationship("AdminUser", foreign_keys=[uploaded_by])
    results = relationship("UploadResult", back_populates="batch", cascade="all, delete-orphan")


class UploadResult(Base):
    __tablename__ = "upload_result_py"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    batch_id: Mapped[int] = mapped_column(ForeignKey("upload_batch_py.id"), nullable=False, index=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    message: Mapped[str] = mapped_column(String(255), nullable=False)
    record_id: Mapped[int | None] = mapped_column(ForeignKey("file_record_py.id"))

    batch = relationship("UploadBatch", back_populates="results")
    record = relationship("FileRecord")
