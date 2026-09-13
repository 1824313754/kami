import os
from secrets import token_urlsafe
from datetime import timedelta
from datetime import timezone, timedelta as datetime_timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import Flask, url_for

from .database import DATA_DIR, SessionLocal, init_db


def app_secret_key() -> str:
    configured = os.environ.get("PYFAKA_SECRET_KEY")
    if configured:
        return configured
    key_file = DATA_DIR / "secret_key.txt"
    if key_file.exists():
        return key_file.read_text(encoding="utf-8").strip()
    generated = token_urlsafe(48)
    key_file.write_text(generated, encoding="utf-8")
    return generated


def app_timezone():
    try:
        return ZoneInfo(os.environ.get("PYFAKA_TIMEZONE", "Asia/Shanghai"))
    except ZoneInfoNotFoundError:
        return timezone(datetime_timedelta(hours=8))


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = app_secret_key()
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=int(os.environ.get("PYFAKA_SESSION_MINUTES", "20")))
    app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("PYFAKA_MAX_CONTENT_LENGTH", str(10 * 1024 * 1024 * 1024)))
    app.config["MAX_FORM_MEMORY_SIZE"] = int(os.environ.get("PYFAKA_MAX_FORM_MEMORY_SIZE", str(64 * 1024 * 1024)))
    app.config["MAX_FORM_PARTS"] = int(os.environ.get("PYFAKA_MAX_FORM_PARTS", "50000"))
    app.config["STATIC_VERSION"] = os.environ.get("PYFAKA_STATIC_VERSION", "20260623-04")
    app.config["SESSION_REFRESH_EACH_REQUEST"] = False
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = os.environ.get("PYFAKA_COOKIE_SECURE", "0") == "1"
    init_db()

    from .routes import bp, recover_interrupted_jobs

    app.register_blueprint(bp)
    recover_interrupted_jobs()

    @app.context_processor
    def inject_asset_url():
        def asset_url(filename: str) -> str:
            return url_for("static", filename=filename, v=app.config["STATIC_VERSION"])
        return {"asset_url": asset_url}

    @app.teardown_appcontext
    def cleanup(_exception=None):
        SessionLocal.remove()

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        if request_is_https():
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    return app


def request_is_https() -> bool:
    from flask import request

    return request.is_secure or request.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip() == "https"
