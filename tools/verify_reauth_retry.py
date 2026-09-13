"""Offline checks of the account worker's retry behavior; no network or database writes."""
import ast
import os
from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["PYFAKA_DATABASE_URL"] = "sqlite:///:memory:"
from pyfaka_app import routes
from pyfaka_app.reauth import oauth_flow
from pyfaka_app.reauth.oauth_client.auth_flow import EmailOtpValidationError


def check_worker(source):
    tree = ast.parse(Path(source).read_text(encoding="utf-8-sig"))
    job = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run_query_reauth_job")
    worker = next(n for n in job.body if isinstance(n, ast.Try))
    process = next(n for n in ast.walk(worker) if isinstance(n, ast.FunctionDef) and n.name == "process")
    code = compile(ast.Module(body=[process], type_ignores=[]), str(source), "exec")
    success = {"access_token": "test-access", "refresh_token": "test-refresh"}
    record = {"id": 1, "email": "test@example.com", "payload": {}}

    def run(outcomes, expected_calls, error=None, cancel=False):
        calls, messages, checks = [], [], []

        def authorize(*args):
            calls.append(args)
            outcome = outcomes[len(calls) - 1]
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        def active(_):
            checks.append(True)
            if cancel and len(checks) == 2:
                raise RuntimeError("task stopped")

        namespace = dict(vars(routes))
        namespace.update(
            job_id="retry-test",
            ensure_active_job_runnable=active,
            update_query_reauth_account_progress=lambda *args, **kwargs: messages.append(args[2]),
            _reauth_credential=lambda _: {"password": "test-password", "totp_secret": "test-secret"},
            _reauth_payload=lambda original, refreshed, email: refreshed,
        )
        exec(code, namespace)
        with patch.object(oauth_flow, "reauthorize_account", side_effect=authorize):
            try:
                result = namespace["process"](record)
            except Exception as exc:
                assert error is not None and error in str(exc), type(exc).__name__
            else:
                assert error is None, "expected terminal failure"
                assert result == (record, success, "")
        assert len(calls) == expected_calls, f"expected {expected_calls} attempts, got {len(calls)}"
        assert all("test-password" not in m and "test-secret" not in m for m in messages)
        return messages

    run([success], 1)
    run([RuntimeError("temporary"), success], 2)
    messages = run([RuntimeError("temporary"), RuntimeError("temporary"), success], 3)
    assert any("3/3" in m for m in messages), "missing attempt progress"
    run([RuntimeError("temporary")] * 3, 3, "temporary")
    run([{"access_token": "test-access"}] * 3, 3, "完整令牌")
    run([EmailOtpValidationError(403, "account_deactivated")], 1, "403")
    run([RuntimeError("rate_limit_exceeded")], 1, "rate_limit_exceeded")
    run([RuntimeError("temporary")], 1, "task stopped", cancel=True)


if __name__ == "__main__":
    try:
        check_worker(sys.argv[1] if len(sys.argv) > 1 else Path(routes.__file__))
    except AssertionError as exc:
        print("FAIL: " + str(exc))
        sys.exit(1)
    print("PASS: retry worker (8 cases)")
