from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class LiveCheckResult:
    alive: bool
    http_status: int | None
    message: str
    token_refreshed: bool
    updated_auth: dict[str, Any] | None = None
    quota: dict[str, str | None] | None = None
    rt_ms: int | None = None
