from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ServiceSettings:
    host: str = "0.0.0.0"
    port: int = 8011
    default_workers: int = 1
    max_workers: int = 30
    proxy: str = ""


def load_settings(path: str | Path | None = None) -> ServiceSettings:
    config_path = Path(path) if path else Path(__file__).with_name("config.json")
    if not config_path.is_file():
        return ServiceSettings()
    with config_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("配置文件必须是 JSON 对象")

    max_workers = max(1, min(100, int(payload.get("max_workers", 30))))
    default_workers = max(
        1,
        min(max_workers, int(payload.get("default_workers", 1))),
    )
    return ServiceSettings(
        host=str(payload.get("host") or "0.0.0.0").strip(),
        port=max(1, min(65535, int(payload.get("port", 8011)))),
        default_workers=default_workers,
        max_workers=max_workers,
        proxy=str(payload.get("proxy") or "").strip(),
    )
