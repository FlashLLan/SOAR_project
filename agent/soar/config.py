from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import os
import yaml

@dataclass(frozen=True)
class SoarConfig:
    eve_log_path: str
    database_path: str

def _candidate_paths() -> list[Path]:
    return [
        Path(os.environ.get("SOAR_CONFIG_PATH", "")),
        Path("/etc/soar/soar.yaml"),
        Path.cwd() / "config.yaml",
    ]

def load_config() -> SoarConfig:
    for p in _candidate_paths():
        if not p or str(p) == ".":
            continue
        if p.exists():
            data = yaml.safe_load(p.read_text()) or {}
            return SoarConfig(
                eve_log_path=data.get("eve_log_path", "/var/log/suricata/eve.json"),
                database_path=data.get("database_path", "/var/lib/soar/alerts.db"),
            )
    raise FileNotFoundError("No config found (tried $SOAR_CONFIG_PATH, /etc/soar/soar.yaml, ./config.yaml)")
