"""Gateway settings: YAML file, overridable by ATTESTA_<FIELD> env vars."""
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel


class GatewaySettings(BaseModel):
    trust_domain: str = "attesta.example.org"
    gateway_spiffe_id: str = "spiffe://attesta.example.org/gateway"
    allowed_scorer_id: str = "spiffe://attesta.example.org/scoring-service"
    spiffe_socket: str = "unix:///run/spire/sockets/agent.sock"
    db_path: Path = Path("/data/ledger.db")
    checkpoint_key_dir: Path = Path("/data/checkpoint_keys")
    scorer_keys_path: Path = Path("/run/attesta/scorer_keys.yaml")
    policy_path: Path = Path("/config/policy.yaml")
    listen_host: str = "0.0.0.0"
    listen_port: int = 8443
    queue_maxsize: int = 256
    svid_refresh_seconds: int = 300
    # Fallback used only if py-spiffe's X509Source fails to connect.
    svid_fallback: bool = False
    svid_fallback_refresh_seconds: int = 1200
    spire_agent_bin: Path = Path("/opt/spire/bin/spire-agent")


def load_settings(path: Path | None = None) -> GatewaySettings:
    path = path or Path(os.environ.get("ATTESTA_GATEWAY_CONFIG", "/config/gateway.yaml"))
    data: dict[str, Any] = {}
    if Path(path).exists():
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    for field in GatewaySettings.model_fields:
        env_value = os.environ.get(f"ATTESTA_{field.upper()}")
        if env_value is not None:
            data[field] = env_value
    return GatewaySettings(**data)
