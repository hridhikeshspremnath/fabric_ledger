"""Evidence floors from an OPA server running config/policy.rego.

Fails strict: if OPA cannot answer, callers get OpaUnavailable and must refuse to
score or accept the record. A silently missing floor would let a weaker decision through.
"""
import http.client
import json
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from attesta.records.trust_record import Decision

FLOOR_PATH = "/v1/data/attesta/policy/floor"
# Only evidence fields reach OPA, never signatures, keys or certificate fingerprints.
EVIDENCE = ("flag_install_exec", "flag_network", "flag_obfuscation", "flag_cred_access",
            "flag_process_spawn", "llm_verdict")

Floor = Callable[[Mapping[str, Any]], Decision]


class OpaUnavailable(RuntimeError):
    """OPA could not be reached or gave an unusable answer."""


def opa_floor(url: str, timeout: float = 5.0) -> Floor:
    parts = urlsplit(url)

    def floor(fields: Mapping[str, Any]) -> Decision:
        body = json.dumps({"input": {k: _plain(fields[k]) for k in EVIDENCE}})
        try:
            conn = http.client.HTTPConnection(parts.hostname or "", parts.port or 8181, timeout=timeout)
            try:
                conn.request("POST", FLOOR_PATH, body, {"Content-Type": "application/json"})
                response = conn.getresponse()
                payload = json.loads(response.read() or b"null")
            finally:
                conn.close()
            if response.status != 200:
                raise OpaUnavailable(f"OPA returned {response.status}")
            return Decision(payload["result"])
        except (OSError, http.client.HTTPException, ValueError, KeyError, TypeError) as exc:
            raise OpaUnavailable(f"OPA query failed: {exc}") from exc

    return floor


def _plain(value: Any) -> Any:
    return getattr(value, "value", value)  # enums -> their string value
