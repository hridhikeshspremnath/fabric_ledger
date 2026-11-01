"""Auditor CLI: override a record's effective decision on Fabric.

Runs as the auditor SPIFFE identity and talks to the AUDITOR bridge only; the
CI-facing bridge never holds the Auditor org's Fabric identity.

    python -m attesta.tools.auditor_override <record_id> <ALLOW|WARN|REVIEW|BLOCK> "<reason>"
"""
import argparse

from attesta.backends.bridge_client import SpiffeBridgeClient
from attesta.gateway.settings import load_settings
from attesta.gateway.svid import create_svid_source


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("record_id")
    parser.add_argument("decision", choices=["ALLOW", "WARN", "REVIEW", "BLOCK"])
    parser.add_argument("reason")
    args = parser.parse_args()

    settings = load_settings()
    source, _ = create_svid_source(settings)
    client = SpiffeBridgeClient(settings.auditor_bridge_host, settings.bridge_port,
                                settings.auditor_bridge_spiffe_id, source,
                                refresh_seconds=settings.svid_refresh_seconds)
    status, body = client.request("POST", "/v1/overrides", {
        "record_id": args.record_id, "decision": args.decision, "reason": args.reason})
    source.close()
    if status != 201:
        raise SystemExit(f"override rejected ({status}): {body}")
    print(f"override recorded: tx_id={body['tx_id']} block={body['block_number']}")


if __name__ == "__main__":
    main()
