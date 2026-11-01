"""Generate a demo scorer Ed25519 key pair (never inside the repo tree).

Writes <out-dir>/<key-id>.key (private, PEM) and <out-dir>/scorer_keys.yaml
(public registry entry with validity window). out-dir should be gitignored.
"""
import argparse
import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate(out_dir: Path, key_id: str, days: int, key_mode: int) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    private_path = out_dir / f"{key_id}.key"
    private_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    private_path.chmod(key_mode)
    public_raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    registry = {"keys": [{
        "key_id": key_id,
        "public_key": base64.b64encode(public_raw).decode("ascii"),
        "not_before": (now - timedelta(minutes=5)).isoformat(),
        "not_after": (now + timedelta(days=days)).isoformat(),
        "revoked": False,
    }]}
    (out_dir / "scorer_keys.yaml").write_text(yaml.safe_dump(registry, sort_keys=False))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--key-id", default="scorer-dev-1")
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--key-mode", default="600", help="octal file mode for the private key")
    args = parser.parse_args()
    generate(args.out_dir, args.key_id, args.days, int(args.key_mode, 8))
    print(f"wrote {args.out_dir}/{args.key_id}.key and scorer_keys.yaml")


if __name__ == "__main__":
    main()
