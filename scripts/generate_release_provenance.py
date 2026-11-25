"""Generate deterministic SHA-256 build provenance digests across backend source and deployment assets."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def compute_repository_provenance(root: Path = REPO_ROOT) -> dict[str, object]:
    """Compute SHA-256 digests for key backend code, API schema, and deployment artifacts."""
    targets = ("apps", "packages", "deploy", "contracts", "operators", "docs/api/openapi.v1.json")
    digests: dict[str, str] = {}

    for rel in targets:
        p = root / rel
        if p.is_file():
            digests[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
        elif p.is_dir():
            for file_path in sorted(p.rglob("*")):
                if not file_path.is_file():
                    continue
                if "__pycache__" in file_path.parts or file_path.suffix == ".pyc":
                    continue
                norm_rel = file_path.relative_to(root).as_posix()
                digests[norm_rel] = hashlib.sha256(file_path.read_bytes()).hexdigest()

    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "file_count": len(digests),
        "sha256_manifest": digests,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit VEXReach release file provenance manifest.")
    parser.add_argument("--output", type=Path, required=True, help="Destination JSON file.")
    args = parser.parse_args()
    payload = compute_repository_provenance()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Wrote SHA-256 provenance manifest for {payload['file_count']} files -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
