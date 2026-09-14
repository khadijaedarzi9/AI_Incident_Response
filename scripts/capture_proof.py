"""Capture runtime versions and SHA-256 digests for generated evidence."""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "artifacts" / "proof"


def command_output(command: list[str]) -> str:
    try:
        return subprocess.check_output(
            command,
            cwd=ROOT,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
        ).strip()
    except (OSError, subprocess.SubprocessError):
        return "unavailable"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    PROOF.mkdir(parents=True, exist_ok=True)
    environment = {
        "captured_utc": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "docker_client": command_output(
            ["docker", "version", "--format", "{{.Client.Version}}"]
        ),
        "docker_server": command_output(
            ["docker", "version", "--format", "{{.Server.Version}}"]
        ),
        "compose": command_output(["docker", "compose", "version", "--short"]),
    }
    (PROOF / "environment.json").write_text(
        json.dumps(environment, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    paths: list[Path] = []
    for relative in (
        "artifacts/demo",
        "artifacts/benchmark",
        "artifacts/scenarios",
        "artifacts/proof",
    ):
        paths.extend(
            path
            for path in (ROOT / relative).glob("*")
            if path.is_file() and path.name != "checksums.json"
        )
    records = [
        {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": sha256(path),
        }
        for path in sorted(set(paths))
    ]
    (PROOF / "checksums.json").write_text(
        json.dumps(records, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"captured {len(records)} artifact digests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

