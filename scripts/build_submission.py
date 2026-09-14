"""Build a deterministic, self-contained BCP-1 submission archive."""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "submission" / "BCP-1-Artifact.zip"
SUMS = ROOT / "submission" / "SHA256SUMS.txt"
FIXED_TIME = (2026, 9, 13, 0, 0, 0)

ROOT_FILES = (
    ".gitignore",
    "CONTROL_MATRIX.md",
    "Dockerfile",
    "EVIDENCE_PROFILE.md",
    "LICENSE",
    "Makefile",
    "README.md",
    "STANDARD.md",
    "SUBMISSION.md",
    "compose.boundary-smoke.yaml",
    "compose.network-ablation.yaml",
    "pyproject.toml",
)
DIRECTORIES = (
    "app",
    "auditor",
    "benchmarks",
    "demo",
    "policies",
    "schemas",
    "scripts",
    "tests",
    "artifacts/benchmark",
    "artifacts/demo",
    "artifacts/proof",
    "artifacts/scenarios",
)
EXCLUDED_PARTS = {
    "__pycache__",
    ".pytest_cache",
}
EXCLUDED_SUFFIXES = {
    ".pyc",
    ".pyo",
}


def included_files() -> list[Path]:
    files = [ROOT / name for name in ROOT_FILES]
    for directory in DIRECTORIES:
        base = ROOT / directory
        if not base.exists():
            continue
        files.extend(path for path in base.rglob("*") if path.is_file())
    files.append(ROOT / "submission" / "DEMO_SCRIPT.md")
    files.append(ROOT / "submission" / "README.md")
    return sorted(
        {
            path
            for path in files
            if path.exists()
            and not EXCLUDED_PARTS.intersection(path.parts)
            and path.suffix not in EXCLUDED_SUFFIXES
            and path not in {OUTPUT, SUMS}
        },
        key=lambda path: path.relative_to(ROOT).as_posix(),
    )


def build_archive() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        OUTPUT,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for path in included_files():
            relative = path.relative_to(ROOT).as_posix()
            info = zipfile.ZipInfo(relative, date_time=FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    build_archive()
    tracked = [OUTPUT]
    SUMS.write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in tracked),
        encoding="utf-8",
    )
    print(
        f"built {OUTPUT.relative_to(ROOT)} with "
        f"{len(included_files())} files"
    )
    print(f"wrote {SUMS.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

