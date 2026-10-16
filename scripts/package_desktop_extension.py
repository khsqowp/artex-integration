"""Package the source MCP bridge as an installable Claude Desktop Extension."""

from __future__ import annotations

import shutil
import json
import zipfile
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
EXTENSION = PROJECT / "desktop-extension"
PACKAGE = PROJECT / "releases" / "artex-desktop-extension-0.4.0.mcpb"
STAGING = PROJECT / ".build" / "artex-desktop-extension"


def main() -> int:
    if STAGING.exists():
        shutil.rmtree(STAGING)
    (STAGING / "src" / "artex_agent").mkdir(parents=True)
    shutil.copy2(EXTENSION / "manifest.json", STAGING / "manifest.json")
    shutil.copy2(EXTENSION / "pyproject.toml", STAGING / "pyproject.toml")
    shutil.copy2(EXTENSION / ".mcpbignore", STAGING / ".mcpbignore")
    shutil.copytree(PROJECT / "src" / "artex_agent", STAGING / "src" / "artex_agent", dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    PACKAGE.parent.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((STAGING / "manifest.json").read_text(encoding="utf-8"))
    required = {"manifest_version", "name", "version", "description", "author", "server"}
    if missing := required - manifest.keys():
        raise ValueError(f"manifest.json missing required fields: {sorted(missing)}")
    entry = STAGING / manifest["server"]["entry_point"]
    if not entry.is_file():
        raise FileNotFoundError(f"MCPB entry point not found: {entry}")
    PACKAGE.parent.mkdir(parents=True, exist_ok=True)
    files = sorted(p for p in STAGING.rglob("*") if p.is_file() and p.name != ".mcpbignore")
    with zipfile.ZipFile(PACKAGE, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            archive.write(path, path.relative_to(STAGING).as_posix())
    with zipfile.ZipFile(PACKAGE) as archive:
        if bad_entry := archive.testzip():
            raise RuntimeError(f"MCPB ZIP integrity check failed: {bad_entry}")
        if "manifest.json" not in archive.namelist() or "pyproject.toml" not in archive.namelist():
            raise RuntimeError("MCPB package is missing required root files")
    print(PACKAGE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
