"""Build the Claude Cowork upload ZIP from the current plugin source tree."""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
SOURCE = PROJECT / "claude-cowork-plugin"
OUTPUT = PROJECT / "dist" / "artex-agent-profiles.zip"


def main() -> None:
    files = sorted(path for path in SOURCE.rglob("*") if path.is_file())
    if not files:
        raise RuntimeError(f"No plugin files found under {SOURCE}")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    temporary = OUTPUT.with_suffix(".zip.tmp")
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for path in files:
                relative = path.relative_to(SOURCE).as_posix()
                entry = zipfile.ZipInfo(relative, date_time=(2026, 1, 1, 0, 0, 0))
                entry.compress_type = zipfile.ZIP_DEFLATED
                entry.external_attr = 0o100644 << 16
                archive.writestr(entry, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        with zipfile.ZipFile(temporary) as archive:
            if bad_entry := archive.testzip():
                raise RuntimeError(f"Plugin ZIP CRC failure: {bad_entry}")
            if set(archive.namelist()) != {path.relative_to(SOURCE).as_posix() for path in files}:
                raise RuntimeError("Plugin ZIP entries do not match the source tree")
        temporary.replace(OUTPUT)
    finally:
        temporary.unlink(missing_ok=True)
    digest = hashlib.sha256(OUTPUT.read_bytes()).hexdigest()
    print(f"{OUTPUT}\nfiles={len(files)} sha256={digest}")


if __name__ == "__main__":
    main()
