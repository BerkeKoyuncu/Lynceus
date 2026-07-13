"""Runtime paths shared by source, frozen executables, and the installer."""

import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def is_frozen():
    return bool(getattr(sys, "frozen", False))


def resource_path(*parts):
    """Return a bundled read-only resource path or a source-tree path."""
    root = Path(getattr(sys, "_MEIPASS", PROJECT_ROOT))
    return root.joinpath(*parts)


def runtime_data_dir():
    """Return the writable persistent directory for DB, secrets, logs, and PID state."""
    override = os.environ.get("LYNCEUS_DATA_DIR")
    if override:
        return Path(override).expanduser().resolve()
    if is_frozen():
        program_data = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
        return program_data / "Lynceus"
    return PROJECT_ROOT / "instance"


def secret_dir():
    """Preserve legacy source secrets while installed builds use ProgramData."""
    override = os.environ.get("LYNCEUS_DATA_DIR")
    if override or is_frozen():
        return runtime_data_dir()
    return PROJECT_ROOT


def ensure_runtime_directories():
    data_dir = runtime_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "logs").mkdir(parents=True, exist_ok=True)
    return data_dir
