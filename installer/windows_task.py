"""Windows Task Scheduler integration shared by setup and Control Panel."""

import os
import subprocess
import sys
import urllib.request
from pathlib import Path


TASK_NAME = "Lynceus Server"
CREATE_NO_WINDOW = 0x08000000


def install_root():
    override = os.environ.get("LYNCEUS_INSTALL_DIR")
    if override:
        return Path(override)
    executable = Path(sys.executable).resolve()
    if getattr(sys, "frozen", False):
        return executable.parent.parent
    return Path(__file__).resolve().parent.parent


def runtime_executable():
    if getattr(sys, "frozen", False):
        return install_root() / "runtime" / "LynceusRuntime.exe"
    return Path(sys.executable).resolve()


def runtime_command(*arguments):
    runtime = runtime_executable()
    if getattr(sys, "frozen", False):
        return [str(runtime), *arguments]
    return [str(runtime), str(install_root() / "installer" / "runtime.py"), *arguments]


def _schtasks(*arguments, check=True):
    return subprocess.run(
        ["schtasks.exe", *arguments],
        check=check,
        capture_output=True,
        text=True,
        creationflags=CREATE_NO_WINDOW,
    )


def install_task():
    runtime = runtime_executable()
    if not runtime.exists():
        raise FileNotFoundError(f"Runtime executable was not found: {runtime}")
    task_command = f'"{runtime}" server'
    _schtasks(
        "/Create",
        "/TN", TASK_NAME,
        "/TR", task_command,
        "/SC", "ONSTART",
        "/RU", "SYSTEM",
        "/RL", "HIGHEST",
        "/F",
    )


def remove_task():
    _schtasks("/Delete", "/TN", TASK_NAME, "/F", check=False)


def start_task():
    _schtasks("/Run", "/TN", TASK_NAME)


def stop_task():
    _schtasks("/End", "/TN", TASK_NAME, check=False)


def task_exists():
    return _schtasks("/Query", "/TN", TASK_NAME, check=False).returncode == 0


def server_is_healthy(port=7321):
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/health",
            timeout=1.0,
        ) as response:
            return response.status == 200
    except Exception:
        return False
