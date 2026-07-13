"""Windows Task Scheduler integration shared by setup and Control Panel."""

import os
import subprocess
import sys
import urllib.request
from pathlib import Path


TASK_NAME = "Lynceus Server"
CREATE_NO_WINDOW = 0x08000000


# Handle the install root operation.
def install_root():
    override = os.environ.get("LYNCEUS_INSTALL_DIR")
    # Handle the branch where override evaluates to true.
    if override:
        return Path(override)
    executable = Path(sys.executable).resolve()
    # Handle the branch where getattr(sys, 'frozen', False) evaluates to true.
    if getattr(sys, "frozen", False):
        return executable.parent.parent
    return Path(__file__).resolve().parent.parent


# Handle the runtime executable operation.
def runtime_executable():
    # Handle the branch where getattr(sys, 'frozen', False) evaluates to true.
    if getattr(sys, "frozen", False):
        return install_root() / "runtime" / "LynceusRuntime.exe"
    return Path(sys.executable).resolve()


# Handle the runtime command operation.
def runtime_command(*arguments):
    runtime = runtime_executable()
    # Handle the branch where getattr(sys, 'frozen', False) evaluates to true.
    if getattr(sys, "frozen", False):
        return [str(runtime), *arguments]
    return [str(runtime), str(install_root() / "installer" / "runtime.py"), *arguments]


# Handle the schtasks operation.
def _schtasks(*arguments, check=True):
    return subprocess.run(
        ["schtasks.exe", *arguments],
        check=check,
        capture_output=True,
        text=True,
        creationflags=CREATE_NO_WINDOW,
    )


# Handle the install task operation.
def install_task():
    runtime = runtime_executable()
    # Handle the branch where not runtime.exists() evaluates to true.
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


# Remove task.
def remove_task():
    _schtasks("/Delete", "/TN", TASK_NAME, "/F", check=False)


# Handle the start task operation.
def start_task():
    _schtasks("/Run", "/TN", TASK_NAME)


# Handle the stop task operation.
def stop_task():
    _schtasks("/End", "/TN", TASK_NAME, check=False)


# Handle the task exists operation.
def task_exists():
    return _schtasks("/Query", "/TN", TASK_NAME, check=False).returncode == 0


# Handle the server is healthy operation.
def server_is_healthy(port=7321):
    # Run this block with structured exception handling.
    try:
        # Manage urllib.request.urlopen(f'http://127.0.0.1:{port}/hea... within this scoped block.
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/health",
            timeout=1.0,
        ) as response:
            return response.status == 200
    # Handle an exception raised by the preceding protected block.
    except Exception:
        return False
