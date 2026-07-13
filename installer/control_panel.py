"""Elevated desktop Control Panel for the installed Lynceus server."""

import ctypes
import os
import sqlite3
import subprocess
import sys
import time
import webbrowser
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, ttk

from installer.windows_task import (
    install_task,
    runtime_command,
    server_is_healthy,
    start_task,
    stop_task,
    task_exists,
)
from services.runtime_paths import ensure_runtime_directories


CREATE_NEW_CONSOLE = 0x00000010


def is_windows_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_elevated():
    arguments = subprocess.list2cmdline(sys.argv[1:])
    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        arguments,
        None,
        1,
    )
    return result > 32


def launch_cli(*arguments):
    return subprocess.Popen(
        runtime_command(*arguments),
        creationflags=CREATE_NEW_CONSOLE,
    )


class ControlPanel(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Lynceus Control Panel")
        self.geometry("620x520")
        self.minsize(620, 520)
        self.data_dir = ensure_runtime_directories()
        self.status_text = tk.StringVar(value="Checking server status...")
        self._build_ui()
        self.after(200, self.refresh_status)

    def _build_ui(self):
        root = ttk.Frame(self, padding=20)
        root.pack(fill="both", expand=True)

        ttk.Label(root, text="Lynceus Server", font=("Segoe UI", 20, "bold")).pack(anchor="w")
        ttk.Label(root, textvariable=self.status_text, font=("Segoe UI", 11)).pack(anchor="w", pady=(4, 16))

        service = ttk.LabelFrame(root, text="Server Control", padding=12)
        service.pack(fill="x", pady=(0, 12))
        for text, command in (
            ("Start", self.start_server),
            ("Stop", self.stop_server),
            ("Restart", self.restart_server),
            ("Open Web UI", lambda: webbrowser.open("http://127.0.0.1:7321")),
        ):
            ttk.Button(service, text=text, command=command).pack(side="left", padx=4)

        admin = ttk.LabelFrame(root, text="Administrator Recovery", padding=12)
        admin.pack(fill="x", pady=(0, 12))
        ttk.Button(
            admin,
            text="Create / Reset Admin",
            command=lambda: launch_cli("setup-admin"),
        ).pack(side="left", padx=4)
        ttk.Button(
            admin,
            text="Reset Password",
            command=lambda: launch_cli("reset-admin-password", "--windows-admin-recovery"),
        ).pack(side="left", padx=4)
        ttk.Button(
            admin,
            text="Reset 2FA",
            command=lambda: launch_cli("reset-admin-2fa", "--windows-admin-recovery"),
        ).pack(side="left", padx=4)

        maintenance = ttk.LabelFrame(root, text="Maintenance", padding=12)
        maintenance.pack(fill="x", pady=(0, 12))
        for text, command in (
            ("Database Upgrade", self.upgrade_database),
            ("Cleanup Stale Scans", lambda: launch_cli("cleanup-scans")),
            ("Backup Database", self.backup_database),
        ):
            ttk.Button(maintenance, text=text, command=command).pack(side="left", padx=4)

        files = ttk.LabelFrame(root, text="Diagnostics", padding=12)
        files.pack(fill="x")
        ttk.Button(files, text="Open Data Folder", command=self.open_data_folder).pack(side="left", padx=4)
        ttk.Button(files, text="Open Server Log", command=self.open_server_log).pack(side="left", padx=4)
        ttk.Button(files, text="Refresh Status", command=self.refresh_status).pack(side="left", padx=4)

        ttk.Label(
            root,
            text=(
                "Data and encryption keys are stored under ProgramData and are preserved "
                "during application updates."
            ),
            wraplength=560,
        ).pack(anchor="w", pady=(18, 0))

    def refresh_status(self):
        exists = task_exists()
        healthy = server_is_healthy()
        if healthy:
            self.status_text.set("Status: Running — http://127.0.0.1:7321")
        elif exists:
            self.status_text.set("Status: Stopped or starting (scheduled task installed)")
        else:
            self.status_text.set("Status: Scheduled task is not installed")

    def start_server(self):
        try:
            if not task_exists():
                install_task()
            start_task()
            self.status_text.set("Status: Starting...")
            self.after(1800, self.refresh_status)
        except Exception as error:
            messagebox.showerror("Start failed", str(error))

    def stop_server(self):
        try:
            stop_task()
            self.status_text.set("Status: Stopping...")
            self.after(1200, self.refresh_status)
        except Exception as error:
            messagebox.showerror("Stop failed", str(error))

    def restart_server(self):
        try:
            stop_task()
            time.sleep(1)
            start_task()
            self.status_text.set("Status: Restarting...")
            self.after(1800, self.refresh_status)
        except Exception as error:
            messagebox.showerror("Restart failed", str(error))

    def backup_database(self):
        database = self.data_dir / "database.db"
        if not database.exists():
            messagebox.showwarning("Backup", "Database does not exist yet.")
            return
        backup_dir = self.data_dir / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        destination = backup_dir / f"database-{datetime.now():%Y%m%d-%H%M%S}.db"
        with sqlite3.connect(database) as source, sqlite3.connect(destination) as backup:
            source.backup(backup)
        messagebox.showinfo("Backup complete", f"Backup created:\n{destination}")

    def upgrade_database(self):
        if not messagebox.askyesno(
            "Database Upgrade",
            "The server will stop while migrations run and restart afterwards. Continue?",
        ):
            return
        try:
            stop_task()
            result = subprocess.run(
                runtime_command("db", "upgrade"),
                creationflags=CREATE_NEW_CONSOLE,
            )
            if result.returncode != 0:
                raise RuntimeError("Database upgrade failed. Review the console output.")
            start_task()
            self.after(1800, self.refresh_status)
        except Exception as error:
            messagebox.showerror("Database upgrade failed", str(error))

    def open_data_folder(self):
        os.startfile(self.data_dir)

    def open_server_log(self):
        log_file = self.data_dir / "logs" / "server.log"
        if not log_file.exists():
            messagebox.showwarning("Server log", "The server log has not been created yet.")
            return
        os.startfile(log_file)


def main():
    if os.name != "nt":
        raise SystemExit("Lynceus Control Panel is supported only on Windows.")
    if "--install-task" in sys.argv:
        install_task()
        return
    if not is_windows_admin():
        if not relaunch_elevated():
            messagebox.showerror("Administrator required", "Control Panel requires elevation.")
        return
    if "--create-admin" in sys.argv:
        launch_cli("setup-admin").wait()
        return
    ControlPanel().mainloop()


if __name__ == "__main__":
    main()
