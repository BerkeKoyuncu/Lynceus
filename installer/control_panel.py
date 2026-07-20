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
CONTROL_PANEL_ICON = "Lynceus-icon-dark-green.ico"


# Resolve bundled and source-tree Control Panel assets.
def control_panel_icon_path():
    bundle_root = getattr(sys, "_MEIPASS", None)
    if bundle_root:
        return Path(bundle_root) / "assets" / CONTROL_PANEL_ICON
    return Path(__file__).resolve().parent / "assets" / CONTROL_PANEL_ICON


# Determine whether windows admin.
def is_windows_admin():
    # Run this block with structured exception handling.
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    # Handle an exception raised by the preceding protected block.
    except Exception:
        return False


# Handle the relaunch elevated operation.
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


# Handle the launch cli operation.
def launch_cli(*arguments):
    return subprocess.Popen(
        runtime_command(*arguments),
        creationflags=CREATE_NEW_CONSOLE,
    )


# Group the state and behavior for ControlPanel.
class ControlPanel(tk.Tk):
    # Handle the init operation.
    def __init__(self):
        super().__init__()
        self.title("Lynceus Control Panel")
        icon_path = control_panel_icon_path()
        if icon_path.exists():
            try:
                self.iconbitmap(default=str(icon_path))
            except tk.TclError:
                pass
        self.geometry("620x520")
        self.minsize(620, 520)
        self.data_dir = ensure_runtime_directories()
        self.status_text = tk.StringVar(value="Checking server status...")
        self._build_ui()
        self.after(200, self.refresh_status)

    # Build ui.
    def _build_ui(self):
        root = ttk.Frame(self, padding=20)
        root.pack(fill="both", expand=True)

        ttk.Label(root, text="Lynceus Server", font=("Segoe UI", 20, "bold")).pack(anchor="w")
        ttk.Label(root, textvariable=self.status_text, font=("Segoe UI", 11)).pack(anchor="w", pady=(4, 16))

        service = ttk.LabelFrame(root, text="Server Control", padding=12)
        service.pack(fill="x", pady=(0, 12))
        # Iterate over (('Start', self.start_server), ('Stop', self.stop_server), ('Restart', self.restart_server), ('Open Web UI'... and bind each item to (text, command).
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
        # Iterate over (('Database Upgrade', self.upgrade_database), ('Cleanup Stale Scans', lambda: launch_cli('cleanup-scans')),... and bind each item to (text, command).
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

    # Handle the refresh status operation.
    def refresh_status(self):
        exists = task_exists()
        healthy = server_is_healthy()
        # Handle the branch where healthy evaluates to true.
        if healthy:
            self.status_text.set("Status: Running — http://127.0.0.1:7321")
        # Handle the branch where exists evaluates to true.
        elif exists:
            self.status_text.set("Status: Stopped or starting (scheduled task installed)")
        # Handle the fallback branch when the preceding condition does not match.
        else:
            self.status_text.set("Status: Scheduled task is not installed")

    # Handle the start server operation.
    def start_server(self):
        # Run this block with structured exception handling.
        try:
            # Handle the branch where not task_exists() evaluates to true.
            if not task_exists():
                install_task()
            start_task()
            self.status_text.set("Status: Starting...")
            self.after(1800, self.refresh_status)
        # Handle an exception raised by the preceding protected block.
        except Exception as error:
            messagebox.showerror("Start failed", str(error))

    # Handle the stop server operation.
    def stop_server(self):
        # Run this block with structured exception handling.
        try:
            stop_task()
            self.status_text.set("Status: Stopping...")
            self.after(1200, self.refresh_status)
        # Handle an exception raised by the preceding protected block.
        except Exception as error:
            messagebox.showerror("Stop failed", str(error))

    # Handle the restart server operation.
    def restart_server(self):
        # Run this block with structured exception handling.
        try:
            stop_task()
            time.sleep(1)
            start_task()
            self.status_text.set("Status: Restarting...")
            self.after(1800, self.refresh_status)
        # Handle an exception raised by the preceding protected block.
        except Exception as error:
            messagebox.showerror("Restart failed", str(error))

    # Handle the backup database operation.
    def backup_database(self):
        database = self.data_dir / "database.db"
        # Handle the branch where not database.exists() evaluates to true.
        if not database.exists():
            messagebox.showwarning("Backup", "Database does not exist yet.")
            return
        backup_dir = self.data_dir / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        destination = backup_dir / f"database-{datetime.now():%Y%m%d-%H%M%S}.db"
        # Manage sqlite3.connect(database), sqlite3.connect(destination) within this scoped block.
        with sqlite3.connect(database) as source, sqlite3.connect(destination) as backup:
            source.backup(backup)
        messagebox.showinfo("Backup complete", f"Backup created:\n{destination}")

    # Handle the upgrade database operation.
    def upgrade_database(self):
        # Handle the branch where not messagebox.askyesno('Database Upgrade', 'The server will stop while migrations run and restart afterwar... evaluates to true.
        if not messagebox.askyesno(
            "Database Upgrade",
            "The server will stop while migrations run and restart afterwards. Continue?",
        ):
            return
        # Run this block with structured exception handling.
        try:
            stop_task()
            result = subprocess.run(
                runtime_command("db", "upgrade"),
                creationflags=CREATE_NEW_CONSOLE,
            )
            # Handle the branch where result.returncode != 0 evaluates to true.
            if result.returncode != 0:
                raise RuntimeError("Database upgrade failed. Review the console output.")
            start_task()
            self.after(1800, self.refresh_status)
        # Handle an exception raised by the preceding protected block.
        except Exception as error:
            messagebox.showerror("Database upgrade failed", str(error))

    # Handle the open data folder operation.
    def open_data_folder(self):
        os.startfile(self.data_dir)

    # Handle the open server log operation.
    def open_server_log(self):
        log_file = self.data_dir / "logs" / "server.log"
        # Handle the branch where not log_file.exists() evaluates to true.
        if not log_file.exists():
            messagebox.showwarning("Server log", "The server log has not been created yet.")
            return
        os.startfile(log_file)


# Handle the main operation.
def main():
    # Handle the branch where os.name != 'nt' evaluates to true.
    if os.name != "nt":
        raise SystemExit("Lynceus Control Panel is supported only on Windows.")
    # Handle the branch where '--install-task' in sys.argv evaluates to true.
    if "--install-task" in sys.argv:
        install_task()
        return
    # Handle the branch where not is_windows_admin() evaluates to true.
    if not is_windows_admin():
        # Handle the branch where not relaunch_elevated() evaluates to true.
        if not relaunch_elevated():
            messagebox.showerror("Administrator required", "Control Panel requires elevation.")
        return
    # Handle the branch where '--create-admin' in sys.argv evaluates to true.
    if "--create-admin" in sys.argv:
        launch_cli("setup-admin").wait()
        return
    ControlPanel().mainloop()


# Handle the branch where __name__ == '__main__' evaluates to true.
if __name__ == "__main__":
    main()
