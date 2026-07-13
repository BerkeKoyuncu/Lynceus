# Lynceus Windows Installer

The installer targets 64-bit Windows 10/11 and Windows Server 2019/2022. It
packages the Python interpreter and Python dependencies, so the target machine
does not need Python or pip.

## One-time build-machine preparation

Use a 64-bit Windows build machine. The repository `.venv` must exist. Install
Inno Setup 6 manually, or let the build script install it through `winget` with
`-InstallBuildTools`.

## Nmap/Npcap prerequisite

Nmap and Npcap are deliberately not bundled. The user installs the normal Nmap
Windows package separately from the official download page:

https://nmap.org/download.html

If Nmap is missing, the Lynceus installer offers to open that page after setup.
The web UI, database, Control Panel, and server can run without Nmap, but network
scans require `nmap.exe` and Npcap. Lynceus detects the standard Nmap installation
under Program Files or through `PATH`; no application reinstall is needed after
Nmap is installed.

## Rebuild after every application update

The easiest method is to double-click `Create-Setup.cmd` in the repository root.
It asks for a numeric version, builds the setup, and opens Explorer with the
resulting EXE selected.

The command-line equivalent is:

```powershell
.\installer\build.ps1 `
  -Version 1.0.0 `
  -InstallBuildTools
```

After Inno Setup is installed, `-InstallBuildTools` can be omitted. If `-Version`
is omitted, the script creates `1.0.<git commit count>`.

The final single installer is written to `installer\output`. PyInstaller uses
one-folder payloads internally for reliable Flask resource loading; Inno Setup
compresses both payloads into one setup executable.

To validate only the bundled Python/runtime payload without an OEM installer or
Inno Setup, run:

```powershell
.\installer\build.ps1 -PayloadOnly
```

## Installed layout

- Program files: `%ProgramFiles%\Lynceus`
- Database, encryption keys, logs, backups: `%ProgramData%\Lynceus`
- Desktop shortcut: `Lynceus Control Panel`
- Startup task: `Lynceus Server` (runs as SYSTEM)
- Web UI: `http://127.0.0.1:7321`

The installer upgrades the database, opens the interactive admin creation CLI
in a dedicated console, and only then installs and starts the server task. The
admin console remains open until Enter is pressed so the 2FA QR/provisioning
details can be recorded. Uninstalling or updating preserves the
ProgramData directory. Its ACL is restricted to `SYSTEM` and local
Administrators because it contains the SQLite database and encryption keys.

The graphical Control Panel requires Windows Server with Desktop Experience.
The scheduled runtime itself can run without an interactive user session.
