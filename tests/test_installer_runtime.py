import builtins
import struct
from pathlib import Path

from installer import runtime


def test_control_panel_uses_lynceus_windows_icon():
    repo_root = Path(__file__).resolve().parents[1]
    icon_path = repo_root / "installer" / "assets" / "Lynceus-icon-dark-green.ico"
    icon_data = icon_path.read_bytes()

    reserved, icon_type, image_count = struct.unpack("<HHH", icon_data[:6])
    assert (reserved, icon_type) == (0, 1)
    assert image_count == 7
    assert b"\x89PNG\r\n\x1a\n" in icon_data

    build_script = (repo_root / "installer" / "build.ps1").read_text(encoding="utf-8")
    assert "--icon $controlIcon" in build_script


# Verify that initial admin setup runs create admin and waits for enter behaves as expected.
def test_initial_admin_setup_runs_create_admin_and_waits_for_enter(monkeypatch):
    calls = []

    # Handle the fake cli operation.
    def fake_cli(args, *, standalone_mode=True):
        calls.append((args, standalone_mode))

    monkeypatch.setattr(runtime, "run_cli", fake_cli)
    monkeypatch.setattr(builtins, "input", lambda prompt: calls.append(prompt))

    assert runtime.run_initial_admin_setup() == 0
    assert calls[0] == (["create-admin"], False)
    assert "Press Enter" in calls[1]
