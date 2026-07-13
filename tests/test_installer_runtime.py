import builtins

from installer import runtime


def test_initial_admin_setup_runs_create_admin_and_waits_for_enter(monkeypatch):
    calls = []

    def fake_cli(args, *, standalone_mode=True):
        calls.append((args, standalone_mode))

    monkeypatch.setattr(runtime, "run_cli", fake_cli)
    monkeypatch.setattr(builtins, "input", lambda prompt: calls.append(prompt))

    assert runtime.run_initial_admin_setup() == 0
    assert calls[0] == (["create-admin"], False)
    assert "Press Enter" in calls[1]
