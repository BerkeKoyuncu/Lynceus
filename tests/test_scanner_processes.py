import threading
import time

import pytest

import scanner


class FakeProcess:
    def __init__(self):
        self.release = threading.Event()
        self.returncode = 0
        self.killed = False
        self.waited = False

    def communicate(self, timeout=None):
        self.release.wait(timeout=5)
        return "", ""

    def kill(self):
        self.killed = True
        self.release.set()

    def wait(self, timeout=None):
        self.waited = True
        if not self.release.wait(timeout):
            raise scanner.subprocess.TimeoutExpired("nmap", timeout)
        return self.returncode

    def poll(self):
        return self.returncode if self.release.is_set() else None


def test_finished_retry_process_does_not_unregister_new_attempt(monkeypatch):
    first = FakeProcess()
    second = FakeProcess()
    processes = iter([first, second])
    monkeypatch.setattr(scanner.subprocess, "Popen", lambda *args, **kwargs: next(processes))
    scanner.active_processes.clear()

    workers = [
        threading.Thread(target=scanner.execute_nmap_subprocess, args=(["nmap"], 42))
        for _ in range(2)
    ]
    for worker in workers:
        worker.start()

    deadline = time.monotonic() + 5
    while len(scanner.active_processes.get(42, set())) < 2:
        assert time.monotonic() < deadline
        time.sleep(0.01)
    first.release.set()
    workers[0].join(timeout=5)
    assert scanner.active_processes[42] == {second}

    second.release.set()
    workers[1].join(timeout=5)
    assert 42 not in scanner.active_processes


def test_stop_scan_kills_every_active_attempt():
    first = FakeProcess()
    second = FakeProcess()
    scanner.active_processes.clear()
    scanner.active_processes[99] = {first, second}

    result = scanner.stop_scan_process(99)
    assert result.had_processes is True
    assert result.all_processes_stopped is True
    assert first.killed is True
    assert second.killed is True
    assert first.waited is True
    assert second.waited is True
    assert 99 not in scanner.active_processes


def test_stop_scan_requires_every_process_to_terminate():
    healthy = FakeProcess()
    stuck = FakeProcess()

    def fail_wait(timeout=None):
        stuck.waited = True
        raise scanner.subprocess.TimeoutExpired("nmap", timeout)

    stuck.wait = fail_wait
    scanner.active_processes.clear()
    scanner.active_processes[100] = {healthy, stuck}

    result = scanner.stop_scan_process(100)
    assert result.had_processes is True
    assert result.all_processes_stopped is False
    assert healthy.killed is True
    assert healthy.waited is True
    assert stuck.killed is True
    assert stuck.waited is True
    assert scanner.active_processes[100] == {stuck}
    scanner.active_processes.clear()


def test_sequential_nmap_fallbacks_refresh_progress(monkeypatch):
    host_xml = (
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        '<address addr="192.0.2.10" addrtype="ipv4"/><ports/></host></nmaprun>'
    )
    results = iter([
        (1, "", "permission denied: raw socket requires privilege"),
        (0, host_xml, ""),
    ])
    phases = []
    monkeypatch.setattr(scanner, "find_nmap_executable", lambda: "nmap")
    monkeypatch.setattr(
        scanner,
        "execute_nmap_subprocess",
        lambda command, scan_id=None, process_token=None: next(results),
    )

    result = scanner.run_nmap_scan(
        "192.0.2.10",
        "syn",
        scan_id=200,
        progress_callback=lambda phase: phases.append(phase) or True,
    )

    assert result["success"] is True
    assert phases == [
        "starting-primary-scan",
        "starting-privilege-fallback-scan",
    ]


def test_ownership_loss_is_not_swallowed_by_single_host_fallback(monkeypatch):
    monkeypatch.setattr(scanner, "find_nmap_executable", lambda: "nmap")
    monkeypatch.setattr(
        scanner,
        "execute_nmap_subprocess",
        lambda command, scan_id=None, process_token=None: (0, "", ""),
    )

    with pytest.raises(scanner.ScanOwnershipLost):
        scanner.run_nmap_scan(
            "192.0.2.20",
            "fast",
            progress_callback=lambda phase: phase != "starting-single-host-fallback-scan",
        )


def test_ownership_loss_is_not_swallowed_by_subnet_fallback(monkeypatch):
    monkeypatch.setattr(scanner, "find_nmap_executable", lambda: "nmap")
    monkeypatch.setattr(
        scanner,
        "execute_nmap_subprocess",
        lambda command, scan_id=None, process_token=None: (0, "", ""),
    )

    with pytest.raises(scanner.ScanOwnershipLost):
        scanner.run_nmap_scan(
            "192.0.2.0/30",
            "fast",
            progress_callback=lambda phase: phase != "starting-host-discovery",
        )


def test_process_registered_during_stop_is_also_terminated(monkeypatch):
    process = FakeProcess()
    constructor_entered = threading.Event()
    allow_constructor = threading.Event()

    def delayed_popen(*args, **kwargs):
        constructor_entered.set()
        assert allow_constructor.wait(timeout=5)
        return process

    monkeypatch.setattr(scanner.subprocess, "Popen", delayed_popen)
    scanner.active_processes.clear()
    scanner.active_scan_process_tokens.clear()
    scanner.allow_scan_process_start(300, "attempt-token")

    worker = threading.Thread(
        target=scanner.execute_nmap_subprocess,
        args=(["nmap"], 300, "attempt-token"),
    )
    worker.start()
    assert constructor_entered.wait(timeout=5)

    stopped = []
    stopper = threading.Thread(
        target=lambda: stopped.append(scanner.stop_scan_process(300))
    )
    stopper.start()
    allow_constructor.set()
    stopper.join(timeout=5)
    worker.join(timeout=5)

    assert len(stopped) == 1
    assert stopped[0].start_permission_revoked is True
    assert stopped[0].had_processes is True
    assert stopped[0].all_processes_stopped is True
    assert process.killed is True
    assert 300 not in scanner.active_processes
    assert 300 not in scanner.active_scan_process_tokens


def test_cross_worker_stop_cannot_revoke_another_process_token():
    scanner.active_processes.clear()
    scanner.active_scan_process_tokens.clear()
    scanner.allow_scan_process_start(301, "owner-worker-token")

    result = scanner.stop_scan_process(301, "different-worker-token")

    assert result.start_permission_revoked is False
    assert result.had_processes is False
    assert scanner.active_scan_process_tokens[301] == "owner-worker-token"
    scanner.active_scan_process_tokens.clear()


def test_wrong_process_token_cannot_kill_current_attempt():
    process = FakeProcess()
    scanner.active_processes.clear()
    scanner.active_process_attempt_tokens.clear()
    scanner.active_scan_process_tokens.clear()
    scanner.active_processes[302] = {process}
    scanner.active_process_attempt_tokens[process] = "current-token"
    scanner.active_scan_process_tokens[302] = "current-token"

    result = scanner.stop_scan_process(302, "stale-token")

    assert result.start_permission_revoked is False
    assert result.had_processes is False
    assert process.killed is False
    assert scanner.active_scan_process_tokens[302] == "current-token"
    assert scanner.active_processes[302] == {process}
    scanner.active_processes.clear()
    scanner.active_process_attempt_tokens.clear()
    scanner.active_scan_process_tokens.clear()
