import threading
import time

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

    assert scanner.stop_scan_process(99) is True
    assert first.killed is True
    assert second.killed is True
    assert first.waited is True
    assert second.waited is True
    scanner.active_processes.clear()


def test_stop_scan_requires_every_process_to_terminate():
    healthy = FakeProcess()
    stuck = FakeProcess()

    def fail_wait(timeout=None):
        stuck.waited = True
        raise scanner.subprocess.TimeoutExpired("nmap", timeout)

    stuck.wait = fail_wait
    scanner.active_processes.clear()
    scanner.active_processes[100] = {healthy, stuck}

    assert scanner.stop_scan_process(100) is False
    assert healthy.killed is True
    assert healthy.waited is True
    assert stuck.killed is True
    assert stuck.waited is True
    scanner.active_processes.clear()
