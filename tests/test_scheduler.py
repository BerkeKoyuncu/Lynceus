from datetime import datetime, timedelta, timezone
import os
import threading
import pytest

from app import (
    _claim_scheduled_scan,
    _dispatch_pending_scheduled_scans,
    cleanup_stale_scans,
    create_app,
)
from models import db, ScanDispatchLock, ScanResolutionAudit, ScanResult, ScanSchedule, User
from services.scan_service import (
    _execute_scan_body,
    _reconcile_scan_worker_exit,
    execute_scan,
    scheduler_claim_is_current,
    scheduler_progress_checkpoint,
)


def test_due_schedule_can_only_be_claimed_once(app):
    with app.app_context():
        user = User.query.first()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        schedule = ScanSchedule(
            user_id=user.id,
            name="Hourly scan",
            input_ip="192.0.2.0",
            subnet_mask="24",
            scan_type="fast",
            network_cidr="192.0.2.0/24",
            frequency="hourly",
            next_run=now - timedelta(minutes=1),
            is_active=True,
        )
        db.session.add(schedule)
        db.session.commit()

        first_claim = _claim_scheduled_scan(schedule, now)
        second_claim = _claim_scheduled_scan(schedule, now)

        assert first_claim is not None
        assert second_claim is None
        assert ScanResult.query.filter_by(user_id=user.id).count() == 1
        db.session.refresh(schedule)
        assert schedule.last_run == now
        assert schedule.next_run == now + timedelta(hours=1)


def test_concurrent_scheduler_workers_create_one_scan(tmp_path):
    database_path = (tmp_path / "scheduler-race.db").as_posix()
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
        "START_SCHEDULER": False,
    })
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    with app.app_context():
        db.create_all()
        user = User(email="scheduler@test.com", password_hash="test")
        db.session.add(user)
        db.session.flush()
        schedule = ScanSchedule(
            user_id=user.id,
            name="Concurrent scan",
            input_ip="198.51.100.0",
            subnet_mask="24",
            scan_type="fast",
            network_cidr="198.51.100.0/24",
            frequency="daily",
            next_run=now - timedelta(minutes=1),
            is_active=True,
        )
        db.session.add(schedule)
        db.session.commit()
        schedule_id = schedule.id

    barrier = threading.Barrier(2)
    results = []
    errors = []

    def claim():
        try:
            with app.app_context():
                candidate = db.session.get(ScanSchedule, schedule_id)
                barrier.wait()
                results.append(_claim_scheduled_scan(candidate, now))
        except Exception as error:  # surfaced by the assertion below
            errors.append(error)

    workers = [threading.Thread(target=claim) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=10)

    assert errors == []
    assert sum(result is not None for result in results) == 1
    with app.app_context():
        assert ScanResult.query.count() == 1


def test_scheduler_job_is_recoverable_if_process_dies_before_thread_start(
    app, monkeypatch
):
    started = []

    class FakeThread:
        def __init__(self, target, args, daemon):
            self.args = args

        def start(self):
            started.append(self.args[1])

    monkeypatch.setattr("app.threading.Thread", FakeThread)
    with app.app_context():
        user = User.query.first()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        schedule = ScanSchedule(
            user_id=user.id,
            name="Recoverable scan",
            input_ip="203.0.113.0",
            subnet_mask="24",
            scan_type="fast",
            network_cidr="203.0.113.0/24",
            frequency="daily",
            next_run=now - timedelta(minutes=1),
            is_active=True,
        )
        db.session.add(schedule)
        db.session.commit()

        scan_id = _claim_scheduled_scan(schedule, now)
        job = db.session.get(ScanResult, scan_id)
        assert job.status == "pending"
        assert job.scheduler_dispatch_state == "queued"

        assert _dispatch_pending_scheduled_scans(app, now) == [scan_id]
        db.session.refresh(job)
        assert job.scheduler_dispatch_state == "claimed"
        first_token = job.scheduler_claim_token
        assert first_token
        assert started == [scan_id]

        # The fake thread never starts execute_scan. After the lease expires,
        # another scheduler process can safely dispatch the same persisted job.
        retry_at = now + timedelta(minutes=2)
        assert _dispatch_pending_scheduled_scans(app, retry_at) == [scan_id]
        db.session.refresh(job)
        assert job.scheduler_claim_token != first_token
        assert job.scheduler_attempt_count == 2
        assert started == [scan_id, scan_id]


def test_expired_claim_thread_cannot_overwrite_new_attempt_process_token(app):
    import scanner

    with app.app_context():
        user = User.query.first()
        job = ScanResult(
            user_id=user.id,
            input_ip="192.0.2.41",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.41/32",
            status="pending",
            scheduler_dispatch_state="claimed",
            scheduler_claim_token="new-attempt-token",
        )
        db.session.add(job)
        db.session.commit()
        job_id = job.id

    scanner.active_scan_process_tokens.clear()
    assert scanner.allow_scan_process_start(job_id, "new-attempt-token") is True

    execute_scan(app, job_id, scheduler_claim_token="expired-attempt-token")

    assert scanner.active_scan_process_tokens[job_id] == "new-attempt-token"
    scanner.end_scan_process_attempt(job_id, "new-attempt-token")


def test_heartbeat_thread_start_failure_runs_attempt_cleanup(app, monkeypatch):
    import scanner

    scanner.active_scan_process_tokens.clear()

    class FailingThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            raise RuntimeError("cannot start heartbeat")

    monkeypatch.setattr("services.scan_service.threading.Thread", FailingThread)
    with app.app_context():
        user = User.query.first()
        job = ScanResult(
            user_id=user.id,
            input_ip="192.0.2.42",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.42/32",
            status="pending",
            scheduler_dispatch_state="claimed",
            scheduler_claim_token="heartbeat-failure-token",
            scheduler_worker_id=app.config["SCAN_WORKER_ID"],
            scheduler_process_id=os.getpid(),
        )
        db.session.add(job)
        db.session.commit()
        job_id = job.id

    execute_scan(app, job_id, scheduler_claim_token="heartbeat-failure-token")

    with app.app_context():
        job = db.session.get(ScanResult, job_id)
        assert job.status == "failed"
        assert job.scheduler_execution_phase == "worker_failed"
    assert job_id not in scanner.active_scan_process_tokens


def test_token_conflict_has_persistent_failure_details(app):
    import scanner

    with app.app_context():
        user = User.query.first()
        job = ScanResult(
            user_id=user.id,
            input_ip="192.0.2.43",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.43/32",
            status="pending",
            scheduler_dispatch_state="claimed",
            scheduler_claim_token="conflicting-new-token",
            scheduler_worker_id=app.config["SCAN_WORKER_ID"],
            scheduler_process_id=os.getpid(),
        )
        db.session.add(job)
        db.session.commit()
        job_id = job.id

    scanner.active_scan_process_tokens.clear()
    scanner.allow_scan_process_start(job_id, "older-local-token")
    execute_scan(app, job_id, scheduler_claim_token="conflicting-new-token")

    with app.app_context():
        job = db.session.get(ScanResult, job_id)
        assert job.status == "termination_failed"
        assert job.scheduler_execution_phase == "token_conflict"
        assert "local process-token conflict" in job.result_data
    scanner.end_scan_process_attempt(job_id, "older-local-token")


def test_stale_cleanup_preserves_recoverable_scheduler_job(app):
    with app.app_context():
        user = User.query.first()
        old_time = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=1)
        job = ScanResult(
            user_id=user.id,
            input_ip="203.0.113.0",
            subnet_mask="24",
            scan_type="fast",
            network_cidr="203.0.113.0/24",
            status="pending",
            schedule_id=1,
            scheduled_for=old_time,
            scheduler_dispatch_state="claimed",
            scheduler_claimed_at=old_time,
            created_at=old_time,
        )
        # The FK target is needed on databases that enforce foreign keys.
        schedule = ScanSchedule(
            id=1,
            user_id=user.id,
            name="Cleanup recovery",
            input_ip="203.0.113.0",
            subnet_mask="24",
            scan_type="fast",
            network_cidr="203.0.113.0/24",
            frequency="daily",
            next_run=old_time + timedelta(days=1),
            is_active=True,
        )
        db.session.add(schedule)
        db.session.flush()
        db.session.add(job)
        db.session.commit()

        cleanup_stale_scans()
        db.session.refresh(job)
        assert job.status == "pending"
        assert job.scheduler_dispatch_state == "claimed"
        assert job.scheduler_claimed_at == old_time


def test_fresh_running_queue_job_is_not_failed_by_cleanup_after_30_minutes(app):
    with app.app_context():
        user = User.query.first()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        job = ScanResult(
            user_id=user.id,
            input_ip="192.0.2.90",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.90/32",
            status="running",
            created_at=now - timedelta(minutes=40),
            scheduler_dispatch_state="started",
            scheduler_claim_token="healthy-token",
            scheduler_started_at=now - timedelta(minutes=10),
            scheduler_heartbeat_at=now,
            scheduler_progress_at=now,
            scheduler_worker_id=app.config["SCAN_WORKER_ID"],
            scheduler_process_id=os.getpid(),
            scheduler_attempt_count=1,
            scheduler_max_attempts=3,
        )
        db.session.add(job)
        db.session.commit()

        cleanup_stale_scans()

        db.session.refresh(job)
        assert job.status == "running"
        assert job.scheduler_dispatch_state == "started"
        dispatch_lock = db.session.get(ScanDispatchLock, 1)
        db.session.refresh(dispatch_lock)
        assert dispatch_lock.touched_at is not None


def test_scheduler_backlog_respects_concurrency_capacity_and_order(app, monkeypatch):
    started = []

    class FakeThread:
        def __init__(self, target, args, daemon):
            self.args = args

        def start(self):
            started.append(self.args[1])

    monkeypatch.setattr("app.threading.Thread", FakeThread)
    app.config["MAX_CONCURRENT_SCANS"] = 2
    with app.app_context():
        user = User.query.first()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        schedule = ScanSchedule(
            user_id=user.id,
            name="Backlog",
            input_ip="198.51.100.0",
            subnet_mask="24",
            scan_type="fast",
            network_cidr="198.51.100.0/24",
            frequency="daily",
            next_run=now + timedelta(days=1),
            is_active=True,
        )
        db.session.add(schedule)
        db.session.flush()
        running = ScanResult(
            user_id=user.id,
            input_ip="192.0.2.1",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.1/32",
            status="running",
        )
        db.session.add(running)
        jobs = []
        for minutes in [3, 1, 2]:
            job = ScanResult(
                user_id=user.id,
                schedule_id=schedule.id,
                scheduled_for=now + timedelta(minutes=minutes),
                scheduler_dispatch_state="queued",
                scheduler_attempt_count=0,
                scheduler_max_attempts=3,
                input_ip="198.51.100.0",
                subnet_mask="24",
                scan_type="fast",
                network_cidr="198.51.100.0/24",
                status="pending",
            )
            jobs.append(job)
            db.session.add(job)
        db.session.commit()

        dispatched = _dispatch_pending_scheduled_scans(app, now)
        expected = next(job.id for job in jobs if job.scheduled_for == now + timedelta(minutes=1))
        assert dispatched == [expected]
        assert started == [expected]
        assert ScanResult.query.filter_by(
            scheduler_dispatch_state="queued", status="pending"
        ).count() == 2


def test_expired_running_lease_is_requeued_with_new_worker_token(app, monkeypatch):
    started = []
    events = []

    class FakeThread:
        def __init__(self, target, args, daemon):
            self.args = args

        def start(self):
            events.append("retry-started")
            started.append(self.args)

    monkeypatch.setattr("app.threading.Thread", FakeThread)
    monkeypatch.setattr(
        "scanner.stop_scan_process",
        lambda scan_id, process_token=None: events.append(("old-process-stopped", scan_id)) or True,
    )
    app.config["MAX_CONCURRENT_SCANS"] = 1
    app.config["SCHEDULER_LEASE_SECONDS"] = 30
    with app.app_context():
        user = User.query.first()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        schedule = ScanSchedule(
            user_id=user.id,
            name="Lease recovery",
            input_ip="192.0.2.0",
            subnet_mask="24",
            scan_type="fast",
            network_cidr="192.0.2.0/24",
            frequency="daily",
            next_run=now + timedelta(days=1),
            is_active=True,
        )
        db.session.add(schedule)
        db.session.flush()
        job = ScanResult(
            user_id=user.id,
            schedule_id=schedule.id,
            scheduled_for=now - timedelta(minutes=5),
            scheduler_dispatch_state="started",
            scheduler_claim_token="expired-token",
            scheduler_claimed_at=now - timedelta(minutes=5),
            scheduler_started_at=now - timedelta(minutes=5),
            scheduler_heartbeat_at=now - timedelta(minutes=2),
            scheduler_progress_at=now - timedelta(minutes=2),
            scheduler_worker_id=app.config["SCAN_WORKER_ID"],
            scheduler_process_id=os.getpid(),
            scheduler_attempt_count=1,
            scheduler_max_attempts=3,
            input_ip="192.0.2.0",
            subnet_mask="24",
            scan_type="fast",
            network_cidr="192.0.2.0/24",
            status="running",
        )
        db.session.add(job)
        db.session.commit()

        assert _dispatch_pending_scheduled_scans(app, now) == [job.id]
        db.session.refresh(job)
        assert job.status == "pending"
        assert job.scheduler_dispatch_state == "claimed"
        assert job.scheduler_claim_token != "expired-token"
        assert job.scheduler_attempt_count == 2
        assert started[0][1] == job.id
        assert started[0][3] == job.scheduler_claim_token
        assert events == [("old-process-stopped", job.id), "retry-started"]


def test_expired_attempt_owned_by_another_process_fails_closed(app, monkeypatch):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    stop_calls = []
    monkeypatch.setattr(
        "scanner.stop_scan_process",
        lambda scan_id, process_token=None: stop_calls.append(scan_id) or True,
    )
    with app.app_context():
        user = User.query.first()
        job = ScanResult(
            user_id=user.id,
            input_ip="192.0.2.61",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.61/32",
            status="running",
            scheduled_for=now - timedelta(minutes=5),
            scheduler_dispatch_state="started",
            scheduler_claim_token="remote-token",
            scheduler_started_at=now - timedelta(minutes=2),
            scheduler_heartbeat_at=now - timedelta(minutes=2),
            scheduler_progress_at=now - timedelta(minutes=2),
            scheduler_worker_id="another-worker",
            scheduler_process_id=999999,
            scheduler_attempt_count=1,
            scheduler_max_attempts=3,
        )
        db.session.add(job)
        db.session.commit()

        assert _dispatch_pending_scheduled_scans(app, now) == []
        db.session.refresh(job)
        assert job.status == "termination_failed"
        assert job.scheduler_dispatch_state == "orphaned"
        assert "not retried" in job.result_data
        assert stop_calls == []


def test_fresh_heartbeat_cannot_hide_scan_runtime_deadline(app, monkeypatch):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    stopped = []
    monkeypatch.setattr("scanner.stop_scan_process", lambda scan_id, process_token=None: stopped.append(scan_id) or True)
    monkeypatch.setattr(
        "app.threading.Thread",
        type(
            "FakeThread",
            (),
            {
                "__init__": lambda self, target, args, daemon: setattr(self, "args", args),
                "start": lambda self: None,
            },
        ),
    )
    app.config.update({
        "MAX_CONCURRENT_SCANS": 1,
        "SCHEDULER_LEASE_SECONDS": 30,
        "SCHEDULER_PROGRESS_TIMEOUT_SECONDS": 300,
        "MAX_SCAN_RUNTIME_SECONDS": 600,
    })
    with app.app_context():
        user = User.query.first()
        job = ScanResult(
            user_id=user.id,
            input_ip="192.0.2.60",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.60/32",
            status="running",
            scheduled_for=now - timedelta(hours=1),
            scheduler_dispatch_state="started",
            scheduler_claim_token="over-runtime",
            scheduler_claimed_at=now - timedelta(hours=1),
            scheduler_started_at=now - timedelta(seconds=601),
            scheduler_heartbeat_at=now,
            scheduler_progress_at=now,
            scheduler_worker_id=app.config["SCAN_WORKER_ID"],
            scheduler_process_id=os.getpid(),
            scheduler_attempt_count=1,
            scheduler_max_attempts=3,
        )
        db.session.add(job)
        db.session.commit()

        assert _dispatch_pending_scheduled_scans(app, now) == []
        assert stopped == [job.id]
        db.session.refresh(job)
        assert job.status == "failed"
        assert job.scheduler_dispatch_state == "failed"
        assert "not retried" in job.result_data


def test_hard_runtime_reports_failed_process_termination(app, monkeypatch, caplog):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    monkeypatch.setattr("scanner.stop_scan_process", lambda scan_id, process_token=None: False)
    app.config["MAX_SCAN_RUNTIME_SECONDS"] = 600
    with app.app_context():
        user = User.query.first()
        job = ScanResult(
            user_id=user.id,
            input_ip="192.0.2.62",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.62/32",
            status="running",
            scheduler_dispatch_state="started",
            scheduler_claim_token="runtime-stop-failed",
            scheduler_started_at=now - timedelta(seconds=601),
            scheduler_heartbeat_at=now,
            scheduler_progress_at=now,
            scheduler_worker_id=app.config["SCAN_WORKER_ID"],
            scheduler_process_id=os.getpid(),
            scheduler_attempt_count=1,
            scheduler_max_attempts=3,
        )
        db.session.add(job)
        db.session.commit()

        assert _dispatch_pending_scheduled_scans(app, now) == []
        db.session.refresh(job)
        assert job.status == "termination_failed"
        assert job.scheduler_dispatch_state == "orphaned"
        assert "could not be confirmed terminated" in job.result_data
        assert "Hard runtime termination failed" in caplog.text


def test_failed_to_terminate_job_still_consumes_capacity(app, monkeypatch):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    started = []
    monkeypatch.setattr("scanner.stop_scan_process", lambda scan_id, process_token=None: False)
    monkeypatch.setattr(
        "app.threading.Thread",
        type(
            "FakeThread",
            (),
            {
                "__init__": lambda self, target, args, daemon: setattr(self, "args", args),
                "start": lambda self: started.append(self.args[1]),
            },
        ),
    )
    app.config.update({"MAX_CONCURRENT_SCANS": 1, "MAX_SCAN_RUNTIME_SECONDS": 600})
    with app.app_context():
        user = User.query.first()
        orphan = ScanResult(
            user_id=user.id,
            input_ip="192.0.2.64",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.64/32",
            status="running",
            scheduler_dispatch_state="started",
            scheduler_claim_token="cannot-stop",
            scheduler_started_at=now - timedelta(seconds=601),
            scheduler_heartbeat_at=now,
            scheduler_progress_at=now,
            scheduler_worker_id=app.config["SCAN_WORKER_ID"],
            scheduler_process_id=os.getpid(),
            scheduler_attempt_count=1,
            scheduler_max_attempts=3,
        )
        queued = ScanResult(
            user_id=user.id,
            input_ip="192.0.2.65",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.65/32",
            status="pending",
            scheduled_for=now,
            scheduler_dispatch_state="queued",
            scheduler_attempt_count=0,
            scheduler_max_attempts=3,
        )
        db.session.add_all([orphan, queued])
        db.session.commit()

        assert _dispatch_pending_scheduled_scans(app, now) == []
        db.session.refresh(orphan)
        db.session.refresh(queued)
        assert orphan.status == "termination_failed"
        assert orphan.scheduler_dispatch_state == "orphaned"
        assert queued.scheduler_dispatch_state == "queued"
        assert started == []


def test_orphan_releases_capacity_when_owner_worker_eventually_exits(app):
    with app.app_context():
        user = User.query.first()
        job = ScanResult(
            user_id=user.id,
            input_ip="192.0.2.66",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.66/32",
            status="termination_failed",
            scheduler_dispatch_state="orphaned",
            scheduler_execution_phase="termination_failed",
            scheduler_claim_token="eventual-exit-token",
            scheduler_worker_id=app.config["SCAN_WORKER_ID"],
            scheduler_process_id=os.getpid(),
        )
        db.session.add(job)
        db.session.commit()
        job_id = job.id

    _reconcile_scan_worker_exit(app, job_id, "eventual-exit-token")

    with app.app_context():
        job = db.session.get(ScanResult, job_id)
        assert job.status == "failed"
        assert job.scheduler_dispatch_state == "failed"
        assert job.scheduler_execution_phase == "terminated"


@pytest.mark.parametrize("phase", ["starting", "post_processing"])
def test_local_stop_without_active_nmap_requests_cancellation(app, client, phase):
    import scanner

    with app.app_context():
        user = User.query.first()
        job = ScanResult(
            user_id=user.id,
            input_ip="192.0.2.67",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.67/32",
            status="running",
            scheduler_dispatch_state="started",
            scheduler_execution_phase=phase,
            scheduler_claim_token="post-process-cancel-token",
            scheduler_worker_id=app.config["SCAN_WORKER_ID"],
            scheduler_process_id=os.getpid(),
        )
        db.session.add(job)
        db.session.commit()
        job_id = job.id
        user_id = user.id
    scanner.allow_scan_process_start(job_id, "post-process-cancel-token")

    with client.session_transaction() as session:
        session["_user_id"] = str(user_id)
        session["_fresh"] = True
    response = client.post(f"/scan/{job_id}/stop")
    assert response.status_code == 302

    with app.app_context():
        job = db.session.get(ScanResult, job_id)
        assert job.status == "cancellation_requested"
        assert job.scheduler_dispatch_state == "cancellation_requested"

    _reconcile_scan_worker_exit(app, job_id, "post-process-cancel-token")
    with app.app_context():
        assert db.session.get(ScanResult, job_id).status == "cancelled"


def test_pending_cancel_racing_with_claim_uses_running_stop_flow(
    app, client, monkeypatch
):
    import scanner

    with app.app_context():
        user = User.query.first()
        job = ScanResult(
            user_id=user.id,
            input_ip="192.0.2.72",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.72/32",
            status="pending",
            scheduler_dispatch_state="queued",
        )
        db.session.add(job)
        db.session.commit()
        job_id, user_id = job.id, user.id

    query_class = type(ScanResult.query)
    real_update = query_class.update
    raced = {"done": False}

    def racing_update(query, values, *args, **kwargs):
        if not raced["done"] and values.get(ScanResult.status) == "cancelled":
            raced["done"] = True
            db.session.execute(
                ScanResult.__table__.update().where(ScanResult.id == job_id).values(
                    status="running",
                    scheduler_dispatch_state="started",
                    scheduler_execution_phase="starting",
                    scheduler_claim_token="race-token",
                    scheduler_worker_id=app.config["SCAN_WORKER_ID"],
                    scheduler_process_id=os.getpid(),
                )
            )
            db.session.commit()
        return real_update(query, values, *args, **kwargs)

    monkeypatch.setattr(query_class, "update", racing_update)
    stop_calls = []
    monkeypatch.setattr(
        scanner,
        "stop_scan_process",
        lambda scan_id, process_token=None: stop_calls.append(process_token)
        or scanner.StopResult(True, False, True),
    )
    with client.session_transaction() as session:
        session["_user_id"] = str(user_id)
        session["_fresh"] = True
    client.post(f"/scan/{job_id}/stop")

    with app.app_context():
        job = db.session.get(ScanResult, job_id)
        assert job.status == "cancellation_requested"
        assert stop_calls == ["race-token"]


def test_running_cancel_cannot_overwrite_completed_status(app, client, monkeypatch):
    import scanner

    with app.app_context():
        user = User.query.first()
        job = ScanResult(
            user_id=user.id,
            input_ip="192.0.2.73",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.73/32",
            status="running",
            scheduler_dispatch_state="started",
            scheduler_execution_phase="starting-primary-scan",
            scheduler_claim_token="completion-race-token",
            scheduler_worker_id=app.config["SCAN_WORKER_ID"],
            scheduler_process_id=os.getpid(),
        )
        db.session.add(job)
        db.session.commit()
        job_id, user_id = job.id, user.id

    def complete_while_stopping(scan_id, process_token=None):
        ScanResult.query.filter_by(id=scan_id).update(
            {
                ScanResult.status: "completed",
                ScanResult.scheduler_dispatch_state: "completed",
                ScanResult.scheduler_execution_phase: "completed",
            },
            synchronize_session=False,
        )
        db.session.commit()
        return scanner.StopResult(True, False, True)

    monkeypatch.setattr(scanner, "stop_scan_process", complete_while_stopping)
    with client.session_transaction() as session:
        session["_user_id"] = str(user_id)
        session["_fresh"] = True
    client.post(f"/scan/{job_id}/stop")

    with app.app_context():
        job = db.session.get(ScanResult, job_id)
        assert job.status == "completed"
        assert job.scheduler_dispatch_state == "completed"


def test_cancel_transition_is_claim_token_fenced(app, client, monkeypatch):
    import scanner

    with app.app_context():
        user = User.query.first()
        job = ScanResult(
            user_id=user.id,
            input_ip="192.0.2.74",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.74/32",
            status="running",
            scheduler_dispatch_state="started",
            scheduler_execution_phase="starting-primary-scan",
            scheduler_claim_token="old-cancel-token",
            scheduler_worker_id=app.config["SCAN_WORKER_ID"],
            scheduler_process_id=os.getpid(),
        )
        db.session.add(job)
        db.session.commit()
        job_id, user_id = job.id, user.id

    def replace_claim_while_stopping(scan_id, process_token=None):
        ScanResult.query.filter_by(id=scan_id).update(
            {ScanResult.scheduler_claim_token: "new-current-token"},
            synchronize_session=False,
        )
        db.session.commit()
        return scanner.StopResult(True, False, True)

    monkeypatch.setattr(scanner, "stop_scan_process", replace_claim_while_stopping)
    with client.session_transaction() as session:
        session["_user_id"] = str(user_id)
        session["_fresh"] = True
    client.post(f"/scan/{job_id}/stop")

    with app.app_context():
        job = db.session.get(ScanResult, job_id)
        assert job.status == "running"
        assert job.scheduler_claim_token == "new-current-token"


@pytest.mark.parametrize(
    "orphan_status", ["termination_failed", "cancellation_requested"]
)
def test_admin_can_resolve_remote_orphan(app, client, orphan_status, caplog):
    with app.app_context():
        admin = User.query.filter_by(is_admin=True).first()
        job = ScanResult(
            user_id=admin.id,
            input_ip="192.0.2.68",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.68/32",
            status=orphan_status,
            scheduler_dispatch_state=(
                "orphaned" if orphan_status == "termination_failed"
                else "cancellation_requested"
            ),
            scheduler_execution_phase=orphan_status,
        )
        db.session.add(job)
        db.session.commit()
        job_id = job.id
        admin_id = admin.id

    with client.session_transaction() as session:
        session["_user_id"] = str(admin_id)
        session["_fresh"] = True
    response = client.post(
        f"/admin/scan/{job_id}/resolve-orphan",
        data={"reason": "Owning worker\r\nwas confirmed stopped" + ("!" * 600)},
    )
    assert response.status_code == 302

    with app.app_context():
        job = db.session.get(ScanResult, job_id)
        assert job.status == "failed"
        assert job.scheduler_execution_phase == "operator_resolved"
        audit = ScanResolutionAudit.query.filter_by(scan_id=job_id).one()
        assert "\n" not in audit.reason and "\r" not in audit.reason
        assert len(audit.reason) == 500
        assert audit.admin_user_id == admin_id
        assert audit.previous_status == orphan_status
    assert "ADMIN_SCAN_ORPHAN_RESOLVED" in caplog.text


def test_failed_active_process_stop_becomes_termination_failed(app, client, monkeypatch):
    import scanner

    with app.app_context():
        user = User.query.first()
        job = ScanResult(
            user_id=user.id,
            input_ip="192.0.2.69",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.69/32",
            status="running",
            scheduler_dispatch_state="started",
            scheduler_execution_phase="starting-primary-scan",
            scheduler_claim_token="unstoppable-token",
            scheduler_worker_id=app.config["SCAN_WORKER_ID"],
            scheduler_process_id=os.getpid(),
        )
        db.session.add(job)
        db.session.commit()
        job_id = job.id
        user_id = user.id

    monkeypatch.setattr(
        scanner,
        "stop_scan_process",
        lambda scan_id, process_token=None: scanner.StopResult(True, True, False),
    )
    with client.session_transaction() as session:
        session["_user_id"] = str(user_id)
        session["_fresh"] = True
    client.post(f"/scan/{job_id}/stop")

    with app.app_context():
        job = db.session.get(ScanResult, job_id)
        assert job.status == "termination_failed"
        assert job.scheduler_dispatch_state == "orphaned"


def test_active_scan_and_its_user_cannot_be_deleted(app, client):
    with app.app_context():
        admin = User.query.filter_by(is_admin=True).first()
        user = User(email="active-owner@test.com", password_hash="test")
        db.session.add(user)
        db.session.flush()
        job = ScanResult(
            user_id=user.id,
            input_ip="192.0.2.70",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.70/32",
            status="running",
            scheduler_dispatch_state="started",
        )
        db.session.add(job)
        db.session.commit()
        admin_id, user_id, job_id = admin.id, user.id, job.id

    with client.session_transaction() as session:
        session["_user_id"] = str(admin_id)
        session["_fresh"] = True

    assert client.post(f"/admin/scan/{job_id}/delete").status_code == 302
    assert client.post(f"/admin/user/{user_id}/delete").status_code == 302

    with app.app_context():
        assert db.session.get(ScanResult, job_id) is not None
        protected_user = db.session.get(User, user_id)
        assert protected_user is not None
        assert protected_user.is_deleting is False


def test_deleting_user_cannot_create_new_scan(app, client):
    with app.app_context():
        user = User(
            email="deleting-user@test.com",
            password_hash="test",
            is_deleting=True,
        )
        db.session.add(user)
        db.session.commit()
        user_id = user.id

    with client.session_transaction() as session:
        session["_user_id"] = str(user_id)
        session["_fresh"] = True
    response = client.post(
        "/scan",
        data={
            "ip_address": "192.0.2.71",
            "subnet_mask": "32",
            "scan_type": "fast",
            "timing_template": "4",
        },
    )

    assert response.status_code == 302
    with app.app_context():
        assert ScanResult.query.filter_by(user_id=user_id).count() == 0


def test_ownership_loss_is_handled_without_thread_traceback(app, monkeypatch, caplog):
    import scanner

    caplog.set_level("INFO")
    monkeypatch.setattr(
        "services.scan_service._execute_scan_body",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            scanner.ScanOwnershipLost("expected fence")
        ),
    )

    execute_scan(app, 9999)

    assert "stopped because claim ownership was lost" in caplog.text


def test_post_processing_stall_fails_closed_without_retry(app, monkeypatch):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    monkeypatch.setattr("scanner.stop_scan_process", lambda scan_id, process_token=None: False)
    app.config.update({
        "SCHEDULER_LEASE_SECONDS": 30,
        "SCHEDULER_PROGRESS_TIMEOUT_SECONDS": 60,
    })
    with app.app_context():
        user = User.query.first()
        job = ScanResult(
            user_id=user.id,
            input_ip="192.0.2.63",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.63/32",
            status="running",
            scheduler_dispatch_state="started",
            scheduler_claim_token="post-processing-stall",
            scheduler_started_at=now - timedelta(minutes=2),
            scheduler_heartbeat_at=now,
            scheduler_progress_at=now - timedelta(minutes=2),
            scheduler_worker_id=app.config["SCAN_WORKER_ID"],
            scheduler_process_id=os.getpid(),
            scheduler_attempt_count=1,
            scheduler_max_attempts=3,
        )
        db.session.add(job)
        db.session.commit()

        assert _dispatch_pending_scheduled_scans(app, now) == []
        db.session.refresh(job)
        assert job.status == "termination_failed"
        assert job.scheduler_dispatch_state == "orphaned"
        assert "could not be safely stopped" in job.result_data
        assert job.scheduler_attempt_count == 1


def test_heartbeat_interval_must_be_safely_below_lease():
    import pytest

    with pytest.raises(RuntimeError, match="at least three times"):
        create_app({
            "TESTING": True,
            "START_SCHEDULER": False,
            "SCHEDULER_LEASE_SECONDS": 60,
            "SCHEDULER_HEARTBEAT_SECONDS": 30,
        })


def test_invalid_scheduler_config_has_clear_error():
    import pytest

    with pytest.raises(RuntimeError, match="MAX_CONCURRENT_SCANS must be an integer"):
        create_app({
            "TESTING": True,
            "START_SCHEDULER": False,
            "MAX_CONCURRENT_SCANS": "many",
        })


def test_progress_timeout_and_runtime_config_are_ordered():
    import pytest

    with pytest.raises(RuntimeError, match="PROGRESS_TIMEOUT_SECONDS"):
        create_app({
            "TESTING": True,
            "SCHEDULER_LEASE_SECONDS": 120,
            "SCHEDULER_PROGRESS_TIMEOUT_SECONDS": 60,
        })

    with pytest.raises(RuntimeError, match="Nmap subprocess timeout"):
        create_app({
            "TESTING": True,
            "SCHEDULER_PROGRESS_TIMEOUT_SECONDS": 600,
        })
    with pytest.raises(RuntimeError, match="720 seconds"):
        create_app({
            "TESTING": True,
            "SCHEDULER_LEASE_SECONDS": 120,
            "SCHEDULER_PROGRESS_TIMEOUT_SECONDS": 719,
        })
    safe_app = create_app({
        "TESTING": True,
        "SCHEDULER_LEASE_SECONDS": 120,
        "SCHEDULER_PROGRESS_TIMEOUT_SECONDS": 720,
    })
    assert safe_app.config["SCHEDULER_PROGRESS_TIMEOUT_SECONDS"] == 720
    with pytest.raises(RuntimeError, match="MAX_SCAN_RUNTIME_SECONDS"):
        create_app({
            "TESTING": True,
            "SCHEDULER_PROGRESS_TIMEOUT_SECONDS": 900,
            "MAX_SCAN_RUNTIME_SECONDS": 600,
        })


def test_manual_scan_respects_global_concurrency_limit(app, monkeypatch):
    started = []

    class FakeThread:
        def __init__(self, target, args, daemon):
            self.args = args

        def start(self):
            started.append(self.args[1])

    monkeypatch.setattr("app.threading.Thread", FakeThread)
    app.config["MAX_CONCURRENT_SCANS"] = 1
    with app.app_context():
        user = User.query.first()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        db.session.add(ScanResult(
            user_id=user.id,
            input_ip="192.0.2.1",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.1/32",
            status="running",
        ))
        manual_job = ScanResult(
            user_id=user.id,
            input_ip="192.0.2.2",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.2/32",
            status="pending",
            scheduled_for=now,
            scheduler_dispatch_state="queued",
            scheduler_attempt_count=0,
            scheduler_max_attempts=3,
        )
        db.session.add(manual_job)
        db.session.commit()

        assert _dispatch_pending_scheduled_scans(app, now) == []
        db.session.refresh(manual_job)
        assert manual_job.status == "pending"
        assert manual_job.scheduler_dispatch_state == "queued"
        assert started == []


def test_two_dispatchers_cannot_exceed_global_capacity(tmp_path, monkeypatch):
    database_path = (tmp_path / "dispatcher-capacity.db").as_posix()
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
        "START_SCHEDULER": False,
        "MAX_CONCURRENT_SCANS": 1,
    })
    real_thread = threading.Thread
    monkeypatch.setattr("app.threading.Thread", type(
        "FakeThread",
        (),
        {"__init__": lambda self, target, args, daemon: setattr(self, "args", args),
         "start": lambda self: None},
    ))
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    with app.app_context():
        db.create_all()
        user = User(email="capacity@test.com", password_hash="test")
        db.session.add(user)
        db.session.flush()
        db.session.add(ScanDispatchLock(id=1))
        for suffix in [1, 2]:
            db.session.add(ScanResult(
                user_id=user.id,
                input_ip=f"192.0.2.{suffix}",
                subnet_mask="32",
                scan_type="fast",
                network_cidr=f"192.0.2.{suffix}/32",
                status="pending",
                scheduled_for=now,
                scheduler_dispatch_state="queued",
                scheduler_attempt_count=0,
                scheduler_max_attempts=3,
            ))
        db.session.commit()

    barrier = threading.Barrier(2)
    results = []
    errors = []

    def dispatch():
        try:
            with app.app_context():
                barrier.wait()
                results.extend(_dispatch_pending_scheduled_scans(app, now))
        except Exception as error:
            errors.append(error)

    workers = [real_thread(target=dispatch) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=10)

    assert errors == []
    assert len(results) == 1
    with app.app_context():
        assert ScanResult.query.filter_by(
            status="pending", scheduler_dispatch_state="claimed"
        ).count() == 1
        assert ScanResult.query.filter_by(
            status="pending", scheduler_dispatch_state="queued"
        ).count() == 1


def test_old_worker_loses_write_fence_after_claim_token_changes(app):
    with app.app_context():
        user = User.query.first()
        job = ScanResult(
            user_id=user.id,
            input_ip="192.0.2.50",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.50/32",
            status="running",
            scheduler_dispatch_state="started",
            scheduler_claim_token="new-token",
        )
        db.session.add(job)
        db.session.commit()

        assert scheduler_claim_is_current(job.id, "old-token") is False
        assert scheduler_claim_is_current(job.id, "new-token") is True


def test_progress_checkpoint_fences_later_host_work(app, monkeypatch):
    observations = []
    with app.app_context():
        user = User.query.first()
        job = ScanResult(
            user_id=user.id,
            input_ip="192.0.2.70",
            subnet_mask="31",
            scan_type="fast",
            network_cidr="192.0.2.70/31",
            status="running",
            scheduler_dispatch_state="started",
            scheduler_claim_token="first-token",
            scheduler_started_at=datetime.now(timezone.utc).replace(tzinfo=None),
        )
        db.session.add(job)
        db.session.commit()
        job_id = job.id

        monkeypatch.setattr("services.scan_service.seed_default_rules", lambda owner_id: None)
        monkeypatch.setattr(
            "services.scan_service.run_nmap_scan",
            lambda **kwargs: {
                "success": True,
                "command": "nmap test",
                "output": "",
                "scanned_endpoints": [],
                "hosts": [
                    {"address": "192.0.2.70", "ports": [], "status": "up"},
                    {"address": "192.0.2.71", "ports": [], "status": "up"},
                ],
            },
        )

        def record_once(**kwargs):
            observations.append(kwargs["ip_address"])
            ScanResult.query.filter_by(id=job_id).update(
                {ScanResult.scheduler_claim_token: "replacement-token"},
                synchronize_session=False,
            )
            db.session.commit()

        monkeypatch.setattr("services.scan_service.record_observation", record_once)
        _execute_scan_body(
            app,
            job_id,
            scheduler_claim_token="first-token",
            already_started=True,
        )

        assert observations == ["192.0.2.70"]
        assert scheduler_progress_checkpoint(job_id, "first-token") is False


def test_progress_checkpoint_does_not_commit_business_session(app):
    with app.app_context():
        user = User.query.first()
        job = ScanResult(
            user_id=user.id,
            input_ip="192.0.2.72",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.72/32",
            status="running",
            scheduler_dispatch_state="started",
            scheduler_claim_token="checkpoint-token",
        )
        db.session.add(job)
        db.session.commit()
        job_id = job.id

        job.result_data = "must remain uncommitted"
        assert scheduler_progress_checkpoint(
            job_id,
            "checkpoint-token",
            force=True,
            phase="asset_processing",
        )
        db.session.rollback()

        db.session.expire_all()
        persisted = db.session.get(ScanResult, job_id)
        assert persisted.result_data is None
        assert persisted.scheduler_progress_at is not None
        assert persisted.scheduler_execution_phase == "asset_processing"


def test_progress_ownership_check_does_not_use_business_session(app, monkeypatch):
    import services.scan_service as scan_service

    with app.app_context():
        user = User.query.first()
        job = ScanResult(
            user_id=user.id,
            input_ip="192.0.2.74",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.74/32",
            status="running",
            scheduler_dispatch_state="started",
            scheduler_claim_token="independent-ownership-token",
        )
        db.session.add(job)
        db.session.commit()

        monkeypatch.setattr(
            scan_service,
            "scheduler_claim_is_current",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                AssertionError("business session ownership check was used")
            ),
        )
        assert scheduler_progress_checkpoint(
            job.id, job.scheduler_claim_token, force=True
        )
        scan_service._clear_scheduler_progress_checkpoint(
            job.id, job.scheduler_claim_token
        )


def test_failed_progress_write_is_throttled(app, monkeypatch):
    import services.scan_service as scan_service

    attempts = []

    class FailingProgressSession:
        def query(self, model):
            attempts.append(model)
            raise RuntimeError("database is locked")

        def rollback(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(
        scan_service,
        "sessionmaker",
        lambda **kwargs: lambda: FailingProgressSession(),
    )
    monkeypatch.setattr(
        scan_service,
        "_independent_scheduler_claim_is_current",
        lambda scan_id, claim_token: True,
    )

    with app.app_context():
        user = User.query.first()
        job = ScanResult(
            user_id=user.id,
            input_ip="192.0.2.73",
            subnet_mask="32",
            scan_type="fast",
            network_cidr="192.0.2.73/32",
            status="running",
            scheduler_dispatch_state="started",
            scheduler_claim_token="locked-progress-token",
        )
        db.session.add(job)
        db.session.commit()

        assert scheduler_progress_checkpoint(job.id, job.scheduler_claim_token, force=True)
        assert scheduler_progress_checkpoint(job.id, job.scheduler_claim_token, force=True)
        assert len(attempts) == 1
        scan_service._clear_scheduler_progress_checkpoint(
            job.id, job.scheduler_claim_token
        )


def test_missing_dispatch_lock_is_a_schema_error(app):
    import pytest

    with app.app_context():
        db.session.delete(db.session.get(ScanDispatchLock, 1))
        db.session.commit()
        with pytest.raises(RuntimeError, match="scan_dispatch_lock row 1 is missing"):
            _dispatch_pending_scheduled_scans(app)


def test_flask_run_starts_dispatcher_but_not_schedule_creator(monkeypatch):
    import app as app_module

    started = []
    monkeypatch.setenv("FLASK_RUN_FROM_CLI", "true")
    monkeypatch.delenv("FLASK_DEBUG", raising=False)
    monkeypatch.delenv("WERKZEUG_RUN_MAIN", raising=False)
    monkeypatch.setattr(app_module, "start_scheduler", lambda flask_app: started.append("scheduler"))
    monkeypatch.setattr(app_module, "start_scan_dispatcher", lambda flask_app: started.append("dispatcher"))

    create_app({
        "TESTING": False,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "START_SCHEDULER": True,
        "SEED_DEMO_DATA": False,
    })

    assert started == ["dispatcher"]


def test_documented_management_cli_form_starts_no_background_work(monkeypatch):
    import sys
    import app as app_module

    calls = []
    monkeypatch.setattr(
        sys, "argv", ["flask", "--app", "app", "db", "upgrade"]
    )
    monkeypatch.setenv("FLASK_RUN_FROM_CLI", "true")
    monkeypatch.setattr(app_module, "start_scheduler", lambda flask_app: calls.append("scheduler"))
    monkeypatch.setattr(app_module, "start_scan_dispatcher", lambda flask_app: calls.append("dispatcher"))
    monkeypatch.setattr(app_module, "cleanup_stale_scans", lambda: calls.append("cleanup"))
    monkeypatch.setattr(app_module, "seed_mock_security_data", lambda: calls.append("seed"))

    create_app({
        "TESTING": False,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "START_SCHEDULER": True,
        "SEED_DEMO_DATA": True,
    })

    assert calls == []


def test_debug_reloader_only_starts_dispatcher_in_child(monkeypatch):
    import app as app_module

    started = []
    monkeypatch.setenv("FLASK_RUN_FROM_CLI", "true")
    monkeypatch.delenv("WERKZEUG_RUN_MAIN", raising=False)
    monkeypatch.setattr(app_module, "start_scan_dispatcher", lambda flask_app: started.append("dispatcher"))
    monkeypatch.setattr(app_module, "cleanup_stale_scans", lambda: None)

    config = {
        "TESTING": False,
        "DEBUG": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SEED_DEMO_DATA": False,
    }
    create_app(config)
    assert started == []

    monkeypatch.setenv("WERKZEUG_RUN_MAIN", "true")
    create_app(config)
    assert started == ["dispatcher"]


def test_manual_scan_post_only_queues_even_if_dispatch_lock_is_missing(app, client):
    with app.app_context():
        user = User.query.first()
        user_id = user.id
        db.session.delete(db.session.get(ScanDispatchLock, 1))
        db.session.commit()

    with client.session_transaction() as session:
        session["_user_id"] = str(user_id)
        session["_fresh"] = True

    response = client.post(
        "/scan",
        data={
            "ip_address": "192.0.2.80",
            "subnet_mask": "32",
            "scan_type": "fast",
            "timing_template": "4",
        },
    )

    assert response.status_code == 302
    with app.app_context():
        job = ScanResult.query.filter_by(input_ip="192.0.2.80").one()
        assert job.status == "pending"
        assert job.scheduler_dispatch_state == "queued"
