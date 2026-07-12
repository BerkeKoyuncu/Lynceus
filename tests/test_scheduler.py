from datetime import datetime, timedelta, timezone
import os
import threading

from app import (
    _claim_scheduled_scan,
    _dispatch_pending_scheduled_scans,
    cleanup_stale_scans,
    create_app,
)
from models import db, ScanDispatchLock, ScanResult, ScanSchedule, User
from services.scan_service import (
    _execute_scan_body,
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
        lambda scan_id: events.append(("old-process-stopped", scan_id)) or True,
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
        lambda scan_id: stop_calls.append(scan_id) or True,
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
        assert job.status == "failed"
        assert "not retried" in job.result_data
        assert stop_calls == []


def test_fresh_heartbeat_cannot_hide_scan_runtime_deadline(app, monkeypatch):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    stopped = []
    monkeypatch.setattr("scanner.stop_scan_process", lambda scan_id: stopped.append(scan_id) or True)
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
        assert scheduler_progress_checkpoint(job_id, "checkpoint-token", force=True)
        db.session.rollback()

        db.session.expire_all()
        persisted = db.session.get(ScanResult, job_id)
        assert persisted.result_data is None
        assert persisted.scheduler_progress_at is not None


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
