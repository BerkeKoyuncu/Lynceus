from datetime import datetime, timedelta, timezone
import threading

from app import (
    _claim_scheduled_scan,
    _dispatch_pending_scheduled_scans,
    cleanup_stale_scans,
    create_app,
)
from models import db, ScanResult, ScanSchedule, User


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
        assert job.scheduler_dispatch_state == "queued"
        assert job.scheduler_claimed_at is None


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

    class FakeThread:
        def __init__(self, target, args, daemon):
            self.args = args

        def start(self):
            started.append(self.args)

    monkeypatch.setattr("app.threading.Thread", FakeThread)
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
