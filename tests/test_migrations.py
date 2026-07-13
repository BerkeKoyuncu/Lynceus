import os
import sqlite3
import tempfile
from datetime import datetime

import pytest
from flask_migrate import downgrade, upgrade
from sqlalchemy import text

from app import create_app
from models import db, ScanResult, ScanSchedule, User


# Handle the database app operation.
def _database_app():
    fd, path = tempfile.mkstemp()
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}",
        "START_SCHEDULER": False,
    })
    return fd, path, app


# Handle the cleanup database operation.
def _cleanup_database(fd, path):
    os.close(fd)
    # Run this block with structured exception handling.
    try:
        os.unlink(path)
    # Handle an exception raised by the preceding protected block.
    except OSError:
        pass


# Verify that sqlite connections enable foreign keys behaves as expected.
def test_sqlite_connections_enable_foreign_keys():
    fd, path, app = _database_app()
    # Run this block with structured exception handling.
    try:
        # Manage app.app_context() within this scoped block.
        with app.app_context():
            enabled = db.session.execute(text("PRAGMA foreign_keys")).scalar_one()
            assert enabled == 1
    # Run cleanup that must occur after the protected block.
    finally:
        _cleanup_database(fd, path)


# Verify that schedule delete sets historical scan schedule to null behaves as expected.
def test_schedule_delete_sets_historical_scan_schedule_to_null():
    fd, path, app = _database_app()
    # Run this block with structured exception handling.
    try:
        # Manage app.app_context() within this scoped block.
        with app.app_context():
            upgrade()
            user = User(email="fk-test@example.com", password_hash="test")
            db.session.add(user)
            db.session.flush()
            schedule = ScanSchedule(
                user_id=user.id,
                name="FK schedule",
                input_ip="192.0.2.10",
                subnet_mask="255.255.255.255",
                scan_type="syn",
                network_cidr="192.0.2.10/32",
                frequency="daily",
                next_run=datetime(2026, 7, 14, 10, 0, 0),
            )
            db.session.add(schedule)
            db.session.flush()
            scan = ScanResult(
                user_id=user.id,
                schedule_id=schedule.id,
                scheduled_for=datetime(2026, 7, 14, 9, 0, 0),
                input_ip="192.0.2.10",
                subnet_mask="255.255.255.255",
                scan_type="syn",
                network_cidr="192.0.2.10/32",
            )
            db.session.add(scan)
            db.session.commit()
            scan_id = scan.id
            user_id = user.id
            schedule_id = schedule.id

            connection = sqlite3.connect(path)
            scheduled_for = connection.execute(
                "SELECT scheduled_for FROM scan_result WHERE id = ?",
                (scan_id,),
            ).fetchone()[0]
            # Manage pytest.raises(sqlite3.IntegrityError) within this scoped block.
            with pytest.raises(sqlite3.IntegrityError) as duplicate_error:
                connection.execute(
                    "INSERT INTO scan_result ("
                    "user_id, schedule_id, scheduled_for, input_ip, subnet_mask, "
                    "scan_type, network_cidr"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        user_id,
                        schedule_id,
                        scheduled_for,
                        "192.0.2.11",
                        "255.255.255.255",
                        "syn",
                        "192.0.2.11/32",
                    ),
                )
            assert (
                "UNIQUE constraint failed: "
                "scan_result.schedule_id, scan_result.scheduled_for"
                in str(duplicate_error.value)
            )
            connection.rollback()
            connection.close()

            db.session.delete(schedule)
            db.session.commit()

            assert db.session.get(ScanResult, scan_id).schedule_id is None
    # Run cleanup that must occur after the protected block.
    finally:
        _cleanup_database(fd, path)


# Verify that status migration preserves values and repairs nullable orphan behaves as expected.
def test_status_migration_preserves_values_and_repairs_nullable_orphan():
    fd, path, app = _database_app()
    # Run this block with structured exception handling.
    try:
        # Manage app.app_context() within this scoped block.
        with app.app_context():
            upgrade(revision="c4f8a2d7e915")

        connection = sqlite3.connect(path)
        connection.execute(
            "INSERT INTO user (id, email, password_hash, is_admin, is_deleting) "
            "VALUES (900, 'migration@example.com', 'test', 0, 0)"
        )
        connection.execute(
            "INSERT INTO scan_result ("
            "id, user_id, input_ip, subnet_mask, scan_type, network_cidr, "
            "status, scheduler_dispatch_state"
            ") VALUES (901, 900, '192.0.2.90', '255.255.255.255', "
            "'syn', '192.0.2.90/32', 'cancellation_requested', "
            "'cancellation_requested')"
        )
        connection.execute(
            "INSERT INTO security_finding ("
            "id, asset_id, ip_address, port, protocol, status"
            ") VALUES (902, 999999, '192.0.2.90', 443, 'tcp', 'open')"
        )
        connection.commit()
        connection.close()

        # Manage app.app_context() within this scoped block.
        with app.app_context():
            upgrade()

        connection = sqlite3.connect(path)
        status_row = connection.execute(
            "SELECT status, scheduler_dispatch_state FROM scan_result WHERE id = 901"
        ).fetchone()
        finding_asset_id = connection.execute(
            "SELECT asset_id FROM security_finding WHERE id = 902"
        ).fetchone()[0]
        violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        connection.close()

        assert status_row == ("cancellation_requested", "cancellation_requested")
        assert finding_asset_id is None
        assert violations == []
    # Run cleanup that must occur after the protected block.
    finally:
        _cleanup_database(fd, path)


# Verify that b5 orphan can reach integrity cleanup revision behaves as expected.
def test_b5_orphan_can_reach_integrity_cleanup_revision():
    fd, path, app = _database_app()
    # Run this block with structured exception handling.
    try:
        # Manage app.app_context() within this scoped block.
        with app.app_context():
            upgrade(revision="b5a93e3d9370")

        connection = sqlite3.connect(path)
        connection.execute(
            "INSERT INTO security_finding ("
            "id, asset_id, ip_address, port, protocol, status"
            ") VALUES (950, 999999, '198.51.100.50', 22, 'tcp', 'open')"
        )
        connection.commit()
        connection.close()

        # Manage app.app_context() within this scoped block.
        with app.app_context():
            upgrade()

        connection = sqlite3.connect(path)
        asset_id = connection.execute(
            "SELECT asset_id FROM security_finding WHERE id = 950"
        ).fetchone()[0]
        revision = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()[0]
        violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        connection.close()

        assert asset_id is None
        assert revision == "e2b7c5d9a401"
        assert violations == []
    # Run cleanup that must occur after the protected block.
    finally:
        _cleanup_database(fd, path)


# Verify that required user orphan stops before dispatch state batch rebuild behaves as expected.
@pytest.mark.parametrize(
    ("table_name", "insert_sql"),
    [
        (
            "scan_result",
            "INSERT INTO scan_result ("
            "id, user_id, input_ip, subnet_mask, scan_type, network_cidr, status"
            ") VALUES (975, 999999, '203.0.113.75', '255.255.255.255', "
            "'syn', '203.0.113.75/32', 'pending')",
        ),
        (
            "scan_schedule",
            "INSERT INTO scan_schedule ("
            "id, user_id, name, input_ip, subnet_mask, scan_type, network_cidr, "
            "frequency, next_run"
            ") VALUES (975, 999999, 'Orphan schedule', '203.0.113.75', "
            "'255.255.255.255', 'syn', '203.0.113.75/32', 'daily', "
            "'2026-07-14 10:00:00')",
        ),
        (
            "system_setting",
            "INSERT INTO system_setting (id, user_id) VALUES (975, 999999)",
        ),
        (
            "scan_credential",
            "INSERT INTO scan_credential (id, user_id, name) "
            "VALUES (975, 999999, 'Orphan credential')",
        ),
        (
            "security_rule",
            "INSERT INTO security_rule (id, user_id, name) "
            "VALUES (975, 999999, 'Orphan rule')",
        ),
    ],
    ids=[
        "scan-result",
        "scan-schedule",
        "system-setting",
        "scan-credential",
        "security-rule",
    ],
)
def test_required_user_orphan_stops_before_dispatch_state_batch_rebuild(
    table_name,
    insert_sql,
    capsys,
):
    fd, path, app = _database_app()
    # Run this block with structured exception handling.
    try:
        # Manage app.app_context() within this scoped block.
        with app.app_context():
            upgrade(revision="d9a4e1c6f320")

        connection = sqlite3.connect(path)
        connection.execute(insert_sql)
        connection.commit()
        connection.close()

        # Manage app.app_context(), pytest.raises(SystemExit) within this scoped block.
        with app.app_context(), pytest.raises(SystemExit) as error:
            upgrade()
        assert error.value.code == 1
        assert (
            f"{table_name}[id=975].user_id=999999"
            in capsys.readouterr().err
        )

        connection = sqlite3.connect(path)
        revision = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()[0]
        dispatch_type = {
            row[1]: row[2]
            for row in connection.execute("PRAGMA table_info(scan_result)").fetchall()
        }["scheduler_dispatch_state"]
        connection.close()

        assert revision == "d9a4e1c6f320"
        assert dispatch_type == "VARCHAR(20)"
    # Run cleanup that must occur after the protected block.
    finally:
        _cleanup_database(fd, path)


# Verify that deployed b5 database runs new cleanup revision behaves as expected.
def test_deployed_b5_database_runs_new_cleanup_revision():
    fd, path, app = _database_app()
    # Run this block with structured exception handling.
    try:
        # Manage app.app_context() within this scoped block.
        with app.app_context():
            upgrade(revision="b5a93e3d9370")

        connection = sqlite3.connect(path)
        connection.execute(
            "INSERT INTO honeypot_blocked_ip (id, ip_address, reason) VALUES (1, '', '')"
        )
        connection.execute(
            "INSERT INTO honeypot_blocked_ip (id, ip_address, reason) VALUES (2, '   ', NULL)"
        )
        connection.execute(
            "INSERT INTO honeypot_blocked_ip "
            "(id, ip_address, reason, created_at) "
            "VALUES (3, '192.0.2.30', 'keep me', '2026-07-12 14:00:00')"
        )
        connection.commit()
        connection.close()

        # Manage app.app_context() within this scoped block.
        with app.app_context():
            upgrade()

        connection = sqlite3.connect(path)
        rows = connection.execute(
            "SELECT id, ip_address, reason, created_at "
            "FROM honeypot_blocked_ip ORDER BY id"
        ).fetchall()
        revision = connection.execute("SELECT version_num FROM alembic_version").fetchone()[0]
        scan_indexes = {
            row[1] for row in connection.execute("PRAGMA index_list(scan_result)").fetchall()
        }
        scan_table_info = connection.execute("PRAGMA table_info(scan_result)").fetchall()
        scan_columns = {row[1] for row in scan_table_info}
        scan_column_types = {row[1]: row[2] for row in scan_table_info}
        audit_column_types = {
            row[1]: row[2]
            for row in connection.execute(
                "PRAGMA table_info(scan_resolution_audit)"
            ).fetchall()
        }
        user_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(user)").fetchall()
        }
        table_names = {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        connection.close()
        assert rows == [(3, "192.0.2.30", "keep me", "2026-07-12 14:00:00")]
        assert revision == "e2b7c5d9a401"
        assert "ix_scan_result_scheduler_queue" in scan_indexes
        assert "ix_scan_result_scheduled_for" in scan_indexes
        assert {
            "scheduler_progress_at",
            "scheduler_execution_phase",
            "scheduler_worker_id",
            "scheduler_worker_host",
            "scheduler_process_id",
        }.issubset(scan_columns)
        assert "is_deleting" in user_columns
        assert "scan_resolution_audit" in table_names
        assert scan_column_types["status"] == "VARCHAR(32)"
        assert scan_column_types["scheduler_dispatch_state"] == "VARCHAR(32)"
        assert audit_column_types["previous_status"] == "VARCHAR(32)"
    # Run cleanup that must occur after the protected block.
    finally:
        _cleanup_database(fd, path)


# Verify that e6 deduplicates drifted blocked ips before unique constraint behaves as expected.
def test_e6_deduplicates_drifted_blocked_ips_before_unique_constraint():
    fd, path, app = _database_app()
    # Run this block with structured exception handling.
    try:
        # Manage app.app_context() within this scoped block.
        with app.app_context():
            upgrade(revision="d4f8a1c6e902")

        connection = sqlite3.connect(path)
        connection.execute("DROP TABLE honeypot_blocked_ip")
        connection.execute(
            "CREATE TABLE honeypot_blocked_ip ("
            "id INTEGER PRIMARY KEY, ip_address VARCHAR(45) NOT NULL, "
            "reason VARCHAR(255), created_at DATETIME)"
        )
        connection.execute(
            "INSERT INTO honeypot_blocked_ip VALUES "
            "(10, '192.0.2.40', 'first', '2026-07-12 10:00:00')"
        )
        connection.execute(
            "INSERT INTO honeypot_blocked_ip VALUES "
            "(11, '192.0.2.40', 'duplicate', '2026-07-12 11:00:00')"
        )
        connection.execute(
            "INSERT INTO honeypot_blocked_ip VALUES "
            "(12, '192.0.2.41', 'distinct', '2026-07-12 12:00:00')"
        )
        connection.commit()
        connection.close()

        # Manage app.app_context() within this scoped block.
        with app.app_context():
            upgrade(revision="e6b3c9d0f417")

        connection = sqlite3.connect(path)
        rows = connection.execute(
            "SELECT id, ip_address, reason FROM honeypot_blocked_ip ORDER BY id"
        ).fetchall()
        unique_indexes = [
            row for row in connection.execute(
                "PRAGMA index_list(honeypot_blocked_ip)"
            ).fetchall() if row[2] == 1
        ]
        connection.close()
        assert rows == [
            (10, "192.0.2.40", "first"),
            (12, "192.0.2.41", "distinct"),
        ]
        assert unique_indexes
    # Run cleanup that must occur after the protected block.
    finally:
        _cleanup_database(fd, path)


# Verify that drifted b5 duplicate ips upgrade directly to head behaves as expected.
def test_drifted_b5_duplicate_ips_upgrade_directly_to_head():
    fd, path, app = _database_app()
    # Run this block with structured exception handling.
    try:
        # Manage app.app_context() within this scoped block.
        with app.app_context():
            upgrade(revision="b5a93e3d9370")

        connection = sqlite3.connect(path)
        connection.execute("DROP TABLE honeypot_blocked_ip")
        connection.execute(
            "CREATE TABLE honeypot_blocked_ip ("
            "id INTEGER PRIMARY KEY, ip_address VARCHAR(45), "
            "reason VARCHAR(255), created_at DATETIME)"
        )
        connection.execute(
            "INSERT INTO honeypot_blocked_ip VALUES "
            "(20, '198.51.100.20', 'first', '2026-07-12 10:00:00')"
        )
        connection.execute(
            "INSERT INTO honeypot_blocked_ip VALUES "
            "(21, '198.51.100.20', 'duplicate', '2026-07-12 11:00:00')"
        )
        connection.commit()
        connection.close()

        # Manage app.app_context() within this scoped block.
        with app.app_context():
            upgrade()

        connection = sqlite3.connect(path)
        rows = connection.execute(
            "SELECT id, ip_address, reason FROM honeypot_blocked_ip"
        ).fetchall()
        revision = connection.execute("SELECT version_num FROM alembic_version").fetchone()[0]
        connection.close()
        assert rows == [(20, "198.51.100.20", "first")]
        assert revision == "e2b7c5d9a401"
    # Run cleanup that must occur after the protected block.
    finally:
        _cleanup_database(fd, path)


# Verify that upgrade to same b5 revision does not mutate drifted data behaves as expected.
def test_upgrade_to_same_b5_revision_does_not_mutate_drifted_data():
    fd, path, app = _database_app()
    # Run this block with structured exception handling.
    try:
        # Manage app.app_context() within this scoped block.
        with app.app_context():
            upgrade(revision="b5a93e3d9370")

        connection = sqlite3.connect(path)
        connection.execute("DROP TABLE honeypot_blocked_ip")
        connection.execute(
            "CREATE TABLE honeypot_blocked_ip ("
            "id INTEGER PRIMARY KEY, ip_address VARCHAR(45), "
            "reason VARCHAR(255), created_at DATETIME)"
        )
        connection.execute(
            "INSERT INTO honeypot_blocked_ip VALUES "
            "(30, '203.0.113.30', 'first', '2026-07-12 10:00:00')"
        )
        connection.execute(
            "INSERT INTO honeypot_blocked_ip VALUES "
            "(31, '203.0.113.30', 'duplicate', '2026-07-12 11:00:00')"
        )
        connection.commit()
        connection.close()

        # Manage app.app_context() within this scoped block.
        with app.app_context():
            upgrade(revision="b5a93e3d9370")

        connection = sqlite3.connect(path)
        rows = connection.execute(
            "SELECT id, ip_address, reason FROM honeypot_blocked_ip ORDER BY id"
        ).fetchall()
        revision = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()[0]
        connection.close()
        assert rows == [
            (30, "203.0.113.30", "first"),
            (31, "203.0.113.30", "duplicate"),
        ]
        assert revision == "b5a93e3d9370"
    # Run cleanup that must occur after the protected block.
    finally:
        _cleanup_database(fd, path)


# Verify that unsafe downgrade below b5 is blocked without data loss behaves as expected.
def test_unsafe_downgrade_below_b5_is_blocked_without_data_loss():
    fd, path, app = _database_app()
    # Run this block with structured exception handling.
    try:
        # Manage app.app_context() within this scoped block.
        with app.app_context():
            upgrade(revision="3f235f89c673")

        connection = sqlite3.connect(path)
        connection.execute(
            "INSERT INTO honeypot_log "
            "(id, ip_address, path, created_at) "
            "VALUES (1, '192.0.2.1', '/probe', '2026-07-12 12:00:00')"
        )
        connection.execute(
            "INSERT INTO honeypot_blocked_ip "
            "(id, ip_address, reason, created_at) "
            "VALUES (1, '192.0.2.2', 'test', '2026-07-12 13:00:00')"
        )
        connection.commit()
        connection.close()

        # Manage app.app_context(), pytest.raises(SystemExit) within this scoped block.
        with app.app_context(), pytest.raises(SystemExit) as error:
            downgrade(revision="4b1d0851377a")
        assert error.value.code == 1

        connection = sqlite3.connect(path)
        log_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(honeypot_log)").fetchall()
        }
        blocked_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(honeypot_blocked_ip)").fetchall()
        }
        log_time = connection.execute(
            "SELECT created_at FROM honeypot_log WHERE id = 1"
        ).fetchone()[0]
        blocked_time = connection.execute(
            "SELECT created_at FROM honeypot_blocked_ip WHERE id = 1"
        ).fetchone()[0]
        revision = connection.execute("SELECT version_num FROM alembic_version").fetchone()[0]
        connection.close()
        assert "timestamp" not in log_columns
        assert "blocked_at" not in blocked_columns
        assert log_time == "2026-07-12 12:00:00"
        assert blocked_time == "2026-07-12 13:00:00"
        assert revision == "3f235f89c673"
    # Run cleanup that must occur after the protected block.
    finally:
        _cleanup_database(fd, path)


# Verify that offline downgrade below b5 is blocked behaves as expected.
def test_offline_downgrade_below_b5_is_blocked():
    fd, path, app = _database_app()
    # Run this block with structured exception handling.
    try:
        # Manage app.app_context(), pytest.raises(SystemExit) within this scoped block.
        with app.app_context(), pytest.raises(SystemExit) as error:
            downgrade(
                revision="c7e9d2f4a681:4b1d0851377a",
                sql=True,
            )
        assert error.value.code == 1
    # Run cleanup that must occur after the protected block.
    finally:
        _cleanup_database(fd, path)
