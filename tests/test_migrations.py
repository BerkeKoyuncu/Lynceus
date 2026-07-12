import os
import sqlite3
import tempfile

import pytest
from flask_migrate import downgrade, upgrade

from app import create_app


def _database_app():
    fd, path = tempfile.mkstemp()
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}",
        "START_SCHEDULER": False,
    })
    return fd, path, app


def _cleanup_database(fd, path):
    os.close(fd)
    try:
        os.unlink(path)
    except OSError:
        pass


def test_deployed_b5_database_runs_new_cleanup_revision():
    fd, path, app = _database_app()
    try:
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
        connection.close()
        assert rows == [(3, "192.0.2.30", "keep me", "2026-07-12 14:00:00")]
        assert revision == "f2c7a4b9d105"
        assert "ix_scan_result_scheduler_queue" in scan_indexes
        assert "ix_scan_result_scheduled_for" in scan_indexes
    finally:
        _cleanup_database(fd, path)


def test_e6_deduplicates_drifted_blocked_ips_before_unique_constraint():
    fd, path, app = _database_app()
    try:
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
    finally:
        _cleanup_database(fd, path)


def test_drifted_b5_duplicate_ips_upgrade_directly_to_head():
    fd, path, app = _database_app()
    try:
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

        with app.app_context():
            upgrade()

        connection = sqlite3.connect(path)
        rows = connection.execute(
            "SELECT id, ip_address, reason FROM honeypot_blocked_ip"
        ).fetchall()
        revision = connection.execute("SELECT version_num FROM alembic_version").fetchone()[0]
        connection.close()
        assert rows == [(20, "198.51.100.20", "first")]
        assert revision == "f2c7a4b9d105"
    finally:
        _cleanup_database(fd, path)


def test_unsafe_downgrade_below_b5_is_blocked_without_data_loss():
    fd, path, app = _database_app()
    try:
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
    finally:
        _cleanup_database(fd, path)


def test_offline_downgrade_below_b5_is_blocked():
    fd, path, app = _database_app()
    try:
        with app.app_context(), pytest.raises(SystemExit) as error:
            downgrade(
                revision="c7e9d2f4a681:4b1d0851377a",
                sql=True,
            )
        assert error.value.code == 1
    finally:
        _cleanup_database(fd, path)
