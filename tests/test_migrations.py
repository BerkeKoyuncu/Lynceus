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
        connection.close()
        assert rows == [(3, "192.0.2.30", "keep me", "2026-07-12 14:00:00")]
        assert revision == "c7e9d2f4a681"
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
