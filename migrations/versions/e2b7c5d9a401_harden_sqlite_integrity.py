"""harden SQLite integrity

Revision ID: e2b7c5d9a401
Revises: d9a4e1c6f320
Create Date: 2026-07-13 21:30:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = "e2b7c5d9a401"
down_revision = "d9a4e1c6f320"
branch_labels = None
depends_on = None


def _repair_orphaned_references():
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())

    def columns(table_name):
        if table_name not in tables:
            return set()
        return {column["name"] for column in inspector.get_columns(table_name)}

    finding_columns = columns("security_finding")

    # Preserve findings because all three references are nullable.
    if "asset_id" in finding_columns and "asset" in tables:
        op.execute(
            "UPDATE security_finding SET asset_id = NULL "
            "WHERE asset_id IS NOT NULL "
            "AND NOT EXISTS (SELECT 1 FROM asset WHERE asset.id = security_finding.asset_id)"
        )
    if "assigned_user_id" in finding_columns and "user" in tables:
        op.execute(
            "UPDATE security_finding SET assigned_user_id = NULL "
            "WHERE assigned_user_id IS NOT NULL "
            "AND NOT EXISTS (SELECT 1 FROM user WHERE user.id = security_finding.assigned_user_id)"
        )
    if "scan_id" in finding_columns and "scan_result" in tables:
        op.execute(
            "UPDATE security_finding SET scan_id = NULL "
            "WHERE scan_id IS NOT NULL "
            "AND NOT EXISTS (SELECT 1 FROM scan_result WHERE scan_result.id = security_finding.scan_id)"
        )
    if (
        "schedule_id" in columns("scan_result")
        and "scan_schedule" in tables
    ):
        op.execute(
            "UPDATE scan_result SET schedule_id = NULL "
            "WHERE schedule_id IS NOT NULL "
            "AND NOT EXISTS (SELECT 1 FROM scan_schedule WHERE scan_schedule.id = scan_result.schedule_id)"
        )

    # Observations require both parents, so an orphan cannot be retained validly.
    observation_columns = columns("asset_observation")
    if (
        {"asset_id", "scan_id"}.issubset(observation_columns)
        and {"asset", "scan_result"}.issubset(tables)
    ):
        op.execute(
            "DELETE FROM asset_observation "
            "WHERE NOT EXISTS (SELECT 1 FROM asset WHERE asset.id = asset_observation.asset_id) "
            "OR NOT EXISTS (SELECT 1 FROM scan_result WHERE scan_result.id = asset_observation.scan_id)"
        )


def _assert_foreign_key_integrity():
    violations = op.get_bind().exec_driver_sql("PRAGMA foreign_key_check").fetchall()
    if violations:
        raise RuntimeError(
            "SQLite foreign-key violations remain after cleanup: "
            + repr(violations[:10])
        )


def upgrade():
    _repair_orphaned_references()

    with op.batch_alter_table("scan_result") as batch_op:
        batch_op.alter_column(
            "scheduler_dispatch_state",
            existing_type=sa.String(length=20),
            type_=sa.String(length=32),
            existing_nullable=True,
        )

    _assert_foreign_key_integrity()


def downgrade():
    with op.batch_alter_table("scan_result") as batch_op:
        batch_op.alter_column(
            "scheduler_dispatch_state",
            existing_type=sa.String(length=32),
            type_=sa.String(length=20),
            existing_nullable=True,
        )
