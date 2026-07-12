"""harden scheduler queue

Revision ID: e6b3c9d0f417
Revises: d4f8a1c6e902
Create Date: 2026-07-13 01:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = "e6b3c9d0f417"
down_revision = "d4f8a1c6e902"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if "honeypot_blocked_ip" in inspector.get_table_names():
        unique_constraints = inspector.get_unique_constraints("honeypot_blocked_ip")
        indexes = inspector.get_indexes("honeypot_blocked_ip")
        has_ip_unique = any(
            constraint.get("column_names") == ["ip_address"]
            for constraint in unique_constraints
        ) or any(
            index.get("unique") is True
            and index.get("column_names") == ["ip_address"]
            for index in indexes
        )
        if not has_ip_unique:
            op.execute(
                "DELETE FROM honeypot_blocked_ip "
                "WHERE ip_address IS NULL OR TRIM(ip_address) = ''"
            )
            op.execute(
                "DELETE FROM honeypot_blocked_ip WHERE id NOT IN ("
                "SELECT keep_id FROM ("
                "SELECT MIN(id) AS keep_id FROM honeypot_blocked_ip GROUP BY ip_address"
                ") AS deduplicated)"
            )
            with op.batch_alter_table("honeypot_blocked_ip") as batch_op:
                batch_op.alter_column(
                    "ip_address", existing_type=sa.String(45), nullable=False
                )
                batch_op.create_unique_constraint(
                    "uq_honeypot_blocked_ip_ip_address", ["ip_address"]
                )

    with op.batch_alter_table("scan_result") as batch_op:
        batch_op.add_column(
            sa.Column("scheduler_claim_token", sa.String(36), nullable=True)
        )
        batch_op.add_column(sa.Column("scheduler_started_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("scheduler_heartbeat_at", sa.DateTime(), nullable=True))
        batch_op.add_column(
            sa.Column(
                "scheduler_attempt_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            )
        )
        batch_op.add_column(
            sa.Column(
                "scheduler_max_attempts",
                sa.Integer(),
                nullable=False,
                server_default="3",
            )
        )
        batch_op.drop_index("ix_scan_result_scheduler_dispatch_state")
        batch_op.create_index(
            "ix_scan_result_scheduler_queue",
            ["status", "scheduler_dispatch_state", "scheduler_claimed_at"],
            unique=False,
        )
        batch_op.create_index(
            "ix_scan_result_scheduled_for", ["scheduled_for"], unique=False
        )


def downgrade():
    with op.batch_alter_table("scan_result") as batch_op:
        batch_op.drop_index("ix_scan_result_scheduled_for")
        batch_op.drop_index("ix_scan_result_scheduler_queue")
        batch_op.create_index(
            "ix_scan_result_scheduler_dispatch_state",
            ["scheduler_dispatch_state"],
            unique=False,
        )
        batch_op.drop_column("scheduler_max_attempts")
        batch_op.drop_column("scheduler_attempt_count")
        batch_op.drop_column("scheduler_heartbeat_at")
        batch_op.drop_column("scheduler_started_at")
        batch_op.drop_column("scheduler_claim_token")
