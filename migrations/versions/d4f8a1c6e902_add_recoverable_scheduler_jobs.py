"""add recoverable scheduler jobs

Revision ID: d4f8a1c6e902
Revises: c7e9d2f4a681
Create Date: 2026-07-13 00:10:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = "d4f8a1c6e902"
down_revision = "c7e9d2f4a681"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("scan_result") as batch_op:
        batch_op.add_column(sa.Column("schedule_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("scheduled_for", sa.DateTime(), nullable=True))
        batch_op.add_column(
            sa.Column("scheduler_dispatch_state", sa.String(20), nullable=True)
        )
        batch_op.add_column(sa.Column("scheduler_claimed_at", sa.DateTime(), nullable=True))
        batch_op.create_foreign_key(
            "fk_scan_result_schedule_id_scan_schedule",
            "scan_schedule",
            ["schedule_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_unique_constraint(
            "uq_scan_result_schedule_occurrence",
            ["schedule_id", "scheduled_for"],
        )
        batch_op.create_index(
            "ix_scan_result_scheduler_dispatch_state",
            ["scheduler_dispatch_state"],
            unique=False,
        )


def downgrade():
    with op.batch_alter_table("scan_result") as batch_op:
        batch_op.drop_index("ix_scan_result_scheduler_dispatch_state")
        batch_op.drop_constraint(
            "uq_scan_result_schedule_occurrence", type_="unique"
        )
        batch_op.drop_constraint(
            "fk_scan_result_schedule_id_scan_schedule", type_="foreignkey"
        )
        batch_op.drop_column("scheduler_claimed_at")
        batch_op.drop_column("scheduler_dispatch_state")
        batch_op.drop_column("scheduled_for")
        batch_op.drop_column("schedule_id")
