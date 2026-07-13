"""track scan worker progress

Revision ID: a8d4f1c6b902
Revises: f2c7a4b9d105
Create Date: 2026-07-13 03:15:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = "a8d4f1c6b902"
down_revision = "f2c7a4b9d105"
branch_labels = None
depends_on = None


# Handle the upgrade operation.
def upgrade():
    # Manage op.batch_alter_table('scan_result') within this scoped block.
    with op.batch_alter_table("scan_result") as batch_op:
        batch_op.add_column(sa.Column("scheduler_progress_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("scheduler_worker_id", sa.String(36), nullable=True))
        batch_op.add_column(sa.Column("scheduler_worker_host", sa.String(255), nullable=True))
        batch_op.add_column(sa.Column("scheduler_process_id", sa.Integer(), nullable=True))


# Handle the downgrade operation.
def downgrade():
    # Manage op.batch_alter_table('scan_result') within this scoped block.
    with op.batch_alter_table("scan_result") as batch_op:
        batch_op.drop_column("scheduler_process_id")
        batch_op.drop_column("scheduler_worker_host")
        batch_op.drop_column("scheduler_worker_id")
        batch_op.drop_column("scheduler_progress_at")
