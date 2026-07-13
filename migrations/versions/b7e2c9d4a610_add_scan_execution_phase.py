"""add scan execution phase

Revision ID: b7e2c9d4a610
Revises: a8d4f1c6b902
Create Date: 2026-07-13 14:30:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = "b7e2c9d4a610"
down_revision = "a8d4f1c6b902"
branch_labels = None
depends_on = None


# Handle the upgrade operation.
def upgrade():
    # Manage op.batch_alter_table('scan_result') within this scoped block.
    with op.batch_alter_table("scan_result") as batch_op:
        batch_op.add_column(
            sa.Column("scheduler_execution_phase", sa.String(50), nullable=True)
        )


# Handle the downgrade operation.
def downgrade():
    # Manage op.batch_alter_table('scan_result') within this scoped block.
    with op.batch_alter_table("scan_result") as batch_op:
        batch_op.drop_column("scheduler_execution_phase")
