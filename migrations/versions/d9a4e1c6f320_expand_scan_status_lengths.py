"""expand scan status lengths

Revision ID: d9a4e1c6f320
Revises: c4f8a2d7e915
Create Date: 2026-07-13 20:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = "d9a4e1c6f320"
down_revision = "c4f8a2d7e915"
branch_labels = None
depends_on = None


# Handle the upgrade operation.
def upgrade():
    # Manage op.batch_alter_table('scan_result') within this scoped block.
    with op.batch_alter_table("scan_result") as batch_op:
        batch_op.alter_column(
            "status",
            existing_type=sa.String(length=20),
            type_=sa.String(length=32),
            existing_nullable=True,
        )

    # Manage op.batch_alter_table('scan_resolution_audit') within this scoped block.
    with op.batch_alter_table("scan_resolution_audit") as batch_op:
        batch_op.alter_column(
            "previous_status",
            existing_type=sa.String(length=20),
            type_=sa.String(length=32),
            existing_nullable=False,
        )


# Handle the downgrade operation.
def downgrade():
    # Manage op.batch_alter_table('scan_resolution_audit') within this scoped block.
    with op.batch_alter_table("scan_resolution_audit") as batch_op:
        batch_op.alter_column(
            "previous_status",
            existing_type=sa.String(length=32),
            type_=sa.String(length=20),
            existing_nullable=False,
        )

    # Manage op.batch_alter_table('scan_result') within this scoped block.
    with op.batch_alter_table("scan_result") as batch_op:
        batch_op.alter_column(
            "status",
            existing_type=sa.String(length=32),
            type_=sa.String(length=20),
            existing_nullable=True,
        )
