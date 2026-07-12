"""add deletion fence and resolution audit

Revision ID: c4f8a2d7e915
Revises: b7e2c9d4a610
Create Date: 2026-07-13 18:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = "c4f8a2d7e915"
down_revision = "b7e2c9d4a610"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("user") as batch_op:
        batch_op.add_column(
            sa.Column(
                "is_deleting",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )

    op.create_table(
        "scan_resolution_audit",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("admin_user_id", sa.Integer(), nullable=False),
        sa.Column("previous_status", sa.String(length=20), nullable=False),
        sa.Column("worker_id", sa.String(length=36), nullable=True),
        sa.Column("worker_host", sa.String(length=255), nullable=True),
        sa.Column("process_id", sa.Integer(), nullable=True),
        sa.Column("reason", sa.String(length=500), nullable=False),
        sa.Column("resolved_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_scan_resolution_audit_scan_id",
        "scan_resolution_audit",
        ["scan_id"],
        unique=False,
    )
    op.create_index(
        "ix_scan_resolution_audit_admin_user_id",
        "scan_resolution_audit",
        ["admin_user_id"],
        unique=False,
    )


def downgrade():
    op.drop_index(
        "ix_scan_resolution_audit_admin_user_id",
        table_name="scan_resolution_audit",
    )
    op.drop_index(
        "ix_scan_resolution_audit_scan_id",
        table_name="scan_resolution_audit",
    )
    op.drop_table("scan_resolution_audit")
    with op.batch_alter_table("user") as batch_op:
        batch_op.drop_column("is_deleting")
