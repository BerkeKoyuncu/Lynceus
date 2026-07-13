"""add scan dispatch lock

Revision ID: f2c7a4b9d105
Revises: e6b3c9d0f417
Create Date: 2026-07-13 01:40:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = "f2c7a4b9d105"
down_revision = "e6b3c9d0f417"
branch_labels = None
depends_on = None


# Handle the upgrade operation.
def upgrade():
    op.create_table(
        "scan_dispatch_lock",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("touched_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.execute("INSERT INTO scan_dispatch_lock (id) VALUES (1)")


# Handle the downgrade operation.
def downgrade():
    op.drop_table("scan_dispatch_lock")
