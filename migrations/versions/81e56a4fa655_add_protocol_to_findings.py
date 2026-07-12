"""add protocol to findings

Revision ID: 81e56a4fa655
Revises: 3f235f89c673
Create Date: 2026-07-12 20:40:02.571881

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '81e56a4fa655'
down_revision = '3f235f89c673'
branch_labels = None
depends_on = None


def upgrade():
    # Pass 1: Add the protocol column as nullable
    with op.batch_alter_table('security_finding', schema=None) as batch_op:
        batch_op.add_column(sa.Column('protocol', sa.String(length=10), nullable=True))

    # Backfill protocol based on scan_result.scan_type
    op.execute(
        "UPDATE security_finding "
        "SET protocol = 'udp' "
        "WHERE scan_id IN (SELECT id FROM scan_result WHERE scan_type = 'udp')"
    )
    op.execute(
        "UPDATE security_finding "
        "SET protocol = 'tcp' "
        "WHERE protocol IS NULL"
    )

    # Pass 2: Set column to NOT NULL
    with op.batch_alter_table('security_finding', schema=None) as batch_op:
        batch_op.alter_column('protocol', existing_type=sa.String(length=10), nullable=False)


def downgrade():
    with op.batch_alter_table('security_finding', schema=None) as batch_op:
        batch_op.drop_column('protocol')
