"""add_finding_cols

Revision ID: f3f3b3fa167d
Revises: 165695dd1775
Create Date: 2026-07-11 20:44:37.100634

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f3f3b3fa167d'
down_revision = '165695dd1775'
branch_labels = None
depends_on = None


def upgrade():
    # Add new columns to security_finding for fingerprinting, scan association,
    # source tracking, and accepted-risk expiry.
    # NOTE: The cascade FK changes on scan_credential, scan_result, scan_schedule,
    # security_rule, and system_setting are defined at the SQLAlchemy model level and
    # are honoured by SQLite via PRAGMA foreign_keys=ON. They cannot be altered as
    # named constraints on SQLite, so we skip the drop/recreate steps here.
    with op.batch_alter_table('security_finding', schema=None) as batch_op:
        batch_op.add_column(sa.Column('source_type', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('source_rule_id', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('scan_id', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('fingerprint', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('acceptance_expiry', sa.DateTime(), nullable=True))


def downgrade():
    with op.batch_alter_table('security_finding', schema=None) as batch_op:
        batch_op.drop_column('acceptance_expiry')
        batch_op.drop_column('fingerprint')
        batch_op.drop_column('scan_id')
        batch_op.drop_column('source_rule_id')
        batch_op.drop_column('source_type')
