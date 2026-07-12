"""align schema with current models

Revision ID: 3f235f89c673
Revises: 4b1d0851377a
Create Date: 2026-07-12 20:38:11.499568

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3f235f89c673'
down_revision = '4b1d0851377a'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    # honeypot_log: Pass 1 (Add column if missing)
    if 'honeypot_log' in existing_tables:
        columns_hl = [c['name'] for c in inspector.get_columns('honeypot_log')]
        with op.batch_alter_table('honeypot_log', schema=None) as batch_op:
            if 'headers' not in columns_hl:
                batch_op.add_column(sa.Column('headers', sa.Text(), nullable=True))
            if 'created_at' not in columns_hl:
                batch_op.add_column(sa.Column('created_at', sa.DateTime(), nullable=True))

        # Copy data
        if 'timestamp' in columns_hl:
            op.execute("UPDATE honeypot_log SET created_at = timestamp WHERE created_at IS NULL AND timestamp IS NOT NULL")

        # Pass 2 (Drop old columns and alter constraints)
        with op.batch_alter_table('honeypot_log', schema=None) as batch_op:
            if 'timestamp' in columns_hl:
                batch_op.drop_column('timestamp')
            if 'method' in columns_hl:
                batch_op.drop_column('method')
            batch_op.alter_column('ip_address', existing_type=sa.String(45), nullable=False)
            batch_op.alter_column('path', existing_type=sa.String(255), nullable=False)

    # honeypot_blocked_ip: Pass 1 (Add column if missing)
    if 'honeypot_blocked_ip' in existing_tables:
        columns_hbi = [c['name'] for c in inspector.get_columns('honeypot_blocked_ip')]
        with op.batch_alter_table('honeypot_blocked_ip', schema=None) as batch_op:
            if 'reason' not in columns_hbi:
                batch_op.add_column(sa.Column('reason', sa.String(255), nullable=True))
            if 'created_at' not in columns_hbi:
                batch_op.add_column(sa.Column('created_at', sa.DateTime(), nullable=True))

        # Copy data & fill defaults
        if 'blocked_at' in columns_hbi:
            op.execute("UPDATE honeypot_blocked_ip SET created_at = blocked_at WHERE created_at IS NULL AND blocked_at IS NOT NULL")
        op.execute("UPDATE honeypot_blocked_ip SET reason = 'Blocked by Honeypot' WHERE reason IS NULL")

        # Pass 2 (Drop old columns and alter constraints)
        with op.batch_alter_table('honeypot_blocked_ip', schema=None) as batch_op:
            if 'blocked_at' in columns_hbi:
                batch_op.drop_column('blocked_at')
            if 'expires_at' in columns_hbi:
                batch_op.drop_column('expires_at')
            batch_op.alter_column('ip_address', existing_type=sa.String(45), nullable=False)

    # Perform backfills on existing tables to avoid constraint errors
    if 'asset' in existing_tables:
        op.execute("UPDATE asset SET ip_assignment_type = 'DHCP' WHERE ip_assignment_type IS NULL")
    if 'scan_schedule' in existing_tables:
        op.execute("UPDATE scan_schedule SET next_run = CURRENT_TIMESTAMP WHERE next_run IS NULL")
    if 'security_anomaly' in existing_tables:
        op.execute("UPDATE security_anomaly SET anomaly_type = 'Rogue Device' WHERE anomaly_type IS NULL")
        op.execute("UPDATE security_anomaly SET ip_address = '0.0.0.0' WHERE ip_address IS NULL")
        op.execute("UPDATE security_anomaly SET description = 'Legacy anomaly record' WHERE description IS NULL")

    # security_anomaly nullability
    if 'security_anomaly' in existing_tables:
        with op.batch_alter_table('security_anomaly', schema=None) as batch_op:
            batch_op.alter_column('anomaly_type', existing_type=sa.String(50), nullable=False)
            batch_op.alter_column('ip_address', existing_type=sa.String(45), nullable=False)
            batch_op.alter_column('description', existing_type=sa.Text(), nullable=False)

    # asset nullability
    if 'asset' in existing_tables:
        with op.batch_alter_table('asset', schema=None) as batch_op:
            batch_op.alter_column('ip_assignment_type', existing_type=sa.String(20), nullable=False)

    # scan_schedule nullability
    if 'scan_schedule' in existing_tables:
        with op.batch_alter_table('scan_schedule', schema=None) as batch_op:
            batch_op.alter_column('next_run', existing_type=sa.DateTime(), nullable=False)


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    if 'scan_schedule' in existing_tables:
        with op.batch_alter_table('scan_schedule', schema=None) as batch_op:
            batch_op.alter_column('next_run', existing_type=sa.DateTime(), nullable=True)

    if 'asset' in existing_tables:
        with op.batch_alter_table('asset', schema=None) as batch_op:
            batch_op.alter_column('ip_assignment_type', existing_type=sa.String(20), nullable=True)

    if 'security_anomaly' in existing_tables:
        with op.batch_alter_table('security_anomaly', schema=None) as batch_op:
            batch_op.alter_column('description', existing_type=sa.Text(), nullable=True)
            batch_op.alter_column('ip_address', existing_type=sa.String(45), nullable=True)
            batch_op.alter_column('anomaly_type', existing_type=sa.String(50), nullable=True)

    if 'honeypot_blocked_ip' in existing_tables:
        columns_hbi = [c['name'] for c in inspector.get_columns('honeypot_blocked_ip')]
        with op.batch_alter_table('honeypot_blocked_ip', schema=None) as batch_op:
            batch_op.alter_column('ip_address', existing_type=sa.String(45), nullable=True)
            if 'created_at' in columns_hbi:
                batch_op.drop_column('created_at')
            if 'reason' in columns_hbi:
                batch_op.drop_column('reason')
            batch_op.add_column(sa.Column('expires_at', sa.DateTime(), nullable=True))
            batch_op.add_column(sa.Column('blocked_at', sa.DateTime(), nullable=True))

    if 'honeypot_log' in existing_tables:
        columns_hl = [c['name'] for c in inspector.get_columns('honeypot_log')]
        with op.batch_alter_table('honeypot_log', schema=None) as batch_op:
            batch_op.alter_column('path', existing_type=sa.String(255), nullable=True)
            batch_op.alter_column('ip_address', existing_type=sa.String(45), nullable=True)
            if 'created_at' in columns_hl:
                batch_op.drop_column('created_at')
            if 'headers' in columns_hl:
                batch_op.drop_column('headers')
            batch_op.add_column(sa.Column('timestamp', sa.DateTime(), nullable=True))
            batch_op.add_column(sa.Column('method', sa.String(10), nullable=True))
