"""backfill and finalize schema

Revision ID: b5a93e3d9370
Revises: 81e56a4fa655
Create Date: 2026-07-12 21:10:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b5a93e3d9370'
down_revision = '81e56a4fa655'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    # 1. Backfill honeypot_log data and drop old fields
    if 'honeypot_log' in existing_tables:
        columns_hl = [c['name'] for c in inspector.get_columns('honeypot_log')]
        
        # Ensure we have created_at and headers columns first
        with op.batch_alter_table('honeypot_log', schema=None) as batch_op:
            if 'headers' not in columns_hl:
                batch_op.add_column(sa.Column('headers', sa.Text(), nullable=True))
            if 'created_at' not in columns_hl:
                batch_op.add_column(sa.Column('created_at', sa.DateTime(), nullable=True))

        # Backfill timestamp to created_at
        if 'timestamp' in columns_hl:
            op.execute("UPDATE honeypot_log SET created_at = timestamp WHERE created_at IS NULL AND timestamp IS NOT NULL")
        
        # Set dummy/default values for null ip_address or path before setting NOT NULL
        op.execute("UPDATE honeypot_log SET ip_address = '0.0.0.0' WHERE ip_address IS NULL")
        op.execute("UPDATE honeypot_log SET path = '/' WHERE path IS NULL")

        # Now drop timestamp/method, and set not-nullable
        with op.batch_alter_table('honeypot_log', schema=None) as batch_op:
            if 'timestamp' in columns_hl:
                batch_op.drop_column('timestamp')
            if 'method' in columns_hl:
                batch_op.drop_column('method')
            batch_op.alter_column('ip_address', existing_type=sa.String(45), nullable=False)
            batch_op.alter_column('path', existing_type=sa.String(255), nullable=False)

    # 2. Backfill honeypot_blocked_ip and drop old fields
    if 'honeypot_blocked_ip' in existing_tables:
        columns_hbi = [c['name'] for c in inspector.get_columns('honeypot_blocked_ip')]
        
        # Ensure reason and created_at columns exist
        with op.batch_alter_table('honeypot_blocked_ip', schema=None) as batch_op:
            if 'reason' not in columns_hbi:
                batch_op.add_column(sa.Column('reason', sa.String(255), nullable=True))
            if 'created_at' not in columns_hbi:
                batch_op.add_column(sa.Column('created_at', sa.DateTime(), nullable=True))

        # Copy data
        if 'blocked_at' in columns_hbi:
            op.execute("UPDATE honeypot_blocked_ip SET created_at = blocked_at WHERE created_at IS NULL AND blocked_at IS NOT NULL")
        op.execute("UPDATE honeypot_blocked_ip SET reason = 'Blocked by Honeypot' WHERE reason IS NULL")
        op.execute("UPDATE honeypot_blocked_ip SET ip_address = '0.0.0.0' WHERE ip_address IS NULL")

        # Now drop old columns and set NOT NULL
        with op.batch_alter_table('honeypot_blocked_ip', schema=None) as batch_op:
            if 'blocked_at' in columns_hbi:
                batch_op.drop_column('blocked_at')
            if 'expires_at' in columns_hbi:
                batch_op.drop_column('expires_at')
            batch_op.alter_column('ip_address', existing_type=sa.String(45), nullable=False)

    # 3. Backfill asset assignment type
    if 'asset' in existing_tables:
        op.execute("UPDATE asset SET ip_assignment_type = 'DHCP' WHERE ip_assignment_type IS NULL")
        with op.batch_alter_table('asset', schema=None) as batch_op:
            batch_op.alter_column('ip_assignment_type', existing_type=sa.String(20), nullable=False)

    # 4. Backfill scan_schedule next_run
    if 'scan_schedule' in existing_tables:
        op.execute("UPDATE scan_schedule SET next_run = CURRENT_TIMESTAMP WHERE next_run IS NULL")
        with op.batch_alter_table('scan_schedule', schema=None) as batch_op:
            batch_op.alter_column('next_run', existing_type=sa.DateTime(), nullable=False)

    # 5. Backfill security_anomaly using lowercase canonical value 'rogue_device'
    if 'security_anomaly' in existing_tables:
        op.execute("UPDATE security_anomaly SET anomaly_type = 'rogue_device' WHERE anomaly_type IS NULL")
        op.execute("UPDATE security_anomaly SET ip_address = '0.0.0.0' WHERE ip_address IS NULL")
        op.execute("UPDATE security_anomaly SET description = 'Legacy anomaly record' WHERE description IS NULL")
        with op.batch_alter_table('security_anomaly', schema=None) as batch_op:
            batch_op.alter_column('anomaly_type', existing_type=sa.String(50), nullable=False)
            batch_op.alter_column('ip_address', existing_type=sa.String(45), nullable=False)
            batch_op.alter_column('description', existing_type=sa.Text(), nullable=False)

    # 6. Backfill security_finding protocol based on scan result type
    if 'security_finding' in existing_tables:
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
        with op.batch_alter_table('security_finding', schema=None) as batch_op:
            batch_op.alter_column('protocol', existing_type=sa.String(length=10), nullable=False)


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    if 'security_finding' in existing_tables:
        with op.batch_alter_table('security_finding', schema=None) as batch_op:
            batch_op.alter_column('protocol', existing_type=sa.String(length=10), nullable=True)

    if 'security_anomaly' in existing_tables:
        with op.batch_alter_table('security_anomaly', schema=None) as batch_op:
            batch_op.alter_column('description', existing_type=sa.Text(), nullable=True)
            batch_op.alter_column('ip_address', existing_type=sa.String(45), nullable=True)
            batch_op.alter_column('anomaly_type', existing_type=sa.String(50), nullable=True)

    if 'scan_schedule' in existing_tables:
        with op.batch_alter_table('scan_schedule', schema=None) as batch_op:
            batch_op.alter_column('next_run', existing_type=sa.DateTime(), nullable=True)

    if 'asset' in existing_tables:
        with op.batch_alter_table('asset', schema=None) as batch_op:
            batch_op.alter_column('ip_assignment_type', existing_type=sa.String(20), nullable=True)

    if 'honeypot_blocked_ip' in existing_tables:
        columns_hbi = [c['name'] for c in inspector.get_columns('honeypot_blocked_ip')]
        with op.batch_alter_table('honeypot_blocked_ip', schema=None) as batch_op:
            batch_op.alter_column('ip_address', existing_type=sa.String(45), nullable=True)
            batch_op.add_column(sa.Column('expires_at', sa.DateTime(), nullable=True))
            batch_op.add_column(sa.Column('blocked_at', sa.DateTime(), nullable=True))
            
        # copy created_at to blocked_at before dropping
        op.execute("UPDATE honeypot_blocked_ip SET blocked_at = created_at WHERE blocked_at IS NULL AND created_at IS NOT NULL")
        
        with op.batch_alter_table('honeypot_blocked_ip', schema=None) as batch_op:
            if 'created_at' in columns_hbi:
                batch_op.drop_column('created_at')
            if 'reason' in columns_hbi:
                batch_op.drop_column('reason')

    if 'honeypot_log' in existing_tables:
        columns_hl = [c['name'] for c in inspector.get_columns('honeypot_log')]
        with op.batch_alter_table('honeypot_log', schema=None) as batch_op:
            batch_op.alter_column('path', existing_type=sa.String(255), nullable=True)
            batch_op.alter_column('ip_address', existing_type=sa.String(45), nullable=True)
            batch_op.add_column(sa.Column('timestamp', sa.DateTime(), nullable=True))
            batch_op.add_column(sa.Column('method', sa.String(10), nullable=True))
            
        # copy created_at to timestamp before dropping
        op.execute("UPDATE honeypot_log SET timestamp = created_at WHERE timestamp IS NULL AND created_at IS NOT NULL")
        
        with op.batch_alter_table('honeypot_log', schema=None) as batch_op:
            if 'created_at' in columns_hl:
                batch_op.drop_column('created_at')
            if 'headers' in columns_hl:
                batch_op.drop_column('headers')
