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


# Handle the upgrade operation.
def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    # 1. Backfill honeypot_log data and drop old fields
    if 'honeypot_log' in existing_tables:
        columns_hl = [c['name'] for c in inspector.get_columns('honeypot_log')]
        
        # Ensure we have created_at and headers columns first
        with op.batch_alter_table('honeypot_log', schema=None) as batch_op:
            # Handle the branch where 'headers' not in columns_hl evaluates to true.
            if 'headers' not in columns_hl:
                batch_op.add_column(sa.Column('headers', sa.Text(), nullable=True))
            # Handle the branch where 'created_at' not in columns_hl evaluates to true.
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
            # Handle the branch where 'timestamp' in columns_hl evaluates to true.
            if 'timestamp' in columns_hl:
                batch_op.drop_column('timestamp')
            # Handle the branch where 'method' in columns_hl evaluates to true.
            if 'method' in columns_hl:
                batch_op.drop_column('method')
            batch_op.alter_column('ip_address', existing_type=sa.String(45), nullable=False)
            batch_op.alter_column('path', existing_type=sa.String(255), nullable=False)

    # 2. Backfill honeypot_blocked_ip and drop old fields
    if 'honeypot_blocked_ip' in existing_tables:
        columns_hbi = [c['name'] for c in inspector.get_columns('honeypot_blocked_ip')]
        
        # Ensure reason and created_at columns exist
        with op.batch_alter_table('honeypot_blocked_ip', schema=None) as batch_op:
            # Handle the branch where 'reason' not in columns_hbi evaluates to true.
            if 'reason' not in columns_hbi:
                batch_op.add_column(sa.Column('reason', sa.String(255), nullable=True))
            # Handle the branch where 'created_at' not in columns_hbi evaluates to true.
            if 'created_at' not in columns_hbi:
                batch_op.add_column(sa.Column('created_at', sa.DateTime(), nullable=True))

        # Copy data
        if 'blocked_at' in columns_hbi:
            op.execute("UPDATE honeypot_blocked_ip SET created_at = blocked_at WHERE created_at IS NULL AND blocked_at IS NOT NULL")
        op.execute("UPDATE honeypot_blocked_ip SET reason = 'Blocked by Honeypot' WHERE reason IS NULL")
        # A blocked record without an IP is unusable. Deleting it also avoids
        # collisions with the unique ip_address constraint.
        op.execute("DELETE FROM honeypot_blocked_ip WHERE ip_address IS NULL")

        # Now drop old columns and set NOT NULL
        with op.batch_alter_table('honeypot_blocked_ip', schema=None) as batch_op:
            # Handle the branch where 'blocked_at' in columns_hbi evaluates to true.
            if 'blocked_at' in columns_hbi:
                batch_op.drop_column('blocked_at')
            # Handle the branch where 'expires_at' in columns_hbi evaluates to true.
            if 'expires_at' in columns_hbi:
                batch_op.drop_column('expires_at')
            batch_op.alter_column('ip_address', existing_type=sa.String(45), nullable=False)

    # 3. Backfill asset assignment type
    if 'asset' in existing_tables:
        op.execute("UPDATE asset SET ip_assignment_type = 'DHCP' WHERE ip_assignment_type IS NULL")
        # Manage op.batch_alter_table('asset', schema=None) within this scoped block.
        with op.batch_alter_table('asset', schema=None) as batch_op:
            batch_op.alter_column('ip_assignment_type', existing_type=sa.String(20), nullable=False)

    # 4. Backfill scan_schedule next_run
    if 'scan_schedule' in existing_tables:
        op.execute("UPDATE scan_schedule SET next_run = CURRENT_TIMESTAMP WHERE next_run IS NULL")
        # Manage op.batch_alter_table('scan_schedule', schema=None) within this scoped block.
        with op.batch_alter_table('scan_schedule', schema=None) as batch_op:
            batch_op.alter_column('next_run', existing_type=sa.DateTime(), nullable=False)

    # 5. Backfill security_anomaly using lowercase canonical value 'rogue_device'
    if 'security_anomaly' in existing_tables:
        op.execute("UPDATE security_anomaly SET anomaly_type = 'rogue_device' WHERE anomaly_type IS NULL")
        op.execute("UPDATE security_anomaly SET ip_address = '0.0.0.0' WHERE ip_address IS NULL")
        op.execute("UPDATE security_anomaly SET description = 'Legacy anomaly record' WHERE description IS NULL")
        # Manage op.batch_alter_table('security_anomaly', schema=None) within this scoped block.
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
        # Manage op.batch_alter_table('security_finding', schema=None) within this scoped block.
        with op.batch_alter_table('security_finding', schema=None) as batch_op:
            batch_op.alter_column('protocol', existing_type=sa.String(length=10), nullable=False)


# Handle the downgrade operation.
def downgrade():
    # This revision only backfills data and reasserts constraints already owned
    # by its ancestors. Reversing those changes would make the physical schema
    # disagree with parent revision 81e56a4fa655.
    pass
