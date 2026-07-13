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


# Handle the upgrade operation.
def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    # honeypot_log
    if 'honeypot_log' in existing_tables:
        columns_hl = [c['name'] for c in inspector.get_columns('honeypot_log')]
        # Manage op.batch_alter_table('honeypot_log', schema=None) within this scoped block.
        with op.batch_alter_table('honeypot_log', schema=None) as batch_op:
            # Handle the branch where 'headers' not in columns_hl evaluates to true.
            if 'headers' not in columns_hl:
                batch_op.add_column(sa.Column('headers', sa.Text(), nullable=True))
            # Handle the branch where 'created_at' not in columns_hl evaluates to true.
            if 'created_at' not in columns_hl:
                batch_op.add_column(sa.Column('created_at', sa.DateTime(), nullable=True))
        # Handle the branch where 'timestamp' in columns_hl evaluates to true.
        if 'timestamp' in columns_hl:
            op.execute("UPDATE honeypot_log SET created_at = timestamp WHERE created_at IS NULL AND timestamp IS NOT NULL")
        op.execute("UPDATE honeypot_log SET ip_address = '0.0.0.0' WHERE ip_address IS NULL")
        op.execute("UPDATE honeypot_log SET path = '/' WHERE path IS NULL")
        # Manage op.batch_alter_table('honeypot_log', schema=None) within this scoped block.
        with op.batch_alter_table('honeypot_log', schema=None) as batch_op:
            # Handle the branch where 'timestamp' in columns_hl evaluates to true.
            if 'timestamp' in columns_hl:
                batch_op.drop_column('timestamp')
            # Handle the branch where 'method' in columns_hl evaluates to true.
            if 'method' in columns_hl:
                batch_op.drop_column('method')
            batch_op.alter_column('ip_address', existing_type=sa.String(45), nullable=False)
            batch_op.alter_column('path', existing_type=sa.String(255), nullable=False)

    # honeypot_blocked_ip
    if 'honeypot_blocked_ip' in existing_tables:
        columns_hbi = [c['name'] for c in inspector.get_columns('honeypot_blocked_ip')]
        # Manage op.batch_alter_table('honeypot_blocked_ip', schema=N... within this scoped block.
        with op.batch_alter_table('honeypot_blocked_ip', schema=None) as batch_op:
            # Handle the branch where 'reason' not in columns_hbi evaluates to true.
            if 'reason' not in columns_hbi:
                batch_op.add_column(sa.Column('reason', sa.String(255), nullable=True))
            # Handle the branch where 'created_at' not in columns_hbi evaluates to true.
            if 'created_at' not in columns_hbi:
                batch_op.add_column(sa.Column('created_at', sa.DateTime(), nullable=True))
        # Handle the branch where 'blocked_at' in columns_hbi evaluates to true.
        if 'blocked_at' in columns_hbi:
            op.execute("UPDATE honeypot_blocked_ip SET created_at = blocked_at WHERE created_at IS NULL AND blocked_at IS NOT NULL")
        op.execute("DELETE FROM honeypot_blocked_ip WHERE ip_address IS NULL")
        # Manage op.batch_alter_table('honeypot_blocked_ip', schema=N... within this scoped block.
        with op.batch_alter_table('honeypot_blocked_ip', schema=None) as batch_op:
            # Handle the branch where 'blocked_at' in columns_hbi evaluates to true.
            if 'blocked_at' in columns_hbi:
                batch_op.drop_column('blocked_at')
            # Handle the branch where 'expires_at' in columns_hbi evaluates to true.
            if 'expires_at' in columns_hbi:
                batch_op.drop_column('expires_at')
            batch_op.alter_column('ip_address', existing_type=sa.String(45), nullable=False)

    # security_anomaly nullability
    if 'security_anomaly' in existing_tables:
        op.execute("UPDATE security_anomaly SET anomaly_type = 'rogue_device' WHERE anomaly_type IS NULL")
        op.execute("UPDATE security_anomaly SET ip_address = '0.0.0.0' WHERE ip_address IS NULL")
        op.execute("UPDATE security_anomaly SET description = 'Legacy anomaly record' WHERE description IS NULL")
        # Manage op.batch_alter_table('security_anomaly', schema=None) within this scoped block.
        with op.batch_alter_table('security_anomaly', schema=None) as batch_op:
            batch_op.alter_column('anomaly_type', existing_type=sa.String(50), nullable=False)
            batch_op.alter_column('ip_address', existing_type=sa.String(45), nullable=False)
            batch_op.alter_column('description', existing_type=sa.Text(), nullable=False)

    # asset nullability
    if 'asset' in existing_tables:
        op.execute("UPDATE asset SET ip_assignment_type = 'DHCP' WHERE ip_assignment_type IS NULL")
        # Manage op.batch_alter_table('asset', schema=None) within this scoped block.
        with op.batch_alter_table('asset', schema=None) as batch_op:
            batch_op.alter_column('ip_assignment_type', existing_type=sa.String(20), nullable=False)

    # scan_schedule nullability
    if 'scan_schedule' in existing_tables:
        op.execute("UPDATE scan_schedule SET next_run = CURRENT_TIMESTAMP WHERE next_run IS NULL")
        # Manage op.batch_alter_table('scan_schedule', schema=None) within this scoped block.
        with op.batch_alter_table('scan_schedule', schema=None) as batch_op:
            batch_op.alter_column('next_run', existing_type=sa.DateTime(), nullable=False)


# Handle the downgrade operation.
def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    # Handle the branch where 'scan_schedule' in existing_tables evaluates to true.
    if 'scan_schedule' in existing_tables:
        # Manage op.batch_alter_table('scan_schedule', schema=None) within this scoped block.
        with op.batch_alter_table('scan_schedule', schema=None) as batch_op:
            batch_op.alter_column('next_run', existing_type=sa.DateTime(), nullable=True)

    # Handle the branch where 'asset' in existing_tables evaluates to true.
    if 'asset' in existing_tables:
        # Manage op.batch_alter_table('asset', schema=None) within this scoped block.
        with op.batch_alter_table('asset', schema=None) as batch_op:
            batch_op.alter_column('ip_assignment_type', existing_type=sa.String(20), nullable=True)

    # Handle the branch where 'security_anomaly' in existing_tables evaluates to true.
    if 'security_anomaly' in existing_tables:
        # Manage op.batch_alter_table('security_anomaly', schema=None) within this scoped block.
        with op.batch_alter_table('security_anomaly', schema=None) as batch_op:
            batch_op.alter_column('description', existing_type=sa.Text(), nullable=True)
            batch_op.alter_column('ip_address', existing_type=sa.String(45), nullable=True)
            batch_op.alter_column('anomaly_type', existing_type=sa.String(50), nullable=True)

    # Handle the branch where 'honeypot_blocked_ip' in existing_tables evaluates to true.
    if 'honeypot_blocked_ip' in existing_tables:
        columns_hbi = [c['name'] for c in inspector.get_columns('honeypot_blocked_ip')]
        # Manage op.batch_alter_table('honeypot_blocked_ip', schema=N... within this scoped block.
        with op.batch_alter_table('honeypot_blocked_ip', schema=None) as batch_op:
            batch_op.alter_column('ip_address', existing_type=sa.String(45), nullable=True)
            # Handle the branch where 'created_at' in columns_hbi evaluates to true.
            if 'created_at' in columns_hbi:
                batch_op.drop_column('created_at')
            # Handle the branch where 'reason' in columns_hbi evaluates to true.
            if 'reason' in columns_hbi:
                batch_op.drop_column('reason')
            batch_op.add_column(sa.Column('expires_at', sa.DateTime(), nullable=True))
            batch_op.add_column(sa.Column('blocked_at', sa.DateTime(), nullable=True))

    # Handle the branch where 'honeypot_log' in existing_tables evaluates to true.
    if 'honeypot_log' in existing_tables:
        columns_hl = [c['name'] for c in inspector.get_columns('honeypot_log')]
        # Manage op.batch_alter_table('honeypot_log', schema=None) within this scoped block.
        with op.batch_alter_table('honeypot_log', schema=None) as batch_op:
            batch_op.alter_column('path', existing_type=sa.String(255), nullable=True)
            batch_op.alter_column('ip_address', existing_type=sa.String(45), nullable=True)
            # Handle the branch where 'created_at' in columns_hl evaluates to true.
            if 'created_at' in columns_hl:
                batch_op.drop_column('created_at')
            # Handle the branch where 'headers' in columns_hl evaluates to true.
            if 'headers' in columns_hl:
                batch_op.drop_column('headers')
            batch_op.add_column(sa.Column('timestamp', sa.DateTime(), nullable=True))
            batch_op.add_column(sa.Column('method', sa.String(10), nullable=True))
