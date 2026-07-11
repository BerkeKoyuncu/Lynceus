"""baseline_full_schema

Creates all Lynceus tables from scratch.
- On a fresh database (PostgreSQL or SQLite): flask db upgrade
- On an existing database that was managed by db.create_all(): flask db stamp 4b1d0851377a

Revision ID: 4b1d0851377a
Revises:
Create Date: 2026-07-11 21:03:43
"""
from alembic import op
import sqlalchemy as sa

revision = '4b1d0851377a'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    # ── user ────────────────────────────────────────────────────────────────
    if 'user' not in existing_tables:
        op.create_table(
            'user',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('email', sa.String(120), nullable=False),
            sa.Column('password_hash', sa.String(255), nullable=False),
            sa.Column('is_admin', sa.Boolean(), nullable=True, default=False),
            sa.Column('otp_secret', sa.String(255), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('email'),
        )

    # ── scan_result ─────────────────────────────────────────────────────────
    if 'scan_result' not in existing_tables:
        op.create_table(
            'scan_result',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('user_id', sa.Integer(), nullable=False),
            sa.Column('input_ip', sa.String(45), nullable=False),
            sa.Column('subnet_mask', sa.String(45), nullable=False),
            sa.Column('scan_type', sa.String(20), nullable=False),
            sa.Column('ports', sa.String(100), nullable=True),
            sa.Column('network_cidr', sa.String(50), nullable=False),
            sa.Column('first_host', sa.String(45), nullable=True),
            sa.Column('last_host', sa.String(45), nullable=True),
            sa.Column('status', sa.String(20), nullable=True),
            sa.Column('exclude_targets', sa.Text(), nullable=True),
            sa.Column('credential_ids', sa.Text(), nullable=True),
            sa.Column('timing_template', sa.String(2), nullable=True),
            sa.Column('audit_credentials', sa.Boolean(), nullable=True),
            sa.Column('result_data', sa.Text(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('id'),
        )

    # ── scan_schedule ───────────────────────────────────────────────────────
    if 'scan_schedule' not in existing_tables:
        op.create_table(
            'scan_schedule',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('user_id', sa.Integer(), nullable=False),
            sa.Column('name', sa.String(100), nullable=False),
            sa.Column('input_ip', sa.String(45), nullable=False),
            sa.Column('subnet_mask', sa.String(45), nullable=False),
            sa.Column('scan_type', sa.String(20), nullable=False),
            sa.Column('ports', sa.String(100), nullable=True),
            sa.Column('network_cidr', sa.String(50), nullable=False),
            sa.Column('frequency', sa.String(20), nullable=False),
            sa.Column('next_run', sa.DateTime(), nullable=True),
            sa.Column('last_run', sa.DateTime(), nullable=True),
            sa.Column('is_active', sa.Boolean(), nullable=True),
            sa.Column('exclude_targets', sa.Text(), nullable=True),
            sa.Column('credential_ids', sa.Text(), nullable=True),
            sa.Column('timing_template', sa.String(2), nullable=True),
            sa.Column('audit_credentials', sa.Boolean(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('id'),
        )

    # ── system_setting ──────────────────────────────────────────────────────
    if 'system_setting' not in existing_tables:
        op.create_table(
            'system_setting',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('user_id', sa.Integer(), nullable=False),
            sa.Column('smtp_server', sa.String(100), nullable=True),
            sa.Column('smtp_port', sa.Integer(), nullable=True),
            sa.Column('smtp_username', sa.String(100), nullable=True),
            sa.Column('smtp_password', sa.String(255), nullable=True),
            sa.Column('smtp_sender', sa.String(100), nullable=True),
            sa.Column('alert_recipient', sa.String(100), nullable=True),
            sa.Column('honeypot_enabled', sa.Boolean(), nullable=True),
            sa.Column('honeypot_auto_block', sa.Boolean(), nullable=True),
            sa.Column('honeypot_block_duration', sa.Integer(), nullable=True),
            sa.Column('scan_freeze_active', sa.Boolean(), nullable=True),
            sa.Column('scan_freeze_start', sa.String(10), nullable=True),
            sa.Column('scan_freeze_end', sa.String(10), nullable=True),
            sa.Column('honeypot_whitelist', sa.Text(), nullable=True),
            sa.Column('nmap_exclude_targets', sa.Text(), nullable=True),
            sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('user_id'),
        )

    # ── scan_credential ─────────────────────────────────────────────────────
    if 'scan_credential' not in existing_tables:
        op.create_table(
            'scan_credential',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('user_id', sa.Integer(), nullable=False),
            sa.Column('name', sa.String(100), nullable=False),
            sa.Column('username', sa.String(255), nullable=True),
            sa.Column('password', sa.String(255), nullable=True),
            sa.Column('protocol', sa.String(20), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('id'),
        )

    # ── asset ────────────────────────────────────────────────────────────────
    if 'asset' not in existing_tables:
        op.create_table(
            'asset',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('name', sa.String(100), nullable=True),
            sa.Column('ip_address', sa.String(45), nullable=True),
            sa.Column('mac_address', sa.String(45), nullable=True),
            sa.Column('mac_vendor', sa.String(100), nullable=True),
            sa.Column('device_type', sa.String(50), nullable=True),
            sa.Column('operating_system', sa.String(100), nullable=True),
            sa.Column('criticality', sa.String(20), nullable=True),
            sa.Column('ip_assignment_type', sa.String(20), nullable=True),
            sa.Column('owner', sa.String(100), nullable=True),
            sa.Column('location', sa.String(100), nullable=True),
            sa.Column('notes', sa.Text(), nullable=True),
            sa.Column('serial_number', sa.String(100), nullable=True),
            sa.Column('is_trusted', sa.Boolean(), nullable=True),
            sa.Column('last_seen', sa.DateTime(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint('id'),
        )

    # ── security_anomaly ────────────────────────────────────────────────────
    if 'security_anomaly' not in existing_tables:
        op.create_table(
            'security_anomaly',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('anomaly_type', sa.String(50), nullable=True),
            sa.Column('ip_address', sa.String(45), nullable=True),
            sa.Column('mac_address', sa.String(45), nullable=True),
            sa.Column('description', sa.Text(), nullable=True),
            sa.Column('confidence_score', sa.String(20), nullable=True),
            sa.Column('resolved', sa.Boolean(), nullable=True, default=False),
            sa.Column('detected_at', sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint('id'),
        )

    # ── honeypot_log ─────────────────────────────────────────────────────────
    if 'honeypot_log' not in existing_tables:
        op.create_table(
            'honeypot_log',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('ip_address', sa.String(45), nullable=True),
            sa.Column('path', sa.String(255), nullable=True),
            sa.Column('method', sa.String(10), nullable=True),
            sa.Column('user_agent', sa.Text(), nullable=True),
            sa.Column('timestamp', sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint('id'),
        )

    # ── honeypot_blocked_ip ──────────────────────────────────────────────────
    if 'honeypot_blocked_ip' not in existing_tables:
        op.create_table(
            'honeypot_blocked_ip',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('ip_address', sa.String(45), nullable=True),
            sa.Column('blocked_at', sa.DateTime(), nullable=True),
            sa.Column('expires_at', sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('ip_address'),
        )

    # ── security_rule ────────────────────────────────────────────────────────
    if 'security_rule' not in existing_tables:
        op.create_table(
            'security_rule',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('user_id', sa.Integer(), nullable=False),
            sa.Column('name', sa.String(100), nullable=False),
            sa.Column('severity', sa.String(20), nullable=True),
            sa.Column('scope', sa.String(100), nullable=True),
            sa.Column('port_service_condition', sa.String(255), nullable=True),
            sa.Column('asset_criticality_condition', sa.String(50), nullable=True),
            sa.Column('exception_list', sa.Text(), nullable=True),
            sa.Column('remediation_text', sa.Text(), nullable=True),
            sa.Column('enabled', sa.Boolean(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('id'),
        )

    # ── security_finding ─────────────────────────────────────────────────────
    if 'security_finding' not in existing_tables:
        op.create_table(
            'security_finding',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('asset_id', sa.Integer(), nullable=True),
            sa.Column('ip_address', sa.String(45), nullable=False),
            sa.Column('port', sa.Integer(), nullable=False),
            sa.Column('service', sa.String(50), nullable=True),
            sa.Column('version', sa.String(100), nullable=True),
            sa.Column('cve', sa.String(50), nullable=True),
            sa.Column('cvss', sa.Float(), nullable=True),
            sa.Column('severity', sa.String(20), nullable=True),
            sa.Column('evidence', sa.Text(), nullable=True),
            sa.Column('first_seen', sa.DateTime(), nullable=True),
            sa.Column('last_seen', sa.DateTime(), nullable=True),
            sa.Column('status', sa.String(20), nullable=True),
            sa.Column('assigned_user_id', sa.Integer(), nullable=True),
            sa.Column('due_date', sa.DateTime(), nullable=True),
            sa.Column('remediation_note', sa.Text(), nullable=True),
            sa.Column('source_type', sa.String(50), nullable=True),
            sa.Column('source_rule_id', sa.Integer(), nullable=True),
            sa.Column('scan_id', sa.Integer(), nullable=True),
            sa.Column('fingerprint', sa.String(64), nullable=True),
            sa.Column('acceptance_expiry', sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(['asset_id'], ['asset.id'], ondelete='CASCADE'),
            sa.ForeignKeyConstraint(['assigned_user_id'], ['user.id'], ondelete='SET NULL'),
            sa.ForeignKeyConstraint(['scan_id'], ['scan_result.id'], ondelete='SET NULL'),
            sa.PrimaryKeyConstraint('id'),
        )

    # ── asset_observation ─────────────────────────────────────────────────────
    if 'asset_observation' not in existing_tables:
        op.create_table(
            'asset_observation',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('asset_id', sa.Integer(), nullable=False),
            sa.Column('scan_id', sa.Integer(), nullable=False),
            sa.Column('ip_address', sa.String(45), nullable=False),
            sa.Column('mac_address', sa.String(45), nullable=True),
            sa.Column('hostname', sa.String(100), nullable=True),
            sa.Column('vendor', sa.String(100), nullable=True),
            sa.Column('operating_system', sa.String(100), nullable=True),
            sa.Column('open_ports_hash', sa.String(64), nullable=True),
            sa.Column('observed_at', sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(['asset_id'], ['asset.id'], ondelete='CASCADE'),
            sa.ForeignKeyConstraint(['scan_id'], ['scan_result.id'], ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('id'),
        )


def downgrade():
    # Drop in reverse dependency order
    op.drop_table('asset_observation')
    op.drop_table('security_finding')
    op.drop_table('security_rule')
    op.drop_table('honeypot_blocked_ip')
    op.drop_table('honeypot_log')
    op.drop_table('security_anomaly')
    op.drop_table('asset')
    op.drop_table('scan_credential')
    op.drop_table('system_setting')
    op.drop_table('scan_schedule')
    op.drop_table('scan_result')
    op.drop_table('user')
