"""finalize security migration fixes

Revision ID: c7e9d2f4a681
Revises: b5a93e3d9370
Create Date: 2026-07-12 23:30:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = "c7e9d2f4a681"
down_revision = "b5a93e3d9370"
branch_labels = None
depends_on = None


def _column_names(inspector, table_name):
    return {column["name"] for column in inspector.get_columns(table_name)}


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "honeypot_log" in tables:
        columns = _column_names(inspector, "honeypot_log")
        with op.batch_alter_table("honeypot_log") as batch_op:
            if "headers" not in columns:
                batch_op.add_column(sa.Column("headers", sa.Text(), nullable=True))
            if "created_at" not in columns:
                batch_op.add_column(sa.Column("created_at", sa.DateTime(), nullable=True))
        if "timestamp" in columns:
            op.execute(
                "UPDATE honeypot_log SET created_at = timestamp "
                "WHERE created_at IS NULL AND timestamp IS NOT NULL"
            )
        op.execute(
            "UPDATE honeypot_log SET ip_address = '0.0.0.0' "
            "WHERE ip_address IS NULL OR TRIM(ip_address) = ''"
        )
        op.execute(
            "UPDATE honeypot_log SET path = '/' "
            "WHERE path IS NULL OR TRIM(path) = ''"
        )
        with op.batch_alter_table("honeypot_log") as batch_op:
            if "timestamp" in columns:
                batch_op.drop_column("timestamp")
            if "method" in columns:
                batch_op.drop_column("method")
            batch_op.alter_column("ip_address", existing_type=sa.String(45), nullable=False)
            batch_op.alter_column("path", existing_type=sa.String(255), nullable=False)

    if "honeypot_blocked_ip" in tables:
        columns = _column_names(inspector, "honeypot_blocked_ip")
        unique_constraints = inspector.get_unique_constraints("honeypot_blocked_ip")
        indexes = inspector.get_indexes("honeypot_blocked_ip")
        has_ip_unique = any(
            constraint.get("column_names") == ["ip_address"]
            for constraint in unique_constraints
        ) or any(
            index.get("unique") is True and index.get("column_names") == ["ip_address"]
            for index in indexes
        )
        with op.batch_alter_table("honeypot_blocked_ip") as batch_op:
            if "reason" not in columns:
                batch_op.add_column(sa.Column("reason", sa.String(255), nullable=True))
            if "created_at" not in columns:
                batch_op.add_column(sa.Column("created_at", sa.DateTime(), nullable=True))
        if "blocked_at" in columns:
            op.execute(
                "UPDATE honeypot_blocked_ip SET created_at = blocked_at "
                "WHERE created_at IS NULL AND blocked_at IS NOT NULL"
            )
        op.execute(
            "DELETE FROM honeypot_blocked_ip "
            "WHERE ip_address IS NULL OR TRIM(ip_address) = ''"
        )
        op.execute(
            "UPDATE honeypot_blocked_ip SET reason = 'Blocked by Honeypot' "
            "WHERE reason IS NULL OR TRIM(reason) = ''"
        )
        with op.batch_alter_table("honeypot_blocked_ip") as batch_op:
            if "blocked_at" in columns:
                batch_op.drop_column("blocked_at")
            if "expires_at" in columns:
                batch_op.drop_column("expires_at")
            batch_op.alter_column("ip_address", existing_type=sa.String(45), nullable=False)
            if not has_ip_unique:
                batch_op.create_unique_constraint(
                    "uq_honeypot_blocked_ip_ip_address", ["ip_address"]
                )

    if "asset" in tables:
        op.execute(
            "UPDATE asset SET ip_assignment_type = 'DHCP' "
            "WHERE ip_assignment_type IS NULL OR TRIM(ip_assignment_type) = ''"
        )
        with op.batch_alter_table("asset") as batch_op:
            batch_op.alter_column(
                "ip_assignment_type", existing_type=sa.String(20), nullable=False
            )

    if "scan_schedule" in tables:
        op.execute("UPDATE scan_schedule SET next_run = CURRENT_TIMESTAMP WHERE next_run IS NULL")
        with op.batch_alter_table("scan_schedule") as batch_op:
            batch_op.alter_column("next_run", existing_type=sa.DateTime(), nullable=False)

    if "security_anomaly" in tables:
        op.execute(
            "UPDATE security_anomaly SET anomaly_type = 'rogue_device' "
            "WHERE anomaly_type IS NULL OR TRIM(anomaly_type) = ''"
        )
        op.execute(
            "UPDATE security_anomaly SET ip_address = '0.0.0.0' "
            "WHERE ip_address IS NULL OR TRIM(ip_address) = ''"
        )
        op.execute(
            "UPDATE security_anomaly SET description = 'Legacy anomaly record' "
            "WHERE description IS NULL OR TRIM(description) = ''"
        )
        with op.batch_alter_table("security_anomaly") as batch_op:
            batch_op.alter_column("anomaly_type", existing_type=sa.String(50), nullable=False)
            batch_op.alter_column("ip_address", existing_type=sa.String(45), nullable=False)
            batch_op.alter_column("description", existing_type=sa.Text(), nullable=False)

    if "security_finding" in tables:
        op.execute(
            "UPDATE security_finding SET protocol = 'udp' "
            "WHERE (protocol IS NULL OR TRIM(protocol) = '') "
            "AND scan_id IN (SELECT id FROM scan_result WHERE scan_type = 'udp')"
        )
        op.execute(
            "UPDATE security_finding SET protocol = 'tcp' "
            "WHERE protocol IS NULL OR TRIM(protocol) = ''"
        )
        with op.batch_alter_table("security_finding") as batch_op:
            batch_op.alter_column("protocol", existing_type=sa.String(10), nullable=False)


def downgrade():
    # Data cleanup/backfill is irreversible. This revision adds nothing beyond
    # the canonical b5a93e3d9370 schema, so downgrade intentionally preserves it.
    pass
