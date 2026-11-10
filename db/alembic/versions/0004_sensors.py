"""sensors: several WAS scanner hosts; profiles and runs reference one

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-11
"""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "sensors",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False, server_default="22"),
        sa.Column("username", sa.String(100), nullable=False, server_default="osadmin"),
        sa.Column("password_enc", sa.LargeBinary()),
        sa.Column("key_path", sa.Text()),
        sa.Column("jump_host", sa.String(255)),
        sa.Column("jump_user", sa.String(100)),
        sa.Column("jump_password_enc", sa.LargeBinary()),
        sa.Column("log_path", sa.Text(), nullable=False, server_default="/var/log/nessus-was/scanner.log"),
        sa.Column("sc_scanner_name", sa.String(200)),
        sa.Column("zone_id", sa.Integer()),
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_sensors"),
        sa.UniqueConstraint("name", name="uq_sensors_name"),
    )
    for table in ("scan_runs", "scan_profiles"):
        op.add_column(table, sa.Column("sensor_id", sa.Integer(), sa.ForeignKey(
            "sensors.id", ondelete="SET NULL", name="fk_{}_sensor_id_sensors".format(table))))
        op.create_index("ix_{}_sensor_id".format(table), table, ["sensor_id"])


def downgrade():
    for table in ("scan_profiles", "scan_runs"):
        op.drop_index("ix_{}_sensor_id".format(table), table)
        op.drop_column(table, "sensor_id")
    op.drop_table("sensors")
