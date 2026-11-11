"""scan profile: SC wizard fields (credentials, reports, scan-time, inactivity, remove-unresponsive)

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-11
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("scan_profiles", sa.Column("credential_ids", JSONB(), nullable=False, server_default="[]"))
    op.add_column("scan_profiles", sa.Column("report_ids", JSONB(), nullable=False, server_default="[]"))
    op.add_column("scan_profiles", sa.Column("max_scan_time", sa.String(16), nullable=False, server_default="unlimited"))
    op.add_column("scan_profiles", sa.Column("inactivity_hours", sa.Integer(), nullable=False, server_default="12"))
    op.add_column("scan_profiles", sa.Column("remove_unresponsive", sa.Boolean(), nullable=False, server_default="true"))


def downgrade():
    op.drop_column("scan_profiles", "remove_unresponsive")
    op.drop_column("scan_profiles", "inactivity_hours")
    op.drop_column("scan_profiles", "max_scan_time")
    op.drop_column("scan_profiles", "report_ids")
    op.drop_column("scan_profiles", "credential_ids")
