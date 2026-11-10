"""port scan runs (RustScan)

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-11
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "port_scan_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column("ports", sa.String(200)),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("error", sa.Text()),
        sa.Column("options", JSONB(), nullable=False, server_default="{}"),
        sa.Column("results", JSONB(), nullable=False, server_default="[]"),
        sa.Column("stats", JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.PrimaryKeyConstraint("id", name="pk_port_scan_runs"),
    )


def downgrade():
    op.drop_table("port_scan_runs")
