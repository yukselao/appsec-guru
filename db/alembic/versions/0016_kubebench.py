"""kube-bench CIS scans

Revision ID: 0016
Revises: 0015
Create Date: 2026-11-25
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "kubebench_scans",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("benchmark", sa.String(length=40), nullable=False),
        sa.Column("targets", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=20), server_default="pending", nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("results", JSONB(), server_default="{}", nullable=False),
        sa.Column("stats", JSONB(), server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_kubebench_scans"),
    )


def downgrade():
    op.drop_table("kubebench_scans")
