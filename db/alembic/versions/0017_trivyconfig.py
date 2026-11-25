"""trivy config / IaC misconfiguration scans

Revision ID: 0017
Revises: 0016
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "trivyconfig_scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("kind", sa.String(40)),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("error", sa.Text()),
        sa.Column("options", JSONB(), nullable=False, server_default="{}"),
        sa.Column("results", JSONB(), nullable=False, server_default="{}"),
        sa.Column("stats", JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.PrimaryKeyConstraint("id", name="pk_trivyconfig_scans"),
    )


def downgrade():
    op.drop_table("trivyconfig_scans")
