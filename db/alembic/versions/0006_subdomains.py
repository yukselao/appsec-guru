"""subdomain discovery runs (subfinder -> dnsx -> httpx)

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-11
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "subdomain_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("stage", sa.String(20)),
        sa.Column("error", sa.Text()),
        sa.Column("options", JSONB(), nullable=False, server_default="{}"),
        sa.Column("subdomains", JSONB(), nullable=False, server_default="[]"),
        sa.Column("results", JSONB(), nullable=False, server_default="[]"),
        sa.Column("stats", JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.PrimaryKeyConstraint("id", name="pk_subdomain_runs"),
    )


def downgrade():
    op.drop_table("subdomain_runs")
