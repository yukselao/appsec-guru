"""fuzz: Hidden Path Discovery (ffuf) runs

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-11
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "fuzz_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_url", sa.Text(), nullable=False),
        sa.Column("wordlist", sa.String(300), nullable=False),
        sa.Column("extensions", sa.String(300)),
        sa.Column("methods", sa.String(100), nullable=False, server_default="GET"),
        sa.Column("match_codes", sa.String(200), nullable=False, server_default="200,204,301,302,307,401,403,405,500"),
        sa.Column("filter_codes", sa.String(200)),
        sa.Column("threads", sa.Integer(), nullable=False, server_default="40"),
        sa.Column("rate", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("extra_headers", JSONB(), nullable=False, server_default="[]"),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("error", sa.Text()),
        sa.Column("total_words", sa.Integer()),
        sa.Column("hits", JSONB(), nullable=False, server_default="[]"),
        sa.Column("stats", JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.PrimaryKeyConstraint("id", name="pk_fuzz_runs"),
    )


def downgrade():
    op.drop_table("fuzz_runs")
