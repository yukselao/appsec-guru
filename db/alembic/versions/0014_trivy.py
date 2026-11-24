"""trivy scans (container image security)

Revision ID: 0014
Revises: 0013
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "trivy_scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("digest", sa.String(120)),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("error", sa.Text()),
        sa.Column("options", JSONB(), nullable=False, server_default="{}"),
        sa.Column("results", JSONB(), nullable=False, server_default="{}"),
        sa.Column("stats", JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.PrimaryKeyConstraint("id", name="pk_trivy_scans"),
    )


def downgrade():
    op.drop_table("trivy_scans")
