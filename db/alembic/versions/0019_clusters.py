"""kubernetes cluster registration + cluster scans

Revision ID: 0019
Revises: 0018
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "clusters",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("server", sa.Text()),
        sa.Column("context", sa.Text()),
        sa.Column("kubeconfig_enc", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_clusters"),
    )
    op.create_table(
        "cluster_scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cluster_id", sa.Integer(), sa.ForeignKey("clusters.id", ondelete="SET NULL")),
        sa.Column("cluster_name", sa.Text()),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("error", sa.Text()),
        sa.Column("options", JSONB(), nullable=False, server_default="{}"),
        sa.Column("results", JSONB(), nullable=False, server_default="{}"),
        sa.Column("stats", JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.PrimaryKeyConstraint("id", name="pk_cluster_scans"),
    )


def downgrade():
    op.drop_table("cluster_scans")
    op.drop_table("clusters")
