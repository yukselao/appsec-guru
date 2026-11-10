"""sast: runs, extracted functions, findings, events

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-11
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "sast_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("repo_url", sa.Text(), nullable=False),
        sa.Column("ref", sa.String(200)),
        sa.Column("commit", sa.String(64)),
        sa.Column("status", sa.String(30), nullable=False, server_default="pending"),
        sa.Column("model", sa.String(100)),
        sa.Column("options", JSONB(), nullable=False, server_default="{}"),
        sa.Column("stats", JSONB(), nullable=False, server_default="{}"),
        sa.Column("error", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.PrimaryKeyConstraint("id", name="pk_sast_runs"),
    )
    op.create_table(
        "sast_functions",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("run_id", sa.Integer(), sa.ForeignKey("sast_runs.id", ondelete="CASCADE",
                                                         name="fk_sast_functions_run_id_sast_runs"), nullable=False),
        sa.Column("file", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("language", sa.String(20)),
        sa.Column("start_line", sa.Integer()),
        sa.Column("end_line", sa.Integer()),
        sa.Column("params", JSONB(), nullable=False, server_default="[]"),
        sa.Column("sinks", JSONB(), nullable=False, server_default="[]"),
        sa.Column("route", sa.Text()),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(20), nullable=False, server_default="extracted"),
        sa.Column("verdict", sa.String(20)),
        sa.Column("summary", sa.Text()),
        sa.Column("agent_stats", JSONB()),
        sa.PrimaryKeyConstraint("id", name="pk_sast_functions"),
    )
    op.create_index("ix_sast_functions_run_id", "sast_functions", ["run_id"])
    op.create_table(
        "sast_findings",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("run_id", sa.Integer(), sa.ForeignKey("sast_runs.id", ondelete="CASCADE",
                                                         name="fk_sast_findings_run_id_sast_runs"), nullable=False),
        sa.Column("function_id", sa.BigInteger(), sa.ForeignKey("sast_functions.id", ondelete="SET NULL",
                                                                 name="fk_sast_findings_function_id_sast_functions")),
        sa.Column("file", sa.Text(), nullable=False),
        sa.Column("line", sa.Integer()),
        sa.Column("function", sa.Text()),
        sa.Column("parameter", sa.Text()),
        sa.Column("cwe", sa.String(20)),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("confidence", sa.String(10), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("evidence", sa.Text()),
        sa.Column("recommendation", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_sast_findings"),
    )
    op.create_index("ix_sast_findings_run_id", "sast_findings", ["run_id"])
    op.create_table(
        "sast_events",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("run_id", sa.Integer(), sa.ForeignKey("sast_runs.id", ondelete="CASCADE",
                                                         name="fk_sast_events_run_id_sast_runs"), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("level", sa.String(10), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_sast_events"),
    )
    op.create_index("ix_sast_events_run_id", "sast_events", ["run_id"])


def downgrade():
    op.drop_table("sast_events")
    op.drop_table("sast_findings")
    op.drop_table("sast_functions")
    op.drop_table("sast_runs")
