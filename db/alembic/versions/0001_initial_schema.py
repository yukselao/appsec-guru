"""initial schema: settings, scan runs, events, log stats, audit, chat

Revision ID: 0001
Revises:
Create Date: 2026-11-11
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "settings",
        sa.Column("key", sa.String(100), primary_key=True),
        sa.Column("value", sa.Text()),
        sa.Column("secret_value", sa.LargeBinary()),
        sa.Column("is_secret", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("key", name="pk_settings"),
    )
    op.create_table(
        "scan_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("target_url", sa.Text(), nullable=False),
        sa.Column("source_policy_id", sa.String(20)),
        sa.Column("derived_policy_id", sa.String(20)),
        sa.Column("families", JSONB(), nullable=False, server_default="[]"),
        sa.Column("fast", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("debug_mode", sa.String(10), nullable=False, server_default="none"),
        sa.Column("keep_objects", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("sc_scan_id", sa.String(20)),
        sa.Column("sc_result_id", sa.String(20)),
        sa.Column("scan_uuid", sa.String(40)),
        sa.Column("status", sa.String(30), nullable=False, server_default="pending"),
        sa.Column("error", sa.Text()),
        sa.Column("log_file", sa.Text()),
        sa.Column("log_counts", JSONB(), nullable=False, server_default="{}"),
        sa.Column("findings", JSONB(), nullable=False, server_default="[]"),
        sa.Column("summary", JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.PrimaryKeyConstraint("id", name="pk_scan_runs"),
    )
    op.create_index("ix_scan_runs_sc_result_id", "scan_runs", ["sc_result_id"])
    op.create_index("ix_scan_runs_scan_uuid", "scan_runs", ["scan_uuid"])
    op.create_table(
        "scan_run_events",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("run_id", sa.Integer(), sa.ForeignKey("scan_runs.id", ondelete="CASCADE",
                                                         name="fk_scan_run_events_run_id_scan_runs"), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("level", sa.String(10), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_scan_run_events"),
    )
    op.create_index("ix_scan_run_events_run_id", "scan_run_events", ["run_id"])
    op.create_table(
        "scan_log_stats",
        sa.Column("run_id", sa.Integer(), sa.ForeignKey("scan_runs.id", ondelete="CASCADE",
                                                         name="fk_scan_log_stats_run_id_scan_runs"), nullable=False),
        sa.Column("minute", sa.DateTime(timezone=True), nullable=False),
        sa.Column("debug", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("info", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("notice", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("warn", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("pages_audited", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("plugins_started", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("urls_found", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("req_per_sec", sa.Numeric(8, 2)),
        sa.PrimaryKeyConstraint("run_id", "minute", name="pk_scan_log_stats"),
    )
    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("action", sa.String(60), nullable=False),
        sa.Column("details", JSONB(), nullable=False, server_default="{}"),
        sa.Column("client_ip", sa.String(64)),
        sa.PrimaryKeyConstraint("id", name="pk_audit_log"),
    )
    op.create_index("ix_audit_log_ts", "audit_log", ["ts"])
    op.create_table(
        "chat_messages",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("session", sa.String(40), nullable=False),
        sa.Column("role", sa.String(12), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("model", sa.String(100)),
        sa.Column("stats", JSONB()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_chat_messages"),
    )
    op.create_index("ix_chat_messages_session", "chat_messages", ["session"])


def downgrade():
    op.drop_table("chat_messages")
    op.drop_table("audit_log")
    op.drop_table("scan_log_stats")
    op.drop_table("scan_run_events")
    op.drop_table("scan_runs")
    op.drop_table("settings")
