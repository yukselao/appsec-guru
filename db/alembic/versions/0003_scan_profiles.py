"""scan profiles in a folder tree, with schedules; runs remember their profile

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-11
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "scan_folders",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("parent_id", sa.Integer(), sa.ForeignKey("scan_folders.id", ondelete="CASCADE",
                                                            name="fk_scan_folders_parent_id_scan_folders")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_scan_folders"),
    )
    op.create_index("ix_scan_folders_parent_id", "scan_folders", ["parent_id"])
    op.create_table(
        "scan_profiles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("folder_id", sa.Integer(), sa.ForeignKey("scan_folders.id", ondelete="SET NULL",
                                                            name="fk_scan_profiles_folder_id_scan_folders")),
        sa.Column("target_url", sa.Text(), nullable=False),
        sa.Column("source_policy_id", sa.String(20), nullable=False),
        sa.Column("families", JSONB(), nullable=False, server_default="[]"),
        sa.Column("debug_mode", sa.String(10), nullable=False, server_default="none"),
        sa.Column("scope", sa.String(10), nullable=False, server_default="fast"),
        sa.Column("prefs", JSONB(), nullable=False, server_default="[]"),
        sa.Column("keep_objects", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("repo_id", sa.Integer()),
        sa.Column("zone_id", sa.Integer()),
        sa.Column("schedule", JSONB(), nullable=False, server_default='{"type": "on_demand"}'),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("next_run_at", sa.DateTime(timezone=True)),
        sa.Column("last_run_at", sa.DateTime(timezone=True)),
        sa.Column("last_run_id", sa.Integer()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_scan_profiles"),
    )
    op.create_index("ix_scan_profiles_folder_id", "scan_profiles", ["folder_id"])
    op.create_index("ix_scan_profiles_next_run_at", "scan_profiles", ["next_run_at"])
    op.add_column("scan_runs", sa.Column("profile_id", sa.Integer(), sa.ForeignKey(
        "scan_profiles.id", ondelete="SET NULL", name="fk_scan_runs_profile_id_scan_profiles")))
    op.add_column("scan_runs", sa.Column("trigger", sa.String(20), nullable=False, server_default="manual"))
    op.create_index("ix_scan_runs_profile_id", "scan_runs", ["profile_id"])


def downgrade():
    op.drop_index("ix_scan_runs_profile_id", "scan_runs")
    op.drop_column("scan_runs", "trigger")
    op.drop_column("scan_runs", "profile_id")
    op.drop_table("scan_profiles")
    op.drop_table("scan_folders")
