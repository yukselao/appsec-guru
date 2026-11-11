"""rename scan_profiles -> tenable_was_scans

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-11

The saved scan definition is a Tenable WAS scan; rename the table to match.
Postgres carries the foreign key from scan_runs.profile_id across the rename.
"""
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade():
    op.rename_table("scan_profiles", "tenable_was_scans")


def downgrade():
    op.rename_table("tenable_was_scans", "scan_profiles")
