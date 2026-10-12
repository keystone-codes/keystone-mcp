"""Service account tables.

Revision ID: 0002_service_accounts
Revises: 0001_initial
Create Date: 2026-01-02

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_service_accounts"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "keystone_service_account",
        sa.Column("name", sa.String(length=63), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_blocked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_by", sa.String(length=330), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("name"),
    )
    op.create_table(
        "keystone_service_account_role",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=63), nullable=False),
        sa.Column("role", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(
            ["name"],
            ["keystone_service_account.name"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", "role", name="uq_keystone_service_account_role"),
    )
    op.create_index(
        "ix_keystone_service_account_role_name",
        "keystone_service_account_role",
        ["name"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_keystone_service_account_role_name",
        table_name="keystone_service_account_role",
    )
    op.drop_table("keystone_service_account_role")
    op.drop_table("keystone_service_account")
