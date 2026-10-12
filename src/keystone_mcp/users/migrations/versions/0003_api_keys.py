"""API key table.

Revision ID: 0003_api_keys
Revises: 0002_service_accounts
Create Date: 2026-01-02

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_api_keys"
down_revision: str | None = "0002_service_accounts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "keystone_api_key",
        sa.Column("key_id", sa.String(length=12), nullable=False),
        sa.Column("subject", sa.String(length=330), nullable=False),
        sa.Column("secret_hash", sa.String(length=64), nullable=False),
        sa.Column("label", sa.String(length=255), nullable=True),
        sa.Column("created_by", sa.String(length=330), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(length=330), nullable=True),
        sa.PrimaryKeyConstraint("key_id"),
    )
    op.create_index("ix_keystone_api_key_subject", "keystone_api_key", ["subject"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_keystone_api_key_subject", table_name="keystone_api_key")
    op.drop_table("keystone_api_key")
