"""Identity provider binding columns on keystone_user.

Revision ID: 0004_identity_binding
Revises: 0003_api_keys
Create Date: 2026-10-14

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_identity_binding"
down_revision: str | None = "0003_api_keys"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("keystone_user", sa.Column("idp_issuer", sa.String(length=512), nullable=True))
    op.add_column("keystone_user", sa.Column("idp_subject", sa.String(length=255), nullable=True))
    op.add_column(
        "keystone_user",
        sa.Column("idp_bound_at", sa.DateTime(timezone=True), nullable=True),
    )
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("keystone_user") as batch_op:
            batch_op.create_unique_constraint(
                "uq_keystone_user_idp",
                ["idp_issuer", "idp_subject"],
            )
    else:
        op.create_unique_constraint(
            "uq_keystone_user_idp",
            "keystone_user",
            ["idp_issuer", "idp_subject"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("keystone_user") as batch_op:
            batch_op.drop_constraint("uq_keystone_user_idp", type_="unique")
    else:
        op.drop_constraint("uq_keystone_user_idp", "keystone_user", type_="unique")
    op.drop_column("keystone_user", "idp_bound_at")
    op.drop_column("keystone_user", "idp_subject")
    op.drop_column("keystone_user", "idp_issuer")
