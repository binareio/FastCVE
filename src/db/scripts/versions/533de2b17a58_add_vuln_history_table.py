"""add vuln_history table

Revision ID: 533de2b17a58
Revises: ecd29e77afe3
Create Date: 2026-01-25 13:16:32.698376

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql



# revision identifiers, used by Alembic.
revision = '533de2b17a58'
down_revision = 'ecd29e77afe3'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "vuln_history",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("vuln_id", sa.String(length=20), nullable=False),
        sa.Column("change_id", sa.String(length=64), nullable=False),
        sa.Column("event_name", sa.String(length=64)),
        sa.Column("source", sa.String(length=100)),
        sa.Column("change_date", sa.DateTime(timezone=True)),
        sa.Column("data", postgresql.JSONB(), nullable=False),
        sa.Column(
            "sys_creation_date",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )

    op.create_index("ix_vuln_history_vuln_id", "vuln_history", ["vuln_id"])
    op.create_index("ix_vuln_history_change_id", "vuln_history", ["change_id"], unique=True)
    op.create_index("ix_vuln_history_event_name", "vuln_history", ["event_name"])
    op.create_index("ix_vuln_history_change_date", "vuln_history", ["change_date"])

    op.create_index(
        "ix_vuln_history_data_gin",
        "vuln_history",
        ["data"],
        postgresql_using="gin",
    )

def downgrade():
    op.drop_index("ix_vuln_history_data_gin", table_name="vuln_history")
    op.drop_index("ix_vuln_history_change_date", table_name="vuln_history")
    op.drop_index("ix_vuln_history_event_name", table_name="vuln_history")
    op.drop_index("ix_vuln_history_change_id", table_name="vuln_history")
    op.drop_index("ix_vuln_history_vuln_id", table_name="vuln_history")
    op.drop_table("vuln_history")

