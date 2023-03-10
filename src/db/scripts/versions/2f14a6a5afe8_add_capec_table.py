"""Add CAPEC table

Revision ID: 2f14a6a5afe8
Revises: c1f79cef457f
Create Date: 2023-03-01 17:35:13.831936

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '2f14a6a5afe8'
down_revision = 'c1f79cef457f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('capec',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('capec_id', sa.Integer(), nullable=False, comment='The ID of the CAPEC'),
    sa.Column('name', sa.String(length=256), nullable=False, comment='the name of the CAPEC'),
    sa.Column('status', sa.String(length=128), nullable=True, comment='the status of the CAPEC'),
    sa.Column('description', sa.Text(), nullable=True, comment='the description of the CAPEC'),
    sa.Column('data', postgresql.JSONB(astext_type=sa.Text()), nullable=True, comment='CAPEC JSON representation'),
    sa.PrimaryKeyConstraint('id'),
    comment='Table that contains the list of CWEs'
    )
    op.create_index('capec_idx1', 'capec', ['name'], unique=False)
    op.create_index('capec_idx2', 'capec', ['description'], unique=False)
    op.create_index(op.f('ix_capec_capec_id'), 'capec', ['capec_id'], unique=False)
    op.alter_column('cwe', 'data',
               existing_type=postgresql.JSONB(astext_type=sa.Text()),
               comment='CWE JSON representation',
               existing_comment='CPE JSON representation',
               existing_nullable=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('cwe', 'data',
               existing_type=postgresql.JSONB(astext_type=sa.Text()),
               comment='CPE JSON representation',
               existing_comment='CWE JSON representation',
               existing_nullable=True)
    op.drop_index(op.f('ix_capec_capec_id'), table_name='capec')
    op.drop_index('capec_idx2', table_name='capec')
    op.drop_index('capec_idx1', table_name='capec')
    op.drop_table('capec')
    # ### end Alembic commands ###
