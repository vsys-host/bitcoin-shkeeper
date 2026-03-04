"""add new columns to transactions

Revision ID: abc123def456
Revises: 8921e5b04057
Create Date: 2026-03-04 12:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'abc123def456'
down_revision = '8921e5b04057'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade schema: add tx_type, uid, score, aml_status columns."""
    op.add_column('transactions', sa.Column('tx_type', sa.String(255), nullable=True))
    op.add_column('transactions', sa.Column('uid', sa.String(255), nullable=True))
    op.add_column(
        'transactions',
        sa.Column('score', sa.Numeric(7,5), server_default='-1', nullable=True)
    )
    op.add_column('transactions', sa.Column('aml_status', sa.String(255), nullable=True))


def downgrade() -> None:
    """Downgrade schema: remove added columns."""
    op.drop_column('transactions', 'tx_type')
    op.drop_column('transactions', 'uid')
    op.drop_column('transactions', 'score')
    op.drop_column('transactions', 'aml_status')