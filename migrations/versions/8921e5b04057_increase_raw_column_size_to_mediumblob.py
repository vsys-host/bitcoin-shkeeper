"""increase raw column size to mediumblob

Revision ID: 8921e5b04057
Revises: 
Create Date: 2026-03-02 10:19:18.009963
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.mysql import MEDIUMBLOB

# revision identifiers, used by Alembic.
revision = '8921e5b04057'
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    """Upgrade schema: increase raw column to MEDIUMBLOB."""
    op.alter_column(
        'transactions',
        'raw',
        existing_type=sa.BLOB(),
        type_=MEDIUMBLOB,
        nullable=True
    )

def downgrade() -> None:
    """Downgrade schema: revert raw column back to BLOB."""
    op.alter_column(
        'transactions',
        'raw',
        existing_type=MEDIUMBLOB,
        type_=sa.BLOB(),
        nullable=True
    )