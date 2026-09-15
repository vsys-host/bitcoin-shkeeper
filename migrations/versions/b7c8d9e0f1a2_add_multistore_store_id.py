"""Add multistore store_id support

Revision ID: b7c8d9e0f1a2
Revises: 8921e5b04057
Create Date: 2026-08-27

"""
from alembic import op
import sqlalchemy as sa


revision = "b7c8d9e0f1a2"
down_revision = "8921e5b04057"
branch_labels = None
depends_on = None

LEGACY_DEFAULT_STORE_ID = 1
STORE_ID_INDEX = "uq_wallets_store_id"
LEGACY_STORE_ID_INDEX = "ix_wallets_store_id"


def _inspector():
    return sa.inspect(op.get_bind())


def _table_exists(name):
    return name in _inspector().get_table_names()


def _column_exists(table, column):
    if not _table_exists(table):
        return False
    return column in {c["name"] for c in _inspector().get_columns(table)}


def _index_exists(table, index_name):
    if not _table_exists(table):
        return False
    return index_name in {idx["name"] for idx in _inspector().get_indexes(table)}


def upgrade():
    bind = op.get_bind()

    if not _column_exists("wallets", "store_id"):
        op.add_column("wallets", sa.Column("store_id", sa.Integer(), nullable=True))

    bind.execute(
        sa.text(
            """
            UPDATE wallets
            SET store_id = :sid
            WHERE store_id IS NULL
              AND parent_id IS NULL
              AND id = (
                SELECT id FROM (
                  SELECT MIN(id) AS id FROM wallets WHERE parent_id IS NULL
                ) t
              )
            """
        ),
        {"sid": LEGACY_DEFAULT_STORE_ID},
    )

    if _index_exists("wallets", LEGACY_STORE_ID_INDEX):
        op.drop_index(LEGACY_STORE_ID_INDEX, table_name="wallets")

    if _column_exists("wallets", "store_id") and not _index_exists("wallets", STORE_ID_INDEX):
        op.create_index(STORE_ID_INDEX, "wallets", ["store_id"], unique=True)


def downgrade():
    if _index_exists("wallets", STORE_ID_INDEX):
        op.drop_index(STORE_ID_INDEX, table_name="wallets")
    if _index_exists("wallets", LEGACY_STORE_ID_INDEX):
        op.drop_index(LEGACY_STORE_ID_INDEX, table_name="wallets")
    if _column_exists("wallets", "store_id"):
        op.drop_column("wallets", "store_id")
