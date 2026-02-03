#!/usr/bin/env python
# python manage.py init_db
import sys
from app import create_app, db
from app.models import (
    DbWallet, DbKey, DbTransaction, DbTransactionInput, DbTransactionOutput,
    DbCacheTransaction, DbCacheTransactionNode, DbCacheAddress,
    DbCacheBlock, DbCacheVars, DbAmlPayout
)
from sqlalchemy import inspect, text

def wait_for_db(engine, timeout=30):
    import time
    from sqlalchemy.exc import OperationalError

    for _ in range(timeout):
        try:
            engine.connect().close()
            return
        except OperationalError:
            time.sleep(1)
    raise RuntimeError("DB not ready after waiting")

def add_new_columns(model, columns: dict):
    table_name = model.__tablename__
    inspector = inspect(db.engine)
    existing_columns = [c['name'] for c in inspector.get_columns(table_name)]

    with db.engine.connect() as conn:
        for col_name, col_type in columns.items():
            if col_name not in existing_columns:
                print(f"Adding column {col_name} to {table_name}")
                conn.execute(text(f'ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}'))

def create_tables_and_columns():
    app = create_app()
    with app.app_context():
        wait_for_db(db.engine)
        print("Creating tables...")

        models = [
            DbWallet, DbTransaction, DbKey, DbTransactionInput,
            DbTransactionOutput, DbCacheTransaction, DbCacheTransactionNode,
            DbCacheAddress, DbCacheBlock, DbCacheVars, DbAmlPayout
        ]

        for model in models:
            model.__table__.create(bind=db.engine, checkfirst=True)

        transaction_new_columns = {
            'tx_type': 'VARCHAR(255)',
            'uid': 'VARCHAR(255)',
            'score': 'NUMERIC(7,5) DEFAULT -1',
            'aml_status': 'VARCHAR(255)'
        }

        add_new_columns(DbTransaction, transaction_new_columns)

        print("Tables and new columns updated.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python manage.py init_db")
        sys.exit(1)

    command = sys.argv[1]

    if command == "init_db":
        create_tables_and_columns()
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
