#!/usr/bin/env python
# python manage.py init_db
import sys
import os
from app import create_app, db
from app.config import COIN
from app.models import (
    DbWallet, DbKey, DbTransaction, DbTransactionInput, DbTransactionOutput,
    DbCacheTransaction, DbCacheTransactionNode, DbCacheAddress,
    DbCacheBlock, DbCacheVars, DbTemporaryMigrationWallet, DbAmlPayout
)
from sqlalchemy import inspect, text
from alembic.config import Config
from alembic import command

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

def run_alembic_upgrade():
    app = create_app()
    with app.app_context():
        alembic_cfg = Config(os.path.join(os.path.dirname(__file__), "alembic.ini"))
        alembic_cfg.set_main_option("sqlalchemy.url", str(db.engine.url))
        command.upgrade(alembic_cfg, "head")
        print("Alembic migrations applied.")

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
        if COIN == "DOGE":
            DbTemporaryMigrationWallet.__table__.create(
                bind=db.engine,
                checkfirst=True
            )    

        transaction_new_columns = {
            'tx_type': 'VARCHAR(255)',
            'uid': 'VARCHAR(255)',
            'score': 'NUMERIC(7,5) DEFAULT -1',
            'aml_status': 'VARCHAR(255)'
        }

        add_new_columns(DbTransaction, transaction_new_columns)

        print("Tables and new columns updated.")
        DbWallet.__table__.create(bind=db.engine, checkfirst=True)
        DbTransaction.__table__.create(bind=db.engine, checkfirst=True)
        DbKey.__table__.create(bind=db.engine, checkfirst=True)
        DbTransactionInput.__table__.create(bind=db.engine, checkfirst=True)
        DbTransactionOutput.__table__.create(bind=db.engine, checkfirst=True)
        DbCacheTransaction.__table__.create(bind=db.engine, checkfirst=True)
        DbCacheTransactionNode.__table__.create(bind=db.engine, checkfirst=True)
        DbCacheAddress.__table__.create(bind=db.engine, checkfirst=True)
        DbCacheBlock.__table__.create(bind=db.engine, checkfirst=True)
        DbCacheVars.__table__.create(bind=db.engine, checkfirst=True)
        if COIN in ("DOGE", "LTC"):
            DbTemporaryMigrationWallet.__table__.create(
                bind=db.engine,
                checkfirst=True
            )
        print("Tables created.")
        # 🚀 Apply Alembic migration
        run_alembic_upgrade()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python manage.py init_db")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "init_db":
        create_tables_and_columns()
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)