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

def run_alembic_upgrade():
    app = create_app()
    with app.app_context():
        alembic_cfg = Config(os.path.join(os.path.dirname(__file__), "alembic.ini"))
        alembic_cfg.set_main_option("sqlalchemy.url", str(db.engine.url))
        command.upgrade(alembic_cfg, "head")
        print("Alembic migrations applied.")

def init_db():
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
        if COIN in ("DOGE", "LTC"):
            DbTemporaryMigrationWallet.__table__.create(
                bind=db.engine,
                checkfirst=True
            )

        print("Tables and new columns updated.")
        # 🚀 Apply Alembic migration
        run_alembic_upgrade()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python manage.py init_db")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "init_db":
        init_db()
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)