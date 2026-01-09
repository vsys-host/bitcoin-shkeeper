#!/usr/bin/env python
# python manage.py init_db
import sys
from app import create_app, db
from app.config import COIN
from app.models import (
    DbWallet, DbKey, DbTransaction, DbTransactionInput, DbTransactionOutput,
    DbCacheTransaction, DbCacheTransactionNode, DbCacheAddress,
    DbCacheBlock, DbCacheVars, DbDogeMigrationWallet
)

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

def init_db():
    app = create_app()
    with app.app_context():
        wait_for_db(db.engine)
        print("Creating tables...")
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
        if COIN == "DOGE":
            DbDogeMigrationWallet.__table__.create(
                bind=db.engine,
                checkfirst=True
            )
        print("Tables created.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python manage.py init_db")
        sys.exit(1)

    command = sys.argv[1]

    if command == "init_db":
        init_db()
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
