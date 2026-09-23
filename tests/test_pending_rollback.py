"""Reproduction of a Celery worker PendingRollbackError.

The worker reuses one Flask-SQLAlchemy Session. A dead DB connection leaves
it invalid; the next payout store-wallet lookup must still succeed.

Uses a file-backed sqlite DB so reconnect keeps tables (like MariaDB).
In-memory sqlite:// is empty after connection.invalidate().
"""
import os
import tempfile

from flask import Flask
from sqlalchemy import text

from app.db_import import db
from app.models import DbWallet
from app.services.store import store_wallet


WALLET_NAME = "store-1"


def _worker_app(db_path):
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db._engine_options = {"connect_args": {"check_same_thread": False}}
    db.init_app(app)
    return app


def test_store_wallet_after_stale_connection():
    fd, db_path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    try:
        app = _worker_app(db_path)
        with app.app_context():
            DbWallet.__table__.create(bind=db.engine, checkfirst=True)
            db.session.add(
                DbWallet(
                    name=WALLET_NAME,
                    scheme="bip32",
                    encoding="bech32",
                    witness_type="segwit",
                    store_id=1,
                )
            )
            db.session.commit()

            db.session.execute(text("SELECT 1"))
            db.session.connection().invalidate()

            wallet = store_wallet(store_id=1)
            assert wallet is not None
            assert wallet.name == WALLET_NAME
    finally:
        os.unlink(db_path)
