import time
from flask import Flask
from . import events
from sqlalchemy import inspect
from sqlalchemy.exc import OperationalError
from app.config import config
from app.db_import import db

def wait_for_db(engine, timeout=30):
    for _ in range(timeout):
        try:
            engine.connect().close()
            return
        except OperationalError:
            time.sleep(1)
    raise RuntimeError("DB not ready after waiting")

def create_app():
    app = Flask(__name__)
    app.config.from_mapping(config)

    from .models import (
        DbWallet, DbKey, DbTransaction, DbTransactionInput, DbTransactionOutput,
        DbCacheTransaction, DbCacheTransactionNode, DbCacheAddress,
        DbCacheBlock, DbCacheVars
    )
    from . import utils
    app.url_map.converters['decimal'] = utils.DecimalConverter
    from .api import api as api_blueprint
    from .api import metrics_blueprint
    app.register_blueprint(api_blueprint)
    app.register_blueprint(metrics_blueprint)
    from .tasks import walletnotify_shkeeper

    db.init_app(app)
    with app.app_context():
        wait_for_db(db.engine)
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

    return app
