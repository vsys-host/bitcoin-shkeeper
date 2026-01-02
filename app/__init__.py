import time
from flask import Flask
from . import events
from sqlalchemy import inspect
from sqlalchemy.exc import OperationalError
from app.config import config
from app.db_import import db

def create_app():
    app = Flask(__name__)
    app.config.from_mapping(config)

    from . import utils
    app.url_map.converters['decimal'] = utils.DecimalConverter
    from .api import api as api_blueprint
    from .api import metrics_blueprint
    app.register_blueprint(api_blueprint)
    app.register_blueprint(metrics_blueprint)

    db.init_app(app)

    return app
