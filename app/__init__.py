from flask import Flask
from . import events
from app.config import config
from app.db_import import db

def create_app():
    app = Flask(__name__)
    app.config.from_mapping(config)
    from . import utils
    # utils.init_wallet(app)

    app.url_map.converters['decimal'] = utils.DecimalConverter
    from .api import api as api_blueprint
    from .api import metrics_blueprint
    app.register_blueprint(api_blueprint)
    app.register_blueprint(metrics_blueprint)
    
    from .tasks import walletnotify_shkeeper

    db.init_app(app)
    with app.app_context():
        # Create tables according to models
        # from .models import Settings
        db.create_all()

    return app
