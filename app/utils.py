import os
from decimal import Decimal
from typing import Literal
from functools import wraps
from flask import current_app, jsonify
from werkzeug.routing import BaseConverter
from .config import config
from .logging import logger
from functools import wraps
from app.wallet import BTCWallet

def block_during_migration(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        wallet = BTCWallet().wallet()

        if os.path.isfile(config['WALLET_DAT_PATH']) and not wallet.migrated:
            logger.warning('Blocked during migration')
            return jsonify({
                'status': 'error',
                'message': 'Blocked during migration'
            }), 423
        return fn(*args, **kwargs)
    return wrapper

class DecimalConverter(BaseConverter):

    def to_python(self, value):
        return Decimal(value)

    def to_url(self, value):
        return BaseConverter.to_url(value)


def skip_if_running(f):
    task_name = f'{f.__module__}.{f.__name__}'

    @wraps(f)
    def wrapped(self, *args, **kwargs):
        workers = self.app.control.inspect().active()

        for worker, tasks in workers.items():
            for task in tasks:
                if (task_name == task['name'] and
                        tuple(args) == tuple(task['args']) and
                        kwargs == task['kwargs'] and
                        self.request.id != task['id']):
                    logger.debug(f'task {task_name} ({args}, {kwargs}) is running on {worker}, skipping')

                    return None
        logger.debug(f'task {task_name} ({args}, {kwargs}) is allowed to run')
        return f(self, *args, **kwargs)

    return wrapped
