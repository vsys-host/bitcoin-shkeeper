import os
import re
from decimal import Decimal
from functools import wraps

import base58
from flask import jsonify
from werkzeug.routing import BaseConverter

from .config import config
from .logging import logger


def _json_error(message, status_code):
    return jsonify({
        'status': 'error',
        'message': message,
    }), status_code


def block_during_migration(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        from app.services import WalletService
        from app.services.store import DEFAULT_STORE_ID

        if not os.path.isfile(config['WALLET_DAT_PATH']):
            return fn(*args, **kwargs)

        wallet = WalletService().wallet(store_id=DEFAULT_STORE_ID)
        if wallet is None:
            logger.warning(
                'Wallet is not available for %s (encryption password not ready, wallet.dat exists=%s)',
                config.get('COIN_NETWORK', '?'),
                os.path.isfile(config['WALLET_DAT_PATH']),
            )
            return _json_error(
                'Wallet is locked or encryption password not available',
                503,
            )

        if not wallet.migrated:
            logger.warning(
                'Blocked during migration for wallet %s (migrated=%s, wallet.dat exists=%s)',
                wallet.name,
                wallet.migrated,
                os.path.isfile(config['WALLET_DAT_PATH']),
            )
            return _json_error('Blocked during migration', 423)
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


def _has_valid_base58_prefix(address, prefixes):
    try:
        base58.b58decode_check(address)
        return address[0] in prefixes
    except Exception:
        return False


class BTCUtils:
    BASE58_PREFIXES = ("1", "3", "m", "n", "2")

    @staticmethod
    def is_valid_btc_address(address: str) -> bool:
        if address.lower().startswith(("bc1", "tb1")):
            return BTCUtils._validate_bech32(address)
        return _has_valid_base58_prefix(address, BTCUtils.BASE58_PREFIXES)

    @staticmethod
    def _validate_bech32(address: str) -> bool:
        return bool(re.match(r'^(bc1|BC1|tb1|TB1)[0-9a-zA-Z]{6,87}$', address))


class LTCUtils:
    MAINNET_PREFIXES = ("L", "M")
    TESTNET_PREFIXES = ("m", "n", "Q", "q")
    PREFIXES = MAINNET_PREFIXES + TESTNET_PREFIXES

    @staticmethod
    def is_valid_ltc_address(address: str) -> bool:
        if not isinstance(address, str):
            return False
        if address.lower().startswith(("ltc1", "tltc1")):
            return LTCUtils._validate_bech32(address)
        return _has_valid_base58_prefix(address, LTCUtils.PREFIXES)

    @staticmethod
    def _validate_bech32(address: str) -> bool:
        return bool(re.fullmatch(
            r'(ltc1|tltc1)[023456789acdefghjklmnpqrstuvwxyz]{11,71}',
            address.lower()
        ))


class DOGEUtils:
    MAINNET_PREFIXES = ("D", "A")
    TESTNET_PREFIXES = ("n", "m", "2")
    PREFIXES = MAINNET_PREFIXES + TESTNET_PREFIXES

    @staticmethod
    def is_valid_doge_address(address: str) -> bool:
        if not isinstance(address, str):
            return False
        return _has_valid_base58_prefix(address, DOGEUtils.PREFIXES)
