from decimal import Decimal
from typing import Literal
from functools import wraps
from flask import current_app
from werkzeug.routing import BaseConverter
from .config import config
from .logging import logger
import re
import base58

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

class BTCUtils:
    # MAINNET_PREFIXES = ("1", "3", "bc1")
    # TESTNET_PREFIXES = ("m", "n", "2", "tb1")

    @staticmethod
    def is_valid_btc_address(address: str) -> bool:
        if address.lower().startswith(("bc1", "tb1")):
            return BTCUtils._validate_bech32(address)
        try:
            decoded = base58.b58decode_check(address)
            prefix = address[0]
            if prefix in ("1", "3", "m", "n", "2"):
                return True
        except Exception:
            return False
        return False

    @staticmethod
    def _validate_bech32(address: str) -> bool:
        if re.match(r'^(bc1|BC1|tb1|TB1)[0-9a-zA-Z]{6,87}$', address):
            return True
        return False

class LTCUtils:
    MAINNET_PREFIXES = ("L", "M")   # P2PKH / P2SH
    TESTNET_PREFIXES = ("m", "n", "Q", "q")  # testnet variants
    @staticmethod
    def is_valid_ltc_address(address: str) -> bool:
        if not isinstance(address, str):
            return False
        if address.lower().startswith(("ltc1", "tltc1")):
            return LTCUtils._validate_bech32(address)
        try:
            decoded = base58.b58decode_check(address)
            prefix = address[0]
            if prefix in LTCUtils.MAINNET_PREFIXES + LTCUtils.TESTNET_PREFIXES:
                return True
        except Exception:
            return False
        return False

    @staticmethod
    def _validate_bech32(address: str) -> bool:
        return bool(re.match(r'^(ltc1|tltc1)[0-9ac-hj-np-z]{11,71}$', address))

