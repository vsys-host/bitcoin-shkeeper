import os
from decimal import Decimal
import json

def detect_active_coin():
    coin = os.environ.get("WALLET")
    if not coin:
        raise ValueError("WALLET env variable is not set")
    coin = coin.upper()
    if coin not in {"BTC", "LTC", "DOGE"}:
        raise ValueError(f"Unsupported coin: {coin}")
    return coin

COIN = detect_active_coin()
DB_NAME_MAP = {
    "BTC": "bitcoin-shkeeper",
    "LTC": "litecoin-shkeeper",
    "DOGE": "dogecoin-shkeeper",
}
FULLNODE_URL =  {
                  "BTC": "http://bitcoinuser:bitcoinpass@195.66.213.33:18332/",
                  # "BTC": "http://shkeeper:shkeeper@fullnode.bitcoin.shkeeper.io:8332",
                  "LTC": "http://shkeeper:shkeeper@fullnode.litecoin.shkeeper.io"
                }
BASE_WALLET_PATHS = {
    "BTC": "/root/.bitcoin/shkeeper/wallet.dat",
    "LTC": "/root/.litecoin/shkeeper/wallet.dat",
    "DOGE": "/root/.dogecoin/shkeeper/wallet.dat",
}
# external_raw = os.environ.get("EXTERNAL_DRAIN_CONFIG")
# if external_raw:
#     try:
#         EXTERNAL_DRAIN_CONFIG = json.loads(external_raw)
#     except Exception:
#         EXTERNAL_DRAIN_CONFIG = None
# else:
#     EXTERNAL_DRAIN_CONFIG = None

# remove
EXTERNAL_DRAIN_CONFIG = {
    "aml_check": {
        "state": "enabled",
        "access_point": "https://example.com",
        "access_id": "access_id",
        "access_key": "access_key",
        "flow": "default",
        "cryptos": {
            "BTC": {
                "min_check_amount": 0.001,
                "risk_scores": {
                    "low": {
                        "min_value": 0,
                        "max_value": 30,
                        "addresses": {
                            "tb1qcvmrnn9c67y0rwl3944z0evlpwmnllvrcshwqz": 0.25,
                            "tb1q2t06ptmj8zqx5shcqeye4znjt9s94lnj2nqzkc": 0.75,
                        },
                    },
                    "medium": {
                        "min_value": 31,
                        "max_value": 70,
                        "addresses": {
                            "tb1qaddress3...": 0.7,
                            "tb1qaddress4...": 0.3,
                        },
                    },
                    "high": {
                        "min_value": 71,
                        "max_value": 100,
                        "addresses": {
                            "tb1qaddress5...": 0.6,
                            "tb1qaddress6...": 0.4,
                        },
                    },
                },
            },
        },
    },
    "regular_split": {
        "state": "enabled",
        "cryptos": {
            "BTC": {
                "addresses": {
                    "tb1qregular1...": 0.6,
                    "tb1qregular2...": 0.4,
                },
                "min_check_amount": 0.001,
            }
        },
    },
}

config = {
    'FULLNODE_URL': os.environ.get('FULLNODE_URL', FULLNODE_URL[COIN]),
    'FULLNODE_TIMEOUT': os.environ.get('FULLNODE_TIMEOUT', '60'),
    'CHECK_NEW_BLOCK_EVERY_SECONDS': os.environ.get('CHECK_NEW_BLOCK_EVERY_SECONDS', 60),
    'EVENTS_MAX_THREADS_NUMBER': int(os.environ.get('EVENTS_MAX_THREADS_NUMBER', 8)),
    'DEBUG': os.environ.get('DEBUG', False),
    'SQLALCHEMY_DATABASE_URI': os.environ.get(
    'SQLALCHEMY_DATABASE_URI',
        (
            f"mariadb+pymysql://root:shkeeper@mariadb/{DB_NAME_MAP[COIN]}"
            "?charset=utf8mb4&binary_prefix=true"
        ),
    ),
    # ... aml_config
    'EXTERNAL_DRAIN_CONFIG': EXTERNAL_DRAIN_CONFIG,
    'DELAY_AFTER_FEE_TRANSFER': 60,
    'AML_RESULT_UPDATE_PERIOD': 120,
    'AML_WAIT_BEFORE_API_CALL': 320,
    # ...
    'SQLALCHEMY_POOL_SIZE' : os.environ.get('SQLALCHEMY_POOL_SIZE', 30),
    'API_USERNAME': os.environ.get(f'{COIN}_USERNAME', 'shkeeper'),
    'API_PASSWORD': os.environ.get(f'{COIN}_PASSWORD', 'shkeeper'),
    'SHKEEPER_KEY': os.environ.get('SHKEEPER_BACKEND_KEY', 'shkeeper'),
    'SHKEEPER_HOST': os.environ.get('SHKEEPER_HOST', 'shkeeper:5000'),
    'REDIS_HOST': os.environ.get('REDIS_HOST', 'localhost'),
    'CELERY_MAX_TASKS_PER_CHILD': os.environ.get('CELERY_MAX_TASKS_PER_CHILD', '10'), 
    'MIN_TRANSFER_THRESHOLD': Decimal(os.environ.get('MIN_TRANSFER_THRESHOLD', '0.000001')),
    'LAST_BLOCK_LOCKED': os.environ.get('LAST_BLOCK_LOCKED', "False"),
    'NETWORK_FEE': os.environ.get('NETWORK_FEE', "0.00005"),
    'ACCOUNT_RESERVED_AMOUNT': os.environ.get('ACCOUNT_RESERVED_AMOUNT', "0.000001"),
    'MIN_CONFIRMS': os.environ.get('MIN_CONFIRMS', "1"),
    'WALLET_DAT_PATH': os.environ.get('WALLET_DAT_PATH', BASE_WALLET_PATHS[COIN]),
    'TIME_WALLET_CREATED': os.environ.get('TIME_WALLET_CREATED'),
    'COIN_NETWORK': os.environ.get(f"{COIN}_NETWORK", "testnet"),  # main, testnet, regtest
}


def is_test_network():
    if config['COIN_NETWORK'] == 'main':
        return False
    else:
        return True
