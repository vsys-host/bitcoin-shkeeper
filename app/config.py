import os
from decimal import Decimal

config = {
    # 'FULLNODE_URL': os.environ.get('FULLNODE_URL', 'http://bitcoinuser:bitcoinpass@195.66.213.33:18443/'), # regtest
    # 'FULLNODE_URL': os.environ.get('FULLNODE_URL', 'http://bitcoinuser:bitcoinpass@195.66.213.33:18332/'), # testnet
    'FULLNODE_URL': os.environ.get('FULLNODE_URL', 'http://shkeeper:shkeeper@fullnode.bitcoin.shkeeper.io:8332'),
    'FULLNODE_TIMEOUT': os.environ.get('FULLNODE_TIMEOUT', '60'),
    'CHECK_NEW_BLOCK_EVERY_SECONDS': os.environ.get('CHECK_NEW_BLOCK_EVERY_SECONDS',60),
    'EVENTS_MAX_THREADS_NUMBER': int(os.environ.get('EVENTS_MAX_THREADS_NUMBER', 5)),
    'EVENTS_MIN_DIFF_TO_RUN_PARALLEL': int(os.environ.get('EVENTS_MIN_DIFF_TO_RUN_PARALLEL', 200)), #min difference between last checked block and last block in blockchain to run checking blocks in parallel mode
    'DEBUG': os.environ.get('DEBUG', False),
    'LOGGING_LEVEL': os.environ.get('LOGGING_LEVEL', 'INFO'),
    'SQLALCHEMY_DATABASE_URI' : os.environ.get('SQLALCHEMY_DATABASE_URI', "mariadb+pymysql://root:shkeeper@mariadb/bitcoin-shkeeper?charset=utf8mb4&binary_prefix=true"),
    'SQLALCHEMY_POOL_SIZE' : os.environ.get('SQLALCHEMY_POOL_SIZE', 30),
    'SQLALCHEMY_TRACK_MODIFICATIONS' : os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS', True), 
    'API_USERNAME': os.environ.get('BTC_USERNAME', 'shkeeper'),
    'API_PASSWORD': os.environ.get('BTC_PASSWORD', 'shkeeper'),
    'SHKEEPER_KEY': os.environ.get('SHKEEPER_BACKEND_KEY', 'shkeeper'),
    'SHKEEPER_HOST': os.environ.get('SHKEEPER_HOST', 'shkeeper:5000'),
    'REDIS_HOST': os.environ.get('REDIS_HOST', 'localhost'),
    'CELERY_MAX_TASKS_PER_CHILD': os.environ.get('CELERY_MAX_TASKS_PER_CHILD', '10'), 
    'MIN_TRANSFER_THRESHOLD': Decimal(os.environ.get('MIN_TRANSFER_THRESHOLD', '0.1')),
    'UPDATE_BALANCES_EVERY_SECONDS': os.environ.get('UPDATE_BALANCES_EVERY_SECONDS', '3600'),
    'LAST_BLOCK_LOCKED': os.environ.get('LAST_BLOCK_LOCKED', "False"),
    'NETWORK_FEE': os.environ.get('NETWORK_FEE', "0.00005"),
    'ACCOUNT_RESERVED_AMOUNT': os.environ.get('ACCOUNT_RESERVED_AMOUNT', "0.000001"),
    'DELETE_ACCOUNT_FEE': os.environ.get('DELETE_ACCOUNT_FEE', "0.2"),
    'COUNT_ADDRESSES': os.environ.get('COUNT_ADDRESSES', "10000"),
    'COUNT_RECEIVED_TRANSACTIONS': os.environ.get('COUNT_RECEIVED_TRANSACTIONS', "1000"),
    'MIN_CONFIRMS': os.environ.get('MIN_CONFIRMS', "1"),
    'LEDGERS_TO_WAIT': os.environ.get('LEDGERS_TO_WAIT', "100"), # used to calc last_ledger_sequence for payments
    'BTC_NETWORK': os.environ.get('BTC_NETWORK', 'main'),  # main, testnet, regtest
}

def is_test_network():
    if config['BTC_NETWORK'] == 'main':
        return False
    else:
        return True
    

