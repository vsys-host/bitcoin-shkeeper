from flask import current_app, g
from app.logging import logger
from app.config import config
from . import api
from app import create_app
from app.lib.values import Value
from app.wallet import CoinWallet
from app.utils import block_during_migration

@api.post("/generate-address")
@block_during_migration
def generate_new_address():
    w = CoinWallet()
    new_address = w.generate_address()
    logger.warning(new_address)
    return {'status': 'success', 'address': new_address}

@api.post('/balance')
def get_balance():
    w = CoinWallet()
    balance = w.get_deposit_account_balance()
    return {'status': 'success', 'balance': balance}

@api.post('/status')
@block_during_migration
def get_status():
    w = CoinWallet()
    delta_blocks = w.delta_synced_block()
    return {'status': 'success', 'delta_blocks': delta_blocks}

@api.post('/transaction/<txid>')
def get_transaction(txid):
    w = CoinWallet()
    transaction = w.get_transaction(txid)
    if not transaction:
        logger.error(f"Cannot receive outputs {txid}: {transaction}")
        return []

    related_transactions = []
    confirmations = transaction.get("confirmations") or 1
    for detail in transaction.get("details", []):
        address = detail.get("address")
        amount = detail.get('amount', 0)
        category = detail.get("category")
        related_transactions.append([
            address,
            amount,
            confirmations,
            category
        ])

    # return related_transactions
    if not related_transactions:
        logger.warning(f"txid {txid} is not related to any known address for {g.symbol}")
        return []

    logger.warning(related_transactions)
    return related_transactions

@api.post('/dump')
def dump():
    w = CoinWallet()
    all_wallets = w.get_dump()
    return all_wallets

@api.post('/fee-deposit-account')
def get_fee_deposit_account():
    return {'account': "", 'balance': 0}

@api.post('/get_all_addresses')
def get_all_addresses():
    w = CoinWallet()
    all_addresses_list = w.get_all_accounts()
    return all_addresses_list
