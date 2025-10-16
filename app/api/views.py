from flask import current_app, g
from app.logging import logger
from app.config import config
from . import api
from app import create_app
from app.lib.values import Value
from app.wallet import BTCWallet

app = create_app()
app.app_context().push()

@api.post("/generate-address")
def generate_new_address():   
    w = BTCWallet() 
    new_address = w.generate_address()
    logger.warning(new_address)
    return {'status': 'success', 'address': new_address}

@api.post('/balance')
def get_balance():
    w = BTCWallet()
    balance = w.get_deposit_account_balance()
    return {'status': 'success', 'balance': balance}

@api.post('/status')
def get_status():
    w = BTCWallet()
    delta_blocks = w.delta_synced_block()
    return {'status': 'success', 'delta_blocks': delta_blocks}

@api.post('/transaction/<txid>')
def get_transaction(txid):
    w = BTCWallet()
    transaction = w.get_transaction(txid)
    if not transaction:
        logger.error(f"Cannt recdeive outputs {txid}: {transaction}")
        return {'error': 'Invalid transaction'}, 400

    related_transactions = []
    confirmations = transaction.get("confirmations") or 1
    for detail in transaction.get("details", []):
        address = detail.get("address")
        # if address == w.get_fee_deposit_account():
        #     continue
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
        return {'status': 'error', 'msg': 'txid is not related to any known address'}

    logger.warning(related_transactions)
    return related_transactions

@api.post('/dump')
def dump():
    w = BTCWallet()
    all_wallets = w.get_dump()
    return all_wallets

@api.post('/fee-deposit-account')
def get_fee_deposit_account():
    # w = BTCWallet()
    return {'account': "", 'balance': 0}

@api.post('/get_all_addresses')
def get_all_addresses():
    w = BTCWallet()
    all_addresses_list = w.get_all_accounts()
    return all_addresses_list