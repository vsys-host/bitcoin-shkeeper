# from decimal import Decimal

from flask import g, request
from flask import current_app as app
from sqlalchemy.exc import PendingRollbackError
from app.db_import import db
import decimal
from app.celery_app import celery
from app.lib.values import decimal_value_to_satoshi
from ..tasks import make_multipayout 
from . import api
from ..wallet import BTCWallet
from ..config import config
from ..logging import logger


@api.post('/calc-tx-fee/<decimal:amount>')
def calc_tx_fee(amount):
    if g.symbol == "BTC":
        w = BTCWallet()
        fee = w.get_transaction_price()
        return {'accounts_num': 1, 'fee': float(fee), 'fee_satoshi': decimal_value_to_satoshi(fee) }
    else:
        return {'status': 'error', 'msg': 'unknown crypto' }


@api.post('/multipayout')
def multipayout():        
    try:
        payout_list = request.get_json(force=True)
    except Exception as e:
        raise Exception(f"Bad JSON in payout list: {e}")

    if not payout_list:
            raise Exception(f"Payout list is empty!")

    for transfer in payout_list:
        try:
            transfer['amount'] = decimal.Decimal(transfer['amount'])
        except Exception as e:
            raise Exception(f"Bad amount in {transfer}: {e}")

        if transfer['amount'] <= 0:
            raise Exception(f"Payout amount should be a positive number: {transfer}")

    if g.symbol == 'BTC':
        task = (make_multipayout.s(g.symbol, payout_list, decimal.Decimal(config['NETWORK_FEE']))).apply_async()
        return{'task_id': task.id}
    else:
        raise Exception(f"{g.symbol} is not defined in config, cannot make payout")
    pass
    
@api.post('/payout/<to>/<decimal:amount>/<fee>')
def payout(to, amount, fee):
    logger.warning(f'starting payout {amount}, to {to}')
    payout_list = [{ "dest": to, "amount": amount }]
    if g.symbol == 'BTC':
        payout_list = [{ "dest": to, "amount": amount }]
        task = (make_multipayout.s(g.symbol, payout_list, decimal.Decimal(fee) if fee else decimal.Decimal(config['NETWORK_FEE']))).apply_async()
        return {'task_id': task.id}
    else:
        raise Exception(f"{g.symbol} is not defined in config, cannot make payout")

@api.post('/task/<id>')
def get_task(id):
    task = celery.AsyncResult(id)
    try:
        result = task.result
    except PendingRollbackError:
        db.session.rollback()
        result = task.result

    if isinstance(task.result, Exception):
        return {'status': task.status, 'result': str(result)}
    return {'status': task.status, 'result': result}

