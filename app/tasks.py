import time
import requests
from app.celery_app import celery
from celery.schedules import crontab
from celery.utils.log import get_task_logger
import requests as rq

from .celery_app import celery
from .config import config
from .utils import skip_if_running
from .wallet import BTCWallet
from .logging import logger

logger = get_task_logger(__name__)

@celery.task()
def make_multipayout(symbol, payout_list, fee):
    if symbol == "BTC":
        w = BTCWallet()
        logger.warning(f"Starting payout {payout_list}")
        payout_results = w.make_multipayout(payout_list, fee)
        post_payout_results.delay(payout_results, symbol)
        return payout_results  
    else:
        return [{"status": "error", 'msg': "Symbol is not in config"}]


@celery.task()
def post_payout_results(data, symbol):
    while True:
        try:
            return requests.post(
                f'http://{config["SHKEEPER_HOST"]}/api/v1/payoutnotify/{symbol}',
                headers={'X-Shkeeper-Backend-Key': config['SHKEEPER_KEY']},
                json=data,
            )
        except Exception as e:
            logger.exception(f'Shkeeper payout notification failed: {e}')
            time.sleep(10)


@celery.task()
def walletnotify_shkeeper(symbol, txid):
    logger.exception(f"walletnotify_shkeeper {txid}")
    while True:
        try:
            r = rq.post(
                    f'http://{config["SHKEEPER_HOST"]}/api/v1/walletnotify/{symbol}/{txid}',
                    headers={'X-Shkeeper-Backend-Key': config['SHKEEPER_KEY']}
                )
            return r
        except Exception as e:
            logger.warning(f'Shkeeper notification failed for {symbol}/{txid}: {e}')
            time.sleep(10)


@celery.task()
def create_wallet(self):
    print("job generate_address")
    w = BTCWallet()
    address = w.generate_address()
    return address

# @celery.task(bind=True)
# @skip_if_running
# def drain_account(self, symbol):
#     logger.warning(f"Start draining from account crypto {symbol}")
#     # return False
#     if symbol == "BTC":
#         w = BTCWallet()
#         # destination = w.get_fee_deposit_account()
#         # results = w.drain_account(destination)
#     else:
#         raise Exception(f"Symbol is not in config")
#     return {}

# @celery.on_after_configure.connect
# def setup_periodic_tasks(sender, **kwargs):
#     # Update cached account balances
#     # sender.add_periodic_task(int(config['UPDATE_BALANCES_EVERY_SECONDS']), refresh_balances.s())
    


