import time
import requests
from app.celery_app import celery
from celery.schedules import crontab
from celery.utils.log import get_task_logger
from .utils import skip_if_running
from .services import PayoutService, WalletService
from .logging import logger
from .payout_lock import payout_lock
from app.config import COIN, config
from app.migrate_addreses import migrate_addreses

logger = get_task_logger(__name__)

@celery.task
def migrate_wallet_task():
    migrate_addreses()

@celery.task()
def make_multipayout(symbol, payout_list, fee, store_id=None):
    if symbol == COIN:
        from .services.store import parse_store_id
        try:
            store_id = parse_store_id(store_id, required=True)
        except ValueError as exc:
            return [{"status": "error", "msg": str(exc)}]
        w = PayoutService()
        logger.warning(f"Starting payout {payout_list} store_id={store_id}")
        with payout_lock(store_id=store_id):
            payout_results = w.make_multipayout(payout_list, fee, store_id=store_id)
        post_payout_results.delay(payout_results, symbol)
        return payout_results  
    else:
        return [{"status": "error", 'msg': "Symbol is not in config"}]

@celery.task()
def withdraw_to_external_wallet_task(symbol, payout_list, store_id=None):
    if symbol == COIN:
        from .services.store import parse_store_id
        try:
            store_id = parse_store_id(store_id, required=True)
        except ValueError as exc:
            return [{"status": "error", "msg": str(exc)}]
        w = PayoutService()
        w.assert_sources_belong_to_store(payout_list, store_id)
        logger.warning(f"Starting withdraw_to_external_wallet_task {payout_list} store_id={store_id}")
        with payout_lock(store_id=store_id):
            payout_results = w.withdraw_to_external_wallet_task(payout_list, store_id=store_id)
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
def create_wallet(self):
    print("job generate_address")
    from .services.store import DEFAULT_STORE_ID
    w = WalletService()
    address = w.generate_address(store_id=DEFAULT_STORE_ID)
    return address

