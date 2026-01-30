import time
import requests
from app.celery_app import celery
from celery.schedules import crontab
from celery.utils.log import get_task_logger
import requests as rq
from .celery_app import celery
from .config import config
from .utils import skip_if_running
from .wallet import CoinWallet
from .logging import logger
from app.config import COIN
from app.migrate_addreses import migrate_addreses

logger = get_task_logger(__name__)

@celery.task
def migrate_wallet_task():
    migrate_addreses()

@celery.task()
def make_multipayout(symbol, payout_list, fee):
    if symbol == COIN:
        w = CoinWallet()
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
def create_wallet(self):
    print("job generate_address")
    w = CoinWallet()
    address = w.generate_address()
    return address

@celery.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    cfg = config.get('EXTERNAL_DRAIN_CONFIG', {}).get('aml_check')
    if cfg and cfg.get('state') == "enabled":
        from app.lib.aml.tasks import recheck_transactions

        sender.add_periodic_task(
            config.get('AML_RESULT_UPDATE_PERIOD', 120),
            recheck_transactions.s(),
            name="Recheck AML transactions periodically"
        )