import time
from app.logging import logger
from app.config import config
from app.wallet import BTCWallet
from app.migrate_addreses import migrate_addreses
from app.models import DbCacheVars
from app.lib.services.services import Service
from decimal import Decimal
import datetime
import os

def handle_event(transaction):        
    logger.info(f'new transaction: {transaction!r}')

def log_loop():
    btc_wallet = BTCWallet()
    wallet = btc_wallet.wallet()
    default_check_interval = int(config.get("CHECK_NEW_BLOCK_EVERY_SECONDS", 60))
    srv = Service(config['BTC_NETWORK'])
    latest_height = btc_wallet.get_last_block_number()
    # value = 4690700
    value = wallet.session.query(DbCacheVars.value).filter_by(
        varname='last_scanned_block',
        network_name=wallet.network.name
    ).scalar()
    logger.info(f"DbCacheVars value {value}")

    if not value:
        logger.info(f"No last_scanned_block found, initializing with {latest_height}")
        new_var = DbCacheVars(
            varname='last_scanned_block',
            network_name=wallet.network.name,
            value=str(latest_height),
            type='int',
            expires=None
        )
        wallet.session.add(new_var)
        wallet.session.commit()
        current_height = latest_height
    else:
        current_height = int(value)
    while True:
        latest_height = btc_wallet.get_last_block_number()
        logger.info(f"latest_height {latest_height}")
        logger.info(f"current_height {current_height}")
        if latest_height > current_height:
            for height in range(current_height + 1, latest_height + 1):
                block_data = srv.getblock(height, 0).as_dict()
                block_hash = block_data['block_hash']
                logger.info(f"Processed bloc latest_height {latest_height}")
                logger.info(f"block_hash atr height {height}")
                logger.info(f"Processed block_hash {block_hash}")
                wallet.scan(block=block_hash)

                wallet.session.query(DbCacheVars).filter_by(
                    varname='last_scanned_block',
                    network_name=wallet.network.name
                ).update({"value": str(height)})
                wallet.session.commit()

            current_height = latest_height
            check_interval = 30
        else:
            check_interval = default_check_interval
        time.sleep(check_interval)

def events_listener():
    try:
        logger.info("log_loop started")
        from app import create_app
        app = create_app()
        app.app_context().push()
        btc_wallet = BTCWallet()
        wallet = btc_wallet.wallet()
        if os.path.isfile('/root/.bitcoin/shkeeper/wallet.dat') and not wallet.migrated:
            migrate_addreses()
        log_loop()
    except Exception as e:
        logger.exception(f"Exception in main block scanner loop: {e}")
        logger.warning("Waiting 60 seconds before retry.")
        time.sleep(60)
        events_listener()
