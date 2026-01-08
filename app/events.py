import time
from app.logging import logger
from app.config import config, COIN
from app.wallet import CoinWallet
from app.tasks import migrate_wallet_task
from app.models import DbCacheVars
from app.lib.services.services import Service
from app.unlock_acc import get_account_password
from decimal import Decimal
import datetime
import os

_node_synced = False

def handle_event(transaction):        
    logger.info(f'new transaction: {transaction!r}')

def log_loop():
    coin_wallet = CoinWallet()
    wallet = coin_wallet.wallet()
    while wallet is None:
        logger.warning("Wallet not loaded yet, waiting 10 seconds...")
        time.sleep(10)
        wallet = coin_wallet.wallet()
    default_check_interval = int(config.get("CHECK_NEW_BLOCK_EVERY_SECONDS", 60))
    srv = Service(config['COIN_NETWORK'])
    latest_height = coin_wallet.get_last_block_number()
    # value = 917515
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
        latest_height = coin_wallet.get_last_block_number()
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
    from app import create_app
    app = create_app()
    app.app_context().push()

    global _node_synced

    while True:
        try:
            wait_for_account_password()

            if not _node_synced:
                wait_until_node_synced(max_delta_minutes=30)
                _node_synced = True

            coin_wallet = CoinWallet()
            wallet = coin_wallet.wallet()

            migration_flag = wallet.session.query(DbCacheVars).filter_by(
                varname="wallet_migration_in_progress",
                network_name=wallet.network.name
            ).scalar()

            if os.path.isfile(config['WALLET_DAT_PATH']) and not wallet.migrated:
                if not migration_flag or migration_flag != "in_progress":
                    wallet.session.query(DbCacheVars).filter_by(
                        varname="wallet_migration_in_progress",
                        network_name=wallet.network.name
                    ).delete()

                    wallet.session.add(DbCacheVars(
                        varname="wallet_migration_in_progress",
                        network_name=wallet.network.name,
                        value="in_progress",
                        type="str",
                        expires=None
                    ))
                    wallet.session.commit()

                    try:
                        logger.info("Wallet migration required, starting migrate_wallet_task...")
                        result = migrate_wallet_task.delay()

                        logger.info("Waiting for migrate_wallet_task to finish (this can take hours)...")

                        while True:
                            if result.ready():
                                if result.successful():
                                    logger.info("Migration completed successfully.")
                                    wallet.session.query(DbCacheVars).filter_by(
                                        varname="wallet_migrated",
                                        network_name=wallet.network.name
                                    ).delete()
                                    wallet.session.add(DbCacheVars(
                                        varname="wallet_migrated",
                                        network_name=wallet.network.name,
                                        value="1",
                                        type="int",
                                        expires=None
                                    ))
                                    wallet.session.commit()
                                else:
                                    logger.error("Migration failed.")
                                break

                            logger.info("Migration still in progress... waiting 60s before next check")
                            time.sleep(60)
                    finally:
                        wallet.session.query(DbCacheVars).filter_by(
                            varname="wallet_migration_in_progress",
                            network_name=wallet.network.name
                        ).delete()
                        wallet.session.commit()
                else:
                    logger.info("Migration already in progress by another process, waiting...")
                    time.sleep(60)
                    continue

                wallet = coin_wallet.wallet()
                migration_done = wallet.session.query(DbCacheVars).filter_by(
                    varname="wallet_migrated",
                    network_name=wallet.network.name
                ).scalar()

                if not migration_done:
                    logger.warning("Wallet still not marked as migrated, retrying later...")
                    time.sleep(60)
                    continue

            log_loop()

        except Exception as e:
            logger.exception(f"Exception in main block scanner loop: {e}")
            logger.warning("Waiting 66 seconds before retry.")
            time.sleep(66)

def wait_for_account_password(interval=20):
    while not get_account_password():
        logger.warning(
            f"Encryption password not available yet, waiting {interval} seconds..."
        )
        time.sleep(interval)

def wait_until_node_synced(max_delta_minutes=30, check_interval=120, error_interval=60):
    coin_wallet = CoinWallet()
    max_delta_seconds = max_delta_minutes * 60

    while True:
        try:
            info = coin_wallet.getblockchaininfo()
            logger.info(f"Retrieved blockchain info: {info}")
        except Exception as e:
            logger.exception(f"Failed to get blockchain info: {e}")
            time.sleep(error_interval)
            continue
        time_last_block = info.get("time") or info.get("mediantime")
        if time_last_block is None:
            logger.warning("Cannot get time_last_block from blockchain info, retrying...")
            time.sleep(error_interval)
            continue
        now_ts = time.time()
        logger.info(f"Node now_ts {now_ts}")
        delta = abs(now_ts - time_last_block)
        logger.info(f"Node delta {delta}")
        if delta <= max_delta_seconds:
            logger.info(f"Node synced (time_last_block={time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time_last_block))})")
            return
        logger.warning(
            f"Node not synced yet (time_last_block={time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time_last_block))}, "
            f"delta={delta:.0f}s), waiting {check_interval} seconds..."
        )
        time.sleep(check_interval)
