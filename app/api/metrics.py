import logging

import prometheus_client
from prometheus_client import Gauge, generate_latest

from . import metrics_blueprint
from app.config import config
from app.models import DbCacheVars, db
from app.wallet import CoinWallet

logger = logging.getLogger(__name__)

for collector in (
    prometheus_client.GC_COLLECTOR,
    prometheus_client.PLATFORM_COLLECTOR,
    prometheus_client.PROCESS_COLLECTOR,
):
    try:
        prometheus_client.REGISTRY.unregister(collector)
    except KeyError:
        pass


bitcoin_fullnode_status = Gauge(
    "bitcoin_fullnode_status", "Connection status to bitcoin fullnode"
)
bitcoin_fullnode_last_block = Gauge(
    "bitcoin_fullnode_last_block", "Last block loaded to the bitcoin fullnode"
)
bitcoin_wallet_last_block = Gauge("bitcoin_wallet_last_block", "Last checked wallet block")
bitcoin_fullnode_last_block_timestamp = Gauge(
    "bitcoin_fullnode_last_block_timestamp", "Fullnode block timestamp"
)
bitcoin_wallet_last_block_timestamp = Gauge(
    "bitcoin_wallet_last_block_timestamp", "Wallet block timestamp"
)


def get_all_metrics():
    try:
        info = CoinWallet().getblockchaininfo() or {}
    except Exception as exc:
        logger.exception("Fullnode status fetch failed: %s", exc)
        return None

    try:
        is_synced = info.get("initialblockdownload") is False
        blocks = int(info.get("blocks", 0) or 0)
        block_timestamp = int(
            info.get("mediantime") or info.get("time") or info.get("bestblocktime") or 0
        )
    except Exception:
        is_synced = False
        blocks = 0
        block_timestamp = 0

    if not is_synced:
        return {"bitcoin_fullnode_status": 0}

    try:
        wallet_last_block_raw = (
            db.session.query(DbCacheVars.value)
            .filter_by(
                varname="last_scanned_block",
                network_name=config["COIN_NETWORK"],
            )
            .scalar()
        )
        wallet_last_block = int(wallet_last_block_raw or 0)
    except Exception as exc:
        logger.warning("Wallet last_scanned_block fetch failed: %s", exc)
        wallet_last_block = 0

    wallet_block_timestamp = 0

    return {
        "bitcoin_fullnode_status": 1,
        "last_fullnode_block_number": blocks,
        "last_fullnode_block_timestamp": block_timestamp,
        "bitcoin_wallet_last_block": wallet_last_block,
        "bitcoin_wallet_last_block_timestamp": wallet_block_timestamp,
    }


@metrics_blueprint.get("/metrics")
def get_metrics():
    try:
        data = get_all_metrics()

        if not data:
            bitcoin_fullnode_status.set(0)
            return generate_latest().decode()

        bitcoin_fullnode_status.set(data.get("bitcoin_fullnode_status", 0))

        if data["bitcoin_fullnode_status"] == 1:
            bitcoin_fullnode_last_block.set(data.get("last_fullnode_block_number", 0))
            bitcoin_fullnode_last_block_timestamp.set(
                data.get("last_fullnode_block_timestamp", 0)
            )
            bitcoin_wallet_last_block.set(data.get("bitcoin_wallet_last_block", 0))
            bitcoin_wallet_last_block_timestamp.set(
                data.get("bitcoin_wallet_last_block_timestamp", 0)
            )
    except Exception as exc:
        logger.exception("Metrics endpoint failed completely: %s", exc)
        bitcoin_fullnode_status.set(0)

    return generate_latest().decode()
