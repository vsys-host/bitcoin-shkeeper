import time
from sqlalchemy.orm import joinedload
from app.celery_app import celery
from app.db_import import db
from app.models import DbTransaction, DbTransactionOutput, DbKey
from app.logging import logger
from app.config import config, COIN
from app.lib.aml.functions import aml_check_transaction, aml_recheck_transaction


def update_transaction_status(
    session, txid: bytes, uid: str, score: float, status: str
):
    tx = session.query(DbTransaction).filter(DbTransaction.txid == txid).first()
    if not tx:
        logger.warning(f"Cannot find BTC tx {txid} in DB")
        return None
    tx.uid = uid
    tx.score = score
    tx.aml_status = status
    session.add(tx)
    session.commit()
    session.refresh(tx)
    return tx


def find_address(tx: DbTransaction):
    output_keys = (
        db.session.query(DbKey)
        .join(DbTransactionOutput, DbTransactionOutput.key_id == DbKey.id)
        .filter(DbTransactionOutput.transaction_id == tx.id)
        .all()
    )
    if not output_keys:
        return None
    return output_keys[0].address


def process_aml_result(txid: str, key, result: dict):
    if (
        result["result"]
        and result["data"].get("status") == "pending"
        and "uid" in result["data"]
    ):
        return "rechecking", result["data"]["uid"], -1
    elif (
        result["result"]
        and "riskscore" in result["data"]
        and "uid" in result["data"]
        and result["data"]["status"] == "success"
    ):
        return "ready", result["data"]["uid"], result["data"]["riskscore"]
    else:
        logger.warning(f"Cannot update BTC transaction {txid}, result: {result}")
        return None, None, None


@celery.task(bind=True)
def check_btc_transaction(self, txid: str):
    tx = (
        db.session.query(DbTransaction)
        .filter(DbTransaction.txid == bytes.fromhex(txid))
        .first()
    )
    if not tx:
        logger.warning(f"BTC tx {txid} not found in DB")
        return False

    keys = [out.key for out in tx.outputs if out.key]
    for key in keys:
        from app.lib.aml.tasks import run_payout_for_tx

        result = aml_check_transaction(key.address, txid)
        status, uid, score = process_aml_result(txid, key, result)
        if not status:
            continue

        tx_db = update_transaction_status(
            db.session, bytes.fromhex(txid), uid, score, status
        )
        if status == "ready" and tx_db:
            address = find_address(tx)
            if address:
                run_payout_for_tx.delay(COIN, address, txid)
                logger.info(f"BTC tx {txid} for key {address} ready for payout")
    return True


@celery.task(bind=True)
def recheck_transaction(self, uid: str, txid: str):
    txid_bytes = bytes.fromhex(txid) if isinstance(txid, str) else txid
    logger.warning(f"recheck_transaction txid_bytes {txid_bytes}")
    tx = (
        db.session.query(DbTransaction)
        .filter(DbTransaction.txid == txid_bytes)
        .first()
    )
    if not tx:
        logger.warning(f"BTC tx {txid} not found in DB")
        return False

    keys = [out.key for out in tx.outputs if out.key]
    for key in keys:
        from app.lib.aml.tasks import run_payout_for_tx

        result = aml_recheck_transaction(uid, txid)
        status, uid, score = process_aml_result(txid, key, result)
        if not status:
            continue

        tx_db = update_transaction_status(
            db.session, txid_bytes, uid, score, status
        )
        if status == "ready" and tx_db:
            address = find_address(tx)
            if address:
                run_payout_for_tx.delay(COIN, address, txid)
                logger.info(f"BTC tx {txid} for key {address} ready for payout")
    return True


@celery.task(bind=True)
def recheck_transactions(self):
    logger.info("Rechecking BTC transactions...")

    txs = (
        db.session.query(DbTransaction)
        .options(joinedload(DbTransaction.outputs).joinedload(DbTransactionOutput.key))
        .filter(DbTransaction.aml_status.in_(["rechecking", "pending"]))
        .all()
    )

    for tx in txs:
        if tx.aml_status == "rechecking":
            recheck_transaction.delay(uid=tx.uid, txid=tx.txid)
        else:
            check_btc_transaction.delay(txid=tx.txid)
    return True


@celery.task(bind=True)
def run_payout_for_tx(self, symbol, account, tx_id):
    from app.lib.aml.classes import AmlWallet

    wallet = AmlWallet(symbol=symbol)
    results = wallet.payout_for_tx(tx_id, account)
    return results


@celery.task(bind=True)
def check_transaction(self, symbol: str, account: str, txid: str):
    from app.lib.aml.tasks import run_payout_for_tx

    result = aml_check_transaction(account, txid)
    status, uid, score = process_aml_result(txid, None, result)
    if not status:
        logger.warning(f"Cannot update the transaction, something wrong - {result}")
        return False

    time.sleep(5)
    tx_db = (
        db.session.query(DbTransaction)
        .filter(DbTransaction.txid == bytes.fromhex(txid))
        .first()
    )
    if not tx_db:
        logger.warning(f"Transaction {txid} not found in DB")
        return False
    tx_db.uid = uid
    tx_db.score = score
    tx_db.aml_status = status

    db.session.add(tx_db)
    db.session.commit()
    db.session.refresh(tx_db)

    if status == "ready":
        run_payout_for_tx.delay(symbol, account, txid)
        return True
