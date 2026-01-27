import time
from sqlalchemy.orm import joinedload
from sqlalchemy import select
from app.celery_app import celery
from app.config import config
from app.logging import logger
from app.db_import import db
from sqlalchemy.orm import Session
# from app.db import engine
from app.models import DbTransaction, DbTransactionOutput, DbTransactionInput, DbKey
from app.utils import skip_if_running
# from .bitcoin_wallet import BitcoinWallet
from app.lib.aml.classes import AmlWallet
# from app.lib.aml.tasks import run_payout_for_tx
from app.lib.aml.functions import aml_check_transaction, aml_recheck_transaction
# from app.utils import short_txid


def update_transaction_status(session: Session, txid: bytes, uid: str, score: float, status: str):
    tx = session.query(DbTransaction).filter(DbTransaction.txid == txid).first()
    if not tx:
        logger.warning(f"Cannot find BTC tx {txid.hex()} in DB")
        return None
    tx.uid = uid
    tx.score = score
    tx.aml_status = status
    session.add(tx)
    session.commit()
    session.refresh(tx)
    return tx


def process_aml_for_key(txid: str, key):
    result = aml_check_transaction(key.address, txid)
    if result["result"] and result["data"].get("status") == "pending" and "uid" in result["data"]:
        status, uid, score = "rechecking", result["data"]["uid"], -1
    elif result["result"] and "riskscore" in result["data"] and "uid" in result["data"] and result["data"]["status"] == "success":
        status, uid, score = "ready", result["data"]["uid"], result["data"]["riskscore"]
    else:
        logger.warning(f"Cannot update BTC transaction {txid}, result: {result}")
        return

    # with Session(engine) as session:
    tx = update_transaction_status(db.session, bytes.fromhex(txid), uid, score, status)

    if status == "ready" and tx:
        run_payout_for_tx.delay(txid=txid, key_id=key.id)
        logger.info(f"BTC tx {txid} for key {key.address} ready for payout")


@celery.task(bind=True)
@skip_if_running
def check_btc_transaction(self, txid: str):
    # with Session(engine) as session:
    tx = db.session.query(DbTransaction).options(joinedload(DbTransaction.outputs).joinedload(DbTransactionOutput.key)).filter(DbTransaction.txid == bytes.fromhex(txid)).first()
    # db.session.commit()
    if not tx:
        logger.warning(f"BTC tx {txid} not found in DB")
        return False

    keys = [out.key for out in tx.outputs if out.key]
    for key in keys:
        process_aml_for_key(txid, key)
    return True


@celery.task(bind=True)
@skip_if_running
def recheck_transaction(self, uid: str, txid: str):
    # with Session(engine) as session:
    tx = db.session.query(DbTransaction).options(joinedload(DbTransaction.outputs).joinedload(DbTransactionOutput.key)).filter(DbTransaction.txid == bytes.fromhex(txid)).first()
    if not tx:
        logger.warning(f"BTC tx {txid} not found in DB")
        return False

    keys = [out.key for out in tx.outputs if out.key]
    for key in keys:
        result = aml_recheck_transaction(uid, txid)
        if result["result"] and result["data"].get("status") == "pending" and "uid" in result["data"]:
            status, uid, score = "rechecking", result["data"]["uid"], -1
        elif result["result"] and "riskscore" in result["data"] and "uid" in result["data"] and result["data"]["status"] == "success":
            status, uid, score = "ready", result["data"]["uid"], result["data"]["riskscore"]
        else:
            logger.warning(f"Cannot update BTC transaction {txid}, result: {result}")
            continue

        # with Session(engine) as session:
        tx_db = update_transaction_status(db.session, bytes.fromhex(txid), uid, score, status)

        if status == "ready" and tx_db:
            run_payout_for_tx.delay(txid=txid, key_id=key.id)
            logger.info(f"BTC tx {txid} for key {key.address} ready for payout")


@celery.task(bind=True)
@skip_if_running
def recheck_transactions(self):
    # with Session(engine) as session:
    recheck_txs = db.session.query(DbTransaction).options(joinedload(DbTransaction.inputs).joinedload(DbTransactionInput.key)).filter(DbTransaction.aml_status == "rechecking").all()
    pending_txs = db.session.query(DbTransaction).options(joinedload(DbTransaction.inputs).joinedload(DbTransactionInput.key)).filter(DbTransaction.aml_status == "pending").all()

    for tx in recheck_txs + pending_txs:
        key_ids = [inp.key_id for inp in tx.inputs if inp.key_id is not None]
        if not key_ids:
            continue
        task = recheck_transaction if tx.aml_status == "rechecking" else check_btc_transaction
        task.delay(txid=tx.txid.hex())
    return True

@celery.task(bind=True)
@skip_if_running
def run_payout_for_tx(self, symbol, account, tx_id):
    wallet = AmlWallet(symbol=symbol)
    if account == wallet.main_account["public"]:
        logger.debug(f"{account} is fee-dopisit, skipping ")
        return False
    results = wallet.payout_for_tx(tx_id, account)
    return results


@celery.task(bind=True)
@skip_if_running
def check_transaction(self, symbol: str, account: str, txid: str):
    # from .functions import (
    #     aml_check_transaction,
    # )

    result = aml_check_transaction(account, txid)
    if (
        result["result"]
        and result["data"]["status"] == "pending"
        and "uid" in result["data"]
    ):
        status = "rechecking"
        uid = result["data"]["uid"]
        score = -1
    elif (
        result["result"]
        and "riskscore" in result["data"]
        and "uid" in result["data"]
        and result["data"]["status"] == "success"
    ):
        status = "ready"
        score = result["data"]["riskscore"]
        uid = result["data"]["uid"]
    else:
        logger.warning(f"Cannot update the transaction, something wrong - {result}")
        return False

    time.sleep(5)

    # with Session(engine) as session:
    pd = db.session.exec(
        select(DbTransaction).where(
            DbTransaction.address == account, DbTransaction.tx_id == txid
        )
    ).one()
    pd.uid = uid
    pd.score = score
    pd.status = status
    db.session.add(pd)
    db.session.commit()
    db.session.refresh(pd)

    if status == "ready":
        run_payout_for_tx.delay(symbol, account, txid)
        return True