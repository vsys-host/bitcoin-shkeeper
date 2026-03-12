from decimal import Decimal
from app.config import COIN
from app.logging import logger
from app.models import DbAmlPayout, DbKey, db


class AmlWallet:
    def __init__(self, symbol=COIN):
        self.symbol = symbol

    def balance_of(self, address):
        logger.debug(f"[AML] Looking up balance for address: {address}")
        key_record = db.session.query(DbKey).filter(DbKey.address == address).first()
        if key_record:
            logger.info(
                f"[AML] Found key: id={key_record.id}, address={address}, balance={key_record.balance}"
            )
        else:
            logger.warning(f"[AML] Key not found for address: {address}")
        amount = key_record.balance if key_record else Decimal(0)
        logger.debug(f"[AML] Returning balance {amount} for address: {address}")
        return amount

    def payout_for_tx(self, tx_id, account):
        from app.wallet import CoinWallet
        from .functions import build_payout_list

        logger.info(
            f"[AML] ===== Starting payout_for_tx: tx_id={tx_id}, account={account}, symbol={self.symbol} ====="
        )

        external_drain_list = build_payout_list(self.symbol, tx_id)
        logger.info(f"[AML] External drain list returned: {external_drain_list}")

        if not external_drain_list:
            logger.warning(f"[AML] No payouts to process for tx {tx_id}, exiting")
            return False

        logger.info(f"[AML] Processing {len(external_drain_list)} payouts")

        tx_id_bytes = bytes.fromhex(tx_id) if isinstance(tx_id, str) else tx_id
        key = db.session.query(DbKey).filter(DbKey.address == account).first()

        if not key:
            logger.error(f"[AML] Key not found for address {account}")
            return False

        logger.info(
            f"[AML] Found key: id={key.id}, address={key.address}, balance={key.balance}"
        )
        input_key_id = key.id

        outputs = [(address, amount) for address, amount, _ in external_drain_list]
        total_payout = sum(amount for _, amount, _ in external_drain_list)
        logger.info(
            f"[AML] Preparing transaction with {len(outputs)} outputs, total amount: {total_payout}"
        )

        for idx, (addr, amt) in enumerate(outputs):
            logger.debug(
                f"[AML] Output {idx + 1}/{len(outputs)}: address={addr}, amount={amt}"
            )

        payout_results = []

        try:
            logger.info(f"[AML] Creating wallet transaction from key_id={input_key_id}")
            wallet = CoinWallet().current_wallet()

            tx = wallet.send(
                outputs, input_key_id=input_key_id, fee_per_kb=2000, allow_partial=True
            )
            txid_str = str(tx.txid)
            txid_bytes = bytes.fromhex(txid_str)

            logger.info(f"[AML] Transaction created: txid={txid_str}")

            # Save to database
            logger.info(
                f"[AML] Saving {len(external_drain_list)} payout records to database"
            )
            for idx, (address, amount, orig_amount) in enumerate(external_drain_list):
                logger.debug(
                    f"[AML] Payout record {idx + 1}: address={address}, amount={amount}, orig_amount={orig_amount}"
                )

                db.session.add(
                    DbAmlPayout(
                        external_tx_id=txid_bytes,
                        tx_id=tx_id_bytes,
                        address=address,
                        crypto=self.symbol,
                        amount_calc=orig_amount,
                        amount_send=amount,
                        status="pending",
                    )
                )

                payout_results.append(
                    {
                        "dest": address,
                        "amount": float(amount),
                        "status": "pending",
                        "txids": [txid_str],
                        "orig_amount": float(orig_amount),
                    }
                )

            db.session.commit()
            logger.info(f"[AML] Database records committed with status=pending")

            # Broadcast transaction
            logger.info(f"[AML] Broadcasting transaction {txid_str} to network...")
            tx.send()
            logger.info(f"[AML] Transaction successfully broadcasted: {txid_str}")

            # Update status to success
            updated_count = (
                db.session.query(DbAmlPayout)
                .filter(DbAmlPayout.external_tx_id == txid_bytes)
                .update({"status": "success"})
            )
            db.session.commit()
            logger.info(
                f"[AML] Updated {updated_count} payout records to status=success"
            )

            for p in payout_results:
                p["status"] = "success"

        except Exception as e:
            logger.exception(f"[AML] Payout failed with exception: {e}")
            logger.error(f"[AML] Exception type: {type(e).__name__}")

            db.session.rollback()
            logger.info(f"[AML] Database rolled back")

            if "txid_str" in locals():
                logger.warning(f"[AML] Marking payouts as 'error' for txid {txid_str}")
                updated = (
                    db.session.query(DbAmlPayout)
                    .filter(DbAmlPayout.external_tx_id == txid_bytes)
                    .update({"status": "error"})
                )
                db.session.commit()
                logger.info(f"[AML] Marked {updated} payouts as error")

            for address, amount, orig_amount in external_drain_list:
                payout_results.append(
                    {
                        "dest": address,
                        "amount": float(amount),
                        "status": "error",
                        "txids": [],
                        "orig_amount": float(orig_amount),
                    }
                )

        # Log final results
        for idx, payout in enumerate(payout_results):
            txid_log = payout.get("txids")[0] if payout.get("txids") else "N/A"
            logger.info(
                f"[AML] Payout {idx + 1}/{len(payout_results)}: {payout['amount']} {self.symbol} -> "
                f"{payout['dest']} | txid={txid_log} | status={payout['status']}"
            )

        logger.info(
            f"[AML] ===== Completed payout_for_tx for {tx_id}: {len(payout_results)} payouts processed ====="
        )
        return payout_results
