from decimal import Decimal
from app.config import COIN
from app.logging import logger
from app.models import DbAmlPayout, DbKey, db


class AmlWallet:
    def __init__(self, symbol=COIN):
        self.symbol = symbol

    def balance_of(self, address):
        key_record = db.session.query(DbKey).filter(DbKey.address == address).first()
        if key_record:
            print("Found key:", key_record)
        else:
            print("Key not found for address", address)
        amount = key_record.balance if key_record else Decimal(0)
        return amount

    def payout_for_tx(self, tx_id, account):
        from app.wallet import CoinWallet
        from .functions import build_payout_list

        logger.info(f"===== BTC AmlWallet.payout_for_tx {tx_id} {account} =====")

        external_drain_list = build_payout_list(self.symbol, tx_id)
        logger.info(f"external_drain_list: {external_drain_list}")
        if not external_drain_list:
            logger.warning("No payouts to process, exiting method")
            return False

        tx_id_bytes = bytes.fromhex(tx_id) if isinstance(tx_id, str) else tx_id
        key = db.session.query(DbKey).filter(DbKey.address == account).first()
        if not key:
            logger.error(f"Key not found for address {account}")
            return False

        input_key_id = key.id

        outputs = [(address, int(orig_amount)) for address, _, orig_amount in external_drain_list]

        payout_results = []

        try:
            wallet = CoinWallet().current_wallet()
            tx = wallet.send(outputs, input_key_id=input_key_id, allow_partial=True)
            txid_str = str(tx.txid)
            txid_bytes = bytes.fromhex(txid_str)

            for address, amount, orig_amount in external_drain_list:
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

            tx.send()
            logger.info(f"Transaction broadcasted: {txid_str}")

            (
                db.session.query(DbAmlPayout)
                .filter(DbAmlPayout.external_tx_id == txid_bytes)
                .update({"status": "success"})
            )
            db.session.commit()

            for p in payout_results:
                p["status"] = "success"

        except Exception as e:
            logger.exception("Payout failed")

            db.session.rollback()

            if "txid_str" in locals():
                (
                    db.session.query(DbAmlPayout)
                    .filter(DbAmlPayout.external_tx_id == txid_bytes)
                    .update({"status": "error"})
                )
                db.session.commit()

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

        for payout in payout_results:
            txid_log = payout.get("txids")[0] if payout.get("txids") else ""
            logger.info(
                f"{tx_id}: Sent {payout['amount']} {self.symbol} -> {payout['dest']} "
                f"({txid_log}), status: {payout['status']}"
            )

        logger.info(f"BTC payout process {tx_id}  complete payout_for_tx {payout_results}")
        return payout_results