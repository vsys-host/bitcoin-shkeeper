from decimal import Decimal

# import tronpy
# from sqlalchemy.orm import Session

from app.config import config, COIN
# from app.db_import import db 
from app.models import DbKey, db
# from app.wallet import CoinWallet
from app.lib.values import Value, decimal_value_to_satoshi
import decimal
# from ...db import engine
from ...logging import logger
from app.models import DbAmlPayout
from app.logging import logger

class AmlWallet():
    def __init__(self, symbol=COIN):
        self.symbol = symbol

    def balance_of(self, address):
        key_record = db.session.query(DbKey).filter(DbKey.address == address).first()
        if key_record:
            print("Found key:", key_record)
        else:
            print("Key not found for address", address)
        amount = key_record.balance if key_record else Decimal(0)
        # amount_converted = Value.from_satoshi(amount).value
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

        account_balance = self.balance_of(account)
        input_key_id = db.session.query(DbKey).filter(DbKey.address == account).first().id
        logger.info(f"Account balance for {account}: {account_balance} {self.symbol} {input_key_id}")

        outputs = [(address, int(orig_amount)) for address, amount, orig_amount in external_drain_list]
        for address, satoshi_amount in outputs:
            logger.info(f"Prepared payout to {address}: {satoshi_amount} satoshi")

        payout_results = []
        try:
            wallet = CoinWallet().current_wallet()
            tx = wallet.send(outputs, input_key_id=input_key_id)
            tx.send()
            txid_str = str(tx.txid)
            logger.info(f"Transaction sent: {txid_str}")

            for address, amount, orig_amount in external_drain_list:
                payout_results.append({
                    "dest": address,
                    "amount": float(amount),
                    "status": "success",
                    "txids": [txid_str],
                    "orig_amount": float(orig_amount)
                })
                db_payout = DbAmlPayout(
                    external_tx_id=txid_str,
                    tx_id=tx_id,
                    address=address,
                    crypto=self.symbol,
                    amount_calc=orig_amount,
                    amount_send=amount,
                    status="success",
                )
                db.session.add(db_payout)
            db.session.commit()

        except Exception as e:
            logger.warning(f"Submit failed: {e}")
            for address, amount, orig_amount in external_drain_list:
                payout_results.append({
                    "dest": address,
                    "amount": float(amount),
                    "status": "error",
                    "txids": [],
                    "orig_amount": float(orig_amount)
                })

        for payout in payout_results:
            txid_log = payout.get('txids')[0] if payout.get('txids') else ''
            logger.info(
                f"{tx_id}: Sent {payout['amount']} {self.symbol} -> {payout['dest']} "
                f"({txid_log}), status: {payout['status']}"
            )

        logger.info(f"{tx_id} BTC payout process complete")
        return payout_results
