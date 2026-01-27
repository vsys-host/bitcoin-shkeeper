from decimal import Decimal

# import tronpy
# from sqlalchemy.orm import Session

from app.config import config, COIN
from app.db_import import db 
# from ...db import engine
from ...logging import logger
from app.models import DbAmlPayout
# from ...utils import short_txid


class AmlWallet():
    def __init__(self, symbol=COIN):
        super().__init__(symbol)

    def payout_for_tx(self, tx_id, account):
        from .functions import build_payout_list

        drain_results = []

        external_drain_list = build_payout_list(self.symbol, tx_id)
        logger.debug(f"{external_drain_list=}")
        if not external_drain_list:
            return False

        account_balance = self.balance_of(account)
        logger.debug(f"{account_balance=} {self.symbol=}")

        logger.debug("BTC workflow")
        if account_balance < config.TRX_MIN_TRANSFER_THRESHOLD:
            # logger.warning(
            #     f"Balance {account_balance} is lower "
            #     f"than {config.TRX_MIN_TRANSFER_THRESHOLD=}, skip draining"
            # )
            return False
        logger.debug(f"{config.TRX_MIN_TRANSFER_THRESHOLD=} passed")

        bandwidth_cost = (
            config.TRX_PER_BANDWIDTH_UNIT * config.BANDWIDTH_PER_TRX_TRANSFER
        )
        total_payout_bandwidth_cost = bandwidth_cost * len(external_drain_list)
        for i in range(len(external_drain_list)):
            external_drain_list[i][1] = external_drain_list[i][1] - bandwidth_cost

        total_payout_sum = Decimal(0)
        for payout_destination in external_drain_list:
            dst_addr, amount, orig_amount = payout_destination
            total_payout_sum += amount
            logger.debug(f"{dst_addr=} {amount=} {total_payout_sum=}")

        if (total_payout_sum + total_payout_bandwidth_cost) > account_balance:
            logger.warning(
                f"Need to drain bigger amount {total_payout_sum}"
                f"than have in balance {account_balance}, skip draining "
            )
            return False
        logger.debug(f"{total_payout_sum=} <= {account_balance=}")
        logger.info(f"{tx_id} payout started")
        for payout_destination in external_drain_list:
            dst_addr, amount, orig_amount = payout_destination
            logger.debug(
                f"Transfering {amount=} {self.symbol=} from {account=} to {dst_addr=}"
            )
            logger.debug(f"{account=} {self.bandwidth_of(account)=}")
            try:
                res = self.transfer(dst_addr, amount, src_address=account)
            except ValidationError as e:
                logger.error(f"error: {e}")
                logger.error(
                    f"balance of {account} is {self.balance_of(account)}, bandwidth is {self.bandwidth_of(account)}"
                )
                return False
            logger.debug(f"Transfer result {res=}")

            # with Session(engine) as session:
            payout = DbAmlPayout(
                external_tx_id=res["txids"][0],
                tx_id=tx_id,
                address=dst_addr,
                crypto=self.symbol,
                amount_calc=orig_amount,
                amount_send=amount,
                status=res["status"],
            )
            logger.debug(f"Writing payout to DB: {payout}...")
            db.session.add(payout)
            db.session.commit()
            db.session.refresh(payout)
            logger.debug("Writing payout to DB: done!")

            drain_results.append(
                {
                    "dest": payout.address,
                    "amount": amount,
                    "status": res["status"],
                    "txids": res["txids"],
                }
            )
            # time.sleep(10)  # FIXME

        for payout in drain_results:
            logger.info(
                f"{tx_id} payment sent: {payout['amount']} {self.symbol} -> {payout['dest']} ({payout['txids'][0]})"
            )
        logger.info(f"{tx_id} payout complete")
        return drain_results
