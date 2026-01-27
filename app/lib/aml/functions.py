from decimal import Decimal
import hashlib
from typing import List, Literal
import requests
from app.config import config, COIN
from sqlalchemy import select
from app.db_import import db

# from ...custom.aml.tasks import (
#     check_transaction,
# )

# from ...exceptions import UnknownToken
# from ...db import engine
from app.logging import logger
from app.config import config
# from ...utils import short_txid
from app.models import DbTransaction, DbAmlPayout


def get_min_check_amount(symbol: str) -> Decimal:
    return config['EXTERNAL_DRAIN_CONFIG']['aml_check.cryptos'][COIN]['min_check_amount']


def get_external_drain_type(
    symbol: str,
) -> Literal["aml", "regular", "symbol_not_found"]:
    if (
        symbol not in config.EXTERNAL_DRAIN_CONFIG.aml_check.cryptos
        or symbol not in config.EXTERNAL_DRAIN_CONFIG.regular_split.cryptos
    ):
        logger.warning(
            f"Symbol {symbol} is not configured for aml or regular split payout."
        )
        return "symbol_not_found"

    if (
        config.EXTERNAL_DRAIN_CONFIG.aml_check.state == "enabled"
        and symbol in config.EXTERNAL_DRAIN_CONFIG.aml_check.cryptos
    ):
        return "aml"

    elif (
        config['EXTERNAL_DRAIN_CONFIG']['regular_split']['state'] == "enabled"
        and symbol in config['EXTERNAL_DRAIN_CONFIG']['regular_split']['cryptos']
    ):
        return "regular"
    else:
        raise Exception(f"Can't get payout type for {symbol}")


def aml_check_transaction(address, txid):
    symbol = COIN
    token_string = f"{txid}:{config['EXTERNAL_DRAIN_CONFIG']['aml_check']['access_key']}:{config['EXTERNAL_DRAIN_CONFIG']['aml_check']['access_id']}"
    token = str(hashlib.md5(token_string.encode()).hexdigest())
    response = requests.post(
        f"{config['EXTERNAL_DRAIN_CONFIG']['aml_check']['access_point']}/",
        data={
            "hash": txid,
            "address": address,
            "asset": symbol,
            "direction": "deposit",
            "token": token,
            "accessId": config['EXTERNAL_DRAIN_CONFIG']['aml_check']['access_id'],
            "locale": "en_US",
            "flow": config['EXTERNAL_DRAIN_CONFIG']['aml_check']['flow'],
        },
    )
    response.raise_for_status()
    return response.json()


def aml_recheck_transaction(uid, txid):
    token_string = f"{txid}:{config['EXTERNAL_DRAIN_CONFIG']['aml_check']['access_key']}:{config['EXTERNAL_DRAIN_CONFIG']['aml_check']['access_id']}"
    token = str(hashlib.md5(token_string.encode()).hexdigest())
    payload = f"uid={uid}&accessId={config['EXTERNAL_DRAIN_CONFIG']['aml_check']['access_id']}&token={token}"
    headers = {}
    response = requests.post(
        f"{config['EXTERNAL_DRAIN_CONFIG']['aml_check']['access_point']}/recheck",
        headers=headers,
        data=payload,
    )
    response.raise_for_status()
    return response.json()


def build_payout_list(
    symbol: str, tx_id: str
) -> List[tuple[str, Decimal, Decimal]] | Literal[False]:
    external_drain_list = []
    addresses_done = []

    # with Session(engine) as session:
    transaction = db.session.exec(
        select(DbTransaction).where(DbTransaction.tx_id == tx_id)
    ).first()

    if not transaction:
        logger.warning(f"Cannot find transaction {tx_id} in database")
        return False

    # with Session(engine) as session:
    pd = db.session.exec(select(DbAmlPayout).where(DbAmlPayout.tx_id == tx_id)).all()

    for drain in pd:
        addresses_done.append(drain.address)

    if transaction.ttype == "from_fee":
        return False

    payout_type = get_external_drain_type(symbol)

    if "aml" == payout_type:
        if transaction.ttype == "aml" and transaction.status == "ready":
            risk_config = config['EXTERNAL_DRAIN_CONFIG']['aml_check']['cryptos'][symbol]
            external_amounts = Decimal(0)
            for risk_level_name, risk_level_config in risk_config.risk_scores.items():
                if (
                    risk_level_config.min_value
                    <= transaction.score
                    <= risk_level_config.max_value
                ):
                    for address, payout_ratio in risk_level_config.addresses.items():
                        external_drain_list.append(
                            [
                                address,
                                payout_ratio,
                            ]
                        )

                    incomplete_payouts = []

                    for payout in external_drain_list:
                        address, payout_ratio = payout
                        if address not in addresses_done:
                            incomplete_payouts.append(address)

                    if not incomplete_payouts:
                        logger.debug(
                            f"Payout has already been done for {tx_id}"
                        )
                        return False

                    for i in range(len(external_drain_list) - 1):
                        payout_ratio = external_drain_list[i][1]
                        amount_to_address = transaction.amount * payout_ratio
                        external_amounts = external_amounts + amount_to_address
                        external_drain_list[i][1] = amount_to_address
                        external_drain_list[i].append(amount_to_address)

                    # send the rest to the last addresss in list
                    the_rest = transaction.amount - external_amounts
                    external_drain_list[-1][1] = the_rest
                    external_drain_list[-1].append(the_rest)

                    new_payout_list = []
                    for payout in external_drain_list:
                        if payout[0] not in addresses_done:
                            new_payout_list.append(payout)

                    logger.info(
                        f"{transaction.tx_id} "
                        f"AML score: {transaction.score} matches '{risk_level_name}' payout rule"
                    )
                    logger.info(f"{transaction.tx_id} payout list:")
                    for payout in external_drain_list:
                        logger.info(f"{payout[1]} {symbol} -> {payout[0]}")

                    return new_payout_list

        elif transaction.ttype == "aml" and transaction.status == "pending":
            return False

        elif transaction.ttype == "aml" and transaction.status == "rechecking":
            return False

        elif transaction.ttype == "regular":
            return False

        else:
            logger.warning(
                f"Unknown status {transaction.status} for transaction {transaction.tx_id}"
            )
            return False

    elif "regular" == payout_type:
        if transaction.ttype == "regular" and transaction.status == "drained":
            return False
        external_amounts = Decimal(0)
        regular_split_config = config['EXTERNAL_DRAIN_CONFIG']['regular_split']['cryptos'][
            symbol
        ]
        for address, payout_ratio in regular_split_config.addresses.items():
            external_drain_list.append([address, payout_ratio])

        incomplete_payouts = []
        for payout in external_drain_list:
            address, payout_ratio = payout
            if address not in addresses_done:
                incomplete_payouts.append(address)

        if not incomplete_payouts:
            return False

        else:
            for i in range(0, len(external_drain_list) - 1):
                payout_ratio = external_drain_list[i][1]
                amount_to_address = transaction.amount * payout_ratio
                external_amounts = external_amounts + amount_to_address
                external_drain_list[i][1] = amount_to_address
                external_drain_list[i].append(amount_to_address)

            # send the rest to the last addresss in list
            the_rest = transaction.amount - external_amounts
            external_drain_list[-1][1] = the_rest
            external_drain_list[-1].append(the_rest)

            new_payout_list = []
            for payout in external_drain_list:
                if payout[0] not in addresses_done:
                    new_payout_list.append(payout)

            logger.info(f"{transaction.tx_id} payout list:")
            for payout in external_drain_list:
                logger.info(f"{payout[1]} {symbol} -> {payout[0]}")

            return new_payout_list

    else:
        return False
