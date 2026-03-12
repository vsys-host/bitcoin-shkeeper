from decimal import Decimal
import hashlib
from typing import List, Literal, Tuple
import requests
from app.config import config, COIN
from app.logging import logging
from app.models import DbTransaction, DbAmlPayout, DbKey, db

_logger = logging.getLogger(__name__)


def get_min_check_amount(symbol: str) -> Decimal:
    _logger.warning("aml get_min_check_amount")
    cfg = (
        config.get("EXTERNAL_DRAIN_CONFIG", {}).get("aml_check", {}).get("cryptos", {})
    )
    coin_cfg = cfg.get(symbol)
    if coin_cfg and "min_check_amount" in coin_cfg:
        return Decimal(coin_cfg["min_check_amount"])
    return Decimal("0")


def get_external_drain_type(
    symbol: str,
) -> Literal["aml", "regular", "symbol_not_found"]:
    _logger.warning("aml get_external_drain_type")
    cfg = config.get("EXTERNAL_DRAIN_CONFIG")
    _logger.warning("aml get_external_drain_type")
    if not cfg:
        _logger.warning("aml get_external_drain_type regular")
        return "regular"

    aml_cfg = cfg.get("aml_check", {})
    reg_cfg = cfg.get("regular_split", {})

    if symbol not in aml_cfg.get("cryptos", []) and symbol not in reg_cfg.get(
        "cryptos", []
    ):
        _logger.warning(
            f"Symbol {symbol} is not configured for aml or regular split payout."
        )
        return "symbol_not_found"

    if aml_cfg.get("state") == "enabled" and symbol in aml_cfg.get("cryptos", []):
        _logger.warning("aml get_external_drain_type aml")
        return "aml"

    if reg_cfg.get("state") == "enabled" and symbol in reg_cfg.get("cryptos", []):
        _logger.warning("aml get_external_drain_type regular")
        return "regular"

    return "regular"


def aml_check_transaction(address, txid_bytes):
    txid = txid_bytes.hex() if isinstance(txid_bytes, bytes) else txid_bytes
    _logger.warning(f"aml check transaction {txid}")
    cfg = config.get("EXTERNAL_DRAIN_CONFIG", {}).get("aml_check")
    if not cfg or cfg.get("state") != "enabled":
        return {}

    symbol = COIN
    token_string = f"{txid}:{cfg.get('access_key', '')}:{cfg.get('access_id', '')}"
    token = str(hashlib.md5(token_string.encode()).hexdigest())
    response = requests.post(
        f"{cfg.get('access_point', '')}/",
        data={
            "hash": txid,
            "address": address,
            "asset": symbol,
            "direction": "deposit",
            "token": token,
            "accessId": cfg.get('access_id', ''),
            "locale": "en_US",
            "flow": cfg.get('flow', 'default'),
        },
    )
    response.raise_for_status()
    _logger.warning(f"aml check transaction response {response}")
    return response.json()

def aml_recheck_transaction(uid, txid_bytes):
    txid = txid_bytes.hex() if isinstance(txid_bytes, bytes) else txid_bytes
    _logger.warning(f"aml recheck transaction {txid}")
    cfg = config.get("EXTERNAL_DRAIN_CONFIG", {}).get("aml_check")
    if not cfg or cfg.get("state") != "enabled":
        return {}

    token_string = f"{txid}:{cfg.get('access_key', '')}:{cfg.get('access_id', '')}"
    token = str(hashlib.md5(token_string.encode()).hexdigest())
    payload = f"uid={uid}&accessId={cfg.get('access_id', '')}&token={token}"
    _logger.warning(f"aml recheck transaction payload {payload}")
    headers = {}
    response = requests.post(
        f"{cfg.get('access_point', '')}/recheck",
        headers=headers,
        data=payload,
    )
    response.raise_for_status()
    _logger.warning(f"aml recheck transaction response {response}")
    return response.json()


def build_payout_list(
    symbol: str, tx_id_hex: str
) -> list[tuple[str, Decimal, Decimal]] | Literal[False]:

    _logger.warning("build payout list started")

    tx_id_bytes = tx_id_hex if isinstance(tx_id_hex, bytes) else bytes.fromhex(tx_id_hex)
    _logger.warning(f"build_payout_list tx_id: {tx_id_bytes.hex()}")

    transaction = (
        db.session.query(DbTransaction)
        .filter(DbTransaction.txid == tx_id_bytes)
        .first()
    )

    if not transaction:
        _logger.warning(f"Transaction {tx_id_hex} not found")
        return False

    if transaction.tx_type == "default":
        return False

    payouts_done = (
        db.session.query(DbAmlPayout.address)
        .filter(DbAmlPayout.tx_id == tx_id_bytes)
        .all()
    )

    addresses_done = {row[0] for row in payouts_done}

    payout_type = get_external_drain_type(symbol)

    _logger.warning(f"aml payout_type {payout_type}")

    if payout_type not in ("aml", "regular"):
        return False

    # -----------------------
    # calculate amount_total
    # -----------------------

    addresses = [out.address for out in transaction.outputs if out.address]

    key_obj = (
        db.session.query(DbKey)
        .filter(DbKey.address.in_(addresses))
        .order_by(DbKey.id.asc())
        .first()
    )

    amount_total = key_obj.balance if key_obj else Decimal("0")

    if amount_total <= 0:
        _logger.warning("amount_total is zero")
        return False

    # -----------------------
    # AML payout
    # -----------------------

    if payout_type == "aml":
        _logger.warning("aml build_payout_list aml type")
        if transaction.tx_type != "aml" or transaction.aml_status != "ready":
            return False

        score = Decimal(str(transaction.score))

        risk_cfg = (
            config.get("EXTERNAL_DRAIN_CONFIG", {})
            .get("aml_check", {})
            .get("cryptos", {})
            .get(symbol, {})
        )

        level_cfg = None

        for _, cfg in risk_cfg.get("risk_scores", {}).items():

            min_v = Decimal(str(cfg["min_value"]))
            max_v = Decimal(str(cfg["max_value"]))

            if min_v <= score <= max_v:
                level_cfg = cfg
                break

        if not level_cfg:
            _logger.warning("AML level config not found")
            return False

        raw_addresses = level_cfg.get("addresses", {})

    # -----------------------
    # REGULAR payout
    # -----------------------

    else:
        _logger.warning("aml build_payout_list regular type")
        if transaction.tx_type == "regular" and transaction.status == "drained":
            return False

        regular_cfg = (
            config.get("EXTERNAL_DRAIN_CONFIG", {})
            .get("regular_split", {})
            .get("cryptos", {})
            .get(symbol, {})
        )

        raw_addresses = regular_cfg.get("addresses", {})

    if not raw_addresses:
        _logger.warning("raw_addresses empty")
        return False

    # -----------------------
    # validate ratios
    # -----------------------

    ratio_sum = sum(Decimal(str(v)) for v in raw_addresses.values())

    if ratio_sum > Decimal("1"):
        _logger.error(f"{payout_type} ratios > 100%")
        return False

    # -----------------------
    # build payout list
    # -----------------------

    items = list(raw_addresses.items())

    payout_list: list[tuple[str, Decimal, Decimal]] = []
    total_assigned = Decimal("0")

    for i, (address, ratio) in enumerate(items):

        ratio = Decimal(str(ratio))

        if address in addresses_done:
            continue

        if i == len(items) - 1:
            amount = amount_total - total_assigned
        else:
            amount = (amount_total * ratio).quantize(Decimal("0.00000001"))

        if amount <= 0:
            continue

        payout_list.append((address, amount, ratio))

        total_assigned += amount

    if not payout_list:
        _logger.warning("payout_list empty")
        return False

    _logger.warning(f"payout_list built: {payout_list}")
    new_payouts = [p for p in payout_list if p[0] not in addresses_done]
    return new_payouts or False
    # return payout_list