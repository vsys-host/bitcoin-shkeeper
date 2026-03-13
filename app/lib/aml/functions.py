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
    external_cfg = config.get("EXTERNAL_DRAIN_CONFIG", {})
    for section_name, section in external_cfg.items():
        if not isinstance(section, dict):
            continue
        if section.get("state") == "enabled":
            cryptos = section.get("cryptos", {})
            coin_cfg = cryptos.get(symbol)
            if coin_cfg and "min_check_amount" in coin_cfg:
                return Decimal(coin_cfg["min_check_amount"])

    aml_cryptos = external_cfg.get("aml_check", {}).get("cryptos", {})
    coin_cfg = aml_cryptos.get(symbol)
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
            "accessId": cfg.get("access_id", ""),
            "locale": "en_US",
            "flow": cfg.get("flow", "default"),
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
    from app.wallet import CoinWallet

    _logger.info(f"[AML] Building payout list: symbol={symbol}, tx_id={tx_id_hex}")

    tx_id_bytes = (
        tx_id_hex if isinstance(tx_id_hex, bytes) else bytes.fromhex(tx_id_hex)
    )
    tx_id_display = tx_id_bytes.hex() if isinstance(tx_id_bytes, bytes) else tx_id_bytes
    _logger.debug(f"[AML] Transaction ID converted: {tx_id_display}")

    transaction = (
        db.session.query(DbTransaction)
        .filter(DbTransaction.txid == tx_id_bytes)
        .first()
    )

    if not transaction:
        _logger.warning(f"[AML] Transaction {tx_id_display} not found in database")
        return False

    _logger.info(
        f"[AML] Transaction found: id={transaction.id}, tx_type={transaction.tx_type}, aml_status={getattr(transaction, 'aml_status', 'N/A')}, score={getattr(transaction, 'score', 'N/A')}"
    )

    if transaction.tx_type == "default":
        _logger.info(f"[AML] Transaction is 'default' type, no payout needed")
        return False

    payouts_done = (
        db.session.query(DbAmlPayout.address)
        .filter(DbAmlPayout.tx_id == tx_id_bytes)
        .all()
    )

    addresses_done = {row[0] for row in payouts_done}
    _logger.info(f"[AML] Found {len(addresses_done)} already processed addresses")
    if addresses_done:
        _logger.debug(f"[AML] Already processed addresses: {list(addresses_done)}")

    payout_type = get_external_drain_type(symbol)
    _logger.info(f"[AML] Payout type determined: {payout_type}")

    if payout_type not in ("aml", "regular"):
        _logger.warning(f"[AML] Invalid payout type '{payout_type}', cannot proceed")
        return False

    # -----------------------
    # calculate amount_total
    # -----------------------

    addresses = [out.address for out in transaction.outputs if out.address]
    _logger.warning(f"[AML] Transaction has {len(addresses)} output addresses")
    if addresses:
        _logger.warning(f"[AML] Transaction output addresses: {addresses}")

    key_obj = (
        db.session.query(DbKey)
        .filter(DbKey.address.in_(addresses))
        .order_by(DbKey.id.asc())
        .first()
    )

    if key_obj:
        _logger.warning(f"[AML] amount balance before update: {key_obj.balance}")
        wallet = CoinWallet().current_wallet()
        _logger.warning(f"[AML] current wallet: {wallet}")
        wallet._balance_update(key_id=key_obj.id)
        key_obj = (
            db.session.query(DbKey)
            .filter(DbKey.address.in_(addresses))
            .order_by(DbKey.id.asc())
            .first()
        )
        amount_total = Decimal(key_obj.balance or 0)
        _logger.warning(f"[AML] Amount balance after update: {amount_total}")
    else:
        amount_total = Decimal("0")
        _logger.warning("[AML] No key object found for transaction addresses")

    _logger.info(
        f"[AML] Total amount available for payout: {amount_total} "
        f"(key_id={key_obj.id if key_obj else 'N/A'}, "
        f"address={key_obj.address if key_obj else 'N/A'})"
    )

    if amount_total <= 0:
        _logger.warning(f"[AML] Amount total is zero or negative, no payout possible")
        return False

    # -----------------------
    # AML payout
    # -----------------------

    if payout_type == "aml":
        _logger.info(f"[AML] Processing AML payout type")

        if transaction.tx_type != "aml":
            _logger.warning(
                f"[AML] Transaction tx_type is '{transaction.tx_type}', expected 'aml'"
            )
            return False

        if transaction.aml_status != "ready":
            _logger.warning(
                f"[AML] Transaction aml_status is '{transaction.aml_status}', expected 'ready'"
            )
            return False

        score = Decimal(str(transaction.score))
        _logger.info(f"[AML] Risk score: {score}")

        risk_cfg = (
            config.get("EXTERNAL_DRAIN_CONFIG", {})
            .get("aml_check", {})
            .get("cryptos", {})
            .get(symbol, {})
        )

        level_cfg = None

        for level_name, cfg in risk_cfg.get("risk_scores", {}).items():
            min_v = Decimal(str(cfg["min_value"]))
            max_v = Decimal(str(cfg["max_value"]))
            _logger.debug(
                f"[AML] Checking risk level '{level_name}': min={min_v}, max={max_v}, score={score}"
            )

            if min_v <= score <= max_v:
                level_cfg = cfg
                _logger.info(
                    f"[AML] Risk level matched: '{level_name}' (score {score} in range [{min_v}, {max_v}])"
                )
                break

        if not level_cfg:
            _logger.error(f"[AML] No risk level configuration found for score {score}")
            return False

        raw_addresses = level_cfg.get("addresses", {})
        _logger.info(
            f"[AML] Risk level addresses configuration: {len(raw_addresses)} addresses"
        )
        _logger.debug(f"[AML] Address ratios: {raw_addresses}")

    # -----------------------
    # REGULAR payout
    # -----------------------

    else:
        _logger.info(f"[AML] Processing regular payout type")

        if transaction.tx_type == "regular" and transaction.status == "drained":
            _logger.info(f"[AML] Transaction already drained, skipping")
            return False

        regular_cfg = (
            config.get("EXTERNAL_DRAIN_CONFIG", {})
            .get("regular_split", {})
            .get("cryptos", {})
            .get(symbol, {})
        )

        raw_addresses = regular_cfg.get("addresses", {})
        _logger.info(
            f"[AML] Regular payout addresses configuration: {len(raw_addresses)} addresses"
        )
        _logger.debug(f"[AML] Address ratios: {raw_addresses}")

    if not raw_addresses:
        _logger.warning(f"[AML] No destination addresses configured")
        return False

    # -----------------------
    # validate ratios
    # -----------------------

    ratio_sum = sum(Decimal(str(v)) for v in raw_addresses.values())
    _logger.info(f"[AML] Total ratio sum: {ratio_sum} (must be <= 1.0)")

    if ratio_sum > Decimal("1"):
        _logger.error(f"[AML] Ratio sum {ratio_sum} exceeds 100%")
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
            _logger.info(f"[AML] Skipping already processed address: {address}")
            continue

        if i == len(items) - 1:
            amount = amount_total - total_assigned
            _logger.debug(f"[AML] Last address {address}: assigning remainder {amount}")
        else:
            amount = (amount_total * ratio).quantize(Decimal("0.00000001"))
            _logger.debug(
                f"[AML] Address {address}: ratio={ratio}, calculated amount={amount}"
            )

        if amount <= 0:
            _logger.warning(f"[AML] Calculated amount <= 0 for {address}, skipping")
            continue

        payout_list.append((address, amount, ratio))

        total_assigned += amount
        _logger.debug(
            f"[AML] Added to payout list: {address} -> {amount} (total_assigned={total_assigned})"
        )

    if not payout_list:
        _logger.warning(f"[AML] No valid payouts generated")
        return False

    new_payouts = [p for p in payout_list if p[0] not in addresses_done]
    _logger.info(
        f"[AML] Payout list built: {len(new_payouts)} new payouts totaling {total_assigned}"
    )

    for idx, (addr, amt, ratio) in enumerate(new_payouts):
        _logger.info(
            f"[AML] Payout {idx + 1}/{len(new_payouts)}: address={addr}, amount={amt}, ratio={ratio}"
        )

    return new_payouts or False
