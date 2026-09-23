from flask import g, jsonify, request

from app.logging import logger
from app.services import NodeService, TransactionLookupService, WalletService
from app.services import store as store_service
from app.utils import _json_error, block_during_migration

from . import api


def _json():
    payload = request.get_json(silent=True)
    return payload if isinstance(payload, dict) else {}


def _request_store_id(*, required=True):
    return store_service.parse_store_id(_json().get("store_id"), required=required)


@api.post("/generate-address")
@block_during_migration
def generate_new_address():
    logger.warning("generate-address request started for symbol=%s", g.symbol)
    try:
        store_id = _request_store_id()
    except ValueError as exc:
        return {"status": "error", "msg": str(exc)}, 400

    new_address = WalletService().generate_address(store_id=store_id)
    logger.warning("generate-address request result symbol=%s address=%s", g.symbol, new_address)
    if not new_address:
        logger.error("Failed to generate address for symbol=%s", g.symbol)
        return jsonify({
            'status': 'error',
            'message': 'Failed to generate address'
        }), 500
    return {'status': 'success', 'address': new_address}


@api.post('/balance')
def get_balance():
    try:
        store_id = _request_store_id()
        balance = WalletService().get_store_balance(store_id=store_id)
    except ValueError as exc:
        logger.warning("Balance request failed for %s: %s", getattr(g, "symbol", "?"), exc)
        return {"status": "error", "msg": str(exc)}, 400
    except PermissionError as exc:
        msg = str(exc)
        status = 503 if "locked" in msg.lower() else 403
        return _json_error(msg, status)
    return {'status': 'success', 'balance': balance}


@api.post('/status')
@block_during_migration
def get_status():
    delta_blocks = NodeService().delta_synced_block()
    return {'status': 'success', 'delta_blocks': delta_blocks}


@api.post('/transaction/<txid>')
def get_transaction(txid):
    try:
        store_id = _request_store_id()
    except ValueError as exc:
        return {"status": "error", "msg": str(exc)}, 400

    transaction = TransactionLookupService().get_transaction(txid, store_id=store_id)
    if not transaction:
        logger.error(f"Cannot receive outputs {txid}: {transaction}")
        return []

    confirmations = transaction.get("confirmations") or 0
    related_transactions = [
        [
            detail.get("address"),
            detail.get('amount', 0),
            confirmations,
            detail.get("category", "change"),
        ]
        for detail in transaction.get("details", [])
    ]

    if not related_transactions:
        logger.warning(
            "txid %s has no wallet-owned outputs for store_id=%s; returning confirmations=%s",
            txid,
            store_id,
            confirmations,
        )
        return [["", 0, confirmations, "change"]]

    logger.debug(related_transactions)
    return related_transactions


@api.post('/dump')
def dump():
    try:
        store_id = _request_store_id()
        return WalletService().get_dump(store_id=store_id, scoped=True)
    except ValueError as exc:
        return {"status": "error", "msg": str(exc)}, 400
    except PermissionError as exc:
        msg = str(exc)
        status = 503 if "locked" in msg.lower() else 403
        return _json_error(msg, status)


@api.post('/fee-deposit-account')
def get_fee_deposit_account():
    # Kept for shkeeper UI compatibility. UTXO has no FDA — return store balance
    # and the first address belonging to the store (may be empty).
    try:
        store_id = _request_store_id()
        wallet = WalletService()
        return {
            'account': wallet.first_store_address(store_id=store_id),
            'balance': wallet.get_store_balance(store_id=store_id),
        }
    except ValueError as exc:
        return {"status": "error", "msg": str(exc)}, 400
    except PermissionError as exc:
        msg = str(exc)
        status = 503 if "locked" in msg.lower() else 403
        return _json_error(msg, status)


@api.post('/get_all_addresses')
def get_all_addresses():
    try:
        store_id = _request_store_id()
    except ValueError as exc:
        return {"status": "error", "msg": str(exc)}, 400
    return WalletService().get_all_accounts(store_id=store_id)
