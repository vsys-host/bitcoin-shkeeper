from sqlalchemy import and_, exists

from app.lib.values import Value

from ..models import DbKey, DbTransaction, DbWallet, db
from . import store as store_service
from .node import NodeService


def _has_owned_output(txs):
    return any(
        getattr(out, "key_id", None) is not None
        for tx in txs
        for out in (getattr(tx, "outputs", None) or [])
    )


def _is_wallet_spend(txs):
    """True for our payouts so external outputs stay category=send.

    Incoming payments have foreign inputs: do not treat payer change as send.
    If inputs are missing, only treat the tx as a spend when there is no
    wallet-owned output (send-all). An incoming payment with unsaved vins
    still has an owned invoice output and must stay category=receive.
    Address fallback is limited to wallets that own these tx rows so a
    cross-store payment is not treated as this store's send.
    """
    input_addresses = []
    saw_input = False
    wallet_ids = {
        tx.wallet_id for tx in txs if getattr(tx, "wallet_id", None) is not None
    }
    for tx in txs:
        for inp in getattr(tx, "inputs", None) or []:
            saw_input = True
            if getattr(inp, "key_id", None) is not None:
                return True
            addr = getattr(inp, "address", None)
            if isinstance(addr, str) and addr:
                input_addresses.append(addr)
    if not saw_input:
        return not _has_owned_output(txs)
    if not input_addresses or not wallet_ids:
        return False
    return bool(
        db.session.query(
            exists().where(
                and_(
                    DbKey.address.in_(input_addresses),
                    DbKey.wallet_id.in_(wallet_ids),
                )
            )
        ).scalar()
    )


class TransactionLookupService:
    def get_txs_by_txid(self, txid_hex, store_id):
        store_id = store_service.parse_store_id(store_id, required=True)
        txid_bytes = bytes.fromhex(txid_hex)
        return (
            db.session.query(DbTransaction)
            .join(DbWallet, DbTransaction.wallet_id == DbWallet.id)
            .filter(
                DbTransaction.txid == txid_bytes,
                DbWallet.store_id == store_id,
            )
            .order_by(DbTransaction.id.asc())
            .all()
        )

    def get_tx_by_txid(self, txid_hex, store_id):
        txs = self.get_txs_by_txid(txid_hex, store_id)
        return txs[0] if txs else None

    def get_transaction(self, txid_hex, store_id):
        store_id = store_service.parse_store_id(store_id, required=True)
        txs = self.get_txs_by_txid(txid_hex, store_id)
        node_confirmations = NodeService().get_confirmations(txid_hex)
        if not txs:
            if node_confirmations is None:
                return None
            return {
                "txid": txid_hex,
                "confirmations": node_confirmations,
                "details": [],
            }

        is_outgoing = _is_wallet_spend(txs)
        send_details = []
        receive_details = []
        seen_outputs = set()
        wallet_confirmations = 0
        for tx in txs:
            wallet_confirmations = max(
                wallet_confirmations, getattr(tx, "confirmations", 0) or 0
            )
            for out in tx.outputs:
                dedupe_key = (out.key_id, out.output_n)
                if dedupe_key in seen_outputs:
                    continue
                seen_outputs.add(dedupe_key)
                if out.key_id is not None:
                    if is_outgoing:
                        continue
                    receive_details.append({
                        "address": out.address,
                        "amount": Value.from_satoshi(out.value).value,
                        "category": "receive",
                    })
                elif is_outgoing:
                    send_details.append({
                        "address": out.address,
                        "amount": Value.from_satoshi(out.value).value,
                        "category": "send",
                    })

        confirmations = (
            node_confirmations
            if node_confirmations is not None
            else wallet_confirmations
        )

        return {
            "txid": txid_hex,
            "confirmations": confirmations,
            "details": send_details + receive_details,
        }
