from sqlalchemy import exists

from app.lib.values import Value

from ..models import DbKey, DbTransaction, DbWallet, db
from . import store as store_service
from .node import NodeService


def _is_wallet_spend(txs):
    """True for our payouts so external outputs stay category=send.

    Incoming payments have foreign inputs: do not treat payer change as send.
    If inputs are missing (3ecce35 / send-all), keep reporting send.
    VIN may live in another store wallet, so address lookup is not scoped
    by the current wallet_id.
    """
    input_addresses = []
    saw_input = False
    for tx in txs:
        for inp in getattr(tx, "inputs", None) or []:
            saw_input = True
            if getattr(inp, "key_id", None) is not None:
                return True
            addr = getattr(inp, "address", None)
            if isinstance(addr, str) and addr:
                input_addresses.append(addr)
    if not saw_input:
        return True
    if not input_addresses:
        return False
    return bool(
        db.session.query(exists().where(DbKey.address.in_(input_addresses))).scalar()
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

        confirmations = wallet_confirmations
        if node_confirmations is not None:
            confirmations = max(confirmations, node_confirmations)

        return {
            "txid": txid_hex,
            "confirmations": confirmations,
            "details": send_details + receive_details,
        }
