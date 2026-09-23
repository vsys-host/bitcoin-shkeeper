from app.lib.services.services import Service
from app.lib.values import Value

from ..config import config


class NodeService:
    def _build_service(self):
        return Service(config['COIN_NETWORK'])

    def delta_synced_block(self):
        return self._build_service().synced_status()

    def getblockchaininfo(self):
        return self._build_service().getblockchaininfo()

    def get_last_block_number(self):
        return self._build_service().blockcount()

    def get_transaction_price(self):
        network_fee = self._build_service().estimatefee()
        return Value.from_satoshi(network_fee).value

    def get_confirmations(self, txid):
        try:
            raw = self._build_service().getverbosetransaction(txid)
        except Exception:
            return None
        if not isinstance(raw, dict):
            return None
        return int(raw.get("confirmations") or 0)
