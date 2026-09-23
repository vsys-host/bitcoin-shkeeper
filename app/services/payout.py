import decimal

from app.config import COIN
from app.lib.keys import deserialize_address
from app.lib.values import decimal_value_to_satoshi, sat_per_kb_to_sat_per_vbyte

from ..logging import logger
from .node import NodeService
from .wallet import WalletService
from . import store as store_service

# Relay dust by scriptPubKey type. BTC: Core 3 sat/vB. LTC Core uses 10x
# (DUST_RELAY_TX_FEE 30_000). DOGE hard dust is 0.001 DOGE, not script-based.
_BTC_RELAY_DUST_BY_SCRIPT = {
    "p2wpkh": 294,
    "p2wsh": 330,
    "p2tr": 330,
    "p2sh": 540,
    "p2sh_p2wpkh": 540,
    "p2sh_p2wsh": 540,
    "p2pkh": 546,
}
_LTC_RELAY_DUST_BY_SCRIPT = {
    script: amount * 10 for script, amount in _BTC_RELAY_DUST_BY_SCRIPT.items()
}
_DOGE_HARD_DUST_SATOSHI = 100_000
_DUST_BY_COIN = {
    "BTC": _BTC_RELAY_DUST_BY_SCRIPT,
    "LTC": _LTC_RELAY_DUST_BY_SCRIPT,
}
# Typical 1-in 2-out p2wpkh size used when a UTXO dry-run is impossible.
# Keep `fee` in satoshis (total), never a sat/kB rate.
_TYPICAL_PAYOUT_VBYTES = 226


def relay_dust_satoshi(address, fallback=1000, coin=None):
    coin = coin or COIN
    if coin == "DOGE":
        return _DOGE_HARD_DUST_SATOSHI
    table = _DUST_BY_COIN.get(coin)
    if not table:
        return int(fallback)
    try:
        script_type = deserialize_address(address)["script_type"]
    except Exception:
        return int(fallback)
    return table.get(script_type, int(fallback))


def coin_fee_from_sat_per_vbyte(fee):
    if fee in (None, "", 0, 0.0, "0"):
        return decimal.Decimal(0)
    value = decimal.Decimal(str(fee))
    return value * decimal.Decimal(1000) / decimal.Decimal(100_000_000)


def _total_fee_from_feerate(sat_per_kb):
    sat_per_vbyte = sat_per_kb_to_sat_per_vbyte(int(sat_per_kb or 0))
    if sat_per_vbyte <= 0:
        return int(sat_per_kb or 0)
    return int(sat_per_vbyte) * _TYPICAL_PAYOUT_VBYTES


def _clamp_fee_per_kb(hd_wallet, fee_per_kb):
    selected = int(fee_per_kb or 0)
    fee_min = getattr(getattr(hd_wallet, "network", None), "fee_min", None)
    try:
        fee_min = int(fee_min)
    except (TypeError, ValueError):
        return selected
    return max(selected, fee_min)


class PayoutService:
    def __init__(self, wallet_service=None, node_service=None):
        self.wallet = wallet_service or WalletService()
        self.node = node_service or NodeService()

    def estimate_tx_fee(self, amount, store_id=None, dest=None):
        sat_per_kb = int(decimal_value_to_satoshi(self.node.get_transaction_price()))
        sat_per_vbyte = sat_per_kb_to_sat_per_vbyte(sat_per_kb)
        total_fee = self._estimate_payout_fee_sats(amount, store_id, dest, sat_per_kb)
        return {
            "accounts_num": 1,
            "fee": int(total_fee),
            "fee_satoshi": int(sat_per_vbyte),
        }

    def _estimate_payout_fee_sats(self, amount, store_id, dest, sat_per_kb):
        fallback = _total_fee_from_feerate(sat_per_kb)
        try:
            amount_sats = int(decimal_value_to_satoshi(amount))
        except Exception as exc:
            logger.warning("estimate_tx_fee bad amount %s: %s", amount, exc)
            return fallback
        if amount_sats <= 0:
            return fallback

        store_id = store_service.parse_store_id(store_id)
        store_keys = store_service.store_address_keys(store_id)
        change_key = store_service.pick_change_key(store_keys) if store_keys else None
        hd_wallet = self.wallet.current_wallet(store_id=store_id)
        if not hd_wallet or not store_keys or not change_key:
            logger.warning(
                "estimate_tx_fee using size-based fee: wallet/keys missing store_id=%s",
                store_id,
            )
            return fallback

        dummy_dest = dest if dest and self.wallet.is_valid_address(dest) else change_key.address
        if not dummy_dest:
            return fallback

        previous_anti_fee_sniping = getattr(hd_wallet, "anti_fee_sniping", True)
        hd_wallet.anti_fee_sniping = False
        try:
            input_key_ids = [key.id for key in store_keys]
            fee_per_kb = sat_per_kb if sat_per_kb > 0 else None
            fee_per_kb = _clamp_fee_per_kb(hd_wallet, fee_per_kb)

            fee = self._dry_run_payout_fee(
                hd_wallet, dummy_dest, amount_sats, fee_per_kb, input_key_ids, change_key.id
            )
            if fee is None and sat_per_kb and amount_sats > sat_per_kb:
                fee = self._dry_run_payout_fee(
                    hd_wallet,
                    dummy_dest,
                    amount_sats - sat_per_kb,
                    fee_per_kb,
                    input_key_ids,
                    change_key.id,
                )
            return fee if fee is not None else fallback
        finally:
            hd_wallet.anti_fee_sniping = previous_anti_fee_sniping

    def _dry_run_payout_fee(
        self, hd_wallet, dest, dest_sats, fee_per_kb, input_key_ids, change_key_id
    ):
        try:
            tx = hd_wallet.transaction_create(
                [(dest, dest_sats)],
                fee_per_kb=fee_per_kb,
                input_key_id=input_key_ids,
                change_key_id=change_key_id,
                random_output_order=False,
                number_of_change_outputs=1,
            )
        except Exception as exc:
            logger.warning(
                "estimate_tx_fee dry-run failed dest_sats=%s: %s", dest_sats, exc
            )
            return None
        return int(tx.fee or 0)

    def make_multipayout(self, payout_list, coin_fee, store_id=None):
        logger.warning(f'make_multipayout wallets {payout_list}')
        logger.warning(f'make_multipayout {coin_fee}')
        fee_per_kb = int(decimal_value_to_satoshi(decimal.Decimal(str(coin_fee or 0))))
        logger.warning(f'make_multipayout fee_per_kb {fee_per_kb}')
        store_id = store_service.parse_store_id(store_id)
        store_keys = store_service.store_address_keys(store_id)
        if not store_keys:
            raise Exception(f"No keys found for store_id={store_id}")
        input_key_ids = [key.id for key in store_keys]
        change_key = store_service.pick_change_key(store_keys)
        if not change_key:
            raise Exception(f"No change key found for store_id={store_id}")

        hd_wallet = self.wallet.current_wallet(store_id=store_id)
        if not hd_wallet:
            raise Exception(f"No wallet found for store_id={store_id}")
        dust_fallback = int(hd_wallet.network.dust_amount)

        transfers = []
        skipped = []
        for payout in payout_list:
            address = self._payout_dest(payout)
            if not self.wallet.is_valid_address(address):
                raise Exception(f"Address {address} is not valid address")
            amount = decimal.Decimal(str(payout['amount']))
            satoshi = decimal_value_to_satoshi(amount)
            dust_limit = relay_dust_satoshi(address, fallback=dust_fallback)
            if satoshi < dust_limit:
                skipped.append({
                    "dest": address,
                    "amount": float(amount),
                    "status": "error",
                    "error": (
                        f"Output {address} amount {satoshi} sat is below dust "
                        f"limit ({dust_limit} sat) and will not be relayed"
                    ),
                })
                continue
            transfers.append({
                "dest": address,
                "amount": amount,
                "satoshi": satoshi,
            })
        if not transfers:
            raise Exception(
                skipped[0]["error"] if skipped else "No outputs to send"
            )

        network_fee = decimal.Decimal(str(self.node.get_transaction_price()))
        logger.warning("make_multipayout network_fee get_transaction_price %s", network_fee)
        network_fee_per_kb = int(decimal_value_to_satoshi(network_fee))
        logger.warning(f'make_multipayout network_fee_per_kb {network_fee_per_kb}')

        network_fee_per_kb = _clamp_fee_per_kb(
            hd_wallet, fee_per_kb or network_fee_per_kb
        )
        logger.warning(f'make_multipayout using fee_per_kb {network_fee_per_kb}')

        output_arr = [(t["dest"], t["satoshi"]) for t in transfers]
        try:
            tx = hd_wallet.send(
                output_arr,
                fee_per_kb=network_fee_per_kb,
                input_key_id=input_key_ids,
                change_key_id=change_key.id,
            )
            txid = self._broadcast_payout_tx(tx)
            payout_results = [
                {
                    "dest": t["dest"],
                    "amount": float(t["amount"]),
                    "status": "success",
                    "txids": [txid],
                }
                for t in transfers
            ] + skipped
        except Exception as e:
            logger.warning(f"Submit failed: {e}")
            payout_results = [
                {
                    "dest": t["dest"],
                    "amount": float(t["amount"]),
                    "status": "error",
                    "error": str(e),
                }
                for t in transfers
            ] + skipped

        logger.warning(f'payout_results wallets {payout_results}')
        return payout_results

    def assert_sources_belong_to_store(self, payout_list, store_id):
        store_id = store_service.parse_store_id(store_id)
        for payout in payout_list:
            source = payout.get("source") if isinstance(payout, dict) else None
            if not source:
                continue
            key = store_service.store_key_by_address(store_id, source)
            if key:
                continue
            if store_service.address_is_known(source):
                raise Exception(
                    f"Source address '{source}' does not belong to store_id={store_id}"
                )

    def withdraw_to_external_wallet_task(self, payout_list, store_id=None):
        logger.warning(f'withdraw_to_external_wallet_task wallets {payout_list}')
        store_id = store_service.parse_store_id(store_id)
        payout_results = []

        for payout in payout_list:
            source = payout.get('source')
            dest = payout.get('dest')

            if not source or not self.wallet.is_valid_address(source):
                raise Exception(f"Source address '{source}' is not valid in payout {payout}")
            if not dest or not self.wallet.is_valid_address(dest):
                raise Exception(f"Destination address '{dest}' is not valid in payout {payout}")

            key = store_service.store_key_by_address(store_id, source)
            if not key:
                raise Exception(f"Source address '{source}' not found")

            hd_wallet = self.wallet.current_wallet(store_id=store_id)
            if not hd_wallet:
                raise Exception(f"No wallet found for source address '{source}'")
            tx = hd_wallet.sweep(dest, input_key_id=key.id)
            payout_results.append(self._send_payout_tx(
                tx,
                success_fields={
                    "source": source,
                    "dest": dest,
                },
                error_fields={
                    "source": source,
                    "dest": dest,
                },
                error_log=lambda exc, src=source, dst=dest: f"Submit failed for {src} -> {dst}: {exc}",
            ))

        logger.warning(f'payout_results wallets {payout_results}')
        return payout_results

    def _payout_dest(self, payout):
        return payout.get('dest') or payout.get('destination')

    @staticmethod
    def _broadcast_payout_tx(tx):
        tx.send()
        error = getattr(tx, "error", None)
        if isinstance(error, str) and error:
            raise Exception(error)
        return str(tx)

    def _send_payout_tx(self, tx, success_fields, error_fields, error_log):
        try:
            txid = self._broadcast_payout_tx(tx)
            return {
                **success_fields,
                "status": "success",
                "txids": [txid],
            }
        except Exception as e:
            logger.warning(error_log(e))
            return {
                **error_fields,
                "status": "error",
                "error": str(e),
            }
