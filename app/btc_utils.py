import re
import base58

class BTCUtils:
    # MAINNET_PREFIXES = ("1", "3", "bc1")
    # TESTNET_PREFIXES = ("m", "n", "2", "tb1")

    @staticmethod
    def is_valid_btc_address(address: str) -> bool:
        if address.lower().startswith(("bc1", "tb1")):
            return BTCUtils._validate_bech32(address)
        try:
            decoded = base58.b58decode_check(address)
            prefix = address[0]
            if prefix in ("1", "3", "m", "n", "2"):
                return True
        except Exception:
            return False
        return False

    @staticmethod
    def _validate_bech32(address: str) -> bool:
        if re.match(r'^(bc1|BC1|tb1|TB1)[0-9a-zA-Z]{6,87}$', address):
            return True
        return False