import json
from app.lib.encoding import *
from app.config import config, COIN

_logger = logging.getLogger(__name__)

class NetworkError(Exception):
    def __init__(self, msg=''):
        self.msg = msg
        _logger.error(msg)

    def __str__(self):
        return self.msg

def _read_network_definitions():
    fn = Path("app/lib/data", 'networks.json')
    f = fn.open('rb')
    try:
        network_definitions = json.loads(f.read())
    except json.decoder.JSONDecodeError as e:
        raise NetworkError("Error reading provider definitions from %s: %s" % (fn, e))
    f.close()
    return network_definitions


NETWORK_DEFINITIONS = {
    config["COIN_NETWORK"]: _read_network_definitions()[COIN][config["COIN_NETWORK"]]
}

def _format_value(field, value):
    if field[:6] == 'prefix':
        return bytes.fromhex(value)
    elif field == 'denominator':
        return float(value)
    else:
        return value


def network_values_for(field):
    return list(dict.fromkeys([_format_value(field, nv[field]) for nv in NETWORK_DEFINITIONS.values()]))

def network_by_value(field, value):
    nws = [(nv, NETWORK_DEFINITIONS[nv]['priority'])
           for nv in NETWORK_DEFINITIONS if NETWORK_DEFINITIONS[nv][field] == value]
    if not nws:
        try:
            value = value.upper()
        except TypeError:
            pass
        nws = [(nv, NETWORK_DEFINITIONS[nv]['priority'])
               for nv in NETWORK_DEFINITIONS if NETWORK_DEFINITIONS[nv][field] == value]
    return [nw[0] for nw in sorted(nws, key=lambda x: x[1], reverse=True)]

def network_defined(network):
    if network not in list(NETWORK_DEFINITIONS.keys()):
        return False
    return True

def wif_prefix_search(wif, witness_type=None, network=None):
    key_hex = wif
    if len(wif) > 8:
        try:
            key_hex = change_base(wif, 58, 16)
        except Exception:
            pass
    prefix = key_hex[:8].upper()
    matches = []
    for nw in NETWORK_DEFINITIONS:
        if network is not None and nw != network:
            continue
        data = NETWORK_DEFINITIONS[nw]
        for pf in data['prefixes_wif']:
            if pf[0] == prefix and (pf[3] is None or pf[3] == False) and \
                    (witness_type is None or pf[4] is None or pf[4] == witness_type):
                matches.append({
                    'prefix': prefix,
                    'is_private': True if pf[2] == 'private' else False,
                    'prefix_str': pf[1],
                    'network': nw,
                    'witness_type': pf[4],
                    'script_type': pf[5]
                })
    return matches


class Network(object):
    def __init__(self, network_name=DEFAULT_NETWORK):
        if network_name not in NETWORK_DEFINITIONS:
            raise NetworkError("Network %s not found in network definitions" % network_name)
        self.name = network_name

        self.currency_name = NETWORK_DEFINITIONS[network_name]['currency_name']
        self.currency_name_plural = NETWORK_DEFINITIONS[network_name]['currency_name_plural']
        self.currency_code = NETWORK_DEFINITIONS[network_name]['currency_code']
        self.currency_symbol = NETWORK_DEFINITIONS[network_name]['currency_symbol']
        self.description = NETWORK_DEFINITIONS[network_name]['description']
        self.prefix_address_p2sh = bytes.fromhex(NETWORK_DEFINITIONS[network_name]['prefix_address_p2sh'])
        self.prefix_address = bytes.fromhex(NETWORK_DEFINITIONS[network_name]['prefix_address'])
        self.prefix_bech32 = NETWORK_DEFINITIONS[network_name]['prefix_bech32']
        self.prefix_wif = bytes.fromhex(NETWORK_DEFINITIONS[network_name]['prefix_wif'])
        self.denominator = NETWORK_DEFINITIONS[network_name]['denominator']
        self.bip44_cointype = NETWORK_DEFINITIONS[network_name]['bip44_cointype']
        self.dust_amount = NETWORK_DEFINITIONS[network_name]['dust_amount']  # Dust amount in satoshi
        self.fee_default = NETWORK_DEFINITIONS[network_name]['fee_default']  # Default fee in satoshi per kilobyte
        self.fee_min = NETWORK_DEFINITIONS[network_name]['fee_min']  # Minimum transaction fee in satoshi per kilobyte
        self.fee_max = NETWORK_DEFINITIONS[network_name]['fee_max']  # Maximum transaction fee in satoshi per kilobyte
        self.priority = NETWORK_DEFINITIONS[network_name]['priority']
        self.prefixes_wif = NETWORK_DEFINITIONS[network_name]['prefixes_wif']

    def __repr__(self):
        return "<Network: %s>" % self.name

    def __eq__(self, other):
        if isinstance(other, str):
            return self.name == other
        return self.name == other.name

    def __hash__(self):
        return hash(self.name)

    def wif_prefix(self, is_private=False, witness_type='legacy'):
        script_type = script_type_default(witness_type, locking_script=True)
        if script_type == 'p2sh' and witness_type in ['p2sh-segwit', 'segwit']:
            script_type = 'p2sh_p2wpkh'
        if is_private:
            ip = 'private'
        else:
            ip = 'public'
        found_prefixes = [bytes.fromhex(pf[0]) for pf in self.prefixes_wif if pf[2] == ip and script_type == pf[5]]
        if found_prefixes:
            return found_prefixes[0]
        else:
            raise NetworkError("WIF Prefix for script type %s not found" % script_type)
