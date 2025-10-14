import hmac
import random
import collections
import json
from app.lib.networks import Network, network_by_value, wif_prefix_search
from app.lib.config.secp256k1 import *
from app.lib.encoding import *
rfc6979_warning_given = False
from fastecdsa import _ecdsa
from fastecdsa.util import RFC6979
from fastecdsa.curve import secp256k1 as fastecdsa_secp256k1
from fastecdsa import keys as fastecdsa_keys
from fastecdsa import point as fastecdsa_point
_logger = logging.getLogger(__name__)


class BKeyError(Exception):
    def __init__(self, msg=''):
        self.msg = msg
        _logger.error(msg)

    def __str__(self):
        return self.msg


def check_network_and_key(key, network=None, kf_networks=None, default_network=DEFAULT_NETWORK):
    if not kf_networks:
        kf = get_key_format(key)
        if kf['networks']:
            kf_networks = kf['networks']
    if kf_networks:
        if network is not None and network not in kf_networks:
            raise BKeyError("Specified key %s is from different network then specified: %s" % (kf_networks, network))
        elif network is None and len(kf_networks) == 1:
            return kf_networks[0]
        elif network is None and len(kf_networks) > 1:
            if default_network in kf_networks:
                return default_network
            elif 'testnet' in kf_networks:
                return 'testnet'
            raise BKeyError("Could not determine network of specified key, multiple networks found: %s" % kf_networks)
    if network is None:
        return default_network
    else:
        return network

def get_key_format(key, is_private=None):
    if not key:
        raise BKeyError("Key empty, please specify a valid key")
    key_format = ""
    networks = None
    script_types = []
    witness_types = [DEFAULT_WITNESS_TYPE]
    if not (is_private is None or isinstance(is_private, bool)):
        raise BKeyError("Attribute 'is_private' must be False or True")
    elif isinstance(key, numbers.Number):
        key_format = 'decimal'
        is_private = True
    elif isinstance(key, bytes) and len(key) in [33, 65] and key[:1] in [b'\2', b'\3']:
        key_format = 'bin_compressed'
        is_private = False
    elif isinstance(key, bytes) and (len(key) in [33, 65] and key[:1] == b'\4'):
        key_format = 'bin'
        is_private = False
    elif isinstance(key, bytes) and len(key) == 33 and key[-1:] == b'\1':
        key_format = 'bin_compressed'
        is_private = True
    elif isinstance(key, bytes) and len(key) == 32:
        key_format = 'bin'
        is_private = True
    elif isinstance(key, tuple):
        key_format = 'point'
        is_private = False
    elif len(key) == 130 and key[:2] == '04' and not is_private:
        key_format = 'public_uncompressed'
        is_private = False
    elif len(key) == 128:
        key_format = 'hex'
        if is_private is None:
            is_private = True
    elif len(key) == 66 and key[:2] in ['02', '03'] and not is_private:
        key_format = 'public'
        is_private = False
    elif len(key) == 64:
        key_format = 'hex'
        if is_private is None:
            is_private = True
    elif len(key) == 66 and key[-2:] in ['01'] and not (is_private is False):
        key_format = 'hex_compressed'
        is_private = True
    elif len(key) == 58 and key[:2] == '6P':
        key_format = 'wif_protected'
        is_private = True
    elif isinstance(key, TYPE_TEXT) and len(key.split(' ')) > 1:
        key_format = 'mnemonic'
        is_private = True
    else:
        try:
            key_hex = change_base(key, 58, 16)
            prefix_data = wif_prefix_search(key_hex[:8])
            if prefix_data:
                networks = list(dict.fromkeys([n['network'] for n in prefix_data]))
                if is_private is None and len(set([n['is_private'] for n in prefix_data])) > 1:
                    raise BKeyError("Cannot determine if key is private or public, please specify is_private "
                                    "attribute")
                is_private = prefix_data[0]['is_private']
                script_types = list(dict.fromkeys([n['script_type'] for n in prefix_data]))
                witness_types = list(dict.fromkeys([n['witness_type'] for n in prefix_data]))
                key_format = 'hdkey_public'
                if is_private:
                    key_format = 'hdkey_private'
            else:
                networks = network_by_value('prefix_wif', key_hex[:2])
                if networks:
                    if key_hex[-10:-8] == '01':
                        key_format = 'wif_compressed'
                    else:
                        key_format = 'wif'
                    is_private = True
        except (TypeError, EncodingError):
            pass
    if not key_format:
        try:
            int(key)
            if 70 < len(key) < 78:
                key_format = 'decimal'
                is_private = True
        except (TypeError, ValueError):
            pass
    if not key_format:
        try:
            da = deserialize_address(key)
            key_format = 'address'
            networks = da['network']
            is_private = False
            script_types = da['script_type']
        except (EncodingError, TypeError):
            pass
    if not key_format:
        raise BKeyError("Unrecognised key format")
    else:
        return {
            "format": key_format,
            "networks": networks,
            "is_private": is_private,
            "script_types": script_types,
            "witness_types": witness_types
        }

def deserialize_address(address, encoding=None, network=None):
    if encoding is None or encoding == 'base58':
        try:
            address_bytes = change_base(address, 58, 256, 25)
        except EncodingError:
            pass
        else:
            check = address_bytes[-4:]
            key_hash = address_bytes[:-4]
            checksum = double_sha256(key_hash)[0:4]
            if check != checksum and encoding == 'base58':
                raise BKeyError("Invalid address %s, checksum incorrect" % address)
            elif check == checksum:
                address_prefix = key_hash[0:1]
                networks_p2pkh = network_by_value('prefix_address', address_prefix.hex())
                networks_p2sh = network_by_value('prefix_address_p2sh', address_prefix.hex())
                public_key_hash = key_hash[1:]
                script_type = ''
                witness_type = ''
                networks = []
                if networks_p2pkh and not networks_p2sh:
                    script_type = 'p2pkh'
                    witness_type = 'legacy'
                    networks = networks_p2pkh
                elif networks_p2sh:
                    script_type = 'p2sh'
                    networks = networks_p2sh
                if network:
                    if network not in networks:
                        raise BKeyError("Network %s not found in extracted networks: %s" % (network, networks))
                elif len(networks) >= 1:
                    network = networks[0]
                return {
                    'address': address,
                    'encoding': 'base58',
                    'public_key_hash': '' if not public_key_hash else public_key_hash.hex(),
                    'public_key_hash_bytes': public_key_hash,
                    'prefix': address_prefix,
                    'network': network,
                    'script_type': script_type,
                    'witness_type': witness_type,
                    'networks': networks,
                    'checksum': checksum,
                    'witver': None,
                    'raw': address_bytes,
                }
    if encoding == 'bech32' or encoding is None:
        try:
            pkh_incl = addr_bech32_to_pubkeyhash(address, include_witver=True)
            public_key_hash = pkh_incl[2:]
            witver = pkh_incl[0] - 0x50 if pkh_incl[0] else 0
            prefix = address[:address.rfind('1')]
            networks = network_by_value('prefix_bech32', prefix)
            witness_type = 'segwit' if not witver else 'taproot'

            if len(public_key_hash) == 20:
                script_type = 'p2wpkh'
            else:
                script_type = 'p2wsh' if not witver else 'p2tr'
            return {
                'address': address,
                'encoding': 'bech32',
                'public_key_hash': '' if not public_key_hash else public_key_hash.hex(),
                'public_key_hash_bytes': public_key_hash,
                'prefix': prefix,
                'network': '' if not networks else networks[0],
                'script_type': script_type,
                'witness_type': witness_type,
                'networks': networks,
                'checksum': addr_bech32_checksum(address),
                'witver': witver,
                'raw': pkh_incl,
            }
        except EncodingError as err:
            raise EncodingError("Invalid address %s: %s" % (address, err))
    else:
        raise EncodingError("Address %s is not in specified encoding %s" % (address, encoding))


def addr_convert(addr, prefix, encoding=None, to_encoding=None):
    if encoding is None:
        da = deserialize_address(addr)
        encoding = da['encoding']
    pkh = addr_to_pubkeyhash(addr, encoding=encoding)
    if to_encoding is None:
        to_encoding = encoding
    if isinstance(prefix, TYPE_TEXT) and to_encoding == 'base58':
        prefix = to_hexstring(prefix)
    return pubkeyhash_to_addr(pkh, prefix=prefix, encoding=to_encoding)


def path_expand(path, path_template=None, level_offset=None, account_id=0, purpose=84,
                address_index=0, change=0, witness_type=DEFAULT_WITNESS_TYPE, network=DEFAULT_NETWORK):
    if isinstance(path, TYPE_TEXT):
        path = path.split('/')
    if not path_template:
        path_template, purpose, _ = get_key_structure_data(witness_type)
    if not isinstance(path, list):
        raise BKeyError("Please provide path as list with at least 1 item. Wallet key path format is %s" %
                        path_template)
    if len(path) > len(path_template):
        raise BKeyError("Invalid path provided. Path should be shorter than %d items. "
                        "Wallet key path format is %s" % (len(path_template), path_template))

    # If path doesn't start with m/M complement path
    poppath = deepcopy(path)
    if path == [] or path[0] not in ['m', 'M']:
        wallet_key_path = path_template
        if level_offset:
            wallet_key_path = wallet_key_path[:level_offset]
        new_path = []
        for pi in wallet_key_path[::-1]:
            if not len(poppath):
                new_path.append(pi)
            else:
                new_path.append(poppath.pop())
        new_path = new_path[::-1]
    else:
        new_path = deepcopy(path)

    # Replace variable names in path with corresponding values
    # network, account_id, _ = self._get_account_defaults(network, account_id)
    script_type_id = 1 if witness_type == 'p2sh-segwit' else 2
    var_defaults = {
        'network': network,
        'account': account_id,
        'purpose': purpose,
        'coin_type': Network(network).bip44_cointype,
        'script_type': script_type_id,
        'change': change,
        'address_index': address_index
    }
    npath = new_path
    for i, pi in enumerate(new_path):
        if not isinstance(pi, TYPE_TEXT):
            pi = str(pi)
        if pi in "mM":
            continue
        hardened = False
        varname = pi
        if pi[-1:] == "'" or (pi[-1:] in "HhPp" and pi[:-1].isdigit()):
            varname = pi[:-1]
            hardened = True
        if path_template[i][-1:] == "'":
            hardened = True
        new_varname = (str(var_defaults[varname]) if varname in var_defaults else varname)
        if new_varname == varname and not new_varname.isdigit():
            raise BKeyError("Variable %s not found in Key structure definitions in main.py" % varname)
        if varname == 'address_index' and address_index is None:
            raise BKeyError("Please provide value for 'address_index' or 'path'")
        npath[i] = new_varname + ("'" if hardened else '')
    if "None'" in npath or "None" in npath:
        raise BKeyError("Could not parse all variables in path %s" % npath)
    return npath


def bip38_decrypt(encrypted_privkey, password):
    d = change_base(encrypted_privkey, 58, 256)
    identifier = d[0:2]
    flagbyte = d[2:3]
    address_hash: bytes = d[3:7]
    if identifier  == BIP38_EC_MULTIPLIED_PRIVATE_KEY_PREFIX:
        owner_entropy: bytes = d[7:15]
        encrypted_half_1_half_1: bytes = d[15:23]
        encrypted_half_2: bytes = d[23:-4]

        lot_and_sequence = None
        if flagbyte in [BIP38_MAGIC_LOT_AND_SEQUENCE_UNCOMPRESSED_FLAG, BIP38_MAGIC_LOT_AND_SEQUENCE_COMPRESSED_FLAG,
                     b'\x0c', b'\x14', b'\x1c', b'\x2c', b'\x34', b'\x3c']:
            owner_salt: bytes = owner_entropy[:4]
            lot_and_sequence = owner_entropy[4:]
        else:
            owner_salt: bytes = owner_entropy

        pass_factor = scrypt_hash(password, owner_salt, 32, 16384, 8, 8)
        if lot_and_sequence:
            pass_factor: bytes = double_sha256(pass_factor + owner_entropy)
        if int.from_bytes(pass_factor, 'big') == 0 or int.from_bytes(pass_factor, 'big') >= secp256k1_n:
            raise ValueError("Invalid EC encrypted WIF (Wallet Import Format)")

        pre_public_key = HDKey(pass_factor).public_byte
        salt = address_hash + owner_entropy
        encrypted_seed_b: bytes = scrypt_hash(pre_public_key, salt, 64, 1024, 1, 1)
        key: bytes = encrypted_seed_b[32:]

        aes = AES.new(key, AES.MODE_ECB)
        encrypted_half_1_half_2_seed_b_last_3 = (
            int.from_bytes(aes.decrypt(encrypted_half_2), 'big') ^
            int.from_bytes(encrypted_seed_b[16:32], 'big')).to_bytes(16, 'big')
        encrypted_half_1_half_2: bytes = encrypted_half_1_half_2_seed_b_last_3[:8]
        encrypted_half_1: bytes = (
                encrypted_half_1_half_1 + encrypted_half_1_half_2
        )

        seed_b: bytes = ((
            int.from_bytes(aes.decrypt(encrypted_half_1), 'big') ^
            int.from_bytes(encrypted_seed_b[:16], 'big')).to_bytes(16, 'big') +
                         encrypted_half_1_half_2_seed_b_last_3[8:])

        factor_b: bytes = double_sha256(seed_b)
        if int.from_bytes(factor_b, 'big') == 0 or int.from_bytes(factor_b, 'big') >= secp256k1_n:
            raise ValueError("Invalid EC encrypted WIF (Wallet Import Format)")

        private_key = HDKey(pass_factor) * HDKey(factor_b)
        compressed = False
        public_key = private_key.public_uncompressed_hex
        if flagbyte in [BIP38_MAGIC_NO_LOT_AND_SEQUENCE_COMPRESSED_FLAG, BIP38_MAGIC_LOT_AND_SEQUENCE_COMPRESSED_FLAG,
                        b'\x28', b'\x2c', b'\x30', b'\x34', b'\x38', b'\x3c', b'\xe0', b'\xe8', b'\xf0', b'\xf8']:
            public_key: str = private_key.public_compressed_hex
            compressed = True

        address = private_key.address(compressed=compressed)
        address_hash_check = double_sha256(bytes(address, 'utf8'))[:4]
        if address_hash_check != address_hash:
            raise ValueError("Address hash has invalid checksum")
        wif = private_key.wif()
        lot = None
        sequence = None
        if lot_and_sequence:
            sequence = int.from_bytes(lot_and_sequence, 'big') % 4096
            lot = int.from_bytes(lot_and_sequence, 'big') // 4096

        retdict = dict(
            wif=wif,
            private_key=private_key.private_hex,
            public_key=public_key,
            seed=seed_b.hex(),
            address=address,
            lot=lot,
            sequence=sequence
        )
        return private_key.private_byte, address_hash, compressed, retdict
    elif identifier == BIP38_NO_EC_MULTIPLIED_PRIVATE_KEY_PREFIX:
        d = d[3:]
        if flagbyte == b'\xc0':
            compressed = False
        elif flagbyte == b'\xe0' or flagbyte == b'\x20':
            compressed = True
        else:
            raise EncodingError("Unrecognised password protected key format. Flagbyte incorrect.")
        if isinstance(password, str):
            password = password.encode('utf-8')
        addresshash = d[0:4]
        d = d[4:-4]

        key = scrypt_hash(password, addresshash, 64, 16384, 8, 8)
        derivedhalf1 = key[0:32]
        derivedhalf2 = key[32:64]
        encryptedhalf1 = d[0:16]
        encryptedhalf2 = d[16:32]

        # aes = pyaes.AESModeOfOperationECB(derivedhalf2)
        aes = AES.new(derivedhalf2, AES.MODE_ECB)
        decryptedhalf2 = aes.decrypt(encryptedhalf2)
        decryptedhalf1 = aes.decrypt(encryptedhalf1)
        priv = decryptedhalf1 + decryptedhalf2
        priv = (int.from_bytes(priv, 'big') ^ int.from_bytes(derivedhalf1, 'big')).to_bytes(32, 'big')
        return priv, addresshash, compressed, {}
    else:
        raise EncodingError("Unknown BIP38 identifier, value must be 0x0142 (non-EC-multiplied) or "
                            "0x0143 (EC-multiplied)")

def bip38_encrypt(private_hex, address, password, flagbyte=b'\xe0'):
    if isinstance(address, str):
        address = address.encode('utf-8')
    if isinstance(password, str):
        password = password.encode('utf-8')
    addresshash = double_sha256(address)[0:4]
    key = scrypt_hash(password, addresshash, 64, 16384, 8, 8)
    derivedhalf1 = key[0:32]
    derivedhalf2 = key[32:64]
    aes = AES.new(derivedhalf2, AES.MODE_ECB)
    # aes = pyaes.AESModeOfOperationECB(derivedhalf2)
    encryptedhalf1 = \
        aes.encrypt((int(private_hex[0:32], 16) ^ int.from_bytes(derivedhalf1[0:16], 'big')).to_bytes(16, 'big'))
    encryptedhalf2 = \
        aes.encrypt((int(private_hex[32:64], 16) ^ int.from_bytes(derivedhalf1[16:32], 'big')).to_bytes(16, 'big'))
    encrypted_privkey = b'\x01\x42' + flagbyte + addresshash + encryptedhalf1 + encryptedhalf2
    encrypted_privkey += double_sha256(encrypted_privkey)[:4]
    return base58encode(encrypted_privkey)


def bip38_intermediate_password(passphrase, lot=None, sequence=None, owner_salt=os.urandom(8)):
    owner_salt = to_bytes(owner_salt)
    if len(owner_salt) not in [4, 8]:
        raise ValueError(f"Invalid owner salt length (expected: 4 or 8 bytes, got: {len(owner_salt)})")
    if len(owner_salt) == 4 and (not lot or not sequence):
        raise ValueError(f"Invalid owner salt length for non lot/sequence (expected: 8 bytes, got:"
                         f" {len(owner_salt)})")
    if (lot and not sequence) or (not lot and sequence):
        raise ValueError(f"Both lot & sequence are required, got: (lot {lot}) (sequence {sequence})")

    if lot and sequence:
        lot, sequence = int(lot), int(sequence)
        if not 100000 <= lot <= 999999:
            raise ValueError(f"Invalid lot, (expected: 100000 <= lot <= 999999, got: {lot})")
        if not 0 <= sequence <= 4095:
            raise ValueError(f"Invalid lot, (expected: 0 <= sequence <= 4095, got: {sequence})")

        pre_factor = scrypt_hash(unicodedata.normalize("NFC", passphrase), owner_salt[:4], 32, 16384, 8, 8)
        owner_entropy = owner_salt[:4] + int.to_bytes((lot * 4096 + sequence), 4, 'big')
        if isinstance(pre_factor, list):
            for pf in pre_factor:
                print(pf.hex())
            print(len(pre_factor))
        pass_factor = double_sha256(pre_factor + owner_entropy)
        magic = BIP38_MAGIC_LOT_AND_SEQUENCE
    else:
        pass_factor = scrypt_hash(unicodedata.normalize("NFC", passphrase), owner_salt, 32, 16384, 8, 8)
        magic = BIP38_MAGIC_NO_LOT_AND_SEQUENCE
        owner_entropy = owner_salt

    return pubkeyhash_to_addr_base58(magic + owner_entropy + HDKey(pass_factor).public_byte, prefix=b'')

class Address(object):
    @classmethod
    def parse(cls, address, compressed=None, encoding=None, depth=None, change=None,
              address_index=None, network=None, network_overrides=None):
        if encoding is None and address[:3].split("1")[0] in ENCODING_BECH32_PREFIXES:
            encoding = 'bech32'
        addr_dict = deserialize_address(address, encoding=encoding, network=network)
        public_key_hash_bytes = addr_dict['public_key_hash_bytes']
        prefix = addr_dict['prefix']
        if network is None:
            network = addr_dict['network']
        script_type = addr_dict['script_type']
        witness_type = addr_dict['witness_type']
        return Address(hashed_data=public_key_hash_bytes, prefix=prefix, script_type=script_type,
                       witness_type=witness_type, compressed=compressed, encoding=addr_dict['encoding'], depth=depth,
                       change=change, address_index=address_index, network=network, network_overrides=network_overrides)

    def __init__(self, data='', hashed_data='', prefix=None, script_type=None,
                 compressed=None, encoding=None, witness_type=None, witver=0, depth=None, change=None,
                 address_index=None, network=DEFAULT_NETWORK, network_overrides=None):
        self.network = network
        if not (data or hashed_data):
            raise BKeyError("Please specify data (public key or script) or hashed_data argument")
        if not isinstance(network, Network):
            self.network = Network(network)
        self.data_bytes = to_bytes(data)
        self._data = None
        self.script_type = script_type
        self.encoding = encoding
        self.compressed = compressed
        self.witver = witver
        if witness_type is None:
            if self.script_type in ['p2wpkh', 'p2wsh']:
                witness_type = 'segwit'
            elif self.script_type in ['p2sh_p2wpkh', 'p2sh_p2wsh']:
                witness_type = 'p2sh-segwit'
            elif self.script_type == 'p2tr':
                witness_type = 'taproot'
                self.witver = 1 if self.witver == 0 else self.witver
            elif self.encoding == 'base58':
                witness_type = 'legacy'
            else:
                witness_type = 'segwit'
        self.witness_type = witness_type
        self.depth = depth
        self.change = change
        self.address_index = address_index

        if self.encoding is None:
            if (self.script_type in ['p2pkh', 'p2sh', 'p2pk'] or self.witness_type == 'legacy' or
                    self.witness_type == 'p2sh-segwit'):
                self.encoding = 'base58'
            else:
                self.encoding = 'bech32'
        self.hash_bytes = to_bytes(hashed_data)
        self.prefix = prefix
        self.redeemscript = b''
        if not self.hash_bytes:
            if (self.encoding == 'bech32' and self.script_type in ['p2sh', 'p2sh_multisig', 'p2tr']) or \
                    self.script_type in ['p2wsh', 'p2sh_p2wsh']:
                self.hash_bytes = hashlib.sha256(self.data_bytes).digest()
            else:
                self.hash_bytes = hash160(self.data_bytes)
        self._hashed_data = None
        if self.encoding == 'base58':
            if self.script_type is None:
                self.script_type = 'p2pkh'
            if self.witness_type == 'p2sh-segwit':
                self.redeemscript = b'\0' + varstr(self.hash_bytes)
                # overwrite hash_bytes with hash of redeemscript
                self.hash_bytes = hash160(self.redeemscript)
            if self.prefix is None:
                if self.script_type in ['p2sh', 'p2sh_p2wpkh', 'p2sh_p2wsh', 'p2sh_multisig'] or \
                        self.witness_type == 'p2sh-segwit':
                    self.prefix = self.network.prefix_address_p2sh
                else:
                    self.prefix = self.network.prefix_address
            else:
                self.prefix = to_bytes(prefix)
        elif self.encoding == 'bech32':
            if self.script_type is None:
                self.script_type = 'p2wpkh'
            if self.prefix is None:
                self.prefix = self.network.prefix_bech32
        else:
            raise BKeyError("Encoding %s not supported" % self.encoding)
        self.address = pubkeyhash_to_addr(self.hash_bytes, prefix=self.prefix, encoding=self.encoding,
                                          witver=self.witver)
        self.address_orig = None
        provider_prefix = None
        if network_overrides and 'prefix_address_p2sh' in network_overrides and self.script_type == 'p2sh':
            provider_prefix = network_overrides['prefix_address_p2sh']
        self.address_orig = self.address
        if provider_prefix:
            self.address = addr_convert(self.address, provider_prefix)

    def __repr__(self):
        return "<Address(address=%s)>" % self.address

    @property
    def hashed_data(self):
        if not self._hashed_data:
            self._hashed_data = self.hash_bytes.hex()
        return self._hashed_data

    @property
    def data(self):
        if not self._data:
            self._data = self.data_bytes.hex()
        return self._data

    def as_dict(self):
        addr_dict = deepcopy(self.__dict__)
        del (addr_dict['data_bytes'])
        del (addr_dict['hash_bytes'])
        if isinstance(addr_dict['network'], Network):
            addr_dict['network'] = addr_dict['network'].name
        addr_dict['redeemscript'] = addr_dict['redeemscript'].hex()
        addr_dict['prefix'] = addr_dict['prefix']
        return addr_dict

    def as_json(self):
        adict = self.as_dict()
        return json.dumps(adict, indent=4)

    def with_prefix(self, prefix):
        return addr_convert(self.address, prefix)


class Key(object):
    @staticmethod
    def from_wif(wif, network=None):
        key_hex = change_base(wif, 58, 16)
        networks = network_by_value('prefix_wif', key_hex[:2])
        compressed = False
        if networks:
            if key_hex[-10:-8] == '01':
                compressed = True
            network = network or next(iter(networks), DEFAULT_NETWORK)
        else:
            raise BKeyError("Could not create key, wif format not recognised")
        return Key(wif, network, compressed, is_private=True)

    def __init__(self, import_key=None, network=None, compressed=True, password='', is_private=None, strict=True):
        self.public_hex = None
        self._public_uncompressed_hex = None
        self.public_compressed_hex = None
        self.public_byte = None
        self._public_uncompressed_byte = None
        self.public_compressed_byte = None
        self.private_byte = None
        self.private_hex = None
        self._x = None
        self._y = None
        self.x_hex = None
        self.y_hex = None
        self.secret = None
        self.compressed = compressed
        self._hash160 = None
        self.key_format = None
        self.is_private = None

        if not import_key:
            import_key = random.SystemRandom().randint(1, secp256k1_n - 1)
            self.key_format = 'decimal'
            networks_extracted = network
            assert is_private is True or is_private is None
            self.is_private = True  # Ignore provided attribute
        else:
            try:
                kf = get_key_format(import_key)
            except BKeyError:
                if strict:
                    raise BKeyError("Unrecognised key format")
                else:
                    networks_extracted = []
            else:
                if kf['format'] == 'address':
                    raise BKeyError("Can not create Key object from address")
                self.key_format = kf["format"]
                networks_extracted = kf["networks"]
                self.is_private = is_private if is_private else kf['is_private']
                if self.is_private is None:
                    raise BKeyError("Could not determine if key is private or public")

        if network is not None:
            self.network = network
            if not isinstance(network, Network):
                self.network = Network(network)
        elif networks_extracted:
            self.network = Network(check_network_and_key(import_key, None, networks_extracted))
        else:
            self.network = Network(DEFAULT_NETWORK)

        if self.key_format == "wif_protected":
            import_key, self.compressed = self._bip38_decrypt(import_key, password, network)
            self.key_format = 'bin_compressed' if self.compressed else 'bin'

        if not self.is_private:
            self.secret = None
            if self.key_format == 'point':
                self.compressed = compressed
                self._x = import_key[0]
                self._y = import_key[1]
                self.x_bytes = self._x.to_bytes(32, 'big')
                self.y_bytes = self._y.to_bytes(32, 'big')
                self.x_hex = self.x_bytes.hex()
                self.y_hex = self.y_bytes.hex()
                prefix = '03' if self._y % 2 else '02'
                self._public_uncompressed_hex = '04' + self.x_hex + self.y_hex
                self.public_compressed_hex = prefix + self.x_hex
                self.public_hex = self.public_compressed_hex if compressed else self._public_uncompressed_hex
            else:
                pub_key = to_hexstring(import_key)
                if len(pub_key) == 130:
                    self._public_uncompressed_hex = pub_key
                    self.x_hex = pub_key[2:66]
                    self.y_hex = pub_key[66:130]
                    self._y = int(self.y_hex, 16)
                    self.compressed = False
                    prefix = '03' if self._y % 2 else '02'
                    self.public_hex = pub_key
                    self.public_compressed_hex = prefix + self.x_hex
                else:
                    self.public_hex = pub_key
                    self.x_hex = pub_key[2:66]
                    self.compressed = True
                    self._x = int(self.x_hex, 16)
                    self.public_compressed_hex = pub_key
            self.public_compressed_byte = bytes.fromhex(self.public_compressed_hex)
            if self._public_uncompressed_hex:
                self._public_uncompressed_byte = bytes.fromhex(self._public_uncompressed_hex)
            self.public_byte = self.public_compressed_byte if self.compressed else self.public_uncompressed_byte

        elif self.is_private and self.key_format == 'decimal':
            self.secret = int(import_key)
            self.private_hex = change_base(self.secret, 10, 16, 64)
            self.private_byte = bytes.fromhex(self.private_hex)
        elif self.is_private:
            if self.key_format == 'hex':
                key_hex = import_key
                key_byte = bytes.fromhex(key_hex)
            elif self.key_format == 'hex_compressed':
                key_hex = import_key[:-2]
                key_byte = bytes.fromhex(key_hex)
                self.compressed = True
            elif self.key_format == 'bin':
                key_byte = import_key
                key_hex = key_byte.hex()
            elif self.key_format == 'bin_compressed':
                key_byte = import_key
                if len(import_key) in [33, 65, 129] and import_key[-1:] == b'\1':
                    key_byte = import_key[:-1]
                key_hex = key_byte.hex()
                self.compressed = True
            elif self.is_private and self.key_format in ['wif', 'wif_compressed']:
                # Check and remove Checksum, prefix and postfix tags
                key = change_base(import_key, 58, 256)
                checksum = key[-4:]
                key = key[:-4]
                if checksum != double_sha256(key)[:4]:
                    raise BKeyError("Invalid checksum, not a valid WIF key")
                found_networks = network_by_value('prefix_wif', key[0:1].hex())
                if not len(found_networks):
                    raise BKeyError("Unrecognised WIF private key, version byte unknown. Versionbyte: %s" % key[0:1])
                self._wif = import_key
                self._wif_prefix = key[0:1]
                # if self.network.name not in found_networks:
                #     if len(found_networks) > 1:
                #         raise BKeyError("More then one network found with this versionbyte, please specify network. "
                #                         "Networks found: %s" % found_networks)
                #     else:
                #         _logger.warning("Current network %s is different from the one found in key: %s" %
                #                         (network, found_networks[0]))
                #         self.network = Network(found_networks[0])
                if key[-1:] == b'\x01':
                    self.compressed = True
                    key = key[:-1]
                else:
                    self.compressed = False
                key_byte = key[1:]
                key_hex = key_byte.hex()
            else:
                raise BKeyError("Unknown key format %s" % self.key_format)

            if not (key_byte or key_hex):
                raise BKeyError("Cannot format key in hex or byte format")
            self.private_hex = key_hex
            self.private_byte = key_byte
            self.secret = int(key_hex, 16)
        else:
            raise BKeyError("Cannot import key. Public key format unknown")

        if self.is_private and not (self.public_byte or self.public_hex):
            if not self.is_private:
                raise BKeyError("Private key has no known secret number")
            p = ec_point(self.secret)
            self._x = p.x
            self._y = p.y
            self.x_hex = change_base(self._x, 10, 16, 64)
            self.y_hex = change_base(self._y, 10, 16, 64)
            if self._y % 2:
                prefix = '03'
            else:
                prefix = '02'

            self.public_compressed_hex = prefix + self.x_hex
            self._public_uncompressed_hex = '04' + self.x_hex + self.y_hex
            self.public_hex = self.public_compressed_hex if self.compressed else self.public_uncompressed_hex

            self.public_compressed_byte = bytes.fromhex(self.public_compressed_hex)
            self._public_uncompressed_byte = bytes.fromhex(self._public_uncompressed_hex)
            self.public_byte = self.public_compressed_byte if self.compressed else self.public_uncompressed_byte
        self._address_obj = None
        self._wif = None
        self._wif_prefix = None

    def __repr__(self):
        return "<Key(public_hex=%s, network=%s)>" % (self.public_hex, self.network.name)

    def __str__(self):
        return self.public_hex

    def __bytes__(self):
        return self.public_byte

    def __add__(self, other):
        assert self.is_private
        assert isinstance(other, Key)
        assert other.is_private
        return Key((self.secret + other.secret) % secp256k1_n, self.network, self.compressed)

    def __sub__(self, other):
        assert self.is_private
        assert isinstance(other, Key)
        assert other.is_private
        return Key((self.secret - other.secret) % secp256k1_n, self.network, self.compressed)

    def __mul__(self, other):
        assert isinstance(other, Key)
        assert self.secret
        assert other.is_private
        return Key((self.secret * other.secret) % secp256k1_n, self.network, self.compressed)

    def __rmul__(self, other):
        return self * other

    def __neg__(self):
        return self.inverse()

    def __len__(self):
        return len(self.public_byte)

    def __eq__(self, other):
        if other is None or not isinstance(other, Key):
            return False
        if self.is_private and other.is_private:
            return self.private_hex == other.private_hex
        else:
            return self.public_hex == other.public_hex

    def __hash__(self):
        if self.is_private:
            return hash(self.private_byte)
        else:
            return hash(self.public_byte)

    def __int__(self):
        if self.is_private:
            return self.secret
        else:
            return None

    def inverse(self):
        if self.is_private:
            return Key(secp256k1_n - self.secret, network=self.network, compressed=self.compressed)
        else:
            # Inverse y in init: self._y = secp256k1_p - self._y
            return Key(('02' if self._y % 2 else '03') + self.x_hex, network=self.network, compressed=self.compressed)

    @property
    def x(self):
        if not self._x and self.x_hex:
            self._x = int(self.x_hex, 16)
        return self._x

    @property
    def y(self):
        if not self._y:
            if not self.y_hex:
                self._public_uncompressed_hex = self.public_uncompressed_hex
            self._y = int(self.y_hex, 16)
        return self._y

    @property
    def public_uncompressed_hex(self):
        if not self._public_uncompressed_hex:
            # Calculate y from x with y=x^3 + 7 function
            sign = self.public_hex[:2] == '03'
            ys = pow(self._x, 3, secp256k1_p) + 7 % secp256k1_p
            self._y = mod_sqrt(ys)
            if self._y & 1 != sign:
                self._y = secp256k1_p - self._y
            self.y_hex = change_base(self._y, 10, 16, 64)
            self._public_uncompressed_hex = '04' + self.x_hex + self.y_hex
        return self._public_uncompressed_hex

    @property
    def public_uncompressed_byte(self):
        if not self._public_uncompressed_byte:
            self._public_uncompressed_byte = bytes.fromhex(self.public_uncompressed_hex)
        return self._public_uncompressed_byte

    def hex(self):
        return self.public_hex

    def as_hex(self, private=False):
        if private:
            return self.private_byte
        else:
            return self.public_hex

    def as_bytes(self, private=False):
        if private:
            return self.private_byte
        else:
            return self.public_byte

    def as_dict(self, include_private=False):
        key_dict = collections.OrderedDict()
        key_dict['network'] = self.network.name
        key_dict['key_format'] = self.key_format
        key_dict['compressed'] = self.compressed
        key_dict['is_private'] = self.is_private
        if include_private:
            key_dict['private_hex'] = self.private_hex
            key_dict['secret'] = self.secret
            key_dict['wif'] = self.wif()
        key_dict['public_hex'] = self.public_hex
        key_dict['public_uncompressed_hex'] = self.public_uncompressed_hex
        key_dict['hash160'] = self.hash160.hex()
        key_dict['address'] = self.address()
        x, y = self.public_point()
        key_dict['point_x'] = x
        key_dict['point_y'] = y
        return key_dict

    def as_json(self, include_private=False):
        return json.dumps(self.as_dict(include_private=include_private), indent=4)

    @staticmethod
    def _bip38_decrypt(encrypted_privkey, password, network=DEFAULT_NETWORK):
        priv, addresshash, compressed, _ = bip38_decrypt(encrypted_privkey, password)

        # Verify addresshash
        k = Key(priv, compressed=compressed, network=network)
        addr = k.address()
        if isinstance(addr, str):
            addr = addr.encode('utf-8')
        if double_sha256(addr)[0:4] != addresshash:
            raise BKeyError('Addresshash verification failed! Password or '
                            'specified network %s might be incorrect' % network)
        return priv, compressed

    def encrypt(self, password):
        flagbyte = b'\xe0' if self.compressed else b'\xc0'
        return bip38_encrypt(self.private_hex, self.address(), password, flagbyte)

    def wif(self, prefix=None):
        if not self.secret:
            raise BKeyError("WIF format not supported for public key")
        if prefix is None:
            versionbyte = self.network.prefix_wif
        else:
            if not isinstance(prefix, bytes):
                versionbyte = bytes.fromhex(prefix)
            else:
                versionbyte = prefix

        if self._wif and self._wif_prefix == versionbyte:
            return self._wif

        key = versionbyte + self.secret.to_bytes(32, byteorder='big')
        if self.compressed:
            key += b'\1'
        key += double_sha256(key)[:4]
        self._wif = base58encode(key)
        self._wif_prefix = versionbyte
        return self._wif

    def public(self):
        key = deepcopy(self)
        key.is_private = False
        key.private_byte = None
        key.private_hex = None
        key.secret = None
        return key

    def public_point(self):
        return (self.x, self.y)

    @property
    def hash160(self):
        if not self._hash160:
            self._hash160 = hash160(self.public_byte if self.compressed else self.public_uncompressed_byte)
        return self._hash160

    @property
    def address_obj(self):
        if not self._address_obj:
            self.address()
        return self._address_obj

    def address(self, compressed=None, prefix=None, script_type=None, encoding=None):
        if (self.compressed and compressed is None) or compressed:
            data = self.public_byte
            self.compressed = True
        else:
            data = self.public_uncompressed_byte
            self.compressed = False
        if encoding is None:
            if self._address_obj:
                encoding = self._address_obj.encoding
            else:
                encoding = 'base58'
        if not self.compressed and encoding == 'bech32':
            raise BKeyError("Uncompressed keys are non-standard for segwit/bech32 encoded addresses")
        if self._address_obj and script_type is None:
            script_type = self._address_obj.script_type
        if not (self._address_obj and self._address_obj.prefix == prefix and self._address_obj.encoding == encoding):
            self._address_obj = Address(data, prefix=prefix, network=self.network, script_type=script_type,
                                        encoding=encoding, compressed=compressed)
        return self._address_obj.address

    def address_uncompressed(self, prefix=None, script_type=None, encoding=None):
        return self.address(compressed=False, prefix=prefix, script_type=script_type, encoding=encoding)

    def info(self):
        print("KEY INFO")
        print(" Network                     %s" % self.network.name)
        print(" Compressed                  %s" % self.compressed)
        if self.secret:
            print("SECRET EXPONENT")
            print(" Private Key (hex)              %s" % self.private_hex)
            print(" Private Key (long)             %s" % self.secret)
            if isinstance(self, HDKey):
                print(" Private Key (wif)              %s" % self.wif_key())
            else:
                print(" Private Key (wif)              %s" % self.wif())
        else:
            print("PUBLIC KEY ONLY, NO SECRET EXPONENT")
        print("PUBLIC KEY")
        print(" Public Key (hex)            %s" % self.public_hex)
        print(" Public Key uncompr. (hex)   %s" % self.public_uncompressed_hex)
        print(" Public Key Hash160          %s" % self.hash160.hex())
        print(" Address (b58)               %s" % self.address())
        point_x, point_y = self.public_point()
        print(" Point x                     %s" % point_x)
        print(" Point y                     %s" % point_y)


class HDKey(Key):
    @staticmethod
    def from_wif(wif, network=None, compressed=True):
        bkey = change_base(wif, 58, 256)
        if len(bkey) != 82:
            raise BKeyError("Invalid BIP32 HDkey WIF. Length must be 82 characters")

        if ord(bkey[45:46]):
            is_private = False
            key = bkey[45:78]
        else:
            is_private = True
            key = bkey[46:78]
        depth = ord(bkey[4:5])
        parent_fingerprint = bkey[5:9]
        child_index = int.from_bytes(bkey[9:13], 'big')
        chain = bkey[13:45]

        key_hex = bkey.hex()
        prefix_data = wif_prefix_search(key_hex[:8], network=network)
        if not prefix_data:
            raise BKeyError("Invalid BIP32 HDkey WIF. Cannot find prefix in network definitions")

        networks = list(dict.fromkeys([n['network'] for n in prefix_data]))
        if not network and networks:
            network = networks[0]
        elif network not in networks:
            raise BKeyError("Network %s not found in list of derived networks %s" % (network, networks))

        witness_type = next(iter(list(dict.fromkeys([n['witness_type'] for n in prefix_data]))), None)
        return HDKey(key=key, chain=chain, depth=depth, parent_fingerprint=parent_fingerprint,
                     child_index=child_index, is_private=is_private, network=network, witness_type=witness_type,
                     compressed=compressed)

    def __init__(self, import_key=None, key=None, chain=None, depth=0, parent_fingerprint=b'\0\0\0\0',
                 child_index=0, is_private=None, network=None, key_type='bip32', password='', compressed=True,
                 encoding=None, witness_type=None):
        script_type = None
        if not key:
            if not import_key:
                # Generate new Master Key
                seed = os.urandom(64)
                key, chain = self._key_derivation(seed)
            # If key is 64 bytes long assume a HDKey with key and chain part
            elif isinstance(import_key, bytes) and len(import_key) == 64:
                key = import_key[:32]
                chain = import_key[32:]
            elif isinstance(import_key, Key):
                if not import_key.compressed:
                    _logger.warning("Uncompressed private keys are not standard for BIP32 keys, use at your own risk!")
                    compressed = False
                chain = chain if chain else b'\0' * 32
                if not import_key.private_byte:
                    raise BKeyError('Cannot import public Key in HDKey')
                key = import_key.private_byte
                key_type = 'private'
            else:
                kf = get_key_format(import_key, is_private=is_private)
                if kf['format'] == 'address':
                    raise BKeyError("Can not create HDKey object from address")
                if len(kf['script_types']) == 1:
                    script_type = kf['script_types'][0]
                if len(kf['witness_types']) == 1 and not witness_type:
                    witness_type = kf['witness_types'][0]
                network = Network(check_network_and_key(import_key, network, kf["networks"]))
                if kf['format'] in ['hdkey_private', 'hdkey_public']:
                    bkey = change_base(import_key, 58, 256)
                    # Derive key, chain, depth, child_index and fingerprint part from extended key WIF
                    if ord(bkey[45:46]):
                        is_private = False
                        key = bkey[45:78]
                    else:
                        key = bkey[46:78]
                    depth = ord(bkey[4:5])
                    parent_fingerprint = bkey[5:9]
                    child_index = int.from_bytes(bkey[9:13], 'big')
                    chain = bkey[13:45]
                elif kf['format'] == 'mnemonic':
                    raise BKeyError("Use HDKey.from_passphrase() method to parse a passphrase")
                elif kf['format'] == 'wif_protected':
                    key, compressed = self._bip38_decrypt(import_key, password, network.name, witness_type)
                    chain = chain if chain else b'\0' * 32
                    key_type = 'private'
                else:
                    key = import_key
                    chain = chain if chain else b'\0' * 32
                    is_private = kf['is_private']
                    key_type = 'private' if is_private else 'public'

        if witness_type is None:
            witness_type = DEFAULT_WITNESS_TYPE
        self.script_type = script_type if script_type else script_type_default(witness_type)
        if not encoding:
            encoding = get_encoding_from_witness(witness_type)

        if is_private is None:
            is_private = True
        Key.__init__(self, key, network, compressed, password, is_private)

        self.encoding = encoding
        self.witness_type = witness_type

        self.chain = chain
        self.depth = depth
        self.parent_fingerprint = parent_fingerprint
        self.child_index = child_index
        self.key_type = key_type

    def __repr__(self):
        return "<HDKey(public_hex=%s, wif_public=%s, network=%s)>" % \
               (self.public_hex, self.wif_public(), self.network.name)

    def __neg__(self):
        return self.inverse()

    def inverse(self):
        if self.is_private:
            return HDKey(secp256k1_n - self.secret, network=self.network.name, compressed=self.compressed,
                         witness_type=self.witness_type, encoding=self.encoding)
        else:
            # Inverse y in init: self._y = secp256k1_p - self._y
            if not self.compressed:
                return self
            return HDKey(('02' if self._y % 2 else '03') + self.x_hex, network=self.network.name,
                         compressed=self.compressed, witness_type=self.witness_type,
                         encoding=self.encoding)

    def info(self):
        super(HDKey, self).info()

        print("EXTENDED KEY")
        print(" Key Type                    %s" % self.key_type)
        print(" Chain code (hex)            %s" % self.chain.hex())
        print(" Child Index                 %s" % self.child_index)
        print(" Parent Fingerprint (hex)    %s" % self.parent_fingerprint.hex())
        print(" Depth                       %s" % self.depth)
        print(" Extended Public Key (wif)   %s" % self.wif_public())
        print(" Witness type                %s" % self.witness_type)
        print(" Script type                 %s" % self.script_type)
        if self.is_private:
            print(" Extended Private Key (wif)  %s" % self.wif(is_private=True))
        print("\n")

    def as_dict(self, include_private=False):
        key_dict = super(HDKey, self).as_dict()
        if include_private:
            key_dict['fingerprint'] = self.fingerprint.hex()
            key_dict['chain_code'] = self.chain.hex()
            key_dict['fingerprint_parent'] = self.parent_fingerprint.hex()
        key_dict['child_index'] = self.child_index
        key_dict['depth'] = self.depth
        key_dict['extended_wif_public'] = self.wif_public()
        if include_private:
            key_dict['extended_wif_private'] = self.wif(is_private=True)
        return key_dict

    def as_json(self, include_private=False):
        return json.dumps(self.as_dict(include_private=include_private), indent=4)

    def _key_derivation(self, seed):
        chain = hasattr(self, 'chain') and self.chain or b"Bitcoin seed"
        i = hmac.new(chain, seed, hashlib.sha512).digest()
        key = i[:32]
        chain = i[32:]
        key_int = int.from_bytes(key, 'big')
        if key_int >= secp256k1_n:
            raise BKeyError("Key cannot be greater than secp256k1_n. Try another index number.")
        return key, chain

    @property
    def fingerprint(self):
        return self.hash160[:4]

    @staticmethod
    def _bip38_decrypt(encrypted_privkey, password, network=DEFAULT_NETWORK, witness_type=DEFAULT_WITNESS_TYPE):
        priv, addresshash, compressed, _ = bip38_decrypt(encrypted_privkey, password)
        # compressed = True if priv[-1:] == b'\1' else False

        # Verify addresshash
        k = HDKey(priv, compressed=compressed, network=network, witness_type=witness_type)
        addr = k.address()
        if isinstance(addr, str):
            addr = addr.encode('utf-8')
        if double_sha256(addr)[0:4] != addresshash:
            raise BKeyError('Addresshash verification failed! Password or '
                            'specified network %s might be incorrect' % network)
        return priv, compressed

    def wif(self, is_private=None, child_index=None, prefix=None, witness_type=None):
        if not witness_type:
            witness_type = DEFAULT_WITNESS_TYPE if not self.witness_type else self.witness_type
        rkey = self.private_byte or self.public_compressed_byte
        if prefix and not isinstance(prefix, bytes):
            prefix = bytes.fromhex(prefix)
        if self.is_private and is_private:
            if not prefix:
                prefix = self.network.wif_prefix(is_private=True, witness_type=witness_type)
            typebyte = b'\x00'
        else:
            if not prefix:
                prefix = self.network.wif_prefix(witness_type=witness_type)
            typebyte = b''
            if not is_private:
                rkey = self.public_byte
        if child_index:
            self.child_index = child_index
        raw = prefix + self.depth.to_bytes(1, 'big') + self.parent_fingerprint + \
              self.child_index.to_bytes(4, 'big') + self.chain + typebyte + rkey
        chk = double_sha256(raw)[:4]
        ret = raw + chk
        return change_base(ret, 256, 58, 111)

    def wif_key(self, prefix=None):
        return super(HDKey, self).wif(prefix)

    def wif_public(self, prefix=None, witness_type=None):
        return self.wif(is_private=False, prefix=prefix, witness_type=witness_type)

    def wif_private(self, prefix=None, witness_type=None):
        return self.wif(is_private=True, prefix=prefix, witness_type=witness_type)

    def address(self, compressed=None, prefix=None, script_type=None, encoding=None):
        if compressed is None:
            compressed = self.compressed
        if script_type is None:
            script_type = self.script_type
        if encoding is None:
            encoding = self.encoding
        return super(HDKey, self).address(compressed, prefix, script_type, encoding)

    def subkey_for_path(self, path, network=None):
        if isinstance(path, TYPE_TEXT):
            path = path.split("/")
        if self.key_type == 'single':
            raise BKeyError("Key derivation cannot be used for 'single' type keys")
        key = self
        first_public = False
        if path[0] == 'm':  # Use Private master key
            path = path[1:]
        elif path[0] == 'M':  # Use Public master key
            path = path[1:]
            first_public = True
        if path:
            if len(path) > 1:
                _logger.info("Path length > 1 can be slow for larger paths, use Wallet Class to generate keys paths")
            for item in path:
                if not item:
                    raise BKeyError("Could not parse path. Index is empty.")
                hardened = item[-1] in "'HhPp"
                if hardened:
                    item = item[:-1]
                index = int(item)
                if index < 0:
                    raise BKeyError("Could not parse path. Index must be a positive integer.")
                if first_public or not key.is_private:
                    key = key.child_public(index=index, network=network)  # TODO hardened=hardened key?
                    first_public = False
                else:
                    key = key.child_private(index=index, hardened=hardened, network=network)
        return key

    def public_master(self, account_id=0, purpose=None, witness_type=None, as_private=False):
        if witness_type:
            self.witness_type = witness_type

        path_template, purpose, _ = get_key_structure_data(self.witness_type, purpose)

        # Use last hardened key as public master root
        pm_depth = path_template.index([x for x in path_template if x[-1:] == "'"][-1]) + 1
        path = path_expand(path_template[:pm_depth], path_template, account_id=account_id, purpose=purpose,
                           witness_type=self.witness_type, network=self.network.name)
        if as_private:
            return self.subkey_for_path(path)
        else:
            return self.subkey_for_path(path).public()

    def child_private(self, index=0, hardened=False, network=None):
        if network is None:
            network = self.network.name
        if not self.is_private:
            raise BKeyError("Need a private key to create child private key")
        if hardened:
            index |= 0x80000000
            data = b'\0' + self.private_byte + index.to_bytes(4, 'big')
        else:
            data = self.public_byte + index.to_bytes(4, 'big')
        key, chain = self._key_derivation(data)

        key = int.from_bytes(key, 'big')
        if key >= secp256k1_n:
            raise BKeyError("Key cannot be greater than secp256k1_n. Try another index number.")
        newkey = (key + self.secret) % secp256k1_n
        if newkey == 0:
            raise BKeyError("Key cannot be zero. Try another index number.")
        newkey = int.to_bytes(newkey, 32, 'big')

        return HDKey(key=newkey, chain=chain, depth=self.depth + 1, parent_fingerprint=self.fingerprint,
                     child_index=index, witness_type=self.witness_type,
                     encoding=self.encoding, network=network)

    def child_public(self, index=0, network=None):
        if network is None:
            network = self.network.name
        if index > 0x80000000:
            raise BKeyError("Cannot derive hardened key from public private key. Index must be less than 0x80000000")
        data = self.public_byte + index.to_bytes(4, 'big')
        key, chain = self._key_derivation(data)
        key = int.from_bytes(key, 'big')
        if key >= secp256k1_n:
            raise BKeyError("Key cannot be greater than secp256k1_n. Try another index number.")

        x, y = self.public_point()
        ki = ec_point(key) + fastecdsa_point.Point(x, y, fastecdsa_secp256k1)
        ki_x = ki.x
        ki_y = ki.y
        if ki_y % 2:
            prefix = '03'
        else:
            prefix = '02'
        xhex = change_base(ki_x, 10, 16, 64)
        secret = bytes.fromhex(prefix + xhex)
        return HDKey(key=secret, chain=chain, depth=self.depth + 1, parent_fingerprint=self.fingerprint,
                     child_index=index, is_private=False, witness_type=self.witness_type,
                     encoding=self.encoding, network=network)

    def public(self):
        hdkey = deepcopy(self)
        hdkey.is_private = False
        hdkey.secret = None
        hdkey.private_hex = None
        hdkey.private_byte = None
        hdkey.key_hex = hdkey.public_hex
        # hdkey.key = self.key.public()
        return hdkey


class Signature(object):
    @classmethod
    def parse(cls, signature, public_key=None):
        if isinstance(signature, bytes):
            return cls.parse_bytes(signature, public_key)
        elif isinstance(signature, str):
            return cls.parse_hex(signature, public_key)

    @classmethod
    def parse_hex(cls, signature, public_key=None):
        return cls.parse_bytes(bytes.fromhex(signature), public_key)

    @staticmethod
    def parse_bytes(signature, public_key=None):
        der_signature = ''
        hash_type = SIGHASH_ALL
        if len(signature) > 64 and signature.startswith(b'\x30'):
            der_signature = signature[:-1]
            hash_type = int.from_bytes(signature[-1:], 'big')
            signature = convert_der_sig(signature[:-1], as_hex=False)
        if len(signature) != 64:
            raise BKeyError("Signature length must be 64 bytes or 128 character hexstring")
        r = int.from_bytes(signature[:32], 'big')
        s = int.from_bytes(signature[32:], 'big')
        return Signature(r, s, signature=signature, der_signature=der_signature, public_key=public_key,
                         hash_type=hash_type)

    @staticmethod
    def create(txid, private, use_rfc6979=True, k=None, hash_type=SIGHASH_ALL):
        if isinstance(txid, bytes):
            txid = txid.hex()
        if len(txid) > 64:
            txid = double_sha256(bytes.fromhex(txid), as_hex=True)
        if not isinstance(private, (Key, HDKey)):
            private = HDKey(private)
        pub_key = private.public()
        secret = private.secret

        if not k:
            if use_rfc6979:
                rfc6979 = RFC6979(txid, secret, secp256k1_n, hashlib.sha256)
                k = rfc6979.gen_nonce()
            else:
                global rfc6979_warning_given
                k = random.SystemRandom().randint(1, secp256k1_n - 1)
        r, s = _ecdsa.sign(
            txid,
            str(secret),
            str(k),
            str(secp256k1_p),
            str(secp256k1_a),
            str(secp256k1_b),
            str(secp256k1_n),
            str(secp256k1_Gx),
            str(secp256k1_Gy)
        )
        if int(s) > secp256k1_n / 2:
            s = secp256k1_n - int(s)
        return Signature(r, s, txid, secret, public_key=pub_key, k=k, hash_type=hash_type)

    def __init__(self, r, s, txid=None, secret=None, signature=None, der_signature=None, public_key=None, k=None,
                 hash_type=SIGHASH_ALL):
        self.r = int(r)
        self.s = int(s)
        self.x = None
        self.y = None
        if self.r < 1 or self.r >= secp256k1_n:
            raise BKeyError('Invalid Signature: r is not a positive integer smaller than the curve order')
        elif self.s < 1 or self.s >= secp256k1_n:
            raise BKeyError('Invalid Signature: s is not a positive integer smaller than the curve order')
        self._txid = None
        self.txid = txid
        self.secret = None if not secret else int(secret)
        if isinstance(signature, bytes):
            self._signature = signature
            signature = signature.hex()
        else:
            self._signature = to_bytes(signature)
        if signature and len(signature) != 128:
            raise BKeyError('Invalid Signature: length must be 64 bytes')
        self._public_key = None
        self.public_key = public_key
        self.k = k
        self.hash_type = hash_type
        self.hash_type_byte = self.hash_type.to_bytes(1, 'big')
        self.der_signature = der_signature
        if not der_signature:
            self.der_signature = der_encode_sig(self.r, self.s)

        self._der_encoded = to_bytes(der_signature) + self.hash_type_byte

    def __repr__(self):
        der_sig = '' if not self._der_encoded else self._der_encoded.hex()
        return "<Signature(r=%d, s=%d, signature=%s, der_signature=%s)>" % \
               (self.r, self.s, self.hex(), der_sig)

    def __str__(self):
        return self.as_der_encoded(as_hex=True)

    def __bytes__(self):
        return self.as_der_encoded()

    def __add__(self, other):
        return self.as_der_encoded() + other

    def __radd__(self, other):
        return other + self.as_der_encoded()

    def __len__(self):
        return len(self.as_der_encoded())

    @property
    def txid(self):
        return self._txid

    @txid.setter
    def txid(self, value):
        if value is not None:
            self._txid = value
            if isinstance(value, bytes):
                self._txid = value.hex()

    @property
    def public_key(self):
        return self._public_key

    @public_key.setter
    def public_key(self, value):
        if value is None:
            return
        if isinstance(value, bytes):
            value = HDKey(value)
        if value.is_private:
            value = value.public()
        self.x, self.y = value.public_point()

        if not fastecdsa_secp256k1.is_point_on_curve((self.x, self.y)):
            raise BKeyError('Invalid public key, point is not on secp256k1 curve')
        self._public_key = value

    def hex(self):
        return self.bytes().hex()

    def __index__(self):
        return self.bytes()

    def bytes(self):
        if not self._signature:
            self._signature = self.r.to_bytes(32, 'big') + self.s.to_bytes(32, 'big')
        return self._signature

    def as_hex(self):
        return self.hex()

    def as_bytes(self):
        return self.bytes()

    def as_der_encoded(self, as_hex=False, include_hash_type=True):
        if not self._der_encoded or len(self._der_encoded) < 2:
            self._der_encoded = der_encode_sig(self.r, self.s) + self.hash_type_byte

        if include_hash_type:
            return self._der_encoded.hex() if as_hex else self._der_encoded
        else:
            return der_encode_sig(self.r, self.s).hex() if as_hex else der_encode_sig(self.r, self.s)

    def verify(self, txid=None, public_key=None):
        if txid is not None:
            self.txid = to_hexstring(txid)
        if public_key is not None:
            self.public_key = public_key

        if not self.txid or not self.public_key:
            raise BKeyError("Please provide txid and public_key to verify signature")
        return _ecdsa.verify(
            str(self.r),
            str(self.s),
            self.txid,
            str(self.x),
            str(self.y),
            str(secp256k1_p),
            str(secp256k1_a),
            str(secp256k1_b),
            str(secp256k1_n),
            str(secp256k1_Gx),
            str(secp256k1_Gy)
        )


def sign(txid, private, use_rfc6979=True, k=None, hash_type=SIGHASH_ALL):
    return Signature.create(txid, private, use_rfc6979, k, hash_type=hash_type)

def verify(txid, signature, public_key=None):
    if not isinstance(signature, Signature):
        if not public_key:
            raise BKeyError("No public key provided, cannot verify")
        signature = Signature.parse(signature, public_key=public_key)
    return signature.verify(txid, public_key)


def ec_point(m):
    m = int(m)
    return fastecdsa_keys.get_public_key(m, fastecdsa_secp256k1)

def mod_sqrt(a):
    k = 28948022309329048855892746252171976963317496166410141009864396001977208667915
    return pow(a, k + 1, secp256k1_p)
