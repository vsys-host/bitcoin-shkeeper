import math
import numbers
from copy import deepcopy
import hashlib
import unicodedata
from app.lib.main import *
from fastecdsa.encoding.der import DEREncoder
_logger = logging.getLogger(__name__)

SCRYPT_ERROR = None
USING_MODULE_SCRYPT = os.getenv("USING_MODULE_SCRYPT") not in ["false", "False", "0", "FALSE"]

from Crypto.Hash import RIPEMD160
from Crypto.Cipher import AES

try:
    if USING_MODULE_SCRYPT is not False:
        import scrypt
        USING_MODULE_SCRYPT = True
except ImportError as SCRYPT_ERROR:
    try:
        from Crypto.Protocol.KDF import scrypt
        _logger.info("Using scrypt method from pycryptodome")
    except ImportError as err:
        _logger.info("Could not import scrypt from pycryptodome: %s" % str(err))
        pass

if 'scrypt' not in sys.modules and 'Crypto.Protocol.KDF' not in sys.modules:
    try:
        import pyscrypt as scrypt
    except ImportError:
        _logger.warning("MISSING MODULES! Please install scrypt, pycryptodome or pyscrypt")
        _logger.warning("The bip38_decrypt and bip38_encrypt methods need a scrypt library to work!")
    USING_MODULE_SCRYPT = False

class EncodingError(Exception):
    def __init__(self, msg=''):
        self.msg = msg

    def __str__(self):
        return self.msg

bytesascii = b''
for bxn in range(256):
    bytesascii += bytes((bxn,))

code_strings = {
    2: b'01',
    3: b' ,.',
    10: b'0123456789',
    16: b'0123456789abcdef',
    32: b'abcdefghijklmnopqrstuvwxyz234567',
    58: b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
    256: b''.join([bytes((csx,)) for csx in range(256)]),
    'bech32': b'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
}

def _get_code_string(base):
    if base in code_strings:
        return code_strings[base]
    else:
        return list(range(0, base))


def _array_to_codestring(array, base):
    codebase = code_strings[base]
    codestring = ""
    for i in array:
        codestring += chr(codebase[i])
    return codestring


def _codestring_to_array(codestring, base):
    codestring = bytes(codestring, 'utf8')
    codebase = code_strings[base]
    array = []
    for s in codestring:
        try:
            array.append(codebase.index(s))
        except ValueError:
            raise EncodingError("Character '%s' not found in codebase" % s)
    return array


def normalize_var(var, base=256):
    try:
        if isinstance(var, str):
            var = var.encode('ISO-8859-1')
    except ValueError:
        try:
            var = var.encode('utf-8')
        except ValueError:
            raise EncodingError("Unknown character '%s' in input format" % var)

    if base == 10:
        return int(var)
    elif isinstance(var, list):
        return deepcopy(var)
    else:
        return var

def change_base(chars, base_from, base_to, min_length=0, output_even=None, output_as_list=None):
    if base_from == 10 and not min_length:
        raise EncodingError("For a decimal input a minimum output length is required")

    code_str = _get_code_string(base_to)

    if base_to not in code_strings:
        output_as_list = True

    code_str_from = _get_code_string(base_from)
    if not isinstance(code_str_from, (bytes, list)):
        raise EncodingError("Code strings must be a list or defined as bytes")
    output = []
    input_dec = 0
    addzeros = 0
    inp = normalize_var(chars, base_from)

    # Use bytes and int's methods for standard conversions to speedup things
    if not min_length:
        if base_from == 256 and base_to == 16:
            return inp.hex()
        elif base_from == 16 and base_to == 256:
            return bytes.fromhex(chars)
    if base_from == 16 and base_to == 10:
        return int(inp, 16)
    if base_from == 10 and base_to == 16:
        hex_outp = hex(inp)[2:]
        return hex_outp.zfill(min_length) if min_length else hex_outp
    if base_from == 256 and base_to == 10:
        return int.from_bytes(inp, 'big')
    if base_from == 10 and base_to == 256:
        return inp.to_bytes(min_length, byteorder='big')
    if base_from == 256 and base_to == 58:
        return base58encode(inp)
    if base_from == 16 and base_to == 58:
        return base58encode(bytes.fromhex(chars))

    if output_even is None and base_to == 16:
        output_even = True

    if isinstance(inp, numbers.Number):
        input_dec = inp
    elif isinstance(inp, (str, list, bytes)):
        factor = 1
        while len(inp):
            if isinstance(inp, list):
                item = inp.pop()
            else:
                item = inp[-1:]
                inp = inp[:-1]
            try:
                pos = code_str_from.index(item)
            except ValueError:
                try:
                    pos = code_str_from.index(item.lower())
                except ValueError:
                    raise EncodingError("Unknown character %s found in input string" % item)
            input_dec += pos * factor

            # Add leading zero if there are leading zero's in input
            firstchar = chr(code_str_from[0]).encode('utf-8')
            if not pos * factor:
                if isinstance(inp, list):
                    if not len([x for x in inp if x != firstchar]):
                        addzeros += 1
                elif not len(inp.strip(firstchar)):
                    addzeros += 1
            factor *= base_from
    else:
        raise EncodingError("Unknown input format %s" % inp)

    # Convert decimal to output base
    while input_dec != 0:
        input_dec, remainder = divmod(input_dec, base_to)
        output = [code_str[remainder]] + output

    if base_to != 10:
        pos_fact = math.log(base_to, base_from)
        expected_length = len(str(chars)) / pos_fact

        zeros = int(addzeros / pos_fact)
        if addzeros == 1:
            zeros = 1
        # Different rules for base58 addresses
        if (base_from == 256 and base_to == 58) or (base_from == 58 and base_to == 256):
            zeros = addzeros
        elif base_from == 16 and base_to == 58:
            zeros = -(-addzeros // 2)
        elif base_from == 58 and base_to == 16:
            zeros = addzeros * 2

        for _ in range(zeros):
            if base_to != 10 and not expected_length == len(output):
                output = [code_str[0]] + output

        # Add zero's to make even number of digits on Hex output (or if specified)
        if output_even and len(output) % 2:
            output = [code_str[0]] + output

        # Add leading zero's
        while len(output) < min_length:
            output = [code_str[0]] + output

    if not output_as_list and isinstance(output, list):
        output = 0 if not len(output) else ''.join([chr(c) for c in output])
    if base_to == 10:
        return int(0) or (output != '' and int(output))
    if base_to == 256 and not output_as_list:
        return output.encode('ISO-8859-1')
    else:
        return output

def base58encode(inp):
    origlen = len(inp)
    inp = inp.lstrip(b'\0')
    padding_zeros = origlen - len(inp)
    code_str = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    acc = int.from_bytes(inp, 'big')

    string = ''
    while acc:
        acc, idx = divmod(acc, 58)
        string = code_str[idx:idx + 1] + string
    return '1' * padding_zeros + string


def varbyteint_to_int(byteint):
    if not isinstance(byteint, (bytes, list)):
        raise EncodingError("Byteint must be a list or defined as bytes")
    if byteint == b'':
        return 0, 0
    ni = byteint[0]
    if ni < 253:
        return ni, 1
    if ni == 253:  # integer of 2 bytes
        size = 2
    elif ni == 254:  # integer of 4 bytes
        size = 4
    else:  # integer of 8 bytes
        size = 8
    return int.from_bytes(byteint[1:1+size][::-1], 'big'), size + 1

def read_varbyteint(s):
    pos = s.tell()
    value, size = varbyteint_to_int(s.read(9))
    s.seek(pos + size)
    return value

def read_varbyteint_return(s):
    pos = s.tell()
    byteint = s.read(9)
    if not byteint:
        return 0, b''

    ni = byteint[0]
    if ni < 253:
        s.seek(pos + 1)
        return ni, byteint[0:1]
    if ni == 253:  # integer of 2 bytes
        size = 2
    elif ni == 254:  # integer of 4 bytes
        size = 4
    else:  # integer of 8 bytes
        size = 8
    varbytes = byteint[1:1+size]
    s.seek(pos + size + 1)
    return int.from_bytes(varbytes[::-1], 'big'), byteint[0:1] + varbytes

def int_to_varbyteint(inp):
    if not isinstance(inp, numbers.Number):
        raise EncodingError("Input must be a number type")
    if inp < 0xfd:
        return inp.to_bytes(1, 'little')
    elif inp < 0xffff:
        return b'\xfd' + inp.to_bytes(2, 'little')
    elif inp < 0xffffffff:
        return b'\xfe' + inp.to_bytes(4, 'little')
    else:
        return b'\xff' + inp.to_bytes(8, 'little')

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_SIV)
    ct, tag = cipher.encrypt_and_digest(data)
    return ct + tag

def aes_decrypt(encrypted_data, key):
    ct = encrypted_data[:-16]
    tag = encrypted_data[-16:]
    cipher2 = AES.new(key, AES.MODE_SIV)
    try:
        res = cipher2.decrypt_and_verify(ct, tag)
    except ValueError as e:
        raise EncodingError("Could not decrypt value (password incorrect?): %s" % e)
    return res

def convert_der_sig(signature, as_hex=True):
    if not signature:
        return ""
    r, s = DEREncoder.decode_signature(bytes(signature))
    sig = '%064x%064x' % (r, s)
    if as_hex:
        return sig
    else:
        return bytes.fromhex(sig)

def der_encode_sig(r, s):
    return DEREncoder.encode_signature(r, s)

def addr_to_pubkeyhash(address, as_hex=False, encoding=None):
    return addr_bech32_to_pubkeyhash(address, as_hex=as_hex)

def addr_bech32_to_pubkeyhash(bech, prefix=None, include_witver=False, as_hex=False):
    if (any(ord(x) < 33 or ord(x) > 126 for x in bech)) or (bech.lower() != bech and bech.upper() != bech):
        raise EncodingError("Invalid bech32 character in bech string")
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        raise EncodingError("Invalid bech32 string length")
    if prefix and prefix != bech[:pos]:
        raise EncodingError("Invalid bech32 address. Prefix '%s', prefix expected is '%s'" % (bech[:pos], prefix))
    hrp = bech[:pos]
    data = _codestring_to_array(bech[pos + 1:], 'bech32')
    hrp_expanded = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    check = _bech32_polymod(hrp_expanded + data)
    if not (check == 1 or check == BECH32M_CONST):
        raise EncodingError("Bech polymod check failed")
    if data[0] == 0 and check != 1:
        raise EncodingError("Invalid checksum (Bech32m instead of Bech32)")
    if data[0] != 0 and check != BECH32M_CONST:
        raise EncodingError("Invalid checksum (Bech32 instead of Bech32m)")
    data = data[:-6]
    decoded = bytes(convertbits(data[1:], 5, 8, pad=False))
    if decoded is None or len(decoded) < 2 or len(decoded) > 40:
        raise EncodingError("Invalid decoded data length, must be between 2 and 40")
    if data[0] > 16:
        raise EncodingError("Invalid witness version")
    if data[0] == 0 and len(decoded) not in [20, 32]:
        raise EncodingError("Invalid decoded data length, must be 20 or 32 bytes")
    prefix = b''
    if include_witver:
        datalen = len(decoded)
        prefix = bytes([data[0] + 0x50 if data[0] else 0, datalen])
    if as_hex:
        return (prefix + decoded).hex()
    return prefix + decoded

def addr_bech32_checksum(bech):
    bech = bech.lower()
    pos = bech.rfind('1')
    hrp = bech[:pos]
    data = _codestring_to_array(bech[pos + 1:], 'bech32')
    hrp_expanded = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    return _bech32_polymod(hrp_expanded + data)

def pubkeyhash_to_addr(pubkeyhash, prefix=None, encoding='base58', witver=0):
    if encoding == 'base58':
        if prefix is None:
            prefix = b'\x00'
        return pubkeyhash_to_addr_base58(pubkeyhash, prefix)
    elif encoding == 'bech32':
        if prefix is None:
            prefix = 'bc'
        return pubkeyhash_to_addr_bech32(pubkeyhash, prefix, witver)
    else:
        raise EncodingError("Encoding %s not supported" % encoding)

def pubkeyhash_to_addr_base58(pubkeyhash, prefix=b'\x00'):
    key = to_bytes(prefix) + to_bytes(pubkeyhash)
    addr256 = key + double_sha256(key)[:4]
    return base58encode(addr256)


def pubkeyhash_to_addr_bech32(pubkeyhash, prefix='bc', witver=0, separator='1', checksum_xor=1):
    pubkeyhash = list(to_bytes(pubkeyhash))
    if len(pubkeyhash) not in [20, 32, 40]:
        if pubkeyhash[0] != 0:
            witver = pubkeyhash[0] - 0x50
        if pubkeyhash[1] != len(pubkeyhash[2:]):
            raise EncodingError("Incorrect pubkeyhash length")
        pubkeyhash = pubkeyhash[2:]

    if witver > 16:
        raise EncodingError("Witness version must be between 0 and 16")

    if checksum_xor == BECH32M_CONST and not witver:
        witver = 1
    elif witver > 0:
        checksum_xor = BECH32M_CONST

    data = [witver] + convertbits(pubkeyhash, 8, 5)

    # Expand the HRP into values for checksum computation
    hrp_expanded = [ord(x) >> 5 for x in prefix] + [0] + [ord(x) & 31 for x in prefix]
    polymod = _bech32_polymod(hrp_expanded + data + [0, 0, 0, 0, 0, 0]) ^ checksum_xor
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

    return prefix + separator + _array_to_codestring(data, 'bech32') + _array_to_codestring(checksum, 'bech32')

def _bech32_polymod(values):
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise EncodingError("Invalid padding bits")
    return ret

def varstr(string):
    s = normalize_var(string)
    if s == b'\0':
        return s
    return int_to_varbyteint(len(s)) + s

def to_bytes(string, unhexlify=True):
    if not string:
        return b''
    if unhexlify:
        try:
            if isinstance(string, bytes):
                string = string.decode()
            s = bytes.fromhex(string)
            return s
        except (TypeError, ValueError):
            pass
    if isinstance(string, bytes):
        return string
    else:
        return bytes(string, 'utf8')

def to_hexstring(string):
    if not string:
        return ''
    try:
        bytes.fromhex(string)
        return string
    except (ValueError, TypeError):
        pass

    if not isinstance(string, bytes):
        string = bytes(string, 'utf8')
    return string.hex()

def double_sha256(string, as_hex=False):
    if not as_hex:
        return hashlib.sha256(hashlib.sha256(string).digest()).digest()
    else:
        return hashlib.sha256(hashlib.sha256(string).digest()).hexdigest()

def sha256(string, as_hex=False):
    if not as_hex:
        return hashlib.sha256(string).digest()
    else:
        return hashlib.sha256(string).hexdigest()

def ripemd160(string):
    try:
        return RIPEMD160.new(string).digest()
    except Exception:
        return hashlib.new('ripemd160', string).digest()

def hash160(string):
    return ripemd160(hashlib.sha256(string).digest())

def scrypt_hash(password, salt, key_len=64, N=16384, r=8, p=1, buflen=64):
    try:               # Try scrypt from Cryptodome
        key = scrypt(password, salt, key_len, N, r, p)
    except TypeError:  # Use scrypt module
        key = scrypt.hash(password, salt, N, r, p, key_len)
    return key