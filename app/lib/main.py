import os
import sys
import functools
import logging
from logging.handlers import RotatingFileHandler
from app.lib.config.config import *
from app.config import COIN

_logger = logging.getLogger(__name__)

def script_type_default(witness_type=None, locking_script=False):
    if COIN == 'DOGE':
        return 'p2pkh'
    if not witness_type:
        return 'p2wpkh'
    if witness_type == 'legacy':
        return 'p2pkh' if locking_script else 'sig_pubkey'
    elif witness_type == 'segwit':
        return 'p2wpkh' if locking_script else 'sig_pubkey'
    elif witness_type == 'p2sh-segwit':
        return 'p2sh' if locking_script else 'p2sh_p2wpkh'
    else:
        raise ValueError("Wallet and key type combination not supported: %s / %s" % (witness_type))

def get_encoding_from_witness(witness_type=None):
    if witness_type == 'segwit':
        return 'bech32'
    elif witness_type in [None, 'legacy', 'p2sh-segwit']:
        return 'base58'
    else:
        raise ValueError("Unknown witness type %s" % witness_type)

def get_key_structure_data(witness_type, purpose=None, encoding=None):
    if not witness_type:
        return None, purpose, encoding
    ks = [k for k in WALLET_KEY_STRUCTURES if
          k['witness_type'] == witness_type and k['purpose'] is not None]
    if len(ks) > 1:
        raise ValueError("Please check definitions in WALLET_KEY_STRUCTURES. Multiple options found for "
                        "witness_type - multisig combination: %s, %s" % (witness_type))
    if not ks:
        raise ValueError("Please check definitions in WALLET_KEY_STRUCTURES. No options found for "
                         "witness_type - multisig combination: %s, %s" % (witness_type))
    purpose = ks[0]['purpose'] if not purpose else purpose
    path_template = ks[0]['key_path']
    encoding = ks[0]['encoding'] if not encoding else encoding
    return path_template, purpose, encoding

