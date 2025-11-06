import json
import random
from itertools import groupby
from operator import itemgetter
import numpy as np
import pickle
import base58
from sqlalchemy.orm import joinedload, sessionmaker
from datetime import timedelta
from app.models import *
from app.config import config
from app.lib.encoding import *
from app.lib.keys import Address, BKeyError, HDKey, check_network_and_key, path_expand
from app.lib.networks import Network
from app.lib.values import Value, value_to_satoshi
from app.lib.services.services import Service
from app.lib.transactions import Input, Output, Transaction, get_unlocking_script_type, TransactionError
from app.lib.main import *
from sqlalchemy import func, or_, asc, text
from sqlalchemy.exc import OperationalError
from concurrent.futures import ThreadPoolExecutor, as_completed
from sqlalchemy.exc import OperationalError
from functools import lru_cache
import time

_logger = logging.getLogger(__name__)

@lru_cache(maxsize=1)
def get_flask_app():
    from app import create_app
    return create_app()

def get_all_key_ids(session, wallet_id, account_id=None, witness_type=None, network=None, addresses=None):
    q = session.query(DbKey.id).filter(DbKey.wallet_id == wallet_id)

    if account_id is not None:
        q = q.filter(DbKey.account_id == account_id)
    if witness_type is not None:
        q = q.filter(DbKey.witness_type == witness_type)
    if network is not None:
        q = q.filter(DbKey.network_name == network)
    if addresses:
        q = q.filter(DbKey.address.in_(addresses))

    q = q.order_by(asc(DbKey.id))
    return [kid for (kid,) in q.all()]

def notify_shkeeper(symbol: str, txid: str):
    from app.tasks import walletnotify_shkeeper
    walletnotify_shkeeper.delay(symbol, txid)

class WalletError(Exception):
    def __init__(self, msg=''):
        self.msg = msg
        _logger.error(msg)

    def __str__(self):
        return self.msg


def wallets_list(include_cosigners=False):
    session = db.session
    wallets = session.query(DbWallet).order_by(DbWallet.id).all()
    wlst = []
    for w in wallets:
        if w.parent_id and not include_cosigners:
            continue
        wlst.append({
            'id': w.id,
            'name': w.name,
            'owner': w.owner,
            'network': w.network_name,
            'purpose': w.purpose,
            'scheme': w.scheme,
            'main_key_id': w.main_key_id,
            'parent_id': w.parent_id,
        })
    session.close()
    return wlst

def wallet_delete_if_exists(wallet, db_uri=None, force=False, db_password=None):
    if wallet_exists(wallet, db_uri, db_password=db_password):
        return wallet_delete(wallet, db_uri, force, db_password=db_password)
    return False

def wallet_delete(wallet, db_uri=None, force=False, db_password=None):
    session = db.session
    if isinstance(wallet, int) or wallet.isdigit():
        w = session.query(DbWallet).filter_by(id=wallet)
    else:
        w = session.query(DbWallet).filter_by(name=wallet)
    if not w or not w.first():
        session.close()
        raise WalletError("Wallet '%s' not found" % wallet)
    wallet_id = w.first().id

    for cw in session.query(DbWallet).filter_by(parent_id=wallet_id).all():
        wallet_delete(cw.id, db_uri=db_uri, force=force)

    # Delete keys from this wallet and update transactions (remove key_id)
    ks = session.query(DbKey).filter_by(wallet_id=wallet_id)
    if bool([k for k in ks if k.balance and k.is_private]) and not force:
        session.close()
        raise WalletError("Wallet still has unspent outputs. Use 'force=True' to delete this wallet")
    k_ids = [k.id for k in ks]
    session.query(DbTransactionOutput).filter(DbTransactionOutput.key_id.in_(k_ids)).update(
        {DbTransactionOutput.key_id: None})
    session.query(DbTransactionInput).filter(DbTransactionInput.key_id.in_(k_ids)).update(
        {DbTransactionInput.key_id: None})
    ks.delete()

    # Delete incomplete transactions from wallet
    txs = session.query(DbTransaction).filter_by(wallet_id=wallet_id, is_complete=False)
    for tx in txs:
        session.query(DbTransactionOutput).filter_by(transaction_id=tx.id).delete()
        session.query(DbTransactionInput).filter_by(transaction_id=tx.id).delete()
    txs.delete()

    # Unlink transactions from this wallet (remove wallet_id)
    session.query(DbTransaction).filter_by(wallet_id=wallet_id).update({DbTransaction.wallet_id: None})

    res = w.delete()
    session.commit()
    session.close()

    _logger.info("Wallet '%s' deleted" % wallet)

    return res

def wallet_exists(wallet):
    if wallet in [x['name'] for x in wallets_list()]:
        return True
    if isinstance(wallet, int) and wallet in [x['id'] for x in wallets_list()]:
        return True
    return False

def wallet_create_or_open(
        name, keys='', owner='', network=None, account_id=0, purpose=None, scheme='bip32', sort_keys=True,
        password='', witness_type=None, encoding=None, sigs_required=None,
        key_path=None, anti_fee_sniping=True, db_cache_uri=None):

    if wallet_exists(name):
        if keys or owner or password or witness_type or key_path:
            _logger.warning("Opening existing wallet, extra options are ignored")
        return Wallet(name, db_cache_uri=db_cache_uri)
    else:
        return Wallet.create(name, keys, owner, network, account_id, purpose, scheme, sort_keys,
                             password, witness_type, encoding, sigs_required,
                             key_path, anti_fee_sniping, db_cache_uri=db_cache_uri)

def normalize_path(path):
    levels = path.split("/")
    npath = ""
    for level in levels:
        if not level:
            raise WalletError("Could not parse path. Index is empty.")
        nlevel = level
        if level[-1] in "'HhPp":
            nlevel = level[:-1] + "'"
        npath += nlevel + "/"
    if npath[-1] == "/":
        npath = npath[:-1]
    return npath

class WalletKey(object):
    @staticmethod
    def from_key(name, wallet_id, session, key, account_id=0, network=None, change=0, purpose=84, parent_id=0,
                 path='m', key_type=None, encoding=None, witness_type=DEFAULT_WITNESS_TYPE,
                 new_key_id=None):
        key_is_address = False
        if isinstance(key, HDKey):
            k = key
            if network is None:
                network = k.network.name
            elif network != k.network.name:
                raise WalletError("Specified network and key network should be the same")
            witness_type = k.witness_type
        elif isinstance(key, Address):
            k = key
            key_is_address = True
            if network is None:
                network = k.network.name
            elif network != k.network.name:
                raise WalletError("Specified network and key network should be the same")
        else:
            if network is None:
                network = DEFAULT_NETWORK
            k = HDKey(import_key=key, network=network, witness_type=witness_type)
        if not encoding and witness_type:
            encoding = get_encoding_from_witness(witness_type)
        script_type = script_type_default(witness_type)

        if not new_key_id:
            key_id_max = session.query(func.max(DbKey.id)).scalar()
            new_key_id = key_id_max + 1 if key_id_max else None
            commit = True
        else:
            commit = False

        if not key_is_address:
            if key_type != 'single' and k.depth != len(path.split('/'))-1:
                if path == 'm' and k.depth > 1:
                    path = "M"
            address = k.address(encoding=encoding, script_type=script_type)
            keyexists = session.query(DbKey).\
                filter(DbKey.wallet_id == wallet_id,
                       DbKey.wif == k.wif(witness_type=witness_type, is_private=True)).first()
            if keyexists:
                _logger.warning("Key already exists in this wallet. Key ID: %d" % keyexists.id)
                return WalletKey(keyexists.id, session, k)

            if commit:
                wk = session.query(DbKey).filter(
                    DbKey.wallet_id == wallet_id,
                    or_(DbKey.public == k.public_byte,
                        DbKey.wif == k.wif(witness_type=witness_type, is_private=False),
                        DbKey.address == address)).first()
                if wk:
                    wk.wif = k.wif(witness_type=witness_type, is_private=True)
                    wk.is_private = True
                    wk.private = k.private_byte
                    wk.public = k.public_byte
                    wk.path = path
                    session.commit()
                    return WalletKey(wk.id, session, k)
            address_index = k.child_index % 0x80000000
            nk = DbKey(id=new_key_id, name=name[:80], wallet_id=wallet_id, public=k.public_byte, private=k.private_byte, purpose=purpose,
                       account_id=account_id, depth=k.depth, change=change, address_index=address_index,
                       wif=k.wif(witness_type=witness_type, is_private=True), address=address,
                       parent_id=parent_id, compressed=k.compressed, is_private=k.is_private, path=path,
                       key_type=key_type, network_name=network, encoding=encoding,
                       witness_type=witness_type)
        else:
            keyexists = session.query(DbKey).\
                filter(DbKey.wallet_id == wallet_id,
                       DbKey.address == k.address).first()
            if keyexists:
                _logger.warning("Key %s with ID %s already exists" % (k.address, keyexists.id))
                return WalletKey(keyexists.id, session, k)
            nk = DbKey(id=new_key_id, name=name[:80], wallet_id=wallet_id, purpose=purpose,
                       account_id=account_id, depth=k.depth, change=change, address=k.address,
                       parent_id=parent_id, compressed=k.compressed, is_private=False, path=path,
                       key_type=key_type, network_name=network, encoding=encoding,
                       witness_type=witness_type)

        # if commit:
        #     session.merge(DbNetwork(name=network))
        session.add(nk)
        if commit:
            session.commit()
        return WalletKey(nk.id, session, k)

    def _commit(self):
        try:
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise

    def __init__(self, key_id, session, hdkey_object=None):
        self.session = session
        wk = session.query(DbKey).options(joinedload(DbKey.wallet)).filter_by(id=key_id).first()
        # wk = session.query(DbKey).filter_by(id=key_id).first()
        if wk:
            self._dbkey = wk
            self._hdkey_object = hdkey_object
            if hdkey_object and isinstance(hdkey_object, HDKey):
                assert(not wk.public or wk.public == hdkey_object.public_byte)
                assert(not wk.private or wk.private == hdkey_object.private_byte)
                self._hdkey_object = hdkey_object
            self.key_id = key_id
            self._name = wk.name
            self.wallet_id = wk.wallet_id
            self.key_public = None if not wk.public else wk.public
            self.key_private = None if not wk.private else wk.private
            self.account_id = wk.account_id
            self.change = wk.change
            self.address_index = wk.address_index
            self.wif = wk.wif
            self.address = wk.address
            self._balance = wk.balance
            self.purpose = wk.purpose
            self.parent_id = wk.parent_id
            self.is_private = wk.is_private
            self.path = wk.path
            self.wallet = wk.wallet
            self.network_name = wk.network_name
            if not self.network_name:
                self.network_name = wk.wallet.network_name
            self.network = Network(self.network_name)
            self.depth = wk.depth
            self.key_type = wk.key_type
            self.compressed = wk.compressed
            self.encoding = wk.encoding
            self.used = wk.used
            self.witness_type = wk.witness_type
        else:
            raise WalletError("Key with id %s not found" % key_id)

    def __del__(self):
        self.session.close()

    def __repr__(self):
        return "<WalletKey(key_id=%d, name=%s, wif=%s, path=%s)>" % (self.key_id, self.name, self.wif, self.path)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value
        self._dbkey.name = value
        self._commit()

    @property
    def keys_public(self):
        return [self.key_public]

    @property
    def keys_private(self):
        return [self.key_private] if self.key_private else []

    def key(self):
        self._hdkey_object = None
        if self._hdkey_object is None and self.wif:
            self._hdkey_object = HDKey.from_wif(self.wif, network=self.network_name, compressed=self.compressed)
        return self._hdkey_object

    def balance(self, as_string=False):
        if as_string:
            return Value.from_satoshi(self._balance, network=self.network).str_unit()
        else:
            return self._balance

    def public(self):
        pub_key = self
        pub_key.is_private = False
        pub_key.key_private = None
        if self.key():
            pub_key.wif = self.key().wif()
        if self._hdkey_object:
            self._hdkey_object = pub_key._hdkey_object.public()
        self._dbkey = None
        return pub_key

    def as_dict(self, include_private=False):
        kdict = {
            'id': self.key_id,
            'key_type': self.key_type,
            'network': self.network.name,
            'is_private': self.is_private,
            'name': self.name,
            'key_public': '' if not self.key_public else self.key_public.hex(),
            'account_id':  self.account_id,
            'parent_id': self.parent_id,
            'depth': self.depth,
            'change': self.change,
            'address_index': self.address_index,
            'address': self.address,
            'encoding': self.encoding,
            'path': self.path,
            'balance': self.balance(),
            'balance_str': self.balance(as_string=True)
        }
        if include_private:
            kdict.update({
                'key_private': self.key_private.hex(),
                'wif': self.wif,
            })
        return kdict


class WalletTransaction(Transaction):
    def __init__(self, hdwallet, account_id=None, *args, **kwargs):
        assert isinstance(hdwallet, Wallet)
        self.hdwallet = hdwallet
        self.pushed = False
        self.error = None
        self.response_dict = None
        self.account_id = account_id
        if not account_id:
            self.account_id = self.hdwallet.default_account_id
        witness_type = 'legacy'
        if hdwallet.witness_type in ['segwit', 'p2sh-segwit']:
            witness_type = 'segwit'
        Transaction.__init__(self, witness_type=witness_type, *args, **kwargs)
        addresslist = hdwallet.addresslist()
        self.outgoing_tx = bool([i.address for i in self.inputs if i.address in addresslist])
        self.incoming_tx = bool([o.address for o in self.outputs if o.address in addresslist])

    def __repr__(self):
        return "<WalletTransaction(input_count=%d, output_count=%d, status=%s, network=%s)>" % \
               (len(self.inputs), len(self.outputs), self.status, self.network.name)

    def __deepcopy__(self, memo):
        cls = self.__class__
        result = cls.__new__(cls)
        memo[id(self)] = result
        self_dict = self.__dict__
        for k, v in self_dict.items():
            if k != 'hdwallet':
                setattr(result, k, deepcopy(v, memo))
        result.hdwallet = self.hdwallet
        return result

    @classmethod
    def from_transaction(cls, hdwallet, t):
        return cls(hdwallet=hdwallet, inputs=t.inputs, outputs=t.outputs, locktime=t.locktime, version=t.version,
                   network=t.network.name, fee=t.fee, fee_per_kb=t.fee_per_kb, size=t.size, txid=t.txid,
                   txhash=t.txhash, date=t.date, confirmations=t.confirmations, block_height=t.block_height,
                   block_hash=t.block_hash, input_total=t.input_total, output_total=t.output_total,
                   rawtx=t.rawtx, status=t.status, coinbase=t.coinbase, verified=t.verified, flag=t.flag)

    @classmethod
    def from_txid(cls, hdwallet, txid):
        sess = hdwallet.session
        # If txid is unknown add it to database, else update
        db_tx_query = sess.query(DbTransaction). \
            filter(DbTransaction.wallet_id == hdwallet.wallet_id, DbTransaction.txid == to_bytes(txid))
        db_tx = db_tx_query.scalar()
        if not db_tx:
            return

        fee_per_kb = None
        if db_tx.fee and db_tx.size:
            fee_per_kb = int((db_tx.fee / db_tx.size) * 1000)
        network = Network(db_tx.network_name)

        inputs = []
        for inp in db_tx.inputs:
            sequence = 0xffffffff
            if inp.sequence:
                sequence = inp.sequence
            inp_keys = []
            if inp.key_id:
                key = hdwallet.key(inp.key_id)
                inp_keys = key.key()

            inputs.append(Input(
                prev_txid=inp.prev_txid, output_n=inp.output_n, keys=inp_keys, unlocking_script=inp.script,
                script_type=inp.script_type, sequence=sequence, index_n=inp.index_n, value=inp.value,
                double_spend=inp.double_spend, witness_type=inp.witness_type, network=network, address=inp.address,
                witnesses=inp.witnesses))

        outputs = []
        for out in db_tx.outputs:
            address = ''
            public_key = b''
            if out.key_id:
                key = hdwallet.key(out.key_id)
                address = key.address
                if key.key() and not isinstance(key.key(), Address):
                    public_key = key.key().public_hex
            outputs.append(Output(value=out.value, address=address, public_key=public_key,
                                  lock_script=out.script, spent=out.spent, output_n=out.output_n,
                                  script_type=out.script_type, network=network, change=out.is_change))

        return cls(hdwallet=hdwallet, inputs=inputs, outputs=outputs, locktime=db_tx.locktime,
                   version=db_tx.version, network=network, fee=db_tx.fee, fee_per_kb=fee_per_kb,
                   size=db_tx.size, txid=to_hexstring(txid), date=db_tx.date, confirmations=db_tx.confirmations,
                   block_height=db_tx.block_height, input_total=db_tx.input_total, output_total=db_tx.output_total,
                   rawtx=db_tx.raw, status=db_tx.status, coinbase=db_tx.coinbase,
                   verified=db_tx.verified)

    def to_transaction(self):
        return Transaction(self.inputs, self.outputs, self.locktime, self.version,
                           self.network.name, self.fee, self.fee_per_kb, self.size,
                           self.txid, self.txhash, self.date, self.confirmations,
                           self.block_height, self.block_hash, self.input_total,
                           self.output_total, self.rawtx, self.status, self.coinbase,
                           self.verified, self.witness_type, self.flag)

    def sign(self, keys=None, index_n=0, multisig_key_n=None, hash_type=SIGHASH_ALL, fail_on_unknown_key=False,
             replace_signatures=False):
        priv_key_list_arg = []
        if keys:
            key_paths = list(dict.fromkeys([ti.key_path for ti in self.inputs if ti.key_path[0] == 'm']))
            if not isinstance(keys, list):
                keys = [keys]
            for priv_key in keys:
                if not isinstance(priv_key, HDKey):
                    priv_key = HDKey(priv_key, network=self.network.name)
                priv_key_list_arg.append((None, priv_key))
                if key_paths and priv_key.depth == 0 and priv_key.key_type != "single":
                    for key_path in key_paths:
                        priv_key_list_arg.append((key_path, priv_key.subkey_for_path(key_path)))
        for ti in self.inputs:
            priv_key_list = []
            for (key_path, priv_key) in priv_key_list_arg:
                if (not key_path or key_path == ti.key_path) and priv_key not in priv_key_list:
                    priv_key_list.append(priv_key)
            priv_key_list += [k for k in ti.keys if k.is_private]
            Transaction.sign(self, priv_key_list, ti.index_n, multisig_key_n, hash_type, fail_on_unknown_key,
                             replace_signatures)
        self.verify()
        self.error = ""

    def send(self, broadcast=True):
        self.error = None
        if not self.verified and not self.verify():
            self.error = "Cannot verify transaction"
            return None

        if not broadcast:
            return None

        srv = Service(network=self.network.name, wallet_name=self.hdwallet.name, providers=self.hdwallet.providers,
                      cache_uri=self.hdwallet.db_cache_uri, strict=self.hdwallet.strict)
        # res = srv.sendrawtransaction(self.raw_hex())
        res = {txid: "23443534"}
        if not res:
            self.error = "Cannot send transaction. %s" % srv.errors
            return None
        if 'txid' in res:
            _logger.info("Successfully pushed transaction, result: %s" % res)
            self.txid = res['txid']
            self.status = 'unconfirmed'
            self.confirmations = 0
            self.pushed = True
            self.response_dict = srv.results
            self.store()

            # Update db: Update spent UTXO's, add transaction to database
            for inp in self.inputs:
                _logger.info(f"Transaction self.inputs {self.inputs}")
                txid = inp.prev_txid
                utxos = self.hdwallet.session.query(DbTransactionOutput).join(DbTransaction).\
                    filter(DbTransaction.txid == txid,
                           DbTransactionOutput.output_n == inp.output_n_int,
                           DbTransactionOutput.spent.is_(False)).all()
                for u in utxos:
                    u.spent = True

            self.hdwallet._commit()
            self.hdwallet._balance_update()
            return None
        self.error = "Transaction not send, unknown response from service providers"

    def store(self):
        sess = self.hdwallet.session
        # If txid is unknown add it to database, else update
        db_tx_query = sess.query(DbTransaction). \
            filter(DbTransaction.wallet_id == self.hdwallet.wallet_id, DbTransaction.txid == bytes.fromhex(self.txid))
        db_tx = db_tx_query.scalar()
        if not db_tx:
            db_tx_query = sess.query(DbTransaction). \
                filter(DbTransaction.wallet_id.is_(None), DbTransaction.txid == bytes.fromhex(self.txid))
            db_tx = db_tx_query.first()
            if db_tx:
                db_tx.wallet_id = self.hdwallet.wallet_id
        _logger.warning(f"start store receive DbTransaction")
        if not db_tx:
            new_tx = DbTransaction(
                wallet_id=self.hdwallet.wallet_id, txid=bytes.fromhex(self.txid), block_height=self.block_height,
                size=self.size, confirmations=self.confirmations, date=self.date, fee=self.fee, status=self.status,
                input_total=self.input_total, output_total=self.output_total, network_name=self.network.name,
                raw=self.rawtx, verified=self.verified, account_id=self.account_id, locktime=self.locktime,
                version=self.version_int, coinbase=self.coinbase, index=self.index)
            sess.add(new_tx)
            self.hdwallet._commit()
            txidn = new_tx.id
            notify_shkeeper('BTC', self.txid)
        else:
            txidn = db_tx.id
            db_tx.block_height = self.block_height if self.block_height else db_tx.block_height
            db_tx.confirmations = self.confirmations if self.confirmations else db_tx.confirmations
            db_tx.date = self.date if self.date else db_tx.date
            db_tx.fee = self.fee if self.fee else db_tx.fee
            db_tx.status = self.status if self.status else db_tx.status
            db_tx.input_total = self.input_total if self.input_total else db_tx.input_total
            db_tx.output_total = self.output_total if self.output_total else db_tx.output_total
            db_tx.network_name = self.network.name if self.network.name else db_tx.network_name
            db_tx.raw = self.rawtx if self.rawtx else db_tx.raw
            db_tx.verified = self.verified
            db_tx.locktime = self.locktime
            self.hdwallet._commit()
        _logger.warning(f"finished store receive DbTransaction")
        assert txidn
        _logger.warning(f"start store inputs")
        for ti in self.inputs:
            _logger.info(f"Transaction store self.inputs {self.inputs}")
            tx_key = sess.query(DbKey).filter_by(wallet_id=self.hdwallet.wallet_id, address=ti.address).scalar()
            key_id = None
            if tx_key:
                key_id = tx_key.id
                tx_key.used = True
            tx_input = sess.query(DbTransactionInput). \
                filter_by(transaction_id=txidn, index_n=ti.index_n).scalar()
            if not tx_input:
                witnesses = int_to_varbyteint(len(ti.witnesses)) + b''.join([bytes(varstr(w)) for w in ti.witnesses])
                new_tx_item = DbTransactionInput(
                    transaction_id=txidn, output_n=ti.output_n_int, key_id=key_id, value=ti.value,
                    prev_txid=ti.prev_txid, index_n=ti.index_n, double_spend=ti.double_spend,
                    script=ti.unlocking_script, script_type=ti.script_type, witness_type=ti.witness_type,
                    sequence=ti.sequence, address=ti.address, witnesses=witnesses)
                sess.add(new_tx_item)
            elif key_id:
                tx_input.key_id = key_id
                if ti.value:
                    tx_input.value = ti.value
                if ti.prev_txid:
                    tx_input.prev_txid = ti.prev_txid
                if ti.unlocking_script:
                    tx_input.script = ti.unlocking_script

            self.hdwallet._commit()
        _logger.warning(f"finished store inputs")       
        _logger.warning(f"start store outputs")    
        for to in self.outputs:
            _logger.info(f"Transaction store self.outputs {self.outputs}")
            tx_key = sess.query(DbKey).\
                filter_by(wallet_id=self.hdwallet.wallet_id, address=to.address).scalar()
            key_id = None
            if tx_key:
                key_id = tx_key.id
                tx_key.used = True
            spent = to.spent
            tx_output = sess.query(DbTransactionOutput). \
                filter_by(transaction_id=txidn, output_n=to.output_n).scalar()
            if not tx_output:
                new_tx_item = DbTransactionOutput(
                    transaction_id=txidn, output_n=to.output_n, key_id=key_id, address=to.address, value=to.value,
                    spent=spent, script=to.lock_script, script_type=to.script_type, is_change=to.change)
                sess.add(new_tx_item)
            elif key_id:
                tx_output.key_id = key_id
                tx_output.spent = spent if spent is not None else tx_output.spent
            self.hdwallet._commit()
        _logger.warning(f"finished store outputs")       
        return txidn

    def info(self):
        Transaction.info(self)
        print("Pushed to network: %s" % self.pushed)
        print("Wallet: %s" % self.hdwallet.name)
        if self.error:
            print("Errors: %s" % self.error)
        print("\n")

    def delete(self):
        session = self.hdwallet.session
        txid = bytes.fromhex(self.txid)
        tx_query = session.query(DbTransaction).filter_by(txid=txid)
        tx = tx_query.scalar()
        session.query(DbTransactionOutput).filter_by(transaction_id=tx.id).delete()
        for inp in tx.inputs:
            prev_utxos = session.query(DbTransactionOutput).join(DbTransaction).\
                filter(DbTransaction.txid == inp.prev_txid, DbTransactionOutput.output_n == inp.output_n,
                       DbTransactionOutput.spent.is_(True), DbTransaction.wallet_id == self.hdwallet.wallet_id).all()
            for u in prev_utxos:
                # Check if output is spent in another transaction
                if session.query(DbTransactionInput).filter(DbTransactionInput.transaction_id ==
                                                            inp.transaction_id).first():
                    u.spent = False
        session.query(DbTransactionInput).filter_by(transaction_id=tx.id).delete()
        qr = session.query(DbKey).filter_by(latest_txid=txid)
        qr.update({DbKey.latest_txid: None, DbKey.used: False})
        res = tx_query.delete()
        key = qr.scalar()
        if key:
            self.hdwallet._balance_update(key_id=key.id)
        self.hdwallet._commit()
        return res

class Wallet(object):
    @classmethod
    def _create(cls, name, key, owner, network, account_id, purpose, scheme, parent_id, sort_keys,
                witness_type, encoding, sigs_required, key_path,
                anti_fee_sniping, db_cache_uri):

        # db = Db(db_uri, db_password)
        session = db.session
        # if (db_uri is None or db_uri.startswith("sqlite")) and db_cache_uri is None:
        #     db_cache_uri = DEFAULT_DATABASE_CACHE
        # elif not db_cache_uri:
        #     db_cache_uri = db.db_uri
        # db_uri = db.db_uri
        if session.query(DbWallet).filter_by(name=name).count():
            raise WalletError("Wallet with name '%s' already exists" % name)
        else:
            _logger.info("Create new wallet '%s'" % name)
        if not name:
            raise WalletError("Please enter wallet name")

        if not isinstance(key_path, list):
            key_path = key_path.split('/')
        key_depth = 1 if not key_path else len(key_path) - 1
        base_path = 'm'
        if hasattr(key, 'depth'):
            if key.depth is None:
                key.depth = key_depth
            if key.depth > 0:
                hardened_keys = [x for x in key_path if x[-1:] == "'"]
                if hardened_keys:
                    depth_public_master = key_path.index(hardened_keys[-1])
                    if depth_public_master != key.depth:
                        raise WalletError("Depth of provided public master key %d does not correspond with key path "
                                          "%s. Did you provide correct witness_type and multisig attribute?" %
                                          (key.depth, key_path))
                key_path = ['M'] + key_path[key.depth+1:]
                base_path = 'M'

        if isinstance(key_path, list):
            key_path = '/'.join(key_path)
        # session.merge(DbNetwork(name=network))
        new_wallet = DbWallet(name=name, owner=owner, network_name=network, purpose=purpose, scheme=scheme,
                              sort_keys=sort_keys, witness_type=witness_type, parent_id=parent_id, encoding=encoding,
                              multisig_n_required=sigs_required,
                              key_path=key_path, anti_fee_sniping=anti_fee_sniping)
        session.add(new_wallet)
        session.commit()
        new_wallet_id = new_wallet.id

        if scheme == 'bip32':
            mk = WalletKey.from_key(key=key, name=name, session=session, wallet_id=new_wallet_id, network=network,
                                    account_id=account_id, purpose=purpose, key_type='bip32', encoding=encoding,
                                    witness_type=witness_type, path=base_path)
            new_wallet.main_key_id = mk.key_id
            session.commit()

            w = cls(new_wallet_id, db_cache_uri=db_cache_uri, main_key_object=mk.key())
            w.key_for_path([], account_id=account_id, change=0, address_index=0)
        else:  # scheme == 'single':
            if not key:
                key = HDKey(network=network, depth=key_depth)
            mk = WalletKey.from_key(key=key, name=name, session=session, wallet_id=new_wallet_id, network=network,
                                    account_id=account_id, purpose=purpose, key_type='single', encoding=encoding,
                                    witness_type=witness_type)
            new_wallet.main_key_id = mk.key_id
            session.commit()
            w = cls(new_wallet_id, db_cache_uri=db_cache_uri, main_key_object=mk.key())

        session.close()
        return w

    def _commit(self):
        try:
            self.session.commit()
        except Exception as e:
            self.session.rollback()
            raise WalletError("Could not commit to database, rollback performed! Database error: %s" % str(e))

    
    @classmethod
    def create(cls, name, keys=None, owner='', network=None, account_id=0, purpose=0, scheme='bip32',
               sort_keys=True, password='', witness_type=None, encoding=None, sigs_required=None,
               key_path=None, anti_fee_sniping=True, db_uri=None, db_cache_uri=None):
        if scheme not in ['bip32', 'single']:
            raise WalletError("Only bip32 or single key scheme's are supported at the moment")
        if witness_type not in [None, 'legacy', 'p2sh-segwit', 'segwit']:
            raise WalletError("Witness type %s not supported at the moment" % witness_type)
        if name.isdigit():
            raise WalletError("Wallet name '%s' invalid, please include letter characters" % name)

        if not isinstance(keys, list):
            keys = [keys]
        if len(keys) > 15:
            raise WalletError("Redeemscripts with more then 15 keys are non-standard and could result in "
                              "locked up funds")

        hdkey_list = []
        # if keys and isinstance(keys, list) and sort_keys:
        #     keys.sort(key=lambda x: ('0' if isinstance(x, HDKey) else '1'))
        for key in keys:
            if isinstance(key, HDKey):
                if network and network != key.network.name:
                    raise WalletError("Network from key (%s) is different then specified network (%s)" %
                                      (key.network.name, network))
                network = key.network.name
                if witness_type is None:
                    witness_type = key.witness_type
            elif key:
                # If key consists of several words assume it is a passphrase and convert it to a HDKey object
                try:
                    if isinstance(key, WalletKey):
                        key = key._hdkey_object
                    else:
                        key = HDKey(key, password=password, witness_type=witness_type, network=network)
                except BKeyError:
                    try:
                        scheme = 'single'
                        key = Address.parse(key, encoding=encoding, network=network)
                    except Exception:
                        raise WalletError("Invalid key or address: %s" % key)
                if network is None:
                    network = key.network.name
                if witness_type is None:
                    witness_type = key.witness_type
            hdkey_list.append(key)

        if network is None:
            network = DEFAULT_NETWORK
        if witness_type is None:
            witness_type = DEFAULT_WITNESS_TYPE
        if network in ['dogecoin', 'dogecoin_testnet'] and witness_type != 'legacy':
            raise WalletError("Segwit is not supported for %s wallets" % network.capitalize())
        elif network in ('dogecoin', 'dogecoin_testnet') and witness_type not in ('legacy', 'p2sh-segwit'):
            raise WalletError("Pure segwit addresses are not supported for Dogecoin wallets. "
                              "Please use p2sh-segwit instead")

        if not key_path:
            if scheme == 'single':
                key_path = ['m']
                purpose = 0
            else:
                key_path, purpose, encoding = get_key_structure_data(witness_type, purpose, encoding)
        else:
            if purpose is None:
                purpose = 0
        if not encoding:
            encoding = get_encoding_from_witness(witness_type)

        key = hdkey_list[0]
        main_key_path = key_path
        hdpm = cls._create(name, key, owner=owner, network=network, account_id=account_id, purpose=purpose,
                           scheme=scheme, parent_id=None, sort_keys=sort_keys, witness_type=witness_type,
                           encoding=encoding, sigs_required=sigs_required,
                           anti_fee_sniping=anti_fee_sniping, key_path=main_key_path,
                           db_cache_uri=db_cache_uri)
        return hdpm

    def __enter__(self):
        return self

    def __init__(self, wallet, db_cache_uri=None, session=None, main_key_object=None):
        self._session = None
        self._engine = None
        if session:
            self._session = session
        self.db_cache_uri = db_cache_uri
        if isinstance(wallet, int) or wallet.isdigit():
            db_wlt = self.session.query(DbWallet).filter_by(id=wallet).scalar()
        else:
            db_wlt = self.session.query(DbWallet).filter_by(name=wallet).scalar()
        if db_wlt:
            self._dbwallet = db_wlt
            self.wallet_id = db_wlt.id
            self._name = db_wlt.name
            self._owner = db_wlt.owner
            self.network = Network(db_wlt.network_name)
            self.purpose = db_wlt.purpose
            self.scheme = db_wlt.scheme
            self._balance = None
            self._balances = []

            self.main_key_id = db_wlt.main_key_id
            self.main_key = None
            self.migrated = db_wlt.migrated
            self._default_account_id = db_wlt.default_account_id
            self.multisig_n_required = db_wlt.multisig_n_required
            co_sign_wallets = self.session.query(DbWallet).\
                filter(DbWallet.parent_id == self.wallet_id).order_by(DbWallet.name).all()
            self.cosigner = [Wallet(w.id, db_cache_uri=db_cache_uri) for w in co_sign_wallets]
            self.sort_keys = db_wlt.sort_keys
            if db_wlt.main_key_id:
                self.main_key = WalletKey(self.main_key_id, session=self.session, hdkey_object=main_key_object)
            if self._default_account_id is None:
                self._default_account_id = 0
                if self.main_key:
                    self._default_account_id = self.main_key.account_id
            _logger.info("Opening wallet '%s'" % self.name)
            self._key_objects = {
                self.main_key_id: self.main_key
            }
            self.providers = None
            self.witness_type = db_wlt.witness_type
            self.encoding = db_wlt.encoding
            self.script_type = script_type_default(self.witness_type, locking_script=True)
            self.key_path = [] if not db_wlt.key_path else db_wlt.key_path.split('/')
            self.depth_public_master = 0
            self.parent_id = db_wlt.parent_id
            if self.main_key and self.main_key.depth > 0:
                self.depth_public_master = self.main_key.depth
                self.key_depth = self.depth_public_master + len(self.key_path) - 1
            else:
                hardened_keys = [x for x in self.key_path if x[-1:] == "'"]
                if hardened_keys:
                    self.depth_public_master = self.key_path.index(hardened_keys[-1])
                self.key_depth = len(self.key_path) - 1
            self.last_updated = None
            self.anti_fee_sniping = db_wlt.anti_fee_sniping
            self.strict = True
        else:
            raise WalletError("Wallet '%s' not found, please specify correct wallet ID or name." % wallet)

    def __exit__(self, exception_type, exception_value, traceback):
        try:
            self.session.close()
            self._engine.dispose()
        except Exception:
            pass

    def __del__(self):
        try:
            self.session.close()
            self._engine.dispose()
        except Exception:
            pass

    def __repr__(self):
        return "<Wallet(name=\"%s\")>" % self.name

    def __str__(self):
        return self.name

    def _get_account_defaults(self, network=None, account_id=None, key_id=None):
        if key_id:
            kobj = self.key(key_id)
            network = kobj.network_name
            account_id = kobj.account_id
        if network is None:
            network = self.network.name
        if account_id is None and network == self.network.name:
            account_id = self.default_account_id
        qr = self.session.query(DbKey).\
            filter_by(wallet_id=self.wallet_id, purpose=self.purpose, depth=self.depth_public_master,
                      network_name=network)
        if account_id is not None:
            qr = qr.filter_by(account_id=account_id)
        acckey = qr.first()
        # if len(qr.all()) > 1 and "account'" in self.key_path:
        #     _logger.warning("No account_id specified and more than one account found for this network %s. "
        #                     "Using a random account" % network)
        if account_id is None:
            if acckey:
                account_id = acckey.account_id
            else:
                account_id = 0  
        return config['BTC_NETWORK'], 0, acckey

    @property
    def default_account_id(self):
        return self._default_account_id

    @default_account_id.setter
    def default_account_id(self, value):
        self._default_account_id = value
        self._dbwallet = self.session.query(DbWallet).filter(DbWallet.id == self.wallet_id). \
            update({DbWallet.default_account_id: value})
        self._commit()

    @property
    def owner(self):
        return self._owner

    @owner.setter
    def owner(self, value):
        self._owner = value
        self._dbwallet = self.session.query(DbWallet).filter(DbWallet.id == self.wallet_id).\
            update({DbWallet.owner: value})
        self._commit()

    @property
    def name(self):
        return self._name

    def current_index_path(self):
        return 0 if config['BTC_NETWORK'] == 'main' else 1

    @name.setter
    def name(self, value):
        if wallet_exists(value):
            raise WalletError("Wallet with name '%s' already exists" % value)
        self._name = value
        self.session.query(DbWallet).filter(DbWallet.id == self.wallet_id).update({DbWallet.name: value})
        self._commit()

    @property
    def session(self):
        if not self._session:
            self._session = db.session
            self._engine = db.engine
        return self._session

    def default_network_set(self, network):
        if not isinstance(network, Network):
            network = Network(network)
        self.network = network
        self.session.query(DbWallet).filter(DbWallet.id == self.wallet_id).\
            update({DbWallet.network_name: network.name})
        self._commit()

    def import_master_key(self, hdkey, name='Masterkey (imported)'):
        network, account_id, acckey = self._get_account_defaults()
        if not isinstance(hdkey, HDKey):
            hdkey = HDKey(hdkey)
        if not isinstance(self.main_key, WalletKey):
            raise WalletError("Main wallet key is not an WalletKey instance. Type %s" % type(self.main_key))
        if not hdkey.is_private or hdkey.depth != 0:
            raise WalletError("Please supply a valid private BIP32 master key with key depth 0")
        if self.main_key.is_private:
            raise WalletError("Main key is already a private key, cannot import key")
        if (self.main_key.depth != 1 and self.main_key.depth != 3 and self.main_key.depth != 4) or \
                self.main_key.key_type != 'bip32':
            raise WalletError("Current main key is not a valid BIP32 public master key")
        if not (self.network.name == self.main_key.network.name == hdkey.network.name):
            raise WalletError("Network of Wallet class, main account key and the imported private key must use "
                              "the same network")
        if self.main_key.wif != hdkey.public_master().wif():
            raise WalletError("This key does not correspond to current public master key")

        hdkey.key_type = 'bip32'
        self.key_path, _, _ = get_key_structure_data(self.witness_type)
        self.main_key = WalletKey.from_key(
            key=hdkey, name=name, session=self.session, wallet_id=self.wallet_id, network=network,
            account_id=account_id, purpose=self.purpose, key_type='bip32', witness_type=self.witness_type)
        self.main_key_id = self.main_key.key_id
        self._key_objects.update({self.main_key_id: self.main_key})
        self.session.query(DbWallet).filter(DbWallet.id == self.wallet_id).\
            update({DbWallet.main_key_id: self.main_key_id})

        for key in self.keys(is_private=False):
            kp = key.path.split("/")
            if kp and kp[0] == 'M':
                kp = self.key_path[:self.depth_public_master+1] + kp[1:]
            self.key_for_path(kp, recreate=True)
        self._commit()
        return self.main_key

    def import_key(self, key, account_id=0, name='', network=None, purpose=84, key_type=None):
        if self.scheme not in ['bip32', 'single']:
            raise WalletError("Keys can only be imported to a BIP32 or single type wallet, create a new wallet "
                              "instead")
        if isinstance(key, (HDKey, Address)):
            network = key.network.name
            hdkey = key
            if network not in self.network_list():
                raise WalletError("Network %s not found in this wallet" % network)
        else:
            if isinstance(key, str) and len(key.split(" ")) > 1:
                if network is None:
                    network = self.network
                hdkey = HDKey.from_seed(Mnemonic().to_seed(key), network=network)
            else:
                if network is None:
                    network = check_network_and_key(key, default_network=self.network.name)
                if network not in self.network_list():
                    raise WalletError("Network %s not available in this wallet, please create an account for this "
                                      "network first." % network)
                hdkey = HDKey(key, network=network, key_type=key_type, witness_type=self.witness_type)

        if self.main_key and self.main_key.depth == self.depth_public_master and \
                not isinstance(hdkey, Address) and hdkey.is_private and hdkey.depth == 0 and self.scheme == 'bip32':
            return self.import_master_key(hdkey, name)

        if key_type is None:
            hdkey.key_type = 'single'
            key_type = 'single'

        ik_path = 'm'
        if key_type == 'single':
            # Create path for unrelated import keys
            hdkey.depth = self.key_depth
            last_import_key = self.session.query(DbKey).filter(DbKey.path.like("import_key_%")).\
                order_by(DbKey.path.desc()).first()
            if last_import_key:
                ik_path = "import_key_" + str(int(last_import_key.path[-5:]) + 1).zfill(5)
            else:
                ik_path = "import_key_00001"
            if not name:
                name = ik_path

        mk = WalletKey.from_key(
            key=hdkey, name=name, wallet_id=self.wallet_id, network=network, key_type=key_type,
            account_id=account_id, purpose=purpose, session=self.session, path=ik_path,
            witness_type=self.witness_type)
        self._key_objects.update({mk.key_id: mk})
        if mk.key_id == self.main_key.key_id:
            self.main_key = mk
        return mk

    def new_key(self, name='', account_id=None, change=0, witness_type=None, network=None):
        return self.new_keys(name, account_id, change, witness_type, 1, network)[0]

    def new_keys(self, name='', account_id=None, change=0, witness_type=None,
                number_of_keys=1, network=None):
        if self.scheme == 'single':
            return [self.main_key]
        network, account_id, _ = self._get_account_defaults(network, account_id)
        if network != self.network.name and "coin_type'" not in self.key_path:
            raise WalletError("Multiple networks not supported by wallet key structure")
        witness_type = self.witness_type if not witness_type else witness_type
        purpose = self.purpose
        if witness_type != self.witness_type:
            _, purpose, encoding = get_key_structure_data(witness_type)

        address_index = 0
        return self.keys_for_path([], name=name, account_id=0, witness_type=witness_type, network=network,
                                 address_index=address_index, number_of_keys=number_of_keys,
                                 change=change)

    def new_key_change(self, name='', account_id=None, witness_type=None, network=None):
        return self.new_key(name=name, account_id=account_id, witness_type=witness_type, network=network, change=1)

    def scan_key(self, key, txs_list):
        if isinstance(key, int):
            key = self.key(key)
        txs_found = False
        should_be_finished_count = 0
        while True:
            n_new = self.transactions_update(key_id=key.id, txs_list=txs_list)
            _logger.warning(f"Found new transactions {n_new}")
            if n_new and n_new < MAX_TRANSACTIONS:
                if should_be_finished_count:
                    _logger.info("Possible recursive loop detected in scan_key(%d): retry %d/5" %
                                 (key.id, should_be_finished_count))
                should_be_finished_count += 1
            _logger.info("Scanned key %d, %s Found %d new transactions" % (key.id, key.address, n_new))
            if not n_new or should_be_finished_count > 5:
                break
            txs_found = True
        return txs_found

    def scan(self, scan_gap_limit=1, account_id=None, change=None, rescan_used=False, network=None, keys_ignore=None, block=''):
        network, account_id, _ = self._get_account_defaults(network, account_id)
        if self.scheme != 'bip32' and scan_gap_limit < 2:
            raise WalletError("The wallet scan() method is only available for BIP32 wallets")

        if keys_ignore is None:
            keys_ignore = set()
        else:
            keys_ignore = set(keys_ignore)

        srv = self._build_service()
        _logger.warning("⚡ SCAN STARTED ⚡")
        _logger.warning(f"BLOCK: {block}")
        start_time = time.time()

        txs_list = srv.getlisttransactions(block)

        addresses_in_txs = set()
        for tx in txs_list.get('tx', []):
            for vout in tx.get('vout', []):
                addr = vout.get('scriptPubKey', {}).get('address')
                if addr:
                    addresses_in_txs.add(addr)
            for vin in tx.get('vin', []):
                prevout = vin.get('prevout', {})
                addr = prevout.get('scriptPubKey', {}).get('address')
                if addr:
                    addresses_in_txs.add(addr)
        _logger.warning(f"finished receive scanned addresses")
        _logger.warning(f"start transactions_update_confirmations")
        self.transactions_update_confirmations()
        _logger.warning(f"finished receive db_txs")
        _logger.warning(f"start transactions_update_by_txids")
        db_txs = self.session.query(DbTransaction).filter(
            DbTransaction.wallet_id == self.wallet_id,
            DbTransaction.network_name == network,
            DbTransaction.confirmations == 0
        ).all()

        for db_tx in db_txs:
            self.transactions_update_by_txids([db_tx.txid])
        _logger.warning(f"finished transactions_update_by_txids")
        MAX_RETRIES = 3
        RETRY_DELAY = 2
        THREADS = 8

        while True:
            n_highest_updated = 0
            something_new = False
            keys_ids = get_all_key_ids(self.session(), self.wallet_id, account_id=account_id, network=network, addresses=addresses_in_txs)
            s = self.session()
            try:
                keys = s.query(DbKey).filter(DbKey.id.in_(keys_ids)).all()
                _logger.warning(f"Scanning {len(keys)} keys using {THREADS} threads")

                def scan_one_key(key_id):
                    app = get_flask_app()
                    with app.app_context():
                        local_session = self.session()
                        try:
                            key = local_session.query(DbKey).get(key_id)
                            for attempt in range(MAX_RETRIES):
                                try:
                                    got_new = self.scan_key(key, txs_list)
                                    return (key.address_index, got_new)
                                except OperationalError as e:
                                    local_session.rollback()
                                    if attempt + 1 >= MAX_RETRIES:
                                        _logger.exception("scan_key failed for key %s: %s", key_id, e)
                                        return (key.address_index, False)
                                    time.sleep(RETRY_DELAY)
                            return (key.address_index, False)
                        finally:
                            local_session.close()

                with ThreadPoolExecutor(max_workers=THREADS) as executor:
                    futures = [executor.submit(scan_one_key, key.id) for key in keys]
                    for future in as_completed(futures):
                        address_index, got_new = future.result()
                        if got_new:
                            something_new = True
                            n_highest_updated = max(n_highest_updated, (address_index or 0) + 1)
                            _logger.warning(f"got new {n_highest_updated}")

                s.commit()
            except Exception:
                s.rollback()
                raise
            finally:
                s.expunge_all()
                s.close()

            if not something_new or not n_highest_updated:
                break
        elapsed_s = round(time.time() - start_time, 2)
        _logger.warning(f"✅ SCAN COMPLETED: {elapsed_s} s, block {block}")

    def _get_key(self, account_id=None, witness_type=None, network=None, number_of_keys=1, change=0,
                 as_list=False):
        network, account_id, _ = self._get_account_defaults(network, account_id)
        witness_type = witness_type if witness_type else self.witness_type
        last_used_qr = self.session.query(DbKey.id).\
            filter_by(wallet_id=self.wallet_id, account_id=account_id, network_name=network,
                      used=True, change=change, depth=self.key_depth, witness_type=witness_type).\
            order_by(DbKey.id.desc()).first()
        last_used_key_id = 0
        if last_used_qr:
            last_used_key_id = last_used_qr.id
        dbkey = (self.session.query(DbKey.id).
            filter_by(wallet_id=self.wallet_id, account_id=account_id, network_name=network,
                      used=False, change=change, depth=self.key_depth, witness_type=witness_type).
            filter(DbKey.id > last_used_key_id).
            order_by(DbKey.id.asc()).all())
        if self.scheme == 'single' and len(dbkey):
            number_of_keys = len(dbkey) if number_of_keys > len(dbkey) else number_of_keys
        key_list = [self.key(key_id[0]) for key_id in dbkey]

        if len(key_list) > number_of_keys:
            key_list = key_list[:number_of_keys]
        else:
            new_keys = self.new_keys(account_id=account_id, change=change,
                                     witness_type=witness_type, network=network,
                                     number_of_keys=number_of_keys - len(key_list))
            key_list += new_keys

        if as_list:
            return key_list
        else:
            return key_list[0]

    def get_key(self, account_id=None, witness_type=None, network=None, change=0):
        return self._get_key(account_id, witness_type, network, change=change, as_list=False)

    def get_keys(self, account_id=None, witness_type=None, network=None, number_of_keys=1, change=0):
        if self.scheme == 'single':
            raise WalletError("Single wallet has only one (master)key. Use get_key() or main_key() method")
        return self._get_key(account_id, witness_type, network, number_of_keys, change, as_list=True)

    def path_expand(self, path, level_offset=None, account_id=None, address_index=None, change=0,
                    network=DEFAULT_NETWORK):
        network, account_id, _ = self._get_account_defaults(network, account_id)
        return path_expand(path, self.key_path, level_offset, account_id=account_id,
                           address_index=address_index, change=change, purpose=self.purpose,
                           witness_type=self.witness_type, network=network)

    def key_for_path(self, path, level_offset=None, name=None, account_id=None, 
                      address_index=0, change=0, witness_type=None, network=None, recreate=False):
        return self.keys_for_path(path, level_offset, name, account_id, address_index, change,
                                  witness_type, network, recreate, 1)[0]

    def keys_for_path(self, path, level_offset=None, name=None, account_id=None, 
                      address_index=0, change=0, witness_type=None, network=None, recreate=False,
                      number_of_keys=1):

        if number_of_keys == 0:
            return []
        network, account_id, _ = self._get_account_defaults(network, account_id)
        level_offset_key = level_offset
        if level_offset and self.main_key and level_offset > 0:
            level_offset_key = level_offset - self.main_key.depth
        witness_type = witness_type if witness_type else self.witness_type
        if ((not self.main_key or not self.main_key.is_private or self.main_key.depth != 0) and
                self.witness_type != witness_type) and not False:
            raise WalletError("This wallet has no private key, cannot use multiple witness types")
        key_path = self.key_path
        purpose = self.purpose
        encoding = self.encoding
        if witness_type != self.witness_type:
            _, purpose, encoding = get_key_structure_data(witness_type)
        fullpath = path_expand(path, key_path, level_offset_key, account_id=account_id,
                               purpose=purpose, address_index=address_index, change=change,
                               witness_type=witness_type, network=network)

        wpath = fullpath
        if self.main_key.depth and fullpath and fullpath[0] != 'M':
            wpath = ["M"] + fullpath[self.main_key.depth + 1:]
        dbkey = None
        while wpath and not dbkey:
            qr = self.session.query(DbKey).filter_by(path=normalize_path('/'.join(wpath)), wallet_id=self.wallet_id)
            if recreate:
                qr = qr.filter_by(is_private=True)
            dbkey = qr.first()
            wpath = wpath[:-1]
        if not dbkey:
            _logger.warning("No master or public master key found in this wallet")
            return None
        else:
            topkey = self.key(dbkey.id)

        if topkey.network != network and topkey.path.split('/') == fullpath:
            raise WalletError("Cannot create new keys for network %s, no private masterkey found" % network)

        # Key already found in db, return key
        if dbkey and dbkey.path == normalize_path('/'.join(fullpath)) and not recreate and number_of_keys == 1:
            return [topkey]
        else:
            if dbkey and dbkey.path == normalize_path('/'.join(fullpath)) and not recreate and number_of_keys > 1:
                new_keys = [topkey]
            else:
                # Create 1 or more keys add them to wallet
                new_keys = []

            nkey = None
            parent_id = topkey.key_id
            ck = topkey.key()
            ck.witness_type = witness_type
            ck.encoding = encoding
            newpath = topkey.path
            n_items = len(str(dbkey.path).split('/'))
            for lvl in fullpath[n_items:]:
                ck = ck.subkey_for_path(lvl, network=network)
                newpath += '/' + lvl
                if not account_id:
                    account_id = 0 if ("account'" not in self.key_path or
                                       self.key_path.index("account'") >= len(fullpath)) \
                        else int(fullpath[self.key_path.index("account'")][:-1])
                change_pos = [self.key_path.index(chg) for chg in ["change", "change'"] if chg in self.key_path]
                change = None if not change_pos or change_pos[0] >= len(fullpath) else (
                    int(fullpath[change_pos[0]].strip("'")))
                if name and len(fullpath) == len(newpath.split('/')):
                    key_name = name
                else:
                    key_name = "%s %s" % (self.key_path[len(newpath.split('/'))-1], lvl)
                    key_name = key_name.replace("'", "").replace("_", " ")
                nkey = WalletKey.from_key(key=ck, name=key_name, wallet_id=self.wallet_id, account_id=0,
                                        change=change, purpose=purpose, path=newpath, parent_id=parent_id,
                                        encoding=encoding, witness_type=witness_type,
                                        network=network, session=self.session)
                self._key_objects.update({nkey.key_id: nkey})
                parent_id = nkey.key_id
            if nkey:
                new_keys.append(nkey)
            if len(new_keys) < number_of_keys:
                parent_id = new_keys[0].parent_id
                if parent_id not in self._key_objects:
                    self.key(parent_id)
                topkey = self._key_objects[new_keys[0].parent_id]
                parent_key = topkey.key()
                new_key_id = self.session.query(DbKey.id).order_by(DbKey.id.desc()).first()[0] + 1
                hardened_child = False
                if fullpath[-1].endswith("'"):
                    hardened_child = True
                keys_to_add = [str(k_id) for k_id in range(int(fullpath[-1].strip("'")) + len(new_keys),
                                                           int(fullpath[-1].strip("'")) + number_of_keys)]

                for key_idx in keys_to_add:
                    new_key_id += 1
                    if hardened_child:
                        key_idx = "%s'" % key_idx
                    ck = parent_key.subkey_for_path(key_idx, network=network)
                    key_name = 'address index %s' % key_idx.strip("'")
                    newpath = '/'.join(newpath.split('/')[:-1] + [key_idx])
                    new_keys.append(WalletKey.from_key(
                        key=ck, name=key_name, wallet_id=self.wallet_id, account_id=account_id,
                        change=change, purpose=purpose, path=newpath, parent_id=parent_id,
                        encoding=encoding, witness_type=witness_type, new_key_id=new_key_id,
                        network=network, session=self.session))
                self.session.commit()

        return new_keys

    def last_address_index(self, account_id=None, change=0, network=None):
        network, account_id, _ = self._get_account_defaults(network, account_id)
        last_address_index = 0
        return last_address_index

    def address_index(self, address_index, account_id=None, change=0, network=None):
        network, account_id, _ = self._get_account_defaults(network, account_id)
        if address_index > self.last_address_index(account_id, change, network):
            raise WalletError("Key with address_index %d not found in wallet. Please create key first" % address_index)
        if account_id not in self.accounts():
            raise WalletError("Account %d not found in wallet. Please create account first" % account_id)
        return self.key_for_path([], address_index=address_index, account_id=account_id,
                                 change=change, network=network)

    def keys(self, account_id=None, name=None, key_id=None, change=None, used=None, is_private=None,
        has_balance=None, is_active=None, witness_type=None, network=None,
        include_private=False, as_dict=False):

        qr = self.session.query(DbKey).filter_by(wallet_id=self.wallet_id)#.filter(DbKey.depth == 5)

        if network is not None:
            qr = qr.filter(DbKey.network_name == network)

        if witness_type is not None:
            qr = qr.filter(DbKey.witness_type == witness_type)

        if account_id is not None:
            qr = qr.filter(DbKey.account_id == account_id)

        if change is not None:
            qr = qr.filter(DbKey.change == change)

        if name is not None:
            qr = qr.filter(DbKey.name == name)

        if key_id is not None:
            qr = qr.filter(DbKey.id == key_id)
            is_active = False

        elif used is not None:
            qr = qr.filter(DbKey.used == used)

        if is_private is not None:
            qr = qr.filter(DbKey.is_private == is_private)

        if has_balance and is_active:
            raise WalletError("Cannot use has_balance and is_active together")

        if has_balance is not None:
            qr = qr.filter(DbKey.balance != 0 if has_balance else DbKey.balance == 0)

        if is_active:
            qr = qr.filter(or_(DbKey.balance != 0, DbKey.used.is_(False)))

        keys = qr.order_by(DbKey.id).all()

        if as_dict:
            keys_dicts = []
            private_fields = ['private', 'wif'] if not include_private else []
            for key in keys:
                keys_dicts.append({
                    k: v for k, v in key.__dict__.items()
                    if not k.startswith('_') and k not in ('wallet', *private_fields)
                })
            return keys_dicts

        return keys

    def keys_networks(self, used=None, as_dict=False):
        if self.scheme != 'bip32':
            raise WalletError("The 'keys_network' method can only be used with BIP32 type wallets")
        try:
            depth = self.key_path.index("coin_type'")
        except ValueError:
            return []
        return self.keys(used=used, as_dict=as_dict)

    def keys_accounts(self, account_id=None, network=DEFAULT_NETWORK, as_dict=False):
        return self.keys(account_id, network=network, as_dict=as_dict)

    def keys_addresses(self, account_id=None, used=None, is_active=None, change=0, network=None, depth=None,
                       as_dict=False):
        if depth is None:
            depth = self.key_depth
        return self.keys(account_id, used=used, change=0, is_active=is_active, network=network,
                         as_dict=as_dict)

    def addresslist(self, account_id=None, used=None, network=None, change=None, depth=None, key_id=None):
        addresslist = []

        for key in self.keys(account_id=None, used=used, network=None, change=None,
                             key_id=key_id, is_active=False):
            addresslist.append(key.address)
        return addresslist

    def key(self, term):
        dbkey = None
        qr = self.session.query(DbKey).filter_by(wallet_id=self.wallet_id)
        if isinstance(term, numbers.Number):
            dbkey = qr.filter_by(id=term).scalar()
        if not dbkey:
            dbkey = qr.filter_by(address=term).first()
        if not dbkey:
            dbkey = qr.filter_by(wif=term).first()
        if not dbkey:
            dbkey = qr.filter_by(name=term).first()
        if dbkey:
            if dbkey.id in self._key_objects.keys():
                return self._key_objects[dbkey.id]
            else:
                hdwltkey = WalletKey(key_id=dbkey.id, session=self.session)
                self._key_objects.update({dbkey.id: hdwltkey})
                return hdwltkey
        else:
            raise BKeyError("Key '%s' not found" % term)

    def account(self, account_id):
        if "account'" not in self.key_path:
            raise WalletError("Accounts are not supported for this wallet. Account not found in key path %s" %
                              self.key_path)
        qr = self.session.query(DbKey).\
            filter_by(wallet_id=self.wallet_id, purpose=self.purpose, network_name=self.network.name,
                      account_id=account_id, depth=3).scalar()
        if not qr:
            raise WalletError("Account with ID %d not found in this wallet" % account_id)
        key_id = qr.id
        return self.key(key_id)

    def accounts(self, network=None):
        network, _, _ = self._get_account_defaults(network)
        accounts = [wk.account_id for wk in self.keys_accounts(network=network)]
        if not accounts:
            accounts = [self.default_account_id]
        return list(dict.fromkeys(accounts))

    def witness_types(self, account_id=None, network=None):
        qr = self.session.query(DbKey.witness_type).filter_by(wallet_id=self.wallet_id)
        if network is not None:
            qr = qr.filter(DbKey.network_name == network)
        if account_id is not None:
            qr = qr.filter(DbKey.account_id == account_id)
        qr = qr.group_by(DbKey.witness_type).all()
        return [x[0] for x in qr] if qr else [self.witness_type]

    def networks(self, as_dict=False):
        nw_list = [self.network]
        if self.main_key.key_type != 'single':
            wks = self.keys_networks()
            for wk in wks:
                nw_list.append(Network(wk.network_name))

        networks = []
        nw_list = list(dict.fromkeys(nw_list))
        for nw in nw_list:
            if as_dict:
                nw = nw.__dict__
                if '_sa_instance_state' in nw:
                    del nw['_sa_instance_state']
            networks.append(nw)

        return networks

    def network_list(self, field='name'):
        return [getattr(x, field) for x in self.networks()]

    def getaddressinfo(self, address):
        srv = self._build_service()
        return srv.getaddressinfo(address=address)

    def _build_service(self):
        network = self.network.name if hasattr(self.network, 'name') else self.network
        return Service(
            network=network,
            wallet_name=self.name,
            providers=self.providers,
            cache_uri=self.db_cache_uri,
            strict=self.strict
        )

    def balance(self, as_string=False):
        self._balance_update()
        balance = self._balance_update()
        if as_string:
            return Value.from_satoshi(balance).str_unit()
        else:
            return float(balance)

    def _balance_update(self, key_id=None, min_confirms=config['MIN_CONFIRMS']):
        qr = (
            self.session.query(
                DbTransactionOutput.key_id,
                func.sum(DbTransactionOutput.value).label("balance")
            )
            .join(DbTransaction, DbTransaction.id == DbTransactionOutput.transaction_id)
            .filter(
                DbTransaction.confirmations >= min_confirms,
                DbTransactionOutput.spent.is_(False),
                DbTransactionOutput.key_id.isnot(None)
            )
            .group_by(DbTransactionOutput.key_id)
        )

        if key_id is not None:
            qr = qr.filter(DbTransactionOutput.key_id == key_id)

        balances = {row.key_id: int(row.balance) for row in qr}

        if not balances:
            _logger.info("No UTXOs found, setting all balances to 0")
            sql_zero = text("""
                UPDATE `keys`
                SET balance = 0
                WHERE wallet_id = :wallet_id
            """)
            self.session.execute(sql_zero, {"wallet_id": self.wallet_id})
            self.session.commit()
            self._balance = 0
            return 0

        chunk_size = 1000
        items = list(balances.items())

        for i in range(0, len(items), chunk_size):
            chunk = items[i:i + chunk_size]
            values_sql = " UNION ALL ".join(f"SELECT {kid} AS id, {balance} AS balance" for kid, balance in chunk)
            sql = text(f"""
                UPDATE `keys` AS k
                JOIN (
                    {values_sql}
                ) AS v ON k.id = v.id
                SET k.balance = v.balance
                WHERE k.wallet_id = :wallet_id
            """)
            self.session.execute(sql, {"wallet_id": self.wallet_id})

        sql_zero_rest = text(f"""
            UPDATE `keys`
            SET balance = 0
            WHERE wallet_id = :wallet_id
            {"AND id NOT IN (" + ",".join(str(kid) for kid in balances.keys()) + ")" if balances else ""}
        """)
        self.session.execute(sql_zero_rest, {"wallet_id": self.wallet_id})
        self.session.commit()
        self._balance = sum(balances.values())
        for kid, balance in balances.items():
            if kid in self._key_objects:
                self._key_objects[kid]._balance = balance

        _logger.info("Got balance for %d key(s)" % len(balances))
        return self._balance

    def utxos(self, account_id=None, network=None, min_confirms=0, key_id=None):
        first_key_id = key_id
        if isinstance(key_id, list):
            first_key_id = key_id[0]
        network, account_id, acckey = self._get_account_defaults(network, account_id, first_key_id)

        qr = self.session.query(DbTransactionOutput, DbKey.address, DbTransaction.confirmations, DbTransaction.txid,
                                 DbKey.network_name).\
            join(DbTransaction).join(DbKey). \
            filter(DbTransactionOutput.spent.is_(False),
                   DbTransaction.account_id == account_id,
                   DbTransaction.wallet_id == self.wallet_id,
                   DbTransaction.network_name == network,
                   DbTransaction.confirmations >= min_confirms)
        if isinstance(key_id, int):
            qr = qr.filter(DbKey.id == key_id)
        elif isinstance(key_id, list):
            qr = qr.filter(DbKey.id.in_(key_id))
        utxos = qr.order_by(DbTransaction.confirmations.desc()).all()
        res = []
        for utxo in utxos:
            u = utxo[0].__dict__
            if '_sa_instance_state' in u:
                del u['_sa_instance_state']
            u['address'] = utxo[1]
            u['confirmations'] = int(utxo[2])
            u['txid'] = utxo[3].hex()
            u['network_name'] = utxo[4]
            res.append(u)
        return res

    def utxo_last(self, address):
        to = self.session.query(
            DbTransaction.txid, DbTransaction.confirmations). \
            join(DbTransactionOutput).join(DbKey). \
            filter(DbKey.address == address, DbTransaction.wallet_id == self.wallet_id,
                   DbTransactionOutput.spent.is_(False)). \
            order_by(DbTransaction.confirmations).first()
        return '' if not to else to[0].hex()

    def transactions_update_confirmations(self):
        network = self.network.name
        srv = Service(network=network, wallet_name=self.name, providers=self.providers, cache_uri=self.db_cache_uri,
                      strict=self.strict)
        blockcount = srv.blockcount()
        self.session.query(DbTransaction).\
            filter(DbTransaction.wallet_id == self.wallet_id,
                   DbTransaction.network_name == network, DbTransaction.block_height > 0, DbTransaction.confirmations < 500).\
                update({DbTransaction.status: 'confirmed',
                        DbTransaction.confirmations: (blockcount - DbTransaction.block_height) + 1})
        self._commit()

    def transactions_update_by_txids(self, txids):
        if not isinstance(txids, list):
            txids = [txids]
        txids = list(dict.fromkeys(txids))

        txs = []
        srv = Service(network=self.network.name, wallet_name=self.name, providers=self.providers,
                      cache_uri=self.db_cache_uri, strict=self.strict)
        for txid in txids:
            tx = srv.gettransaction(to_hexstring(txid))
            if tx:
                txs.append(tx)

        utxo_set = set()
        for t in txs:
            wt = WalletTransaction.from_transaction(self, t)
            wt.store()
            utxos = [(ti.prev_txid.hex(), ti.output_n_int) for ti in wt.inputs]
            utxo_set.update(utxos)

        for utxo in list(utxo_set):
            tos = self.session.query(DbTransactionOutput).join(DbTransaction). \
                filter(DbTransaction.txid == bytes.fromhex(utxo[0]), DbTransactionOutput.output_n == utxo[1],
                       DbTransactionOutput.spent.is_(False)).all()
            for u in tos:
                u.spent = True
        self._commit()
        # self._balance_update(account_id=account_id, network=network, key_id=key_id)

    def transactions_update(self, account_id=None, used=None, network=None, key_id=None, depth=None, change=None,
                            limit=MAX_TRANSACTIONS, txs_list=[]):
        network, account_id, acckey = self._get_account_defaults(network, account_id, key_id)
        if depth is None:
            depth = self.key_depth

        # Update number of confirmations and status for already known transactions
        _logger.warning(f"transactions_update transactions_update_confirmations")
        self.transactions_update_confirmations()
        _logger.warning(f"transactions_update transactions_update_confirmations finished")

        srv = Service(network=network, wallet_name=self.name, providers=self.providers, cache_uri=self.db_cache_uri,
                      strict=self.strict)

        # Get transactions for wallet's addresses
        txs = []
        
        # utx_list = [tx.txid for tx in self.transactions()]
        addresslist = self.addresslist(
            account_id=account_id, used=used, network=network, key_id=key_id, change=change, depth=depth)
        last_updated = datetime.now(timezone.utc)
        _logger.warning(f"transactions_update addresslist {addresslist}")
        for address in addresslist:
            txs += srv.gettransactions(address, limit=limit, after_txid=self.transaction_last(address), txs_list=txs_list)
            _logger.warning(f"txs transactions_update {txs}")
            if not srv.complete:
                if txs and txs[-1].date and txs[-1].date < last_updated:
                    last_updated = txs[-1].date
            if txs and txs[-1].confirmations:
                dbkey = self.session.query(DbKey).filter(DbKey.address == address, DbKey.wallet_id == self.wallet_id)
                if not dbkey.update({DbKey.latest_txid: bytes.fromhex(txs[-1].txid)}):
                    raise WalletError("Failed to update latest transaction id for key with address %s" % address)
                self._commit()
        if txs is False:
            raise WalletError("No response from any service provider, could not update transactions")

        # Update Transaction outputs to get list of unspent outputs (UTXO's)
        utxo_set = set()
        _logger.warning(f"transactions_update from_transaction {txs}")
        unique_txs = list({t.txid: t for t in txs}.values())
        for t in unique_txs:
            _logger.warning(f"start transactions_update from_transaction 1 txs {txs}")
            wt = WalletTransaction.from_transaction(self, t)
            _logger.warning(f"finished transactions_update from_transaction")
            _logger.warning(f"start transactions_update store")
            wt.store()
            _logger.warning(f"finished transactions_update store")
            _logger.warning(f"start transactions_update utxos")
            utxos = [(ti.prev_txid.hex(), ti.output_n_int) for ti in wt.inputs]
            utxo_set.update(utxos)
            _logger.warning(f"finished transactions_update utxo_set.update(utxos)")
        _logger.warning(f"transactions_update list utxo_set {utxo_set}")    
        for utxo in list(utxo_set):
            tos = self.session.query(DbTransactionOutput).join(DbTransaction).\
                filter(DbTransaction.txid == bytes.fromhex(utxo[0]), DbTransactionOutput.output_n == utxo[1],
                       DbTransactionOutput.spent.is_(False), DbTransaction.wallet_id == self.wallet_id).all()
            for u in tos:
                u.spent = True

        self.last_updated = last_updated
        self._commit()
        _logger.warning(f"transactions_update balance update {key_id}")
        self._balance_update(key_id=key_id)
        _logger.warning(f"transactions_update balance update finished")

        return len(txs)

    def transaction_last(self, address):
        txid = self.session.query(DbKey.latest_txid).\
            filter(DbKey.address == address, DbKey.wallet_id == self.wallet_id).scalar()
        return '' if not txid else txid.hex()

    def transactions(self, account_id=None, network=None, include_new=False, key_id=None, as_dict=False):
        network, account_id, acckey = self._get_account_defaults(network, account_id, key_id)
        # Transaction inputs
        qr = self.session.query(DbTransactionInput, DbTransactionInput.address, DbTransaction.confirmations,
                                 DbTransaction.txid, DbTransaction.network_name, DbTransaction.status). \
            join(DbTransaction).join(DbKey). \
            filter(DbTransaction.account_id == account_id,
                   DbTransaction.wallet_id == self.wallet_id,
                   DbKey.wallet_id == self.wallet_id,
                   DbTransaction.network_name == network)
        if key_id is not None:
            qr = qr.filter(DbTransactionInput.key_id == key_id)
        if not include_new:
            qr = qr.filter(or_(DbTransaction.status == 'confirmed', DbTransaction.status == 'unconfirmed'))
        txs = qr.all()
        # Transaction outputs
        qr = self.session.query(DbTransactionOutput, DbTransactionOutput.address, DbTransaction.confirmations,
                                 DbTransaction.txid, DbTransaction.network_name, DbTransaction.status). \
            join(DbTransaction).join(DbKey). \
            filter(DbTransaction.account_id == account_id,
                   DbTransaction.wallet_id == self.wallet_id,
                   DbKey.wallet_id == self.wallet_id,
                   DbTransaction.network_name == network)
        if key_id is not None:
            qr = qr.filter(DbTransactionOutput.key_id == key_id)
        if not include_new:
            qr = qr.filter(or_(DbTransaction.status == 'confirmed', DbTransaction.status == 'unconfirmed'))
        txs += qr.all()

        txs = sorted(txs, key=lambda k: (k[2], pow(10, 20)-k[0].transaction_id, k[3]), reverse=True)
        res = []
        txids = []
        for tx in txs:
            txid = tx[3].hex()
            if as_dict:
                u = tx[0].__dict__
                u['block_height'] = tx[0].transaction.block_height
                u['date'] = tx[0].transaction.date
                if '_sa_instance_state' in u:
                    del u['_sa_instance_state']
                u['address'] = tx[1]
                u['confirmations'] = None if tx[2] is None else int(tx[2])
                u['txid'] = txid
                u['network_name'] = tx[4]
                u['status'] = tx[5]
                if 'index_n' in u:
                    u['is_output'] = True
                    u['value'] = -u['value']
                else:
                    u['is_output'] = False
            else:
                if txid in txids:
                    continue
                txids.append(txid)
                u = self.transaction(txid)
            res.append(u)
        return res

    def transaction(self, txid):
        return WalletTransaction.from_txid(self, txid)

    def transaction_delete(self, txid):
        wt = self.transaction(txid)
        if wt:
            wt.delete()
        else:
            raise WalletError("Transaction %s not found in this wallet" % txid)

    def _objects_by_key_id(self, key_id):
        self.session.expire_all()
        key = self.session.query(DbKey).filter_by(id=key_id).scalar()
        if not key:
            raise WalletError("Key '%s' not found in this wallet" % key_id)
        if key.key_type in ['bip32', 'single']:
            if not key.wif:
                raise WalletError("WIF of key is empty cannot create HDKey")
            inp_keys = [HDKey.from_wif(key.wif, network=key.network_name, compressed=key.compressed)]
        else:
            raise WalletError("Input key type %s not supported" % key.key_type)
        return inp_keys, key

    def select_inputs(self, amount, variance=None, input_key_id=None, account_id=None, network=None, min_confirms=1,
                      max_utxos=None, return_input_obj=True, skip_dust_amounts=True):
        network, account_id, _ = self._get_account_defaults(network, account_id)
        dust_amount = Network(network).dust_amount
        if variance is None:
            variance = dust_amount

        utxo_query = self.session.query(DbTransactionOutput).join(DbTransaction).join(DbKey). \
            filter(DbTransaction.wallet_id == self.wallet_id, DbTransaction.account_id == account_id,
                   DbTransaction.network_name == network, DbKey.public != b'',
                   DbTransactionOutput.spent.is_(False), DbTransaction.confirmations >= min_confirms)
        if input_key_id:
            if isinstance(input_key_id, int):
                utxo_query = utxo_query.filter(DbKey.id == input_key_id)
            else:
                utxo_query = utxo_query.filter(DbKey.id.in_(input_key_id))
        if skip_dust_amounts:
            utxo_query = utxo_query.filter(DbTransactionOutput.value >= dust_amount)
        utxo_query = utxo_query.order_by(DbTransaction.confirmations.desc())
        try:
            utxos = utxo_query.all()
        except Exception as e:
            self.session.close()
            # logger.warning("Error when querying database, retry: %s" % str(e))
            utxos = utxo_query.all()
        

        _logger.info(f"Transaction utxos {utxos}")
        # if not utxos:
        #     raise WalletError("Create transaction: No unspent transaction outputs found or no key available for UTXO's")
        one_utxo = utxo_query.filter(DbTransactionOutput.spent.is_(False),
                                     DbTransactionOutput.value >= amount,
                                     DbTransactionOutput.value <= amount + variance).first()
        selected_utxos = []
        if one_utxo:
            selected_utxos = [one_utxo]
        else:
            # Try to find one utxo with higher amount
            one_utxo = utxo_query. \
                filter(DbTransactionOutput.spent.is_(False), DbTransactionOutput.value >= amount).\
                order_by(DbTransactionOutput.value).first()
            if one_utxo:
                selected_utxos = [one_utxo]
            elif max_utxos and max_utxos <= 1:
                _logger.info("No single UTXO found with requested amount, use higher 'max_utxo' setting to use "
                             "multiple UTXO's")
                return []

        # Otherwise compose of 2 or more lesser outputs
        if not selected_utxos:
            _logger.info(f"Transaction not selected_utxos {selected_utxos}")
            lessers = utxo_query. \
                filter(DbTransactionOutput.spent.is_(False), DbTransactionOutput.value < amount).\
                order_by(DbTransactionOutput.value.desc()).all()
            total_amount = 0
            selected_utxos = []
            for utxo in lessers[:max_utxos]:
                if total_amount < amount:
                    selected_utxos.append(utxo)
                    total_amount += utxo.value
            if total_amount < amount:
                return []
        if not return_input_obj:
            return selected_utxos
        else:
            inputs = []
            for utxo in selected_utxos:
                _logger.info(f"Transaction selected_utxos {selected_utxos}")
                inp_keys, key = self._objects_by_key_id(utxo.key_id)
                script_type = get_unlocking_script_type(utxo.script_type)
                inputs.append(Input(utxo.transaction.txid, utxo.output_n, keys=inp_keys, script_type=script_type,
                              sigs_required=self.multisig_n_required, sort=self.sort_keys, address=key.address,
                              compressed=key.compressed, value=utxo.value, network=key.network_name))
            _logger.info(f"Transaction inputs {inputs}")
            return inputs

    def transaction_create(self, output_arr, input_arr=None, input_key_id=None, account_id=None, network=None, fee=None,
                           min_confirms=1, max_utxos=None, locktime=0, number_of_change_outputs=1,
                           random_output_order=True, replace_by_fee=False, fee_per_kb=None):

        if not isinstance(output_arr, list):
            raise WalletError("Output array must be a list of tuples with address and amount. "
                              "Use 'send_to' method to send to one address")
        network, account_id, acckey = self._get_account_defaults(network, account_id)

        if input_arr and max_utxos and len(input_arr) > max_utxos:
            raise WalletError("Input array contains %d UTXO's but max_utxos=%d parameter specified" %
                              (len(input_arr), max_utxos))

        # Create transaction and add outputs
        amount_total_output = 0
        transaction = WalletTransaction(hdwallet=self, account_id=account_id, network=network, locktime=locktime,
                                        replace_by_fee=replace_by_fee)
        transaction.outgoing_tx = True
        _logger.info(f"Transaction feoutput_arre_exact {output_arr}")
        for o in output_arr:
            if isinstance(o, Output):
                transaction.outputs.append(o)
                amount_total_output += o.value
            else:
                value = value_to_satoshi(o[1], network=transaction.network)
                amount_total_output += value
                addr = o[0]
                if isinstance(addr, WalletKey):
                    addr = addr.key()
                transaction.add_output(value, addr, change=False)

        srv = Service(network=network, wallet_name=self.name, providers=self.providers, cache_uri=self.db_cache_uri,
                      strict=self.strict)

        if not locktime and self.anti_fee_sniping:
            srv = Service(network=network, providers=self.providers, cache_uri=self.db_cache_uri, strict=self.strict)
            blockcount = srv.blockcount()
            if blockcount:
                transaction.locktime = blockcount

        transaction.fee_per_kb = None
        if isinstance(fee, int):
            fee_estimate = fee
        else:
            n_blocks = 3
            priority = ''
            if isinstance(fee, str):
                priority = fee
            transaction.fee_per_kb = fee_per_kb or srv.estimatefee(blocks=n_blocks, priority=priority)
            if not input_arr:
                fee_estimate = int(transaction.estimate_size(number_of_change_outputs=number_of_change_outputs) /
                                   1000.0 * transaction.fee_per_kb)
            else:
                fee_estimate = 0
            if isinstance(fee, str):
                fee = fee_estimate

        # Add inputs
        sequence = 0xffffffff
        if replace_by_fee:
            sequence = SEQUENCE_REPLACE_BY_FEE
        elif 0 < transaction.locktime < 0xffffffff:
            sequence = SEQUENCE_ENABLE_LOCKTIME
        amount_total_input = 0
        if input_arr is None:
            selected_utxos = self.select_inputs(amount_total_output + fee_estimate, transaction.network.dust_amount,
                                                input_key_id, account_id, network, min_confirms, max_utxos, False)
            if not selected_utxos:
                raise WalletError("Not enough unspent transaction outputs found")
            for utxo in selected_utxos:
                _logger.info(f"Transaction selected_utxos {selected_utxos}")
                amount_total_input += utxo.value
                inp_keys, key = self._objects_by_key_id(utxo.key_id)
                witness_type = utxo.key.witness_type if utxo.key.witness_type else self.witness_type
                unlock_script_type = get_unlocking_script_type(utxo.script_type, witness_type)
                transaction.add_input(utxo.transaction.txid, utxo.output_n, keys=inp_keys,
                                      script_type=unlock_script_type, sigs_required=self.multisig_n_required,
                                      sort=self.sort_keys, compressed=key.compressed, value=utxo.value,
                                      address=utxo.key.address, sequence=sequence,
                                      key_path=utxo.key.path, witness_type=witness_type)
        else:
            for inp in input_arr:
                _logger.info(f"Transaction input_arr {input_arr}")
                locking_script = None
                unlocking_script_type = ''
                if isinstance(inp, Input):
                    prev_txid = inp.prev_txid
                    output_n = inp.output_n
                    key_id = None
                    value = inp.value
                    signatures = inp.signatures
                    locking_script = inp.locking_script
                    unlocking_script = inp.unlocking_script
                    unlocking_script_type = inp.script_type
                    address = inp.address
                    sequence = inp.sequence
                    witness_type = inp.witness_type
                else:
                    prev_txid = inp[0]
                    output_n = inp[1]
                    key_id = None if len(inp) <= 2 else inp[2]
                    value = 0 if len(inp) <= 3 else inp[3]
                    signatures = None if len(inp) <= 4 else inp[4]
                    unlocking_script = b'' if len(inp) <= 5 else inp[5]
                    address = '' if len(inp) <= 6 else inp[6]
                    witness_type = self.witness_type
                # Get key_ids, value from Db if not specified
                if not (key_id and value and unlocking_script_type):
                    if not isinstance(output_n, TYPE_INT):
                        output_n = int.from_bytes(output_n, 'big')
                    inp_utxo = self.session.query(DbTransactionOutput).join(DbTransaction). \
                        filter(DbTransaction.wallet_id == self.wallet_id,
                               DbTransaction.txid == to_bytes(prev_txid),
                               DbTransactionOutput.output_n == output_n).first()
                    if inp_utxo:
                        key_id = inp_utxo.key_id
                        value = inp_utxo.value
                        address = inp_utxo.key.address
                        unlocking_script_type = get_unlocking_script_type(inp_utxo.script_type)
                        witness_type = inp_utxo.key.witness_type
                    else:
                        _logger.info("UTXO %s not found in this wallet. Please update UTXO's if this is not an "
                                     "offline wallet" % to_hexstring(prev_txid))
                        key_id = self.session.query(DbKey.id).\
                            filter(DbKey.wallet_id == self.wallet_id, DbKey.address == address).scalar()
                        if not key_id:
                            raise WalletError("UTXO %s and key with address %s not found in this wallet" % (
                                to_hexstring(prev_txid), address))
                        if not value:
                            raise WalletError("Input value is zero for address %s. Import or update UTXO's first "
                                              "or import transaction as dictionary" % address)

                amount_total_input += value
                inp_keys, key = self._objects_by_key_id(key_id)
                transaction.add_input(prev_txid, output_n, keys=inp_keys, script_type=unlocking_script_type,
                                      sigs_required=self.multisig_n_required, sort=self.sort_keys,
                                      compressed=key.compressed, value=value, signatures=signatures,
                                      unlocking_script=unlocking_script, address=address,
                                      locking_script=locking_script,
                                      sequence=sequence,
                                      witness_type=witness_type, key_path=key.path)
        # Calculate fees
        transaction.fee = fee
        fee_per_output = None
        transaction.size = transaction.estimate_size(number_of_change_outputs=number_of_change_outputs)
        if fee is None:
            if not input_arr:
                if not transaction.fee_per_kb:
                    transaction.fee_per_kb = srv.estimatefee()
                if transaction.fee_per_kb < transaction.network.fee_min:
                    transaction.fee_per_kb = transaction.network.fee_min
                transaction.fee = int((transaction.size / 1000.0) * transaction.fee_per_kb)
                fee_per_output = int((50 / 1000.0) * transaction.fee_per_kb)
            else:
                if amount_total_output and amount_total_input:
                    fee = False
                else:
                    transaction.fee = 0

        if fee is False:
            transaction.change = 0
            transaction.fee = int(amount_total_input - amount_total_output)
        else:
            transaction.change = int(amount_total_input - (amount_total_output + transaction.fee))

        # Skip change if amount is smaller than the dust limit or estimated fee
        if (fee_per_output and transaction.change < fee_per_output) or transaction.change <= transaction.network.dust_amount:
            transaction.fee += transaction.change
            transaction.change = 0
        if transaction.change < 0:
            raise WalletError("Total amount of outputs is greater then total amount of inputs")
        if transaction.change:
            _logger.info(f"Transaction change {transaction.change}")
            min_output_value = transaction.network.dust_amount * 2 + transaction.network.fee_min * 4
            if transaction.fee and transaction.size:
                if not transaction.fee_per_kb:
                    transaction.fee_per_kb = int((transaction.fee * 1000.0) / transaction.vsize)
                min_output_value = transaction.fee_per_kb + transaction.network.fee_min * 4 + \
                                   transaction.network.dust_amount

            if number_of_change_outputs == 0:
                if transaction.change < amount_total_output / 10 or transaction.change < min_output_value * 8:
                    number_of_change_outputs = 1
                elif transaction.change / 10 > amount_total_output:
                    number_of_change_outputs = random.randint(2, 5)
                else:
                    number_of_change_outputs = random.randint(1, 3)
                    # Prefer 1 and 2 as number of change outputs
                    if number_of_change_outputs == 3:
                        number_of_change_outputs = random.randint(3, 4)
                transaction.size = transaction.estimate_size(number_of_change_outputs=number_of_change_outputs)

            average_change = transaction.change // number_of_change_outputs
            if number_of_change_outputs > 1 and average_change < min_output_value:
                raise WalletError("Not enough funds to create multiple change outputs. Try less change outputs "
                                  "or lower fees")

            if self.scheme == 'single':
                change_keys = [self.get_key(account_id, self.witness_type, network, change=1)]
            else:
                change_keys = self.get_keys(account_id, self.witness_type, network, change=1,
                                            number_of_keys=number_of_change_outputs)

            if number_of_change_outputs > 1:
                rand_prop = transaction.change - number_of_change_outputs * min_output_value
                change_amounts = list(((np.random.dirichlet(np.ones(number_of_change_outputs), size=1)[0] *
                                        rand_prop) + min_output_value).astype(int))
                # Fix rounding problems / small amount differences
                diffs = transaction.change - sum(change_amounts)
                for idx, co in enumerate(change_amounts):
                    if co - diffs > min_output_value:
                        change_amounts[idx] += change_amounts.index(co) + diffs
                        break
            else:
                change_amounts = [transaction.change]

            for idx, ck in enumerate(change_keys):
                on = transaction.add_output(change_amounts[idx], ck.address, encoding=self.encoding, change=True)
                transaction.outputs[on].key_id = ck.key_id

        # Shuffle output order to increase privacy
        if random_output_order:
            transaction.shuffle()

        # Check tx values
        transaction.input_total = sum([i.value for i in transaction.inputs])
        transaction.output_total = sum([o.value for o in transaction.outputs])
        if transaction.input_total != transaction.fee + transaction.output_total:
            raise WalletError("Sum of inputs values is not equal to sum of outputs values plus fees")

        transaction.txid = transaction.signature_hash()[::-1].hex()
        if not transaction.fee_per_kb:
            transaction.fee_per_kb = int((transaction.fee * 1000.0) / transaction.vsize)
        if transaction.fee_per_kb < transaction.network.fee_min:
            raise WalletError("Fee per kB of %d is lower then minimal network fee of %d" %
                              (transaction.fee_per_kb, transaction.network.fee_min))
        elif transaction.fee_per_kb > transaction.network.fee_max:
            raise WalletError("Fee per kB of %d is higher then maximum network fee of %d" %
                              (transaction.fee_per_kb, transaction.network.fee_max))

        return transaction

    def send(self, output_arr, input_arr=None, input_key_id=None, account_id=None, network=None, fee=None,
             min_confirms=1, priv_keys=None, max_utxos=None, locktime=0, broadcast=False, number_of_change_outputs=1,
             random_output_order=True, replace_by_fee=False, fee_per_kb=None):

        if input_arr and max_utxos and len(input_arr) > max_utxos:
            raise WalletError("Input array contains %d UTXO's but max_utxos=%d parameter specified" %
                              (len(input_arr), max_utxos))

        transaction = self.transaction_create(output_arr, input_arr, input_key_id, account_id, network, fee,
                                              min_confirms, max_utxos, locktime, number_of_change_outputs,
                                              random_output_order, replace_by_fee, fee_per_kb=fee_per_kb)
        _logger.info(f"Transaction {transaction}")
        transaction.sign(priv_keys)
        # Calculate exact fees and update change output if necessary
        if fee is None and transaction.fee_per_kb and transaction.change:
            fee_exact = transaction.calculate_fee()
            _logger.info(f"Transaction fee_exact {fee_exact}")
            # Recreate transaction if fee estimation more than 10% off
            if fee_exact != self.network.fee_min and fee_exact != self.network.fee_max and \
                    fee_exact and abs((float(transaction.fee) - float(fee_exact)) / float(fee_exact)) > 0.10:
                _logger.info("Transaction fee not correctly estimated (est.: %d, real: %d). "
                             "Recreate transaction with correct fee" % (transaction.fee, fee_exact))
                transaction = self.transaction_create(output_arr, input_arr, input_key_id, account_id, network,
                                                      fee_exact, min_confirms, max_utxos, locktime,
                                                      number_of_change_outputs, random_output_order,
                                                      replace_by_fee)
                transaction.sign(priv_keys)

        transaction.rawtx = transaction.raw()
        transaction.size = len(transaction.rawtx)
        transaction.calc_weight_units()
        transaction.fee_per_kb = int(float(transaction.fee) / float(transaction.vsize) * 1000)
        transaction.txid = transaction.signature_hash()[::-1].hex()
        _logger.info(f"Transaction txid {transaction.txid }")
        transaction.send(broadcast)
        return transaction

    def send_to(self, to_address, amount, input_key_id=None, account_id=None, network=None, fee=None, min_confirms=1,
                priv_keys=None, locktime=0, broadcast=False, number_of_change_outputs=1, random_output_order=True,
                replace_by_fee=False, fee_per_kb=None):
        outputs = [(to_address, amount)]
        return self.send(outputs, input_key_id=input_key_id, account_id=account_id, network=network, fee=fee,
                         min_confirms=min_confirms, priv_keys=priv_keys, locktime=locktime, broadcast=broadcast,
                         number_of_change_outputs=number_of_change_outputs, random_output_order=random_output_order,
                         replace_by_fee=replace_by_fee, fee_per_kb=fee_per_kb)

    def sweep(self, to_address, account_id=None, input_key_id=None, network=None, max_utxos=999, min_confirms=1,
              fee_per_kb=None, fee=None, locktime=0, broadcast=False, replace_by_fee=False):
        network, account_id, acckey = self._get_account_defaults(network, account_id)

        utxos = self.utxos(account_id=account_id, network=network, min_confirms=min_confirms, key_id=input_key_id)
        utxos = utxos[0:max_utxos]
        input_arr = []
        total_amount = 0

        if not utxos:
            raise WalletError("Cannot sweep wallet, no UTXO's found")
        for utxo in utxos:
            # Skip dust transactions to avoid forced address reuse
            if utxo.get('address') == to_address:
               continue
            if utxo['value'] <= self.network.dust_amount:
                continue
            input_arr.append((utxo['txid'], utxo['output_n'], utxo['key_id'], utxo['value']))
            total_amount += utxo['value']
        srv = Service(network=network, wallet_name=self.name, providers=self.providers, cache_uri=self.db_cache_uri,
                      strict=self.strict)

        fee_modifier = 1 if self.witness_type == 'legacy' else 0.6
        if isinstance(fee, str):
            fee_per_kb = srv.estimatefee(priority=fee)
            fee = None
        if not fee:
            if fee_per_kb is None:
                fee_per_kb = srv.estimatefee()
            n_outputs = 1 if not isinstance(to_address, list) else len(to_address)
            tr_size = 125 + (len(input_arr) * (77 + self.multisig_n_required * 72)) + n_outputs * 30
            fee = int(100 + ((tr_size / 1000.0) * fee_per_kb * fee_modifier))

        if total_amount - fee <= self.network.dust_amount:
            raise WalletError("Amount to send is smaller then dust amount: %s" % (total_amount - fee))

        if isinstance(to_address, str):
            to_list = [(to_address, total_amount - fee)]
        else:
            to_list = []
            for o in to_address:
                if o[1] == 0:
                    o_amount = total_amount - sum([x[1] for x in to_list]) - fee
                    if o_amount > 0:
                        to_list.append((o[0], o_amount))
                else:
                    to_list.append(o)

        if sum(x[1] for x in to_list) + fee != total_amount:
            raise WalletError("Total amount of outputs does not match total input amount. If you specify a list of "
                              "outputs, use amount value = 0 to indicate a change/rest output")

        return self.send(to_list, input_arr, network=network, fee=fee, min_confirms=min_confirms, locktime=locktime,
                         broadcast=broadcast, replace_by_fee=replace_by_fee)

    def wif(self, is_private=False, account_id=0):
        if is_private and self.main_key:
            return self.main_key.wif
        else:
            return self.public_master(account_id=account_id).key().\
                wif(is_private=is_private, witness_type=self.witness_type)

    def public_master(self, account_id=None, name=None, as_private=False, witness_type=None, network=None):
        if self.main_key and self.main_key.key_type == 'single':
            key = self.main_key
            return key if as_private else key.public()
        elif not self.cosigner:
            witness_type = witness_type if witness_type else self.witness_type
            depth = -self.key_depth + self.depth_public_master
            key = self.key_for_path([], depth, name=name, account_id=account_id, network=network,
                                     witness_type=witness_type)
            return key if as_private else key.public()
        else:
            pm_list = []
            for cs in self.cosigner:
                pm_list.append(cs.public_master(account_id, name, as_private, network))
            return pm_list

    def info(self, detail=3):
        print("=== WALLET ===")
        print(" ID                             %s" % self.wallet_id)
        print(" Name                           %s" % self.name)
        print(" Owner                          %s" % self.owner)
        print(" Scheme                         %s" % self.scheme)
        print(" Witness type                   %s" % self.witness_type)
        print(" Main network                   %s" % self.network.name)
        print(" Latest update                  %s" % self.last_updated)

        if detail and self.main_key:
            print("\n= Wallet Master Key =")
            print(" ID                             %s" % self.main_key_id)
            print(" Private                        %s" % self.main_key.is_private)
            print(" Depth                          %s" % self.main_key.depth)

        generated_count = (
            self.session.query(DbWallet.generated_address_count)
            .filter_by(id=self.wallet_id)
            .scalar()
        )
        if generated_count is None:
            generated_count = 0
        print(" Generated address count        %s" % generated_count)

        balances = self._balance_update()
        if detail > 1:
            for nw in self.networks():
                print("\n- NETWORK: %s -" % nw.name)
                print("- - Keys")

                printed_keys = set()
                # keys = self.keys(network=nw.name, is_active=True)
                # keys = (
                #     self.session.query(DbKey)
                #     .filter_by(wallet_id=self.wallet_id)
                #     .order_by(DbKey.id.asc())
                #     .all()
                # )
                keys = self.keys(network=nw.name)
                # count = 0

                for key in keys:
                    if key.address in printed_keys:
                        continue
                    printed_keys.add(key.address)

                    print("%5s %-28s %-45s %-25s %25s" %
                        (key.id, key.path, key.address, key.name,
                        Value.from_satoshi(key.balance, network=nw).str_unit(currency_repr='symbol')))

                    # count += 1
                    # if count > generated_count:
                    #     break

                if detail > 2:
                    include_new = detail > 3
                    accounts = self.accounts(network=nw.name) or [0]

                    for account_id in accounts:
                        txs = self.transactions(
                            include_new=include_new,
                            account_id=account_id,
                            network=nw.name,
                            as_dict=True
                        )
                        print("\n- - Transactions Account %d (%d)" % (account_id, len(txs)))
                        for tx in txs:
                            spent = " "
                            address = tx['address'] or 'nulldata'
                            if tx.get('spent') is False:
                                spent = "U"
                            status = "" if tx['status'] in ['confirmed', 'unconfirmed'] else tx['status']
                            print("%64s %43s %8d %21s %s %s" % (
                                tx['txid'], address, tx['confirmations'],
                                Value.from_satoshi(tx['value'], network=nw).str_unit(currency_repr='symbol'),
                                spent, status))

        print("\n= Balance Totals (includes unconfirmed) =")
        for na_balance in balances:
            print("%-20s %-20s %20s" % (
                na_balance['network'],
                "(Account %s)" % na_balance['account_id'],
                Value.from_satoshi(na_balance['balance'], network=na_balance['network']).str_unit(currency_repr='symbol')
            ))
        print("\n")

    def as_dict(self, include_private=False):
        keys = []
        transactions = []
        for netw in self.networks():
            for key in self.keys(network=netw.name, include_private=include_private, as_dict=True):
                keys.append(key)

            accounts = self.accounts(network=netw.name)
            if not accounts:
                accounts = [0]
            for account_id in accounts:
                for t in self.transactions(include_new=True, account_id=account_id, network=netw.name):
                    transactions.append(t.as_dict())

        return {
            'wallet_id': self.wallet_id,
            'name': self.name,
            'owner': self._owner,
            'scheme': self.scheme,
            'witness_type': self.witness_type,
            'main_network': self.network.name,
            'main_balance': self.balance(),
            'main_balance_str': self.balance(as_string=True),
            'balances': self._balances,
            'default_account_id': self.default_account_id,
            'multisig_n_required': self.multisig_n_required,
            'cosigner_wallet_ids': [w.wallet_id for w in self.cosigner],
            'cosigner_public_masters': [w.public_master().key().wif() for w in self.cosigner],
            'sort_keys': self.sort_keys,
            'main_key_id': self.main_key_id,
            'encoding': self.encoding,
            'keys': keys,
            'transactions': transactions,
        }

    def as_json(self, include_private=False):
        adict = self.as_dict(include_private=include_private)
        return json.dumps(adict, indent=4, default=str)
