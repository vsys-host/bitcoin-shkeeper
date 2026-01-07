import json
import random
import time
from datetime import timedelta
from sqlalchemy import func
from app.lib import services
from app.lib.networks import Network
from app.lib.encoding import to_bytes, int_to_varbyteint, varstr
from app.models import *
from app.config import config, COIN
from app.lib.transactions import Transaction, transaction_update_spents
from app.lib.blocks import Block
from app.lib.main import *

_logger = logging.getLogger(__name__)

PROVIDER_MAP = {
    "BTC": {
        "key": "bitcoind",
        "client_class": "BitcoindClient",
    },
    "LTC": {
        "key": "litecoind",
        "client_class": "LitecoindClient",
    },
    # "DOGE": {
    #     "key": "dogecoind",
    #     "client_class": "DogecoindClient",
    # },
}

class ServiceError(Exception):
    def __init__(self, msg=''):
        self.msg = msg
        _logger.error(msg)

    def __str__(self):
        return self.msg

class Service(object):
    def __init__(self, network=DEFAULT_NETWORK, providers=None,
                 timeout=TIMEOUT_REQUESTS, cache_uri=None, exclude_providers=None,
                 max_errors=SERVICE_MAX_ERRORS, strict=True, wallet_name=None, provider_name=None):

        self.network = network
        if not isinstance(network, Network):
            self.network = Network(network)
        if COIN not in PROVIDER_MAP:
            raise ServiceError(
                f"Unsupported coin configured: '{COIN}'. "
                f"Supported coins are: {', '.join(PROVIDER_MAP.keys())}"
            )

        provider_key = PROVIDER_MAP[COIN]["key"]
        client_class = PROVIDER_MAP[COIN]["client_class"]
        custom_providers = {
            provider_key: {
                "provider": provider_key,
                "network": config['COIN_NETWORK'],
                "client_class": client_class,
                "provider_coin_id": "",
                "url": config["FULLNODE_URL"],
                "api_key": "",
                "priority": 20,
                "denominator": 100000000,
                "network_overrides": None
            }
        }
        self.providers_defined = custom_providers
        provider_set = {self.providers_defined[x]['provider'] for x in self.providers_defined}

        if providers is None:
            providers = []
        if exclude_providers is None:
            exclude_providers = []
        if not isinstance(providers, list):
            providers = [providers]
        for p in providers:
            if p not in provider_set:
                raise ServiceError(f"Provider '{p}' not found in provider definitions")

        self.providers = {}
        if provider_name:
            if provider_name not in self.providers_defined:
                raise ServiceError(f"Provider with name '{provider_name}' not found in provider definitions")
            if self.providers_defined[provider_name]['network'] != self.network:
                raise ServiceError(f"Network from provider '{provider_name}' is different than Service network")
            self.providers.update({provider_name: self.providers_defined[provider_name]})
        else:
            for p in self.providers_defined:
                if (self.providers_defined[p]['network'] == network or self.providers_defined[p]['network'] == '') and \
                        (not providers or self.providers_defined[p]['provider'] in providers):
                    self.providers.update({p: self.providers_defined[p]})
        exclude_providers_keys = {pi: self.providers[pi]['provider'] for
                                  pi in self.providers if self.providers[pi]['provider'] in exclude_providers}.keys()
        for provider_key in exclude_providers_keys:
            del(self.providers[provider_key])

        if not self.providers:
            raise ServiceError(f"No providers found for network {network}")

        self.results = {}
        self.errors = {}
        self.max_errors = max_errors
        self.complete = None
        self.timeout = timeout
        self._blockcount_update = 0
        self._blockcount = None
        self.cache = None
        self.cache_uri = cache_uri
        self.wallet_name = wallet_name
        try:
            self.cache = Cache(self.network)
        except Exception as e:
            self.cache = Cache(self.network)
            _logger.warning(f"Could not connect to cache database. Error: {e}")
        self.results_cache_n = 0
        self.strict = strict
        self.execution_time = None
        self._blockcount = self.blockcount()

    def _reset_results(self):
        self.results = {}
        self.errors = {}
        self.complete = None
        self.execution_time = None

    def _provider_execute(self, method, *arguments, retries: int = 3, retry_delay: int = 2):
        if method == "gettransactions":
            print(f"--> Executing method '{method}'")
        else:
            print(f"--> Executing method '{method}' with arguments: {arguments}")

        attempt = 0
        while attempt < retries:
            attempt += 1
            self._reset_results()
            provider_lst = list(self.providers.keys())

            for sp in provider_lst:
                try:
                    provider_conf = self.providers[sp]
                    client = getattr(services, provider_conf['provider'])
                    providerclient = getattr(client, provider_conf['client_class'])

                    pc_instance = providerclient(
                        self.network,
                        provider_conf['url'],
                        provider_conf['denominator'],
                        provider_conf['api_key'],
                        provider_conf['provider_coin_id'],
                        provider_conf['network_overrides'],
                        self.timeout,
                        self._blockcount,
                        self.strict,
                        self.wallet_name
                    )
                    if not hasattr(pc_instance, method):
                        print(f"--> Method {method} not found for provider {sp}")
                        continue

                    providermethod = getattr(pc_instance, method)
                    print(f"--> Calling method '{method}' on provider '{sp}' (attempt {attempt})")
                    res = providermethod(*arguments)

                    if res is False:
                        self.errors[sp] = 'Received empty response'
                        print(f"--> Empty response from {sp} when calling {method}")
                        continue
                    self.results[sp] = res
                    if method in ("getblock", "getblocktransactions"):
                        print(f"--> Success from provider {sp}")
                    else:
                        print(f"--> Success from provider {sp}: {res}")

                except Exception as e:
                    err_msg = getattr(e, 'msg', str(e))
                    self.errors[sp] = err_msg
                    print(f"--> Error from provider {sp}: {err_msg}")

            if self.results:
                return list(self.results.values())[0]

            if attempt < retries:
                print(f"--> No result, retrying {attempt}/{retries} in {retry_delay}s...")
                time.sleep(retry_delay)

        print(f"--> Failed to get result for {method} after {retries} retries")
        print(f"--> list(self.results.values())[0] {self.results.values()}")
        return list(self.results.values())[0]

    def getbalance(self, addresslist, addresses_per_request=5):
        if isinstance(addresslist, TYPE_TEXT):
            addresslist = [addresslist]

        tot_balance = 0
        while addresslist:
            for address in addresslist:
                db_addr = self.cache.getaddress(address)
                if db_addr and db_addr.last_block and db_addr.last_block >= self.blockcount() and db_addr.balance:
                    tot_balance += db_addr.balance
                    addresslist.remove(address)

            balance = self._provider_execute('getbalance', addresslist[:addresses_per_request])
            if balance:
                tot_balance += balance
            if len(addresslist) == 1:
                self.cache.store_address(addresslist[0], balance=balance)
            addresslist = addresslist[addresses_per_request:]
        return tot_balance

    def getutxos(self, address, after_txid='', limit=MAX_TRANSACTIONS):
        if not isinstance(address, TYPE_TEXT):
            raise ServiceError("Address parameter must be of type text")
        self.results_cache_n = 0
        self.complete = True

        utxos_cache = []
        utxos_cache = self.cache.getutxos(address, bytes.fromhex(after_txid)) or []
        if utxos_cache:
            self.results_cache_n = len(utxos_cache)

            # Last updated block does not always include spent info...
            # if db_addr and db_addr.last_block and db_addr.last_block >= self.blockcount():
            #     return utxos_cache
            after_txid = utxos_cache[-1:][0]['txid']

        utxos = self._provider_execute('getutxos', address, after_txid, limit)
        if utxos is False:
            raise ServiceError("Error when retrieving UTXO's")
        else:
            # Update cache_transactions_node
            for utxo in utxos:
                self.cache.store_utxo(utxo['txid'], utxo['output_n'], commit=False)
            self.cache.commit()
            if utxos and len(utxos) >= limit:
                self.complete = False
            elif not after_txid:
                balance = sum(u['value'] for u in utxos)
                self.cache.store_address(address, balance=balance, n_utxos=len(utxos))

        return utxos_cache + utxos

    def gettransaction(self, txid):
        tx = None
        self.results_cache_n = 0

        tx = self.cache.gettransaction(bytes.fromhex(txid))
        if tx:
            self.results_cache_n = 1
        if not tx:
            tx = self._provider_execute('gettransaction', txid)
            if tx and tx.txid != txid:
                _logger.warning("Incorrect txid after parsing")
                tx.txid = txid
            if len(self.results):
                self.cache.store_transaction(tx)
        return tx

    def createwallet(self, attrs):
       self._provider_execute('createwallet', attrs)

    def getblockcount(self):
       self._provider_execute('getblockcount')

    def gettransactions(self, address, after_txid='', limit=MAX_TRANSACTIONS, txs_list=[]):
        self._reset_results()
        self.results_cache_n = 0
        if not address:
            return []
        if not isinstance(address, TYPE_TEXT):
            raise ServiceError("Address parameter must be of type text")
        if after_txid is None:
            after_txid = ''
        db_addr = self.cache.getaddress(address)
        txs_cache = []
        qry_after_txid = bytes.fromhex(after_txid)
        txs_cache = self.cache.gettransactions(address, qry_after_txid, limit) or []
        if txs_cache:
            self.results_cache_n = len(txs_cache)
            if len(txs_cache) == limit:
                return txs_cache
            limit = limit - len(txs_cache)
            qry_after_txid = bytes.fromhex(txs_cache[-1:][0].txid)

        # Get (extra) transactions from service providers
        txs = []
        if not (db_addr and db_addr.last_block and db_addr.last_block >= self.blockcount()):
            txs = self._provider_execute('gettransactions', address, qry_after_txid.hex(), txs_list)
            if txs is False:
                raise ServiceError("Error when retrieving transactions from service provider")
            for tx in txs:
                if tx.date and not tx.date.tzinfo:
                    tx.date = tx.date.replace(tzinfo=timezone.utc)

        last_block = None
        last_txid = None
        if not (after_txid and not db_addr):
            last_block = self.blockcount()
            last_txid = qry_after_txid
            self.complete = True
            if len(txs) == limit:
                self.complete = False
                last_block = txs[-1:][0].block_height
            if len(txs):
                last_txid = bytes.fromhex(txs[-1:][0].txid)
            if len(self.results):
                index = 0
                for t in txs:
                    if t.confirmations != 0:
                        res = self.cache.store_transaction(t, index, commit=False)
                        index += 1
                        # Failure to store transaction: stop caching transaction and store last tx block height - 1
                        if res is False:
                            if t.block_height:
                                last_block = t.block_height - 1
                            break
                self.cache.commit()
                self.cache.store_address(address, last_block, last_txid=last_txid, txs_complete=self.complete)

        all_txs = txs_cache + txs
        # If we have txs for this address update spent and balance information in cache
        if self.complete:
            all_txs = transaction_update_spents(all_txs, address)
            self.cache.store_address(address, last_block, last_txid=last_txid, txs_complete=True)
            for t in all_txs:
                self.cache.store_transaction(t, commit=False)
            self.cache.commit()
        return all_txs

    def getrawtransaction(self, txid):
        self.results_cache_n = 0
        rawtx = self.cache.getrawtransaction(bytes.fromhex(txid))
        if rawtx:
            self.results_cache_n = 1
            return rawtx
        return self._provider_execute('getrawtransaction', txid)

    def sendrawtransaction(self, rawtx):
        return self._provider_execute('sendrawtransaction', rawtx)

    def getblocktransactions(self, block):
        return self._provider_execute('getblocktransactions', block)
    
    def getblockhash(self, height):
        return self._provider_execute('getblockhash', height)

    def estimatefee(self, blocks=5, priority=''):
        self.results_cache_n = 0
        if priority:
            if priority == 'low':
                blocks = 25
            elif priority == 'high':
                blocks = 2
        fee = self.cache.estimatefee(blocks)
        if fee:
            self.results_cache_n = 1
            return fee
        fee = self._provider_execute('estimatefee', blocks)
        if not fee:  # pragma: no cover
            if self.network.fee_default:
                fee = self.network.fee_default
            else:
                raise ServiceError("Could not estimate fees, please define default fees in network settings")
        if fee < self.network.fee_min:
            fee = self.network.fee_min
        elif fee > self.network.fee_max:
            fee = self.network.fee_max
        self.cache.store_estimated_fee(blocks, fee)
        return fee
    
    def synced_status(self):
        synced_count = self._provider_execute('synced_status')
        return synced_count

    def getblockchaininfo(self):
        blockchain_info = self._provider_execute('getblockchaininfo')
        return blockchain_info

    def blockcount(self):
        blockcount = self.cache.blockcount()
        last_cache_blockcount = self.cache.blockcount(never_expires=True)
        if blockcount:
            self._blockcount = blockcount
            return blockcount

        current_timestamp = time.time()
        if self._blockcount_update < current_timestamp - BLOCK_COUNT_CACHE_TIME:
            new_count = self._provider_execute('blockcount')
            if last_cache_blockcount > new_count:
                _logger.warning(f"New block count ({new_count}) is lower than block count in cache "
                                f"({last_cache_blockcount}). Will try to find provider consensus")
                blockcounts = [last_cache_blockcount]
                for _ in range(5):
                    blockcounts.append(self._provider_execute('blockcount'))
                # return third last blockcount in list, assume last 2 and first 3 could be wrong
                self._blockcount = sorted(blockcounts)[-2]
                self._blockcount_update = current_timestamp
            elif not self._blockcount or (new_count and new_count > self._blockcount):
                self._blockcount = new_count
                self._blockcount_update = current_timestamp
            # Store result in cache
            if len(self.results) and list(self.results.keys())[0] != 'caching':
                self.cache.store_blockcount(self._blockcount)
        return self._blockcount

    def getblock(self, blockid, parse_transactions=True, page=1, limit=None):
        if limit is None:
            limit = 25 if parse_transactions else 99999

        block = self.cache.getblock(blockid)
        is_last_page = False
        if block:
            # Block found get transactions from cache
            txs = self.cache.getblocktransactions(block.height, page, limit)
            if parse_transactions:
                block.transactions = txs
            else:
                block.transactions = [tx.txid for tx in txs]
            if block.transactions:
                self.results_cache_n = 1
            is_last_page = page*limit > block.tx_count
        if not block or (not len(block.transactions) and limit != 0) or (not is_last_page and len(block.transactions) < limit) or \
                (is_last_page and ((page-1)*limit - block.tx_count + len(block.transactions)) < 0):
            self.results_cache_n = 0
            bd = self._provider_execute('getblock', blockid, parse_transactions, page, limit)
            if not bd or isinstance(bd, bool):
                return False
            block = Block(bd['block_hash'], bd['version'], bd['prev_block'], bd['merkle_root'], bd['time'], bd['bits'],
                          bd['nonce'], bd['txs'], bd['height'], bd['depth'], self.network)
            block.tx_count = bd['tx_count']
            block.limit = limit
            block.page = page

            if parse_transactions:
                index = (page-1)*limit
                for tx in block.transactions:
                    if isinstance(tx, Transaction):
                        self.cache.store_transaction(tx, index, commit=False)
                    index += 1
                self.cache.commit()
            self.complete = True if len(block.transactions) == block.tx_count else False
            self.cache.store_block(block)
        return block

    def getrawblock(self, blockid):
        return self._provider_execute('getrawblock', blockid)

    def get_output_transaction(self, txid):
        tx = self._provider_execute('get_output_transaction', txid)
        return tx

    def getaddressinfo(self, address):
        return self._provider_execute('getaddressinfo', address)

    def mempool(self, txid=''):
        return self._provider_execute('mempool', txid)

    def getcacheaddressinfo(self, address):
        addr_dict = {'address': address}
        addr_rec = self.cache.getaddress(address)
        if isinstance(addr_rec, DbCacheAddress):
            addr_dict['balance'] = addr_rec.balance
            addr_dict['last_block'] = addr_rec.last_block
            addr_dict['n_txs'] = addr_rec.n_txs
            addr_dict['n_utxos'] = addr_rec.n_utxos
        return addr_dict

    def isspent(self, txid, output_n):
        t = self.cache.gettransaction(bytes.fromhex(txid))
        if t and len(t.outputs) > output_n and t.outputs[output_n].spent is not None:
            return t.outputs[output_n].spent
        else:
            return bool(self._provider_execute('isspent', txid, output_n))

    def getinfo(self):
        return self._provider_execute('getinfo')

    def getinputvalues(self, t):
        prev_txs = []
        for i in t.inputs:
            if not i.value:
                if i.prev_txid not in prev_txs and i.prev_txid != 32 * b'\0':
                    prev_t = self.gettransaction(i.prev_txid.hex())
                else:
                    prev_t = [t for t in prev_txs if t.txid == i.prev_txid][0]
                i.value = prev_t.outputs[i.output_n_int].value
        return t


class Cache(object):
    def __init__(self, network):
        self.session = None
        self.network = network

    def cache_enabled(self):
        if not self.session:
            return False
        return True

    def commit(self):
        if not self.session:
            return
        try:
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise

    @staticmethod
    def _parse_db_transaction(db_tx):
        t = Transaction(locktime=db_tx.locktime, version=db_tx.version, network=db_tx.network_name,
                        fee=db_tx.fee, txid=db_tx.txid.hex(), date=db_tx.date, confirmations=db_tx.confirmations,
                        block_height=db_tx.block_height, status='confirmed', witness_type=db_tx.witness_type.value,
                        index=db_tx.index)
        if t.date and not t.date.tzinfo:
            t.date = t.date.replace(tzinfo=timezone.utc)
        for n in db_tx.nodes:
            if n.is_input:
                witness_type = None
                if n.ref_txid == b'\00' * 32:
                    t.coinbase = True
                    witness_type = db_tx.witness_type.value
                t.add_input(n.ref_txid.hex(), n.ref_index_n, unlocking_script=n.script, address=n.address,
                            sequence=n.sequence, value=n.value, index_n=n.index_n, witnesses=n.witnesses,
                            strict=False, witness_type=witness_type)
            else:
                t.add_output(n.value, n.address, lock_script=n.script, spent=n.spent, output_n=n.index_n,
                             spending_txid=None if not n.ref_txid else n.ref_txid.hex(),
                             spending_index_n=n.ref_index_n, strict=False)

        t.update_totals()
        t.size = len(t.raw())
        t.calc_weight_units()
        _logger.info("Retrieved transaction %s from cache" % t.txid)
        return t

    def gettransaction(self, txid):
        if not self.cache_enabled():
            return False
        db_tx = self.session.query(DbCacheTransaction).filter_by(txid=txid, network_name=self.network.name).first()
        if not db_tx:
            return False
        db_tx.txid = txid
        t = self._parse_db_transaction(db_tx)
        if t.block_height:
            t.confirmations = (self.blockcount() - t.block_height) + 1
        return t

    def getaddress(self, address):
        if not self.cache_enabled():
            return
        return self.session.query(DbCacheAddress).filter_by(address=address, network_name=self.network.name).scalar()

    def gettransactions(self, address, after_txid='', limit=MAX_TRANSACTIONS):
        if not self.cache_enabled():
            return False
        db_addr = self.getaddress(address)
        txs = []
        if db_addr:
            if after_txid:
                after_tx = self.session.query(DbCacheTransaction).\
                    filter_by(txid=after_txid, network_name=self.network.name).scalar()
                if after_tx and db_addr.last_block and after_tx.block_height:
                    db_txs = self.session.query(DbCacheTransaction).join(DbCacheTransactionNode).\
                        filter(DbCacheTransactionNode.address == address,
                               DbCacheTransaction.block_height >= after_tx.block_height,
                               DbCacheTransaction.block_height <= db_addr.last_block).\
                        order_by(DbCacheTransaction.block_height, DbCacheTransaction.index).all()
                    db_txs2 = []
                    for d in db_txs:
                        db_txs2.append(d)
                        if d.txid == after_txid:
                            db_txs2 = []
                    db_txs = db_txs2
                else:
                    return []
            else:
                db_txs = self.session.query(DbCacheTransaction).join(DbCacheTransactionNode). \
                    filter(DbCacheTransactionNode.address == address). \
                    order_by(DbCacheTransaction.block_height, DbCacheTransaction.index).all()
            for db_tx in db_txs:
                t = self._parse_db_transaction(db_tx)
                if t:
                    if t.block_height:
                        t.confirmations = (self.blockcount() - t.block_height) + 1
                    txs.append(t)
                    if len(txs) >= limit:
                        break
                
            for tx in txs:
                tx.date = tx.date.replace(tzinfo=timezone.utc)

            return txs
        return []

    def getblocktransactions(self, height, page, limit):
        if not self.cache_enabled():
            return False
        n_from = (page-1) * limit
        n_to = page * limit
        db_txs = self.session.query(DbCacheTransaction).\
            filter(DbCacheTransaction.block_height == height, DbCacheTransaction.index >= n_from,
                   DbCacheTransaction.index < n_to).all()
        txs = []
        for db_tx in db_txs:
            t = self._parse_db_transaction(db_tx)
            if t:
                txs.append(t)
        return txs

    def getrawtransaction(self, txid):
        if not self.cache_enabled():
            return False
        tx = self.session.query(DbCacheTransaction).filter_by(txid=txid, network_name=self.network.name).first()
        if not tx:
            return False
        t = self._parse_db_transaction(tx)
        return t.raw_hex()

    def getutxos(self, address, after_txid=''):
        if not self.cache_enabled():
            return False
        db_utxos = self.session.query(DbCacheTransactionNode.spent, DbCacheTransactionNode.index_n,
                                      DbCacheTransactionNode.value, DbCacheTransaction.confirmations,
                                      DbCacheTransaction.block_height, DbCacheTransaction.fee,
                                      DbCacheTransaction.date, DbCacheTransaction.txid).join(DbCacheTransaction). \
            order_by(DbCacheTransaction.block_height, DbCacheTransaction.index). \
            filter(DbCacheTransactionNode.address == address, DbCacheTransactionNode.is_input == False,
                   DbCacheTransaction.network_name == self.network.name).all()
        utxos = []
        for db_utxo in db_utxos:
            if db_utxo.spent is False:
                utxos.append({
                    'address': address,
                    'txid': db_utxo.txid.hex(),
                    'confirmations': db_utxo.confirmations,
                    'output_n': db_utxo.index_n,
                    'input_n': 0,
                    'block_height': db_utxo.block_height,
                    'fee': db_utxo.fee,
                    'size': 0,
                    'value': db_utxo.value,
                    'script': '',
                    'date': db_utxo.date
                })
            elif db_utxo.spent is None:
                return utxos
            if db_utxo.txid == after_txid:
                utxos = []
        return utxos

    def estimatefee(self, blocks):
        if not self.cache_enabled():
            return False
        if blocks <= 1:
            varname = 'fee_high'
        elif blocks <= 5:
            varname = 'fee_medium'
        else:
            varname = 'fee_low'
        dbvar = self.session.query(DbCacheVars).filter_by(varname=varname, network_name=self.network.name).\
            filter(DbCacheVars.expires > datetime.now()).scalar()
        if dbvar:
            return int(dbvar.value)
        return False

    def blockcount(self, never_expires=False):
        if not self.cache_enabled():
            return False
        qr = self.session.query(DbCacheVars).filter_by(varname='blockcount', network_name=self.network.name)
        if not never_expires:
            qr = qr.filter(DbCacheVars.expires > datetime.now())
        dbvar = qr.scalar()
        if dbvar:
            return int(dbvar.value)
        return False

    def getblock(self, blockid):
        if not self.cache_enabled():
            return False
        qr = self.session.query(DbCacheBlock)
        if isinstance(blockid, int):
            block = qr.filter_by(height=blockid, network_name=self.network.name).scalar()
        else:
            block = qr.filter_by(block_hash=to_bytes(blockid)).scalar()
        if not block:
            return False
        b = Block(block_hash=block.block_hash, height=block.height, network=block.network_name,
                  merkle_root=block.merkle_root, time=block.time, nonce=block.nonce,
                  version=block.version, prev_block=block.prev_block, bits=block.bits)
        b.tx_count = block.tx_count
        _logger.info("Retrieved block with height %d from cache" % b.height)
        return b

    def store_blockcount(self, blockcount):
        if not self.cache_enabled():
            return
        dbvar = DbCacheVars(varname='blockcount', network_name=self.network.name, value=str(blockcount), type='int',
                            expires=datetime.now() + timedelta(seconds=60))
        self.session.merge(dbvar)
        self.commit()

    def store_transaction(self, t, index=None, commit=True):
        if not self.cache_enabled():
            return
        # Only store complete and confirmed transaction in cache
        if not t.txid:    # pragma: no cover
            _logger.info("Caching failure tx: Missing transaction hash")
            return False
        elif not t.date or not t.block_height or not t.network:
            _logger.info("Caching failure tx: Incomplete transaction missing date, block height or network info")
            return False
        elif not t.coinbase and [i for i in t.inputs if not i.value]:
            _logger.info("Caching failure tx: One the transaction inputs has value 0")
            return False
        # TODO: Check if inputs / outputs are complete? script, value, prev_txid, sequence, output/input_n

        txid = bytes.fromhex(t.txid)
        if self.session.query(DbCacheTransaction).filter_by(txid=txid).count():
            return
        new_tx = DbCacheTransaction(txid=txid, date=t.date, confirmations=t.confirmations,
                                    block_height=t.block_height, network_name=t.network.name,
                                    fee=t.fee, index=index, version=t.version_int,
                                    locktime=t.locktime, witness_type=t.witness_type)
        self.session.add(new_tx)
        for i in t.inputs:
            if i.value is None or i.address is None or i.output_n is None:    # pragma: no cover
                _logger.info("Caching failure tx: Input value, address or output_n missing")
                return False
            witnesses = int_to_varbyteint(len(i.witnesses)) + b''.join([bytes(varstr(w)) for w in i.witnesses])
            new_node = DbCacheTransactionNode(txid=txid, address=i.address, index_n=i.index_n, value=i.value,
                                              is_input=True, ref_txid=i.prev_txid, ref_index_n=i.output_n_int,
                                              script=i.unlocking_script, sequence=i.sequence, witnesses=witnesses)
            self.session.add(new_node)
        for o in t.outputs:
            if o.value is None or o.address is None or o.output_n is None:    # pragma: no cover
                _logger.info("Caching failure tx: Output value, address or output_n missing")
                return False
            new_node = DbCacheTransactionNode(
                txid=txid, address=o.address, index_n=o.output_n, value=o.value, is_input=False, spent=o.spent,
                ref_txid=None if not o.spending_txid else bytes.fromhex(o.spending_txid),
                ref_index_n=o.spending_index_n, script=o.lock_script)
            self.session.add(new_node)

        if commit:
            try:
                self.commit()
                _logger.info("Added transaction %s to cache" % t.txid)
            except Exception as e:    # pragma: no cover
                _logger.warning("Caching failure tx: %s" % e)

    def store_utxo(self, txid, index_n, commit=True):
        if not self.cache_enabled():
            return False
        txid = bytes.fromhex(txid)
        result = self.session.query(DbCacheTransactionNode). \
            filter(DbCacheTransactionNode.txid == txid, DbCacheTransactionNode.index_n == index_n,
                   DbCacheTransactionNode.is_input == False).\
            update({DbCacheTransactionNode.spent: False})
        if commit:
            try:
                self.commit()
            except Exception as e:    # pragma: no cover
                _logger.warning("Caching failure utxo %s:%d: %s" % (txid.hex(), index_n, e))

    def store_address(self, address, last_block=None, balance=0, n_utxos=None, txs_complete=False, last_txid=None):
        if not self.cache_enabled():
            return
        n_txs = None
        if txs_complete:
            n_txs = len(self.session.query(DbCacheTransaction).join(DbCacheTransactionNode).
                        filter(DbCacheTransactionNode.address == address).all())
            if n_utxos is None:
                n_utxos = self.session.query(DbCacheTransactionNode).\
                    filter(DbCacheTransactionNode.address == address, DbCacheTransactionNode.spent.is_(False),
                           DbCacheTransactionNode.is_input.is_(False)).count()
                if self.session.query(DbCacheTransactionNode).\
                        filter(DbCacheTransactionNode.address == address, DbCacheTransactionNode.spent.is_(None),
                               DbCacheTransactionNode.is_input.is_(False)).count():
                    n_utxos = None
            if not balance:
                plusmin = self.session.query(DbCacheTransactionNode.is_input, func.sum(DbCacheTransactionNode.value)). \
                    filter(DbCacheTransactionNode.address == address). \
                    group_by(DbCacheTransactionNode.is_input).all()
                balance = 0 if not plusmin else sum([(-p[1] if p[0] else p[1]) for p in plusmin])
        db_addr = self.getaddress(address)
        new_address = DbCacheAddress(
            address=address, network_name=self.network.name,
            last_block=last_block if last_block else getattr(db_addr, 'last_block', None),
            balance=balance if balance is not None else getattr(db_addr, 'balance', None),
            n_utxos=n_utxos if n_utxos is not None else getattr(db_addr, 'n_utxos', None),
            n_txs=n_txs if n_txs is not None else getattr(db_addr, 'n_txs', None),
            last_txid=last_txid if last_txid is not None else getattr(db_addr, 'last_txid', None))
        self.session.merge(new_address)
        try:
            self.commit()
        except Exception as e:    # pragma: no cover
            _logger.warning("Caching failure addr: %s" % e)

    def store_estimated_fee(self, blocks, fee):
        if not self.cache_enabled():
            return
        if blocks <= 1:
            varname = 'fee_high'
        elif blocks <= 5:
            varname = 'fee_medium'
        else:
            varname = 'fee_low'
        dbvar = DbCacheVars(varname=varname, network_name=self.network.name, value=str(fee), type='int',
                            expires=datetime.now() + timedelta(seconds=600))
        self.session.merge(dbvar)
        self.commit()

    def store_block(self, block):
        if not self.cache_enabled():
            return
        if not (block.height and block.block_hash and block.prev_block and block.merkle_root and
                block.bits and block.version) \
                and not block.block_hash == b'\x00\x00\x00\x00\x00\x19\xd6h\x9c\x08Z\xe1e\x83\x1e\x93O\xf7c\xaeF' \
                                            b'\xa2\xa6\xc1r\xb3\xf1\xb6\n\x8c\xe2o':  # Bitcoin genesis block
            _logger.info("Caching failure block: incomplete data")
            return

        new_block = DbCacheBlock(
            block_hash=block.block_hash, height=block.height, network_name=self.network.name,
            version=block.version_int, prev_block=block.prev_block, bits=block.bits_int,
            merkle_root=block.merkle_root, nonce=block.nonce_int, time=block.time, tx_count=block.tx_count)
        self.session.merge(new_block)
        try:
            self.commit()
        except Exception as e:    # pragma: no cover
            _logger.warning("Caching failure block: %s" % e)
