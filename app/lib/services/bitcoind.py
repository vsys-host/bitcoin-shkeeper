import configparser
from app.lib.main import *
from app.lib.services.authproxy import AuthServiceProxy
from app.lib.services.baseclient import BaseClient, ClientError
from app.lib.transactions import Transaction
from app.lib.networks import Network
from app.config import config
from app.models import db, DbCacheVars

PROVIDERNAME = 'bitcoind'

_logger = logging.getLogger(__name__)

class BitcoindClient(BaseClient):
    def __init__(self, network=config['BTC_NETWORK'], base_url='', denominator=100000000, *args):
        if isinstance(network, Network):
            network = network.name
        if not base_url:
            raise ValueError("Please provide rpc connection url to bitcoind node")
        wallet_name = '' if not len(args) > 6 else args[6]
        if wallet_name:
            base_url = base_url.replace("{wallet_name}", wallet_name)
        _logger.info("Connect to bitcoind")
        self.proxy = AuthServiceProxy(base_url)
        super(self.__class__, self).__init__(network, PROVIDERNAME, base_url, denominator, *args)

    def getbalance(self, addresslist):
        balance = 0
        for address in addresslist:
            res = self.proxy.getaddressinfo(address)
            if not (res['ismine'] or res['iswatchonly']):
                raise ClientError(
                    "Address %s not found in bitcoind wallet, use 'importpubkey' or 'importaddress' to add "
                    "address to wallet." % address)
            txs_list = self.proxy.listunspent(0, 99999999, [address])
            for tx in txs_list:
                balance += int(tx['amount'] * self.units)
        return balance

    def get_output_transaction(self, txid):
        tx_raw = self.proxy.gettransaction(txid)
        return tx_raw

    def getutxos(self, address, after_txid='', limit=MAX_TRANSACTIONS):
        utxos = []
        res = self.proxy.getaddressinfo(address)
        if not (res['ismine'] or res['iswatchonly']):
            raise ClientError("Address %s not found in bitcoind wallet, use 'importpubkey' or 'importaddress' to add "
                              "address to wallet." % address)

        txs_list = self.proxy.listunspent(0, 9999999, [address])
        blockcount = self.blockcount()
        for tx in sorted(txs_list, key=lambda x: x['confirmations'], reverse=True):
            utxos.append({
                'address': tx['address'],
                'txid': tx['txid'],
                'confirmations': tx['confirmations'],
                'output_n': tx['vout'],
                'input_n': -1,
                'block_height': blockcount - tx['confirmations'] + 1,
                'fee': None,
                'size': 0,
                'value': int(tx['amount'] * self.units),
                'script': tx['scriptPubKey'],
                'date': None,
            })
            if tx['txid'] == after_txid:
                utxos = []

        return utxos

    def _parse_transaction(self, tx, block_height=None, get_input_values=True):
        t = Transaction.parse_hex(tx['hex'], strict=self.strict, network=self.network, default_txid=tx['txid'])
        t.confirmations = tx.get('confirmations')
        t.block_hash = tx.get('blockhash')
        t.status = 'unconfirmed'
        for i in t.inputs:
            if i.prev_txid == b'\x00' * 32:
                i.script_type = 'coinbase'
                continue
            if get_input_values:
                txi = self.proxy.getrawtransaction(i.prev_txid.hex(), 1)
                i.value = int(round(float(txi['vout'][i.output_n_int]['value']) / self.network.denominator))
        for o in t.outputs:
            o.spent = None

        if not block_height and t.block_hash:
            block_height = self.proxy.getblock(t.block_hash, 1)['height']
        t.block_height = block_height
        if not t.confirmations and block_height is not None:
            if not self.latest_block:
                self.latest_block = self.blockcount()
            t.confirmations = (self.latest_block - block_height) + 1
        if t.confirmations or block_height:
            t.status = 'confirmed'
            t.verified = True
        t.version = tx['version'].to_bytes(4, 'big')
        t.version_int = tx['version']
        t.date = None if 'time' not in tx else datetime.fromtimestamp(tx['time'], timezone.utc)
        t.update_totals()
        return t

    def _parse_transaction_new(self, tx, block_height=None, block_hash=None, block_time=None, confirmations=None, get_input_values=True):
        t = Transaction.parse_hex(tx['hex'], strict=self.strict, network=self.network, default_txid=tx['txid'])
        t.block_height = block_height
        t.block_hash = block_hash
        t.confirmations = confirmations
        t.date = datetime.fromtimestamp(block_time, timezone.utc) if block_time else None

        t.status = 'unconfirmed'

        total_input_value = 0
        total_output_value = 0

        for i, vin in enumerate(tx.get('vin', [])):
            if i >= len(t.inputs):
                break

            input_obj = t.inputs[i]

            if vin.get('coinbase'):
                input_obj.script_type = 'coinbase'
                continue

            if get_input_values and 'prevout' in vin and vin['prevout']:
                value = vin['prevout'].get('value')
                if value is not None:
                    sat_value = int(round(float(value) / float(self.network.denominator)))
                    input_obj.value = sat_value
                    total_input_value += sat_value

        for i, vout in enumerate(tx.get('vout', [])):
            if i >= len(t.outputs):
                break

            output_obj = t.outputs[i]
            output_obj.spent = None

            value = vout.get('value')
            if value is not None:
                sat_value = int(round(float(value) / float(self.network.denominator)))
                output_obj.value = sat_value
                total_output_value += sat_value

        if not block_height and t.block_hash:
            block = self.proxy.getblock(t.block_hash, 1)
            block_height = block['height']

        t.block_height = block_height

        if not t.confirmations and block_height is not None:
            if not self.latest_block:
                self.latest_block = self.blockcount()
            t.confirmations = (self.latest_block - block_height) + 1

        if t.confirmations or block_height:
            t.status = 'confirmed'
            t.verified = True

        t.version = tx['version'].to_bytes(4, 'big')
        t.version_int = tx['version']
        t.date = None if 'time' not in tx else datetime.fromtimestamp(tx['time'], timezone.utc)

        t.total_input = total_input_value
        t.total_output = total_output_value
        t.fee = total_input_value - total_output_value if total_input_value > 0 else None

        return t

    def gettransaction(self, txid):
        tx_raw = self.proxy.getrawtransaction(txid, 1)
        return self._parse_transaction(tx_raw)

    def gettransactions(self, address, after_txid='', txs_list=[]):
        txs = []
        # Use dict to avoid duplicates when address appears in both inputs and outputs
        txids = {}

        block_hash = txs_list.get('hash')
        block_height = txs_list.get('height')
        block_time = txs_list.get('time')
        confirmations = txs_list.get('confirmations')

        for tx in txs_list['tx']:
            tx_id = tx.get('txid')
            matched = False

            for vout in tx.get('vout', []):
                addr = vout.get('scriptPubKey', {}).get('address')
                if addr == address:
                    matched = True
                    break

            if not matched:
                for vin in tx.get('vin', []):
                    prevout = vin.get('prevout', {})
                    addr = prevout.get('scriptPubKey', {}).get('address')
                    if addr == address:
                        matched = True
                        break

            if matched:
                txids[tx_id] = (tx, block_height, block_hash, block_time, confirmations)

        for tx_id, (tx, block_height, block_hash, block_time, confirmations) in txids.items():
            try:
                t = self._parse_transaction_new(tx, block_height, block_hash, block_time, confirmations)
                txs.append(t)
                if tx_id == after_txid:
                    txs = []
            except Exception as e:
                _logger.error(f"Failed to parse tx {tx}: {e}")

        return txs


    def getblocktransactions(self, block_hash):
        _logger.warning("REQUEST getblocktransactions")
        # MAX_WALLET_TRANSACTIONS = int(config['COUNT_RECEIVED_TRANSACTIONS'])
        # txs_list = self.proxy.listtransactions("*", MAX_WALLET_TRANSACTIONS, 0, True)
        txs_list = self.proxy.getblock(block_hash, 3)
        return txs_list

    def importaddress(self, address):
        res = self.proxy.importaddress(address, "", False)
        return res

    def loadwallet(self, wallet_name):
       return self.proxy.loadwallet(wallet_name)

    def created_and_import_descriptors(self, descriptor_no_checksum):         
        desc_info = self.proxy.getdescriptorinfo(descriptor_no_checksum)
        descriptor_with_checksum = desc_info['descriptor']
        count_addresse = int(config['COUNT_ADDRESSES'])
        descriptors = [{
            "desc": descriptor_with_checksum,
            "timestamp": 'now',
            "active": True,
            "internal": False,

            "range": [0, count_addresse]
        }]
        res = self.proxy.importdescriptors(descriptors)
        return res

    def createwallet(self, name):
        res = self.proxy.createwallet(name, True, True, "", False, True)
        return res

    def getblockcount(self):
        res = self.proxy.getblockcount()
        return res

    def getblockhash(self, height):
        res = self.proxy.getblockhash(height)
        return res

    def getrawtransaction(self, txid):
        res = self.proxy.getrawtransaction(txid)
        return res

    def sendrawtransaction(self, rawtx):
        res = self.proxy.sendrawtransaction(rawtx)
        return {
            'txid': res,
            'response_dict': res
        }

    def estimatefee(self, blocks):
        pres = ''
        try:
            pres = self.proxy.estimatesmartfee(blocks)
            res = pres['feerate']
        except KeyError as e:
            _logger.info("bitcoind error: %s, %s" % (e, pres))
            res = self.proxy.estimatefee(blocks)
        return int(res * self.units)

    def blockcount(self):
        bcinfo = self.proxy.getblockchaininfo()
        return bcinfo['blocks']

    def synced_status(self):
        bcinfo = self.proxy.getblockchaininfo()
        not_synced_block = bcinfo['headers'] - bcinfo['blocks']
        last_scanned_block_obj = db.session.query(DbCacheVars).filter_by(varname='last_scanned_block').scalar()
        if last_scanned_block_obj is None:
            last_scanned_block = 0
        else:
            last_scanned_block = int(last_scanned_block_obj.value)
        current_scanned_blocks = bcinfo['headers'] - last_scanned_block
        return max(not_synced_block, current_scanned_blocks)

    def mempool(self, txid=''):
        txids = self.proxy.getrawmempool()
        if not txid:
            return txids
        elif txid in txids:
            return [txid]
        return []

    def getblock(self, blockid, parse_transactions=True, page=1, limit=None):
        if isinstance(blockid, int) or len(blockid) < 10:
            blockid = self.proxy.getblockhash(int(blockid))
        if not limit:
            limit = 99999

        txs = []
        if parse_transactions:
            bd = self.proxy.getblock(blockid, 3)
            # use _parse_transaction_new which uses prevout data
            # from verbosity=3 response instead of making individual RPC calls per input
            for tx in bd['tx'][(page - 1) * limit:page * limit]:
                tx['time'] = bd['time']
                tx['blockhash'] = bd['hash']
                # Use optimized parser that extracts values from prevout (no extra RPC calls)
                txs.append(self._parse_transaction_new(
                    tx,
                    block_height=bd['height'],
                    block_hash=bd['hash'],
                    block_time=bd['time'],
                    confirmations=bd.get('confirmations'),
                    get_input_values=True
                ))
        else:
            bd = self.proxy.getblock(blockid, 1)
            txs = bd['tx']

        block = {
            'bits': int(bd['bits'], 16),
            'depth': bd['confirmations'],
            'block_hash': bd['hash'],
            'height': bd['height'],
            'merkle_root': bd['merkleroot'],
            'nonce': bd['nonce'],
            'prev_block': None if 'previousblockhash' not in bd else bd['previousblockhash'],
            'time': bd['time'],
            'tx_count': bd['nTx'],
            'txs': txs,
            'version': bd['version'],
            'page': page,
            'pages': None,
            'limit': limit
        }
        return block

    def getrawblock(self, blockid):
        if isinstance(blockid, int):
            blockid = self.proxy.getblockhash(blockid)
        return self.proxy.getblock(blockid, 0)

    def isspent(self, txid, index):
        res = self.proxy.gettxout(txid, index)
        if not res:
            return 1
        return 0

    def getaddressinfo(self, address):
        info = self.proxy.getaddressinfo(address)
        return {
            'ismine': info['ismine'],
            'address': info['address'],
        }

    def getinfo(self):
        info = self.proxy.getmininginfo()
        return {
            'blockcount': info['blocks'],
            'chain': info['chain'],
            'difficulty': int(info['difficulty']),
            'hashrate': int(info['networkhashps']),
            'mempool_size': int(info['pooledtx']),
        }