from io import BytesIO
from app.lib.encoding import *
from app.lib.networks import Network
from app.lib.transactions import Transaction


class Block:
    def __init__(self, block_hash, version, prev_block, merkle_root, time, bits, nonce, transactions=None,
                 height=None, confirmations=None, network=DEFAULT_NETWORK):
        self.block_hash = to_bytes(block_hash)
        if isinstance(version, int):
            self.version = version.to_bytes(4, byteorder='big')
            self.version_int = version
        else:
            self.version = to_bytes(version)
            self.version_int = 0 if not self.version else int.from_bytes(self.version, 'big')
        self.prev_block = to_bytes(prev_block)
        self.merkle_root = to_bytes(merkle_root)
        self.time = time
        if not isinstance(time, int):
            self.time = int.from_bytes(time, 'big')
        if isinstance(bits, int):
            self.bits = bits.to_bytes(4, 'big')
            self.bits_int = bits
        else:
            self.bits = to_bytes(bits)
            self.bits_int = 0 if not self.bits else int.from_bytes(self.bits, 'big')
        if isinstance(nonce, int):
            self.nonce = nonce.to_bytes(4, 'big')
            self.nonce_int = nonce
        else:
            self.nonce = to_bytes(nonce)
            self.nonce_int = 0 if not self.nonce else int.from_bytes(self.nonce, 'big')
        self.transactions = transactions
        self.transactions_dict = []
        if self.transactions is None:
            self.transactions = []
        self.txs_data = None
        self.confirmations = confirmations
        self.network = network
        if not isinstance(network, Network):
            self.network = Network(network)
        self.tx_count = 0
        self.page = 1
        self.limit = 0
        self.height = height
        self.total_in = 0
        self.total_out = 0
        self.size = 0
        if self.transactions and len(self.transactions) and isinstance(self.transactions[0], Transaction) \
                and self.version_int > 1:
            # first bytes of unlocking script of coinbase transaction contains block height (BIP0034)
            if self.transactions[0].coinbase and self.transactions[0].inputs[0].unlocking_script:
                calc_height = int.from_bytes(self.transactions[0].inputs[0].unlocking_script[1:4] + b'\x00', 'little')
                if height and calc_height != height and height > 227835:
                    raise ValueError("Specified block height %d is different than calculated block height according to "
                                     "BIP0034" % height)
                self.height = calc_height

    def __repr__(self):
        return "<Block(%s, %s, transactions: %s)>" % (self.block_hash.hex(), self.height, self.tx_count)

    @classmethod
    def parse(cls, raw, block_hash=None, height=None, parse_transactions=False, limit=0, network=DEFAULT_NETWORK):
        if isinstance(raw, bytes):
            b = cls.parse_bytesio(BytesIO(raw), block_hash, height, parse_transactions, limit, network)
            b.size = len(raw)
            return b
        else:
            return cls.parse_bytesio(raw, block_hash, height, parse_transactions, limit, network)

    @classmethod
    def parse_bytes(cls, raw_bytes, block_hash=None, height=None, parse_transactions=False, limit=0,
                    network=DEFAULT_NETWORK):
        raw_bytesio = BytesIO(raw_bytes)
        b = cls.parse_bytesio(raw_bytesio, block_hash, height, parse_transactions, limit, network)
        b.size = len(raw_bytes)
        return b

    @classmethod
    def parse_bytesio(cls, raw, block_hash=None, height=None, parse_transactions=False, limit=0,
                      network=DEFAULT_NETWORK):
        block_header = raw.read(80)
        block_hash_calc = double_sha256(block_header)[::-1]
        if not block_hash:
            block_hash = block_hash_calc
        elif block_hash != block_hash_calc:
            raise ValueError("Provided block hash does not correspond to calculated block hash %s" %
                             block_hash_calc.hex())

        raw.seek(0)
        version = raw.read(4)[::-1]
        prev_block = raw.read(32)[::-1]
        merkle_root = raw.read(32)[::-1]
        time = raw.read(4)[::-1]
        bits = raw.read(4)[::-1]
        nonce = raw.read(4)[::-1]
        tx_count = read_varbyteint(raw)
        tx_start_pos = raw.tell()
        txs_data_size = raw.seek(0, 2)
        raw.seek(tx_start_pos)
        transactions = []

        index = 0
        while parse_transactions and raw.tell() < txs_data_size:
            if limit != 0 and len(transactions) >= limit:
                break
            t = Transaction.parse_bytesio(raw, strict=False, index=index)
            transactions.append(t)
            index += 1
        if parse_transactions and limit == 0 and tx_count != len(transactions):
            raise ValueError("Number of found transactions %d is not equal to expected number %d" %
                             (len(transactions), tx_count))

        block = cls(block_hash, version, prev_block, merkle_root, time, bits, nonce, transactions, height,
                    network=network)
        block.txs_data = raw
        block.tx_count = tx_count
        return block

    def parse_transactions(self, limit=0):
        n = 0
        while self.txs_data and (limit == 0 or n < limit) and len(self.transactions) < self.tx_count:
            t = Transaction.parse_bytesio(self.txs_data, strict=False, network=self.network)  # , check_size=False
            self.transactions.append(t)
            n += 1

    def as_dict(self):
        return {
            'block_hash': self.block_hash.hex(),
            'height': self.height,
            'version': self.version_int,
            'prev_block': None if not self.prev_block else self.prev_block.hex(),
            'merkle_root': self.merkle_root.hex(),
            'timestamp': self.time,
            'bits': self.bits_int,
            'nonce': self.nonce_int,
            'target': self.target_hex,
            'difficulty': self.difficulty,
            'tx_count': self.tx_count,
            'transactions': self.transactions,
            'confirmations': self.confirmations
        }

    @property
    def target(self):
        if not self.bits:
            return 0
        exponent = self.bits[0]
        coefficient = int.from_bytes(b'\x00' + self.bits[1:], 'big')
        return coefficient * 256 ** (exponent - 3)

    @property
    def target_hex(self):
        if not self.bits:
            return ''
        return hex(int(self.target))[2:].zfill(64)

    def parse_transaction(self):
        if self.txs_data and len(self.transactions) < self.tx_count:
            t = Transaction.parse_bytesio(self.txs_data, strict=False, network=self.network)  # , check_size=False
            self.transactions.append(t)
            return t
        return False
    
    @property
    def difficulty(self):
        if not self.bits:
            return 0
        return 0xffff * 256 ** (0x1d - 3) / self.target

    def serialize(self):
        if len(self.transactions) != self.tx_count or len(self.transactions) < 1:
            raise ValueError("Block contains incorrect number of transactions, can not serialize")
        rb = self.version[::-1]
        rb += self.prev_block[::-1]
        rb += self.merkle_root[::-1]
        rb += self.time.to_bytes(4, 'little')
        rb += self.bits[::-1]
        rb += self.nonce[::-1]
        if len(rb) != 80:
            raise ValueError("Missing or incorrect length of 1 of the block header variables: version, prev_block, "
                             "merkle_root, time, bits or nonce.")
        rb += int_to_varbyteint(len(self.transactions))
        for t in self.transactions:
            rb += t.raw()
        return rb

    def update_totals(self):
        self.total_in = 0
        self.total_out = 0
        for t in self.transactions:
            self.total_in += sum([i.value for i in t.inputs])
            self.total_out += sum([o.value for o in t.outputs])
