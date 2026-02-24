import enum
from datetime import datetime, timezone
from .db_import import db
from app.config import config
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.mysql import VARBINARY
from sqlalchemy.orm import sessionmaker, relationship, session
from sqlalchemy import BLOB, TypeDecorator, String, func
from hashlib import sha256
from app.lib.encoding import aes_decrypt, aes_encrypt, double_sha256
from app.unlock_acc import get_account_password

class EncryptedBinary(TypeDecorator):
    cache_ok = True
    impl = VARBINARY

    @property
    def key(self):
        password = get_account_password()
        if not password or not isinstance(password, str):
            return None
        return sha256(password.encode('utf-8')).digest()

    def process_bind_param(self, value, dialect):
        if value is None:
            return value

        key = self.key
        if not key:
            raise RuntimeError("Encryption password not loaded — cannot save encrypted field")

        if not isinstance(value, bytes):
            value = value.encode('utf-8')

        return aes_encrypt(value, key)

    def process_result_value(self, value, dialect):
        if value is None:
            return value

        key = self.key
        if not key:
            print("No encryption key, returning raw bytes.")
            return value

        return aes_decrypt(value, key)

class DbWallet(db.Model):
    __tablename__ = 'wallets'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    owner = db.Column(db.String(50))
    network_name = db.Column(db.String(20))
    network = db.Column(db.String(20), default=config['COIN_NETWORK'])
    generated_address_count = db.Column(db.Integer, default=0)
    purpose = db.Column(db.Integer)
    scheme = db.Column(db.String(25))
    witness_type = db.Column(db.String(20), default='segwit')
    encoding = db.Column(db.String(15), default='base58')
    main_key_id = db.Column(db.Integer)
    migrated = db.Column(db.Boolean, default=False)
    multisig_n_required = db.Column(db.Integer, default=1)
    sort_keys = db.Column(db.Boolean, default=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('wallets.id'))
    key_path = db.Column(db.String(100))
    anti_fee_sniping = db.Column(db.Boolean, default=True)
    default_account_id = db.Column(db.Integer, default=0)
    keys = db.relationship("DbKey", backref="wallet", lazy=True)
    transactions = db.relationship("DbTransaction", backref="wallet", lazy=True)
    children = db.relationship("DbWallet", backref=db.backref('parent', remote_side=[id]), lazy=True)

    __table_args__ = (
        db.CheckConstraint(scheme.in_(['single', 'bip32']), name='constraint_allowed_schemes'),
        db.CheckConstraint(encoding.in_(['base58', 'bech32']), name='constraint_default_address_encodings_allowed'),
        db.CheckConstraint(witness_type.in_(['legacy', 'segwit', 'p2sh-segwit', 'p2tr']),
                           name='wallet_constraint_allowed_types'),
    )

class DbKey(db.Model):
    __tablename__ = 'keys'

    id = db.Column(db.Integer, primary_key=True)
    parent_id = db.Column(db.Integer)
    name = db.Column(db.String(80), index=True)
    account_id = db.Column(db.Integer, index=True)
    depth = db.Column(db.Integer)
    change = db.Column(db.Integer)
    address_index = db.Column(db.BigInteger)
    public = db.Column(db.VARBINARY(65), index=True)
    private = db.Column(EncryptedBinary(48))
    wif = db.Column(EncryptedBinary(128), index=True)
    compressed = db.Column(db.Boolean, default=True)
    key_type = db.Column(db.String(10), default='bip32')
    address = db.Column(db.String(100), index=True)
    encoding = db.Column(db.String(15), default='base58')
    purpose = db.Column(db.Integer, default=44)
    is_private = db.Column(db.Boolean)
    path = db.Column(db.String(100))
    wallet_id = db.Column(db.Integer, db.ForeignKey('wallets.id'), index=True)
    network_name = db.Column(db.String(20))
    latest_txid = db.Column(db.VARBINARY(33))
    witness_type = db.Column(db.String(20), default='segwit')
    network = db.Column(db.String(20), default=config['COIN_NETWORK'])
    balance = db.Column(db.BigInteger, default=0)
    used = db.Column(db.Boolean, default=False)

    transaction_inputs = db.relationship("DbTransactionInput", backref="key", cascade="all, delete")
    transaction_outputs = db.relationship("DbTransactionOutput", backref="key", cascade="all, delete")

    __table_args__ = (
        db.CheckConstraint(key_type.in_(['single', 'bip32']), name='constraint_key_types_allowed'),
        db.CheckConstraint(encoding.in_(['base58', 'bech32']), name='constraint_address_encodings_allowed'),
        db.UniqueConstraint('wallet_id', 'public', name='constraint_wallet_pubkey_unique'),
        db.UniqueConstraint('wallet_id', 'private', name='constraint_wallet_privkey_unique'),
        db.UniqueConstraint('wallet_id', 'wif', name='constraint_wallet_wif_unique'),
        db.UniqueConstraint('wallet_id', 'address', name='constraint_wallet_address_unique'),
    )

class DbTransaction(db.Model):
    __tablename__ = 'transactions'

    id = db.Column(db.Integer, primary_key=True)
    txid = db.Column(db.VARBINARY(33), index=True)
    wallet_id = db.Column(db.Integer, db.ForeignKey('wallets.id'), index=True)
    account_id = db.Column(db.Integer, index=True)
    witness_type = db.Column(db.String(20), default='segwit')
    version = db.Column(db.BigInteger, default=1)
    locktime = db.Column(db.BigInteger, default=0)
    date = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    coinbase = db.Column(db.Boolean, default=False)
    confirmations = db.Column(db.Integer, default=0, index=True)
    block_height = db.Column(db.Integer, index=True)
    size = db.Column(db.Integer)
    fee = db.Column(db.BigInteger)
    status = db.Column(db.String(20), default='new', index=True)
    tx_type = db.Column(db.String(255), nullable=True, index=True)
    uid = db.Column(db.String(255), nullable=True, index=True)
    score = db.Column(db.Numeric(7, 5), default=-1)
    aml_status = db.Column(db.String(255), nullable=True, index=True)
    is_complete = db.Column(db.Boolean, default=True)
    input_total = db.Column(db.BigInteger, default=0)
    output_total = db.Column(db.BigInteger, default=0)
    network_name = db.Column(db.String(20))
    network = db.Column(db.String(20))
    raw = db.Column(db.BLOB)
    verified = db.Column(db.Boolean, default=False)
    index = db.Column(db.Integer)

    inputs = db.relationship("DbTransactionInput", backref="transaction", cascade="all, delete")
    outputs = db.relationship("DbTransactionOutput", backref="transaction", cascade="all, delete")

    __table_args__ = (
        db.UniqueConstraint('wallet_id', 'txid', name='constraint_wallet_transaction_hash_unique'),
        db.Index('idx_tx_wallet_confirm', 'confirmations'),
        db.CheckConstraint(status.in_(['new', 'unconfirmed', 'confirmed']), name='constraint_status_allowed'),
        db.CheckConstraint(witness_type.in_(['legacy', 'segwit']), name='transaction_constraint_allowed_types'),
    )

class DbTransactionInput(db.Model):
    __tablename__ = 'transaction_inputs'

    transaction_id = db.Column(db.Integer, db.ForeignKey('transactions.id'), primary_key=True)
    index_n = db.Column(db.Integer, primary_key=True)
    key_id = db.Column(db.Integer, db.ForeignKey('keys.id'), index=True)
    address = db.Column(db.String(255), index=True)
    witnesses = db.Column(db.BLOB)
    witness_type = db.Column(db.String(20), default='segwit')
    prev_txid = db.Column(db.VARBINARY(33), index=True)
    output_n = db.Column(db.BigInteger)
    script = db.Column(db.BLOB)
    script_type = db.Column(db.String(20), default='sig_pubkey')
    sequence = db.Column(db.BigInteger)
    value = db.Column(db.BigInteger, default=0)
    double_spend = db.Column(db.Boolean, default=False, index=True)

    __table_args__ = (
        db.UniqueConstraint('transaction_id', 'index_n', name='constraint_transaction_input_unique'),
        db.Index('idx_input_prevtx_output', 'prev_txid', 'output_n'),
        db.CheckConstraint(witness_type.in_(['legacy', 'segwit', 'p2sh-segwit', 'taproot']),
                           name='transactioninput_constraint_allowed_types'),
    )

class DbTransactionOutput(db.Model):
    __tablename__ = 'transaction_outputs'

    transaction_id = db.Column(db.Integer, db.ForeignKey('transactions.id'), primary_key=True)
    output_n = db.Column(db.BigInteger, primary_key=True)
    key_id = db.Column(db.Integer, db.ForeignKey('keys.id'), index=True)
    address = db.Column(db.String(255), index=True)
    script = db.Column(db.BLOB)
    script_type = db.Column(db.String(20), default='p2pkh')
    value = db.Column(db.BigInteger, default=0)
    spent = db.Column(db.Boolean, default=False, index=True)
    spending_txid = db.Column(db.VARBINARY(33), index=True)
    spending_index_n = db.Column(db.Integer)
    is_change = db.Column(db.Boolean, default=False)

    __table_args__ = (
        db.UniqueConstraint('transaction_id', 'output_n', name='constraint_transaction_output_unique'),
        db.Index('idx_output_key_spent', 'key_id', 'spent'),
    )

class DbAmlPayout(db.Model):
    __tablename__ = 'aml_payouts'

    id = db.Column(db.Integer, primary_key=True)
    tx_id = db.Column(db.VARBINARY(33), index=True)
    external_tx_id = db.Column(db.VARBINARY(33), index=True)
    status = db.Column(db.String(20), index=True)
    dtype = db.Column(db.String(20), index=True, nullable=True)
    crypto = db.Column(db.String(10))
    amount_calc = db.Column(db.Numeric(52, 18), default=0)
    amount_send = db.Column(db.Numeric(52, 18), default=0)
    address = db.Column(db.String(255), index=True)
    created_at = db.Column(db.DateTime, default=func.now())
    updated_at = db.Column(db.DateTime, default=func.now(), onupdate=func.now())

class WitnessTypeTransactions(enum.Enum):
    legacy = "legacy"
    segwit = "segwit"

class DbCacheTransactionNode(db.Model):
    __tablename__ = 'cache_transactions_node'

    txid = db.Column(db.VARBINARY(32), db.ForeignKey('cache_transactions.txid'), primary_key=True)
    index_n = db.Column(db.Integer, primary_key=True)
    is_input = db.Column(db.Boolean, primary_key=True)
    value = db.Column(db.BigInteger, default=0)
    address = db.Column(db.String(255), index=True)
    script = db.Column(db.BLOB)
    witnesses = db.Column(db.BLOB)
    sequence = db.Column(db.BigInteger, default=0xffffffff)
    spent = db.Column(db.Boolean, default=None)
    ref_txid = db.Column(db.VARBINARY(32), index=True)
    ref_index_n = db.Column(db.BigInteger)

    transaction = db.relationship("DbCacheTransaction", back_populates='nodes')

    def prev_txid(self):
        if self.is_input:
            return self.ref_txid

    def output_n(self):
        if self.is_input:
            return self.ref_index_n

    def spending_txid(self):
        if not self.is_input:
            return self.ref_txid

    def spending_index_n(self):
        if not self.is_input:
            return self.ref_index_n

class DbCacheTransaction(db.Model):
    __tablename__ = 'cache_transactions'

    txid = db.Column(db.VARBINARY(32), primary_key=True)
    date = db.Column(db.DateTime)
    version = db.Column(db.BigInteger, default=1)
    locktime = db.Column(db.BigInteger, default=0)
    confirmations = db.Column(db.Integer, default=0)
    block_height = db.Column(db.Integer, index=True)
    network_name = db.Column(db.String(20))
    fee = db.Column(db.BigInteger)
    index = db.Column(db.Integer)
    witness_type = db.Column(db.Enum(WitnessTypeTransactions), default=WitnessTypeTransactions.legacy)

    nodes = db.relationship("DbCacheTransactionNode", cascade="all, delete-orphan", back_populates='transaction')

class DbCacheAddress(db.Model):
    __tablename__ = 'cache_address'

    address = db.Column(db.String(255), primary_key=True)
    network_name = db.Column(db.String(20))
    balance = db.Column(db.BigInteger, default=0)
    last_block = db.Column(db.Integer)
    last_txid = db.Column(db.VARBINARY(32))
    n_utxos = db.Column(db.Integer)
    n_txs = db.Column(db.Integer)


class DbCacheBlock(db.Model):
    __tablename__ = 'cache_blocks'

    height = db.Column(db.Integer, primary_key=True)
    block_hash = db.Column(db.VARBINARY(32), index=True)
    network_name = db.Column(db.String(20))
    version = db.Column(db.BigInteger)
    prev_block = db.Column(db.VARBINARY(32))
    merkle_root = db.Column(db.VARBINARY(32))
    time = db.Column(db.BigInteger)
    bits = db.Column(db.BigInteger)
    nonce = db.Column(db.BigInteger)
    tx_count = db.Column(db.Integer)


class DbCacheVars(db.Model):
    __tablename__ = 'cache_variables'

    varname = db.Column(db.String(50), primary_key=True)
    network_name = db.Column(db.String(20), primary_key=True)
    value = db.Column(db.String(255))
    type = db.Column(db.String(20))
    expires = db.Column(db.DateTime)

class DbTemporaryMigrationWallet(db.Model):
    __tablename__ = "temporary_migration_wallets"

    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(64), nullable=False, unique=True)
    network = db.Column(db.String(16), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())