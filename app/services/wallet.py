import time

import sqlalchemy

from app.lib.values import Value
from app.lib.wallets import Wallet, WalletKey, WalletError
from app.unlock_acc import get_account_password
from app.utils import BTCUtils, DOGEUtils, LTCUtils

from ..config import COIN, config
from ..logging import logger
from ..models import DbWallet, db
from . import store as store_service

_WALLET_GENERATE_RETRIES = 3

_ADDRESS_VALIDATORS = {
    "BTC": BTCUtils.is_valid_btc_address,
    "LTC": LTCUtils.is_valid_ltc_address,
    "DOGE": DOGEUtils.is_valid_doge_address,
}


class WalletService:
    def current_wallet(self, store_id=None):
        name = self.wallet_name(store_id=store_id)
        if not name:
            return None
        return Wallet(name)

    def wallet(self, store_id=None):
        if not get_account_password():
            return
        name = self.wallet_name(store_id=store_id)
        if not name:
            return
        return Wallet(name)

    def db_wallet(self, store_id=None, for_update=False):
        return store_service.store_wallet(store_id, for_update=for_update)

    def all_hd_wallets(self):
        if not get_account_password():
            return []
        rows = (
            db.session.query(DbWallet)
            .filter(DbWallet.parent_id.is_(None))
            .order_by(DbWallet.id.asc())
            .all()
        )
        wallets = []
        for row in rows:
            try:
                wallets.append(Wallet(row.name))
            except Exception:
                logger.exception("Failed to load wallet %s", row.name)
                raise
        return wallets

    def scan_block(self, block_hash, current_block_height):
        wallets = self.all_hd_wallets()
        if not wallets:
            raise RuntimeError(f"No HD wallets to scan for block {block_hash}")
        Wallet.scan_block(wallets, block=block_hash, current_block_height=current_block_height)

    def wallet_name(self, store_id=None):
        if not get_account_password():
            return
        store_id = store_service.parse_store_id(store_id)
        dbw = self.db_wallet(store_id)
        if dbw is None and store_id == store_service.DEFAULT_STORE_ID:
            dbw = self._ensure_db_wallet(store_id)
        return dbw.name if dbw else None

    def witness_type(self):
        return 'legacy' if COIN == "DOGE" else 'segwit'

    def generate_wallet_name(self, store_id=None):
        return f"store-{store_service.parse_store_id(store_id)}"

    def get_store_balance(self, store_id=None):
        store_id = store_service.parse_store_id(store_id)
        if not get_account_password():
            raise PermissionError("Wallet is locked or encryption password not available")
        wallet = self.wallet(store_id=store_id)
        if not wallet:
            return Value.from_satoshi(0).value
        return Value.from_satoshi(wallet.balance()).value

    def get_dump(self, store_id=None, scoped=False):
        logger.warning('Start dumping wallets')
        if not get_account_password():
            raise PermissionError("Wallet is locked or encryption password not available")
        if scoped:
            store_id = store_service.parse_store_id(store_id, required=True)
        else:
            store_id = store_service.parse_store_id(
                store_id if store_id is not None else store_service.DEFAULT_STORE_ID
            )
        if store_id != store_service.DEFAULT_STORE_ID:
            raise PermissionError("Wallet dump is only allowed for the default store")
        dump = {}
        rows = (
            db.session.query(DbWallet)
            .filter(DbWallet.parent_id.is_(None))
            .order_by(DbWallet.id.asc())
            .all()
        )
        for row in rows:
            if row.store_id != store_id:
                continue
            try:
                wallet = Wallet(row.name)
            except Exception:
                logger.exception("Failed to load wallet %s", row.name)
                raise
            for key in wallet.keys():
                if not key.address:
                    continue
                wif = key.wif
                if isinstance(wif, bytes):
                    wif = wif.decode('utf-8')
                dump[key.address] = {
                    'public_address': key.address,
                    'private': key.key_private.hex() if key.key_private else None,
                    'wif': wif,
                    'public': key.key_public.hex() if key.key_public else None,
                }
        return dump

    def get_all_accounts(self, store_id=None):
        wallet = self.current_wallet(store_id=store_id)
        if not wallet:
            return []
        current_index_path = wallet.current_index_path()
        segwit_prefix = f"m/84'/{current_index_path}'/0'/0/"
        accounts = []
        for key in wallet.keys():
            if not key.address:
                continue
            path = key.path or ""
            if not (
                path.startswith(segwit_prefix) or path.startswith("m/0'/0'/")
            ):
                continue
            accounts.append(key.address)
        return accounts

    def first_store_address(self, store_id=None):
        store_id = store_service.parse_store_id(store_id)
        keys = store_service.store_address_keys(store_id)
        receive = next((key for key in keys if key.change == 0), None)
        key = receive or (keys[0] if keys else None)
        return key.address if key else ""

    def generate_address(self, store_id=None):
        logger.warning("generate_address started for coin=%s network=%s", COIN, config['COIN_NETWORK'])
        store_id = store_service.parse_store_id(store_id)
        wallet, address_index = self._prepare_wallet_for_new_address(store_id)
        if COIN == "DOGE":
            return self._generate_doge_address(store_id)
        return self._generate_hd_address(wallet, address_index)

    def is_valid_address(self, address: str) -> bool:
        validator = _ADDRESS_VALIDATORS.get(COIN)
        if validator is None:
            raise ValueError(f"Unknown coin type: {COIN}")
        return validator(address)

    def _create_wallet(self, store_id=None, wallet_name=None):
        store_id = store_service.parse_store_id(store_id)
        try:
            wallet = Wallet.create(
                wallet_name or self.generate_wallet_name(store_id),
                network=config['COIN_NETWORK'],
                witness_type=self.witness_type(),
                scheme="single" if COIN == "DOGE" else "bip32",
                encoding="base58" if COIN == "DOGE" else "bech32",
                store_id=store_id,
                generated_address_count=1,
            )
            return wallet, True
        except (sqlalchemy.exc.IntegrityError, WalletError) as exc:
            db.session.rollback()
            if isinstance(exc, WalletError) and "already exists" not in str(exc):
                raise
            logger.warning("Wallet already exists for store_id=%s", store_id)
            existing = self.db_wallet(store_id)
            if existing is None:
                raise
            return Wallet(existing.name), False

    def _ensure_db_wallet(self, store_id=None):
        store_id = store_service.parse_store_id(store_id)
        for attempt in range(1, _WALLET_GENERATE_RETRIES + 1):
            try:
                self.generate_address(store_id=store_id)
                db.session.commit()
                return self.db_wallet(store_id)
            except sqlalchemy.exc.SQLAlchemyError as e:
                db.session.rollback()
                wait_time = 2 * attempt
                logger.warning(
                    "SQLAlchemy error detected: %s. Retrying in %ss (attempt %s)",
                    e,
                    wait_time,
                    attempt,
                )
                time.sleep(wait_time)
        raise RuntimeError(
            f"Could not generate wallet after {_WALLET_GENERATE_RETRIES} attempts due to repeated errors"
        )

    def _prepare_wallet_for_new_address(self, store_id):
        db_wallet = self.db_wallet(store_id, for_update=True)
        if db_wallet is None:
            wallet, created = self._create_wallet(store_id)
            if created:
                logger.warning("Wallet created for %s store_id=%s", COIN, store_id)
                return wallet, 1
            db_wallet = self.db_wallet(store_id, for_update=True)
            if db_wallet is None:
                raise RuntimeError(f"Failed to create wallet for store_id={store_id}")

        wallet = Wallet(db_wallet.name)
        address_index = (db_wallet.generated_address_count or 0) + 1
        db_wallet.generated_address_count = address_index
        db.session.commit()
        logger.warning(
            "generate_address %s: wallet=%s store_id=%s purpose=%s migrated=%s index=%s",
            COIN,
            db_wallet.name,
            db_wallet.store_id,
            wallet.purpose,
            db_wallet.migrated,
            address_index,
        )
        return wallet, address_index

    def _generate_doge_address(self, store_id):
        from app.lib.keys import HDKey

        new_key = HDKey(network=config['COIN_NETWORK'], witness_type='legacy')
        db_wallet = self.db_wallet(store_id)
        wallet_key = WalletKey.from_key(
            name=f"{db_wallet.name}_{db_wallet.generated_address_count}",
            wallet_id=db_wallet.id,
            session=db.session,
            key=new_key,
        )
        db.session.commit()
        return wallet_key.address

    def _generate_hd_address(self, wallet, address_index):
        if wallet.purpose == 0:
            path = f"m/0'/0/{address_index}"
            path_old = f"m/0'/1/{address_index}"
            keys = self._keys_for_path(wallet, path)
            self._keys_for_path(wallet, path_old)
        else:
            current_index_path = wallet.current_index_path()
            path = f"m/84'/{current_index_path}'/0'/0/{address_index}"
            change_path = f"m/84'/{current_index_path}'/0'/1/{address_index}"
            self._keys_for_path(wallet, change_path)
            keys = self._keys_for_path(wallet, path)

        keys_count = len(keys) if keys else 0
        logger.warning("generate_address %s: path=%s keys_count=%s", COIN, path, keys_count)
        if not keys:
            logger.warning(f"No keys returned for path {path}")
            return None

        address = keys[0].address
        logger.warning("generate_address finished for coin=%s address=%s", COIN, address)
        return address

    def _keys_for_path(self, wallet, path):
        return wallet.keys_for_path(
            path=path,
            witness_type=self.witness_type(),
            account_id=0,
            network=config['COIN_NETWORK'],
        )
