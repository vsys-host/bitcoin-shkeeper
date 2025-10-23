import os
import json
import decimal
import random
import uuid
import logging
from app.btc_utils import BTCUtils
from app.lib.wallets import Wallet
from app.lib.services.services import Service
# from app.lib.encoding import addr_bech32_to_pubkeyhash, addr_base58_to_pubkeyhash
import requests
from flask import current_app as app
from .config import config
from .models import DbWallet, DbTransaction, db
from app.lib.values import Value, decimal_value_to_satoshi
from .logging import logger

WALLETS_DIRECTORY = "wallets"

class BTCWallet():
    def __init__(self) -> None:
        self.client = config["FULLNODE_URL"]
    
    def get_tx_by_txid(self, txid_hex):
      txid_bytes = bytes.fromhex(txid_hex)
      return db.session.query(DbTransaction).filter_by(txid=txid_bytes).one_or_none()

    def get_transaction(self, txid_hex):
        tx = self.get_tx_by_txid(txid_hex)
        if not tx:
            return None
        balance_satoshi = 0
        details = []

        for out in tx.outputs:
            addr = out.address
            spent = getattr(out, 'spent', False)
            if not spent:
                balance_satoshi += out.value
                val = Value.from_satoshi(balance_satoshi).value
                details.append({
                    'address': addr,
                    'amount': val,
                    'category': 'receive'
                })
        # for inp in tx.inputs:
        #     # prev_txid = inp.prev_txid
        #     # output_n = inp.output_n
        #     # prev_tx = self.get_tx_by_txid(prev_txid)
        #     # if prev_tx:
        #     addr = inp.address
        #     balance_satoshi -= inp.value
        #     val = Value.from_satoshi(balance_satoshi).value
        #     details.append({
        #         'address': addr,
        #         'amount': val,
        #         'category': 'send'
        #     })

        return {
            'txid': txid_hex,
            'balance': balance_satoshi / 1e8,
            'confirmations': getattr(tx, 'confirmations', 0),
            'details': details
        }

    def delta_synced_block(self):
        srv = self._build_service()    
        last_number =  srv.synced_status()
        return last_number

    def get_last_block_number(self):
        srv = self._build_service()    
        last_number =  srv.blockcount()
        return last_number

    def _build_service(self):
        return Service(config['BTC_NETWORK'])
    
    def get_transaction_price(self):
        srv = self._build_service()
        network_fee = srv.estimatefee()
        network_fee_btc = Value.from_satoshi(network_fee).value

        return network_fee_btc

    def get_fee_deposit_account(self):
        wallet = self.current_wallet()
        if not wallet:
            wallet_name = self.generate_wallet_name()
            wallet = Wallet.create(wallet_name, network=config['BTC_NETWORK'], witness_type='segwit')
        
        current_index_path = wallet.current_index_path()
        # add code
        keys = wallet.keys_for_path(path=f"m/84'/{current_index_path}'/0'/0/0")
        # keys = wallet.keys_for_path(path="m/0'/0/0")

        return keys[0].address

    def current_wallet(self):
        wallet_name = self.wallet_name()
        return Wallet(wallet_name)

    def wallet(self):
       wallet_name = self.wallet_name()
       return  Wallet(wallet_name)

    def get_deposit_account_balance(self):
        amount = self.wallet().balance()
        amount_btc = Value.from_satoshi(amount).value
        return amount_btc

    def scan(self):
        w = self.wallet()
        if not w:
            self.generate_address()
            w = self.wallet()
        w.scan()
    
    def db_wallet(self):
       wallet = db.session.query(DbWallet).first()
       return wallet
    
    def wallet_name(self):
        dbw = self.db_wallet()
        if dbw is None:
            self.generate_address()
            dbw = self.db_wallet()
        return dbw.name

    def get_dump(self):
        logger.warning('Start dumping wallets')
        all_keys = self.current_wallet().keys()
        all_wallets = {}
        for key in all_keys:
            all_wallets[key.address] = {
                'public_address': key.address,
                'private': key.private.hex(),
                'public': key.public.hex()
            }
        return all_wallets

    def get_all_addresses(self):
        address_list = []
        tries = 3
        for i in range(tries):
            try:
                wallet_list = Wallet.query.all()
            except:
                if i < tries - 1: # i is zero indexed
                    db.session.rollback()
                    continue
                else:
                    db.session.rollback()
                    raise Exception(f"There was exception during query to the database, try again later")
            break
        for wallet in wallet_list:
            address_list.append(wallet.pub_address)
        return address_list

    def get_all_accounts(self):
      wallet = self.current_wallet()
      current_index_path = wallet.current_index_path()
      addresses = [
          key.address for key in wallet.keys()
          if key.path.startswith(f"m/84'/{current_index_path}'/0'/0/") or key.path.startswith("m/0'/0'/")
      ]
      return addresses

    def generate_wallet_name(self):
        adjectives = ["brave", "lucky", "silent", "quick", "happy", "clever", "bold", "wise", "calm", "fierce"]
        animals = ["fox", "tiger", "eagle", "wolf", "panther", "lion", "hawk", "bear", "cobra", "rhino"]
        adj = random.choice(adjectives)
        animal = random.choice(animals)
        unique = uuid.uuid4().hex[:6] 
        return f"{adj}-{animal}-{unique}"

    def generate_address(self):
        if db.session.query(DbWallet).count() == 0:
            wallet_name = self.generate_wallet_name()
            wallet = Wallet.create(wallet_name, network=config['BTC_NETWORK'], witness_type='segwit')
            address_index = 1
            logger.warning("Wallet created")
        else:
            wallet = self.current_wallet()
            db_wallet = self.db_wallet()
            address_index = db_wallet.generated_address_count + 1
            db_wallet.generated_address_count = address_index
            db.session.commit()
            logger.warning("Updated generated_address_count")
        if wallet.purpose == 0:
           path = f"m/0'/0/{address_index}"
           path_old = f"m/0'/1/{address_index}"
           keys = wallet.keys_for_path(path=path, witness_type='segwit', account_id=0, network=config['BTC_NETWORK']) 
           wallet.keys_for_path(path=path_old, witness_type='segwit', account_id=0, network=config['BTC_NETWORK']) 
        else:
            current_index_path = wallet.current_index_path()
            path = f"m/84'/{current_index_path}'/0'/0/{address_index}"
            change_path = f"m/84'/{current_index_path}'/0'/1/{address_index}"
            wallet.keys_for_path(path=change_path, account_id=0, network=config['BTC_NETWORK'], witness_type='segwit')
            keys = wallet.keys_for_path(path=path, account_id=0, network=config['BTC_NETWORK'], witness_type='segwit')
        if not keys:
            logger.warning(f"No keys returned for path {path}")
            return None

        address = keys[0].address
        return address

    def make_multipayout(self, payout_list, btc_fee):
        fee = Value.from_satoshi(btc_fee).value
        payout_results = []
        for payout in payout_list:
            if not self.is_valid_btc_address(payout['dest']):
                raise Exception(f"Address {payout['dest']} is not valid BTC address")

        should_pay = decimal.Decimal('0')

        for payout in payout_list:
            should_pay += decimal.Decimal(str(payout['amount']))

        network_fee_btc = decimal.Decimal(str(self.get_transaction_price()))
        fee = decimal.Decimal(str(fee))
        if network_fee_btc > fee:
            network_fee = decimal_value_to_satoshi(network_fee_btc)
            raise Exception(f"Current fee is {btc_fee} but network fee is {network_fee}")
        network_fee_per_kb = decimal_value_to_satoshi(fee or network_fee_btc)
        total_fee = decimal.Decimal(len(payout_list)) * network_fee_btc
        reserved = decimal.Decimal(str(config['ACCOUNT_RESERVED_AMOUNT']))
        should_pay += total_fee + reserved
        have_crypto = self.get_deposit_account_balance()
        if have_crypto < should_pay:
            raise Exception(
                f"Have not enough crypto on fee account, need {should_pay} have {have_crypto}. "
                f"Please note that {should_pay} includes {reserved} which is reserved by the account "
                f"and network fee for all transactions."
            )
        for payout in payout_list:
            satoshi_amount = decimal_value_to_satoshi(payout['amount'])
            tx = self.current_wallet().send_to(payout['dest'], satoshi_amount, fee_per_kb=network_fee_per_kb)
            try:
                tx.send()
                payout_results.append({
                    "dest": payout['dest'],
                    "amount": float(payout['amount']),
                    "status": "success",
                    "txids": [str(tx)],
                })
            except Exception as e:
                logger.warning(f"Submit failed: {e}")
                payout_results.append({
                    "dest": payout['dest'],
                    "amount": float(payout['amount']),
                    "status": "error",
                    "error": str(e),
                })
        logger.warning(f'payout_results wallets {payout_results}')
        return payout_results

    def is_valid_btc_address(self, address: str) -> bool:
        return BTCUtils.is_valid_btc_address(address)

    # def drain_account(self, destination):
    #     wallet = self.current_wallet()
    #     tx = wallet.sweep(destination)
    #     result = tx.send()
    #     return result
 