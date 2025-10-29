import time
import socket
import shutil
from app.logging import logger
from app.config import config
from app.wallet import BTCWallet
from app.models import DbWallet, db, DbCacheVars
from app.lib.services.services import Service
from os import environ
import shutil
import requests
from sqlalchemy import exists
from decimal import Decimal
from pathlib import Path
from datetime import datetime
import subprocess
import time
import os
import secrets, string

def gen_password(length=32):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.<>/?"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

SRC = "/root/.bitcoin/shkeeper/wallet.dat"
DST = "/app/wallet.dat"
try:
    shutil.copy(SRC, DST)
    print(f"Copied {SRC} → {DST}")
except FileNotFoundError:
    print(f"{SRC} not found, skipping copy")
except PermissionError:
    print(f"Permission denied copying {SRC} → {DST}")

DATADIR = "/app"
WALLET = "wallet.dat"
RPC_USER = gen_password(32)
RPC_PASSWORD = gen_password(32)
RPC_PORT = "18332"
DUMP_FILE = "keys.txt"

os.makedirs(DATADIR, exist_ok=True)
# wallet_path = os.path.join(DATADIR, WALLET)

rpc_bind = "0.0.0.0"
# rpc_bind = socket.gethostbyname(socket.gethostname()) or "127.0.0.1"

bitcoind_cmd = [
    "bitcoind",
    f"-datadir={DATADIR}",
    "-server",
    # f"-{config['BTC_NETWORK']}",
    # "-rpcallowip=127.0.0.1",
    "-rpcallowip=0.0.0.0/0",
    f"-rpcbind={rpc_bind}",
    f"-rpcport={RPC_PORT}",
    f"-rpcuser={RPC_USER}",
    f"-rpcpassword={RPC_PASSWORD}",
    f"-walletdir={DATADIR}",
    "-connect=0",
    "-disablewallet=0",
    "-deprecatedrpc=addresses",
    "-printtoconsole",
    "-daemon=0",
    "-persistmempool=0",
    "-rebroadcast=0",
    "-debug=1",
    "-logips=1",
    "-loglevelalways=1",

]

def handle_event(transaction):        
    logger.info(f'new transaction: {transaction!r}')

def gethost():
    return f"{rpc_bind}:{RPC_PORT}"
    # return "127.0.0.1:18332"

def get_rpc_credentials():
    username = RPC_USER
    password = RPC_PASSWORD
    return (username, password)

def build_rpc_request(method, *params):
    return {"jsonrpc": "1.0", "id": "shkeeper", "method": method, "params": params}

def get_legacy_main_key():
    dump_file = Path("keys.txt")
    main_key = None
    privkeys = {}
    with dump_file.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("# extended private masterkey:"):
                main_key = line.split(":")[1].strip()
            elif line and not line.startswith("#"):
                parts = line.split()
                priv = parts[0]
                if "# addr=" in line:
                    addr = line.split("# addr=")[1].split()[0]
                    privkeys[addr] = priv
    return main_key

def is_descriptor():
    try:
        response = requests.post(
            "http://" + gethost(),
            auth=get_rpc_credentials(),
            json=build_rpc_request("getwalletinfo"),
        ).json()
        get_wallet_info = response["result"]
        descriptor = get_wallet_info['descriptors']
    except requests.exceptions.RequestException:
        descriptor = False
    return descriptor

def list_legacy_address():
    try:
        response = requests.post(
            "http://" + gethost(),
            auth=get_rpc_credentials(),
            json=build_rpc_request("listreceivedbyaddress", 0, True),
        ).json()
        addresses = response["result"]
    except requests.exceptions.RequestException:
        addresses = False
    return addresses

def time_wallet_created():
    try:
        response = requests.post(
            "http://" + gethost(),
            auth=get_rpc_credentials(),
            json=build_rpc_request("getwalletinfo"),
        ).json()
        list_transaction = response["result"]
    except requests.exceptions.RequestException:
        list_transaction = False
    return list_transaction.get("birthtime") or list_transaction.get("keypoololdest")

def get_descriptors():
    try:
        response = requests.post(
            "http://" + gethost(),
            auth=get_rpc_credentials(),
            json=build_rpc_request("listdescriptors", True),
        ).json()
        get_descriptors = response["result"]
    except requests.exceptions.RequestException:
        get_descriptors = False
    return get_descriptors

def get_main_key(descriptors):
    last_desc = descriptors['descriptors'][-1]['desc']
    wif = last_desc.split('(')[1].split(')')[0].replace('/*','')
    master_key = wif.split('/')[0]
    return master_key

def get_quantity_generated_adresses(descriptors):
    descriptors = descriptors['descriptors']
    quantity_generated_adresses = len(['descriptors'])
    return quantity_generated_adresses + 10

def get_legacy_quantity_generated_adresses(list_addreses):
    quantity_generated_adresses = len(list_addreses)
    return quantity_generated_adresses + 10

def find_closest_block_by_timestamp(target_timestamp):
    srv = Service(config['BTC_NETWORK'])
    start_height = 0
    end_height = BTCWallet().get_last_block_number()
    closest_block = None
    closest_diff = float('inf')
    while start_height <= end_height:
        mid = (start_height + end_height) // 2
        block = srv.getblock(mid, 0).as_dict()
        ts = block['timestamp']
        diff = abs(ts - target_timestamp)
        if diff < closest_diff:
            closest_diff = diff
            closest_block = block
        if ts < target_timestamp:
            start_height = mid + 1
        elif ts > target_timestamp:
            end_height = mid - 1
        else:
            return block
    return closest_block

def generate_addresses(btc_wallet, current_index_path, quantity_generated_addresses, witness_type='segwit'):
    for address_index in range(quantity_generated_addresses):
        path = f"m/84'/{current_index_path}'/0'/0/{address_index}"
        change_path = f"m/84'/{current_index_path}'/0'/1/{address_index}"
        btc_wallet.keys_for_path(path=change_path, witness_type=witness_type)
        keys = btc_wallet.keys_for_path(path=path, witness_type=witness_type)
        addr = keys[0].address
        yield path, addr

def migrate_addreses():
    time.sleep(20)
    bitcoind_proc = subprocess.Popen(bitcoind_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(20)
    from app import create_app
    app = create_app()
    app.app_context().push()
    btc_wallet = BTCWallet()
    wallet = btc_wallet.wallet()
    from app.lib.wallets import Wallet, DbWallet, wallets_list, wallet_delete, db

    if is_descriptor():
        print("is_descriptor")
        descriptor = get_descriptors()
        wif = get_main_key(descriptor)
        for wallet in wallets_list():
            wallet_name = wallet['name']
            print(wallet_name)
            wallet_delete(wallet_name, force=True)
        btc_wallet = Wallet.create('Wallet7', wif, witness_type='segwit', purpose='84')
        # transactions = list_transactions()
        # save_sent_addresses(transactions)
        legacy_address = list_legacy_address()
        quantity_generated_adresses = get_legacy_quantity_generated_adresses(legacy_address)

        db_wallet = db.session.query(DbWallet).first()
        db_wallet.generated_address_count = quantity_generated_adresses
        db_wallet.migrated = True
        db.session.commit()

        current_index_path = btc_wallet.current_index_path()
        for path, addr in generate_addresses(btc_wallet, current_index_path, quantity_generated_addresses=quantity_generated_adresses):
            print(f"Path: {path} → Address: {addr}")
        # for address_index in range(quantity_generated_adresses):
        #     path = f"m/84'/{current_index_path}'/0'/0/{address_index}"
        #     change_path = f"m/84'/{current_index_path}'/0'/1/{address_index}"
        #     btc_wallet.keys_for_path(path=change_path, witness_type='segwit')
        #     keys = btc_wallet.keys_for_path(path=path, witness_type='segwit') 
        #     addr = keys[0].address
        #     print(f"Path: {path} → Address: {addr}")
    else:
        bitcoind_proc.terminate()
        bitcoind_proc.wait()
        bitcoind_cmd.append(f"-wallet={WALLET}")
        bitcoind_proc = subprocess.Popen(bitcoind_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(20)

        print("legacy")
        dump_cmd = [
            "bitcoin-cli",
            f"-datadir={DATADIR}",
            f"-rpcuser={RPC_USER}",
            f"-rpcpassword={RPC_PASSWORD}",
            f"-rpcport={RPC_PORT}",
            f"-rpcwallet={WALLET}",
            "dumpwallet",
            os.path.join(DATADIR, DUMP_FILE)
        ]
        subprocess.run(dump_cmd, check=True)
        print(f"Wallet dumped to {DUMP_FILE}")
        wif = get_legacy_main_key()
        for wallet in wallets_list():
            wallet_name = wallet['name']
            print(wallet_name)
            wallet_delete(wallet_name, force=True)
        btc_wallet = Wallet.create('Wallet7', wif, witness_type='segwit', purpose='0')
        print(list_legacy_address())
        legacy_address = list_legacy_address()
        legacy_quantity_generated_adresses = get_legacy_quantity_generated_adresses(legacy_address)
        db_wallet = db.session.query(DbWallet).first()
        db_wallet.generated_address_count = legacy_quantity_generated_adresses
        db_wallet.migrated = True
        db.session.commit()
        for address_index in range(legacy_quantity_generated_adresses):
            path = f"m/0'/0/{address_index}"
            path_old = f"m/0'/1/{address_index}"
            btc_wallet.keys_for_path(path=path_old, witness_type='segwit', account_id=0, network=config['BTC_NETWORK'], number_of_keys=2) 
            keys = btc_wallet.keys_for_path(path=path, account_id=0, network=config['BTC_NETWORK'], witness_type='segwit', number_of_keys=2) 
            addr = keys[0].address
            print(f"Path: {path} → Address: {addr}")

    target_timestamp = time_wallet_created()
    closest = find_closest_block_by_timestamp(target_timestamp)
    # btc_wallet.session.query(DbCacheVars).filter_by(varname='last_scanned_block',network_name=btc_wallet.network.name).update({"value": str('4706400')})
    print("closest[height]")
    print(closest['height'])
    record = btc_wallet.session.query(DbCacheVars)\
      .filter_by(varname='last_scanned_block', network_name=btc_wallet.network.name)\
      .first()

    if record:
        btc_wallet.session.delete(record)
        btc_wallet.session.commit()

    new_var = DbCacheVars(
        varname='last_scanned_block',
        network_name=btc_wallet.network.name,
        value=str(closest['height'] - 20),
        type='int',
        expires=None
    )
    btc_wallet.session.add(new_var)
    btc_wallet.session.commit()
    bitcoind_proc.terminate()
    bitcoind_proc.wait()
    paths_to_remove = {
        "files": ["db.log", ".walletlock", ".lock", "debug.log", "settings.json", "keys.txt", "peers.dat", "fee_estimates.dat", "mempool.dat", "banlist.json"],
        "dirs": ["blocks", "chainstate", "testnet3"]
    }
    for filename in paths_to_remove["files"]:
        path = os.path.join(DATADIR, filename)
        if os.path.exists(path):
            os.remove(path)

    for dirname in paths_to_remove["dirs"]:
        path = os.path.join(DATADIR, dirname)
        if os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True)
