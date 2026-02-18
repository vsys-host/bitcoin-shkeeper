import time
import socket
import shutil
from app.logging import logger
from app.config import config, COIN
from app.wallet import CoinWallet
from app.models import DbWallet, db, DbCacheVars, DbDogeMigrationWallet
from app.lib.services.services import Service
from os import environ
import shutil
import requests
from sqlalchemy import exists
from decimal import Decimal
from pathlib import Path
import subprocess
import os
import secrets, string

def gen_password(length=32):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.<>/?"
    return ''.join(secrets.choice(alphabet) for _ in range(length))
    
TMP_DATADIR = "/app/tmp_coin"
WALLET = "wallet.dat"
RPC_USER = gen_password(32)
RPC_PASSWORD = gen_password(32)
if COIN == "BTC":
    RPC_PORT = "18332"
elif COIN == "LTC":
    RPC_PORT = "9332"
elif COIN == "DOGE":
    RPC_PORT = "19332"
else:
    raise ValueError(f"Unsupported coin: {COIN}")
DUMP_FILE = "keys.txt"
rpc_bind = "0.0.0.0"

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

def get_legacy_main_key(tmp_datadir=TMP_DATADIR, dump_file_name="keys.txt"):
    dump_file = Path(tmp_datadir) / dump_file_name
    main_key = None
    privkeys = {}
    if not dump_file.exists():
        raise FileNotFoundError(f"{dump_file} does not exist")
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

def list_unique_wallet_addresses(batch_size=1000):
    addresses = set()
    offset = 0
    while True:
        response = requests.post(
            "http://" + gethost(),
            auth=get_rpc_credentials(),
            json=build_rpc_request(
                "listtransactions",
                "*",
                batch_size,
                offset
            ),
            timeout=30,
        ).json()
        batch = response.get("result", [])
        if not batch:
            break
        for tx in batch:
            addr = tx.get("address")
            if addr:
                addresses.add(addr)
        if len(batch) < batch_size:
            break
        offset += batch_size
    return sorted(addresses)

def save_doge_addresses(session, addresses, network):
    for addr in addresses:
        exists = session.query(DbDogeMigrationWallet.id)\
            .filter_by(address=addr, network=network)\
            .first()
        if exists:
            continue
        session.add(DbDogeMigrationWallet(
            address=addr,
            network=network
        ))

def time_wallet_created():
    configured_time = config.get("TIME_WALLET_CREATED")
    if configured_time:
        try:
            return int(configured_time)
        except (TypeError, ValueError):
            logger.warning("Invalid TIME_WALLET_CREATED value in config: %r", configured_time)
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

def find_closest_block_by_timestamp(target_timestamp, max_diff_seconds=86400):
    srv = Service(config['COIN_NETWORK'])
    wallet = CoinWallet()
    start_height = 0
    end_height = wallet.get_last_block_number()
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
            closest_block = block
            closest_diff = 0
            break
    if closest_block is None:
        raise ValueError("No block found.")
    if closest_diff > max_diff_seconds:
        raise ValueError(
            f"Closest block is too far from wallet creation date: {closest_diff} seconds"
        )
    return closest_block

def generate_addresses(coin_wallet, current_index_path, quantity_generated_addresses, witness_type='segwit'):
    for address_index in range(quantity_generated_addresses):
        path = f"m/84'/{current_index_path}'/0'/0/{address_index}"
        change_path = f"m/84'/{current_index_path}'/0'/1/{address_index}"
        coin_wallet.keys_for_path(path=change_path, witness_type=witness_type)
        keys = coin_wallet.keys_for_path(path=path, witness_type=witness_type)
        addr = keys[0].address
        yield path, addr

def mark_wallet_migrated(session, coin_wallet, height):
    network = coin_wallet.network.name
    value = str(height - 20)
    record = session.query(DbCacheVars).filter_by(varname="last_scanned_block", network_name=network).first()
    if record:
        record.value = value
    else:
        session.add(DbCacheVars(varname="last_scanned_block", network_name=network, value=value, type="int", expires=None))
    db_wallet = session.query(DbWallet).first()
    if db_wallet:
        db_wallet.migrated = True
        print(f"migrated updated")
        session.add(db_wallet)
    session.commit()

def list_all_wallet_addresses():
    addresses = set()
    try:
        # 1. listreceivedbyaddress
        resp1 = requests.post(
            "http://" + gethost(),
            auth=get_rpc_credentials(),
            json=build_rpc_request("listreceivedbyaddress", 0, True),
        ).json()
        for item in resp1.get("result", []):
            addresses.add(item["address"])
        # 2. listaddressgroupings
        resp2 = requests.post(
            "http://" + gethost(),
            auth=get_rpc_credentials(),
            json=build_rpc_request("listaddressgroupings"),
        ).json()
        for group in resp2.get("result", []):
            for addr_info in group:
                addresses.add(addr_info[0])
        # 3. getaddressesbylabel
        resp3 = requests.post(
            "http://" + gethost(),
            auth=get_rpc_credentials(),
            json=build_rpc_request("getaddressesbylabel", ""),
        ).json()
        if resp3.get("result"):
            for addr in resp3["result"].keys():
                addresses.add(addr)
    except requests.exceptions.RequestException:
        pass
    return list(addresses)

def get_privkey(address):
    try:
        response = requests.post(
            "http://" + gethost(),
            auth=get_rpc_credentials(),
            json=build_rpc_request("dumpprivkey", address)
        ).json()
        if response.get("error"):
            return {"error": response["error"]}
        return {"address": address, "privkey": response["result"]}
    except Exception as e:
        return {"error": str(e)}

def migrate_addreses():
    if COIN == 'BTC':
        _migrate_btc()
    elif COIN == 'LTC':
        _migrate_ltc()
    elif COIN == 'DOGE':
        _migrate_doge()
    else:
        raise ValueError(f"Unsupported coin {COIN}")

def _migrate_btc():
    SRC = config['WALLET_DAT_PATH']
    os.makedirs(TMP_DATADIR, exist_ok=True)
    DST = os.path.join(TMP_DATADIR, "wallet.dat")
    try:
        shutil.copy(SRC, DST)
        print(f"Copied {SRC} → {DST}")
    except FileNotFoundError:
        print(f"{SRC} not found, skipping copy")
    except PermissionError:
        print(f"Permission denied copying {SRC} → {DST}")

    bitcoind_cmd = [
        "bitcoind",
        f"-datadir={TMP_DATADIR}",
        "-server",
        "-rpcallowip=0.0.0.0/0",
        f"-rpcbind={rpc_bind}",
        f"-rpcport={RPC_PORT}",
        f"-rpcuser={RPC_USER}",
        f"-rpcpassword={RPC_PASSWORD}",
        f"-walletdir={TMP_DATADIR}",
        "-connect=0",
        "-disablewallet=0",
        "-deprecatedrpc=addresses",
        "-printtoconsole",
        "-daemon=0",
        "-persistmempool=0",
        # "-rebroadcast=0",
        "-walletbroadcast=0",
        "-debug=1",
        "-logips=1",
        "-loglevelalways=1",
    ]
    time.sleep(20)
    bitcoind_proc = subprocess.Popen(bitcoind_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(20)
    from app import create_app
    app = create_app()
    app.app_context().push()
    coin_wallet = CoinWallet()
    from app.lib.wallets import Wallet, DbWallet, wallets_list, wallet_delete, db
    try:
        target_timestamp = time_wallet_created()
        if not target_timestamp:
            raise RuntimeError("Wallet creation date not found. Aborting migration.")
        closest = find_closest_block_by_timestamp(target_timestamp)
        print(f"Closest block height: {closest['height']}")
    except Exception as e:
        print(f"Migration migrate_addresses failed: {e}")
        if bitcoind_proc:
            print("Terminate bitcoind_proc")
            bitcoind_proc.terminate()
            bitcoind_proc.wait()
        if os.path.exists(TMP_DATADIR):
            shutil.rmtree(TMP_DATADIR, ignore_errors=True)
            print(f"Removed temporary directory {TMP_DATADIR}")
        raise RuntimeError(f"Migration failed: {type(e).__name__}: {e}") from e

    if is_descriptor():
        print("descriptor")
        descriptor = get_descriptors()
        wif = get_main_key(descriptor)
        for wallet in wallets_list():
            wallet_name = wallet['name']
            print(wallet_name)
            wallet_delete(wallet_name, force=True)
        coin_wallet = Wallet.create('Wallet7', wif, witness_type='segwit', purpose='84')
        legacy_address = list_legacy_address()
        quantity_generated_adresses = get_legacy_quantity_generated_adresses(legacy_address)

        db_wallet = db.session.query(DbWallet).first()
        db_wallet.generated_address_count = quantity_generated_adresses
        db.session.commit()

        current_index_path = coin_wallet.current_index_path()
        for path, addr in generate_addresses(coin_wallet, current_index_path, quantity_generated_addresses=quantity_generated_adresses):
            print(f"Path: {path} → Address: {addr}")
    else:
        bitcoind_proc.terminate()
        bitcoind_proc.wait()
        bitcoind_cmd.append(f"-wallet={WALLET}")
        bitcoind_proc = subprocess.Popen(bitcoind_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(20)

        print("legacy")
        dump_cmd = [
            "bitcoin-cli",
            f"-datadir={TMP_DATADIR}",
            f"-rpcuser={RPC_USER}",
            f"-rpcpassword={RPC_PASSWORD}",
            f"-rpcport={RPC_PORT}",
            f"-rpcwallet={WALLET}",
            "dumpwallet",
            os.path.join(TMP_DATADIR, DUMP_FILE)
        ]
        subprocess.run(dump_cmd, check=True)
        print(f"Wallet dumped to {DUMP_FILE}")
        wif = get_legacy_main_key()
        for wallet in wallets_list():
            wallet_name = wallet['name']
            print(wallet_name)
            wallet_delete(wallet_name, force=True)
        coin_wallet = Wallet.create('Wallet7', wif, witness_type='segwit', purpose='0')
        print(list_legacy_address())
        legacy_address = list_legacy_address()
        legacy_quantity_generated_adresses = get_legacy_quantity_generated_adresses(legacy_address)
        db_wallet = db.session.query(DbWallet).first()
        db_wallet.generated_address_count = legacy_quantity_generated_adresses
        db.session.commit()
        for address_index in range(legacy_quantity_generated_adresses):
            path = f"m/0'/0/{address_index}"
            path_old = f"m/0'/1/{address_index}"
            coin_wallet.keys_for_path(path=path_old, witness_type='segwit', account_id=0, network=config['COIN_NETWORK'], number_of_keys=2)
            keys = coin_wallet.keys_for_path(path=path, account_id=0, network=config['COIN_NETWORK'], witness_type='segwit', number_of_keys=2)
            addr = keys[0].address
            print(f"Path: {path} → Address: {addr}")
    session = db.session
    mark_wallet_migrated(session, coin_wallet, closest["height"])
    if bitcoind_proc:
        bitcoind_proc.terminate()
        bitcoind_proc.wait()

    if os.path.exists(TMP_DATADIR):
        shutil.rmtree(TMP_DATADIR, ignore_errors=True)
        print(f"Removed temporary directory {TMP_DATADIR}")

def _migrate_ltc():
    SRC = config['WALLET_DAT_PATH']
    os.makedirs(TMP_DATADIR, exist_ok=True)
    DST = os.path.join(TMP_DATADIR, "wallet.dat")
    try:
        shutil.copy(SRC, DST)
        print(f"Copied {SRC} → {DST}")
    except FileNotFoundError:
        print(f"{SRC} not found, skipping copy")
    except PermissionError:
        print(f"Permission denied copying {SRC} → {DST}")
    litecoind_cmd = [
        "litecoind",
        f"-datadir={TMP_DATADIR}",
        "-server",
        # f"-{config['COIN_NETWORK']}",
        # "-rpcallowip=127.0.0.1",
        "-rpcallowip=0.0.0.0/0",
        f"-rpcbind={rpc_bind}",
        f"-rpcport={RPC_PORT}",
        f"-rpcuser={RPC_USER}",
        f"-rpcpassword={RPC_PASSWORD}",
        f"-walletdir={TMP_DATADIR}",
        f"-wallet={WALLET}",
        "-connect=0",
        "-disablewallet=0",
        "-deprecatedrpc=addresses",
        "-printtoconsole",
        "-walletbroadcast=0",
        "-daemon=0"
    ]
    logger.info('migrate_addreses')
    print("migrate_addreses")
    time.sleep(20)
    litecoind_proc = subprocess.Popen(litecoind_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    time.sleep(20)
    print("litecoind_proc")
    from app import create_app
    app = create_app()
    app.app_context().push()
    from app.lib.wallets import Wallet, DbWallet, wallets_list, wallet_delete, db
    try:
        target_timestamp = time_wallet_created()
        if not target_timestamp:
            raise RuntimeError("Wallet creation date not found. Aborting migration.")
        closest = find_closest_block_by_timestamp(target_timestamp)
        print(f"Closest block height: {closest['height']}")
    except Exception as e:
        print(f"Migration migrate_addresses failed: {e}")
        if litecoind_proc:
            print("Terminate litecoind_proc")
            litecoind_proc.terminate()
            litecoind_proc.wait()
        if os.path.exists(TMP_DATADIR):
            shutil.rmtree(TMP_DATADIR, ignore_errors=True)
            print(f"Removed temporary directory {TMP_DATADIR}")
        raise RuntimeError(f"Migration failed: {type(e).__name__}: {e}") from e

    print("legacy")
    print("time_wallet_created")
    print(time_wallet_created())
    dump_cmd = [
        "litecoin-cli",
        f"-datadir={TMP_DATADIR}",
        f"-rpcuser={RPC_USER}",
        f"-rpcpassword={RPC_PASSWORD}",
        f"-rpcport={RPC_PORT}",
        f"-rpcwallet={WALLET}",
        "dumpwallet",
        os.path.join(TMP_DATADIR, DUMP_FILE)
    ]
    subprocess.run(dump_cmd, check=True)
    print(f"Wallet dumped to {DUMP_FILE}")
    wif = get_legacy_main_key()
    print("wif")
    print(wif)
    for wallet in wallets_list():
        wallet_name = wallet['name']
        print(wallet_name)
        wallet_delete(wallet_name, force=True)
    coin_wallet = Wallet.create('Wallet7', wif, witness_type='segwit', purpose='0')
    print(list_legacy_address())

    legacy_address = list_legacy_address()
    legacy_quantity_generated_adresses = get_legacy_quantity_generated_adresses(legacy_address)
    db_wallet = db.session.query(DbWallet).first()
    db_wallet.generated_address_count = legacy_quantity_generated_adresses
    db.session.commit()
    for address_index in range(legacy_quantity_generated_adresses):
        path = f"m/0'/0/{address_index}"
        path_old = f"m/0'/1/{address_index}"
        coin_wallet.keys_for_path(path=path_old, witness_type='segwit', account_id=0, network=config['COIN_NETWORK'], number_of_keys=2)
        keys = coin_wallet.keys_for_path(path=path, account_id=0, network=config['COIN_NETWORK'], witness_type='segwit', number_of_keys=2) 
        addr = keys[0].address
        print(f"Path: {path} → Address: {addr}")
    
    session = db.session
    mark_wallet_migrated(session, coin_wallet, closest["height"])

    if litecoind_proc:
        litecoind_proc.terminate()
        litecoind_proc.wait()

    if os.path.exists(TMP_DATADIR):
        shutil.rmtree(TMP_DATADIR, ignore_errors=True)
        print(f"Removed temporary directory {TMP_DATADIR}")


def _migrate_doge():
    from app.lib.keys import  HDKey
    from app.lib.wallets import WalletKey
    SRC = config['WALLET_DAT_PATH']
    os.makedirs(TMP_DATADIR, exist_ok=True)
    WALLET = "shkeeper"
    DST = os.path.join(TMP_DATADIR, WALLET)
    try:
        shutil.copy(SRC, DST)
        print(f"Copied {SRC} → {DST}")
    except FileNotFoundError:
        print(f"{SRC} not found, skipping copy")
    except PermissionError:
        print(f"Permission denied copying {SRC} → {DST}")
    dogecoind_cmd = [
        "dogecoind",
        f"-datadir={TMP_DATADIR}",
        "-server",
        # f"-{config['COIN_NETWORK']}",
        # "-rpcallowip=127.0.0.1",
        "-rpcallowip=0.0.0.0/0",
        f"-rpcbind={rpc_bind}",
        f"-rpcport={RPC_PORT}",
        f"-rpcuser={RPC_USER}",
        f"-rpcpassword={RPC_PASSWORD}",
        f"-walletdir={TMP_DATADIR}",
        f"-wallet={WALLET}",
        "-connect=0",
        "-disablewallet=0",
        "-deprecatedrpc=addresses",
        "-printtoconsole",
        "-daemon=0"
    ]
    logger.info('migrate_addreses')
    print("migrate_addreses")
    time.sleep(20)
    dogecoind_proc = subprocess.Popen(dogecoind_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    time.sleep(20)
    print("dogecoind_proc")
    from app import create_app
    app = create_app()
    app.app_context().push()
    from app.lib.wallets import Wallet, DbWallet, wallets_list, wallet_delete, db
    try:
        target_timestamp = time_wallet_created()
        if not target_timestamp:
            raise RuntimeError("Wallet creation date not found. Aborting migration.")
        closest = find_closest_block_by_timestamp(target_timestamp)
        print(f"Closest block height: {closest['height']}")
    except Exception as e:
        print(f"Migration migrate_addreses failed: {e}")
        if dogecoind_proc:
            print("Terminate dogecoind_proc")
            dogecoind_proc.terminate()
            dogecoind_proc.wait()
        if os.path.exists(TMP_DATADIR):
            shutil.rmtree(TMP_DATADIR, ignore_errors=True)
            print(f"Removed temporary directory {TMP_DATADIR}")
        raise RuntimeError(f"Migration failed: {type(e).__name__}: {e}") from e

    print("legacy")
    for wallet in wallets_list():
        wallet_name = wallet['name']
        print(wallet_name)
        wallet_delete(wallet_name, force=True)

    doge_wallet = Wallet.create(
        'Wallet7',
        network=config['COIN_NETWORK'],
        witness_type='legacy',
        scheme="single",
        encoding="base58"
    )
    legacy_address = list_all_wallet_addresses()
    print(list_all_wallet_addresses())
    legacy_quantity_generated_adresses = get_legacy_quantity_generated_adresses(legacy_address)
    db_wallet = db.session.query(DbWallet).first()
    db_wallet.generated_address_count = legacy_quantity_generated_adresses
    db.session.commit()
    legacy_address = [{'address': addr} for addr in legacy_address]
    for address_index, addr_dict in enumerate(legacy_address):
        addr = addr_dict['address']
        privkey_data = get_privkey(addr)
        print(f"[{address_index}] Address: {addr}")
        if 'privkey' in privkey_data:
            new_key = HDKey(import_key=privkey_data['privkey'], network=config['COIN_NETWORK'], witness_type='legacy')
            WalletKey.from_key(
                name=f"{db_wallet.name}_{address_index + 1}",
                wallet_id=db_wallet.id,
                session=db.session,
                key=new_key
            )
            db.session.commit()
            print(f"  → SUCCESS: {privkey_data.get('privkey')}")
        else:
            print(f"  → ERROR: {privkey_data.get('error')}")

    addresses = list_unique_wallet_addresses()
    session = db.session
    save_doge_addresses(
        session=session,
        addresses=addresses,
        network=config['COIN_NETWORK']
    )
    # 45810 5996300
    mark_wallet_migrated(session, doge_wallet, closest["height"])
    if dogecoind_proc:
        dogecoind_proc.terminate()
        dogecoind_proc.wait()
    if os.path.exists(TMP_DATADIR):
        shutil.rmtree(TMP_DATADIR, ignore_errors=True)
        print(f"Removed temporary directory {TMP_DATADIR}")
