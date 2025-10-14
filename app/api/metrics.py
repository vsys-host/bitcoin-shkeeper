import json
import requests
import prometheus_client
from prometheus_client import generate_latest, Info, Gauge

from . import metrics_blueprint
from app.config import config
# from ..models import Settings, db
from app.wallet import BTCWallet

prometheus_client.REGISTRY.unregister(prometheus_client.GC_COLLECTOR)
prometheus_client.REGISTRY.unregister(prometheus_client.PLATFORM_COLLECTOR)
prometheus_client.REGISTRY.unregister(prometheus_client.PROCESS_COLLECTOR)


def get_rippled_status(rpc_url):
    headers = {'Content-Type': 'application/json'}
    payload = {
        "method": "server_info",
        "params": [{}]
    }

    try:
        response = requests.post(rpc_url, headers=headers, data=json.dumps(payload))
        if response.status_code == 200:
            data = response.json()
            return data
        else:
            return False
    except requests.exceptions.RequestException as e:
        return False


# def get_latest_release(name):
#     if name == 'rippled':
#         url = 'https://api.github.com/repos/XRPLF/rippled/releases/latest'
#     else:
#         return False
#     try:
#         data = requests.get(url).json()
#         version = data["tag_name"]
#         info = { key:data[key] for key in ["name", "tag_name", "published_at"] }
#         info['version'] = version
#     except Exception as e:
#         info = {}
#     return info


# def get_all_metrics():
#     response = {}
#     status = get_rippled_status(config["FULLNODE_URL"])
#     if not status:
#         response['xrp_fullnode_status'] = 0
#         return response
#     else:
#         w = BTCWallet()
#         last_fullnode_block_number = w.get_last_block_number()
#         response['last_fullnode_block_number'] = last_fullnode_block_number
#         response['last_fullnode_block_timestamp'] = w.get_ledger_data(last_fullnode_block_number).result['ledger']['close_time']
#         try:
#             rippled_version =  status["result"]["info"]["build_version"]
#         except Exception as e:
#             rippled_version =  status["result"]["info"]["rippled_version"]
#         response['rippled_version'] = rippled_version
        
#         # pd = Settings.query.filter_by(name = 'last_block').first()
#         # if pd.value is None:
#         #     last_checked_block = 0
#         # else:
#         #     last_checked_block = int(pd.value)
        
#         last_checked_block = 0
#         response['xrp_wallet_last_block'] = last_checked_block
#         response['xrp_wallet_last_block_timestamp'] = w.get_ledger_data(last_checked_block).result['ledger']['close_time']
#         response['xrp_fullnode_status'] = 1
#         return response
    
# rippled_last_release = Info(
#          'rippled_last_release',
#          'Version of the latest release from https://github.com/XRPLF/rippled/releases'
#      )
        
# rippled_last_release.info(get_latest_release('rippled'))
# rippled_fullnode_version = Info('rippled_fullnode_version', 'Current rippled version in use')
# xrp_fullnode_status = Gauge('xrp_fullnode_status', 'Connection status to BTC fullnode')
# xrp_fullnode_last_block = Gauge('xrp_fullnode_last_block', 'Last block loaded to the fullnode', )
# xrp_wallet_last_block = Gauge('xrp_wallet_last_block', 'Last checked block ') 
# xrp_fullnode_last_block_timestamp = Gauge('xrp_fullnode_last_block_timestamp', 'Last block timestamp loaded to the fullnode', )
# xrp_wallet_last_block_timestamp = Gauge('xrp_wallet_last_block_timestamp', 'Last checked block timestamp')



# @metrics_blueprint.get("/metrics")
# def get_metrics():
#     response = get_all_metrics()
#     if response['xrp_fullnode_status'] == 1:
#         rippled_fullnode_version.info({'version': response['rippled_version']})
#         xrp_fullnode_last_block.set(response['last_fullnode_block_number'])
#         xrp_fullnode_last_block_timestamp.set(response['last_fullnode_block_timestamp'])
#         xrp_wallet_last_block.set(response['xrp_wallet_last_block'])
#         xrp_wallet_last_block_timestamp.set(response['xrp_wallet_last_block_timestamp'])
#         xrp_fullnode_status.set(response['xrp_fullnode_status'])
#     else:
#         xrp_fullnode_status.set(response['xrp_fullnode_status'])

#     return generate_latest().decode()
