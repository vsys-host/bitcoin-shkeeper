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

