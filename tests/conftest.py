import json
import os
from pathlib import Path

# Required before any `app` import during test collection.
os.environ.setdefault("WALLET", "BTC")
os.environ.setdefault("SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")


def pytest_configure(config):
    """Expose all coin network definitions in tests, not only COIN_NETWORK."""
    from app.config import COIN
    from app.lib import networks as networks_module

    networks_path = Path(__file__).parent.parent / "app/lib/data/networks.json"
    coin_definitions = json.loads(networks_path.read_text()).get(COIN, {})
    for name, definition in coin_definitions.items():
        networks_module.NETWORK_DEFINITIONS[name] = definition
