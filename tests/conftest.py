import json
import os
from pathlib import Path

# Required before any `app` import during test collection.
os.environ.setdefault("WALLET", "BTC")
# Always override inherited shell/k8s URIs. Tests must never touch MariaDB.
_TEST_DB_URI = "sqlite:///:memory:"
os.environ["SQLALCHEMY_DATABASE_URI"] = _TEST_DB_URI


def pytest_configure(config):
    """Expose all coin network definitions in tests, not only COIN_NETWORK."""
    from app.config import COIN, config as app_config
    from app.lib import networks as networks_module

    app_config["SQLALCHEMY_DATABASE_URI"] = _TEST_DB_URI
    uri = str(app_config["SQLALCHEMY_DATABASE_URI"])
    if uri.startswith("mysql") or uri.startswith("mariadb") or "mariadb" in uri:
        raise RuntimeError(
            f"Refusing to run tests against {uri!r}; the main database must not be used."
        )

    networks_path = Path(__file__).parent.parent / "app/lib/data/networks.json"
    coin_definitions = json.loads(networks_path.read_text()).get(COIN, {})
    for name, definition in coin_definitions.items():
        networks_module.NETWORK_DEFINITIONS[name] = definition
