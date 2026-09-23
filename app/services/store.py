from sqlalchemy.exc import PendingRollbackError
from sqlalchemy import exists
from sqlalchemy.orm import aliased

from ..config import config
from ..logging import logger
from ..models import DbKey, DbWallet, db

DEFAULT_STORE_ID = 1


def parse_store_id(value, required=True):
    if value is None:
        if required:
            raise ValueError("store_id is required")
        return None
    if isinstance(value, bool):
        raise ValueError(f"Invalid store_id {value!r}")
    if isinstance(value, int):
        if value <= 0:
            raise ValueError(f"Invalid store_id {value!r}")
        return value
    raw = str(value).strip()
    if not raw:
        if required:
            raise ValueError("store_id is required")
        return None
    if raw.lower() == "default":
        return DEFAULT_STORE_ID
    try:
        store_id = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid store_id {value!r}") from exc
    if store_id <= 0:
        raise ValueError(f"Invalid store_id {value!r}")
    return store_id


def _query_first(query):
    """Recover a Flask-SQLAlchemy Session left in a failed transaction."""
    try:
        return query.first()
    except PendingRollbackError:
        logger.warning("Invalid DB transaction; rolling back and retrying query")
        db.session.rollback()
        return query.first()


def _query_all(query):
    try:
        return query.all()
    except PendingRollbackError:
        logger.warning("Invalid DB transaction; rolling back and retrying query")
        db.session.rollback()
        return query.all()


def store_wallet(store_id=None, for_update=False):
    store_id = parse_store_id(store_id)
    query = (
        DbWallet.query.filter_by(store_id=store_id)
        .filter(DbWallet.parent_id.is_(None))
        .order_by(DbWallet.id.asc())
    )
    if for_update:
        query = query.with_for_update()
    return _query_first(query)


def store_address_keys(store_id=None):
    """Leaf keys with a spendable address on the configured network.

    Childless is not enough: incomplete derivation leaves intermediate
    chain/account nodes with an address and no children. Those are not
    spendable HD leaves (depth differs by purpose/coin), so drop them by
    path rather than a single depth filter.
    """
    store_id = parse_store_id(store_id)
    child = aliased(DbKey)
    keys = _query_all(
        DbKey.query.join(DbWallet, DbKey.wallet_id == DbWallet.id)
        .filter(
            DbWallet.store_id == store_id,
            DbKey.address.isnot(None),
            DbKey.address != "",
            DbKey.network_name == config["COIN_NETWORK"],
            ~exists().where(child.parent_id == DbKey.id),
        )
        .order_by(DbKey.id.asc())
    )
    return _leaf_address_keys(keys)


def store_key_by_address(store_id, address):
    """Return the key for this address in the given store, or None."""
    store_id = parse_store_id(store_id)
    if not address:
        return None
    return _query_first(
        DbKey.query.join(DbWallet, DbKey.wallet_id == DbWallet.id)
        .filter(
            DbWallet.store_id == store_id,
            DbKey.address == address,
            DbKey.network_name == config["COIN_NETWORK"],
        )
        .order_by(DbKey.id.asc())
    )


def address_is_known(address):
    if not address:
        return False
    return _query_first(DbKey.query.filter(DbKey.address == address)) is not None


def _is_hd_chain_node(key):
    """True for receive/change chain nodes, not BIP32/purpose-0 leaf addresses."""
    path = getattr(key, "path", None) or ""
    parts = [part for part in path.split("/") if part]
    if len(parts) not in (3, 5):
        return False
    return parts[-1].rstrip("'HhPp") in ("0", "1")


def _leaf_address_keys(keys):
    """Spendable address keys: skip empty addresses and HD chain nodes."""
    return [
        key for key in keys if getattr(key, "address", None) and not _is_hd_chain_node(key)
    ]


def pick_change_key(keys):
    """Prefer unused change-chain address; fall back to any leaf address key."""
    address_keys = _leaf_address_keys(keys)
    if not address_keys:
        return None
    change_keys = [key for key in address_keys if key.change == 1]
    unused_change = next((key for key in change_keys if not key.used), None)
    if unused_change:
        return unused_change
    if change_keys:
        return change_keys[0]
    return address_keys[0]
