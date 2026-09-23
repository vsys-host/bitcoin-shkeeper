"""Serialize payouts per store so concurrent workers cannot double-spend the same UTXOs."""
from contextlib import contextmanager
from threading import Event, Thread

import redis

from app.config import COIN, config
from app.logging import logger
from app.services.store import parse_store_id

# Payout builds can take several minutes (signing many inputs).
_DEFAULT_LOCK_TIMEOUT = int(config.get('PAYOUT_LOCK_TIMEOUT', 1200))
_DEFAULT_BLOCKING_TIMEOUT = int(config.get('PAYOUT_LOCK_BLOCKING_TIMEOUT', 1200))


def _redis_client():
    return redis.Redis.from_url(f"redis://{config['REDIS_HOST']}", decode_responses=True)


def _lock_heartbeat(lock, timeout, stop_event):
    """Refresh Redis TTL until the payout context exits.

    thread_local=False is required on the Lock so this thread can see the token.
    """
    interval = max(1, timeout // 3)
    while not stop_event.wait(interval):
        try:
            if not lock.reacquire():
                logger.error("Failed to extend payout lock; it may have expired")
                return
            logger.debug("Extended payout lock TTL by %ss", timeout)
        except redis.exceptions.LockError as e:
            logger.error("Payout lock heartbeat failed: %s", e)
            return


@contextmanager
def payout_lock(*, store_id=None, timeout=None, blocking_timeout=None):
    timeout = _DEFAULT_LOCK_TIMEOUT if timeout is None else timeout
    blocking_timeout = _DEFAULT_BLOCKING_TIMEOUT if blocking_timeout is None else blocking_timeout
    store_id = parse_store_id(store_id, required=True)
    client = _redis_client()
    lock_key = f"{COIN}:payout_lock:{store_id}"
    lock = client.lock(
        lock_key,
        timeout=timeout,
        blocking_timeout=blocking_timeout,
        thread_local=False,
    )
    logger.info("Acquiring payout lock %s (timeout=%ss, blocking_timeout=%ss)",
                lock_key, timeout, blocking_timeout)
    acquired = lock.acquire(blocking=True)
    if not acquired:
        raise RuntimeError(f"Could not acquire payout lock {lock_key}")
    logger.info("Acquired payout lock %s", lock_key)
    stop_event = Event()
    heartbeat = Thread(
        target=_lock_heartbeat,
        args=(lock, timeout, stop_event),
        name=f"{lock_key}-heartbeat",
        daemon=True,
    )
    heartbeat.start()
    try:
        yield
    finally:
        stop_event.set()
        heartbeat.join(timeout=5)
        try:
            lock.release()
            logger.info("Released payout lock %s", lock_key)
        except redis.exceptions.LockError:
            logger.warning("Payout lock %s already expired or released", lock_key)
