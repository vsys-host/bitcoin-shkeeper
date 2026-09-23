import unittest
from unittest.mock import MagicMock, patch

import pymysql
from sqlalchemy.exc import OperationalError

from app.lib.wallets import Wallet, WalletTransaction, WalletError, _is_deadlock_error


class TestDeadlockErrorDetection(unittest.TestCase):
    def test_detects_pymysql_deadlock(self):
        orig = pymysql.err.OperationalError(
            1213, "Deadlock found when trying to get lock; try restarting transaction"
        )
        exc = OperationalError("stmt", {}, orig)
        self.assertTrue(_is_deadlock_error(exc))

    def test_detects_deadlock_in_wallet_error_message(self):
        exc = WalletError("Could not commit to database (1213, 'Deadlock found')")
        self.assertTrue(_is_deadlock_error(exc))

    def test_ignores_other_operational_errors(self):
        orig = pymysql.err.OperationalError(1205, "Lock wait timeout exceeded")
        exc = OperationalError("stmt", {}, orig)
        self.assertFalse(_is_deadlock_error(exc))


class TestMarkUtxosSpent(unittest.TestCase):
    def test_mark_utxos_spent_executes_batch_update(self):
        wallet = Wallet.__new__(Wallet)
        wallet.wallet_id = 42
        wallet._session = MagicMock()

        txid = bytes.fromhex("ab" * 32)
        wallet._mark_utxos_spent([(txid, 0), (txid, 1)])

        wallet.session.execute.assert_called_once()
        sql = str(wallet.session.execute.call_args[0][0])
        self.assertIn("UPDATE transaction_outputs", sql)
        self.assertIn("SET o.spent = TRUE", sql)
        params = wallet.session.execute.call_args[0][1]
        self.assertEqual(params["wallet_id"], 42)
        self.assertEqual(params["txid0"], txid)
        self.assertEqual(params["txid1"], txid)
        self.assertEqual(params["n0"], 0)
        self.assertEqual(params["n1"], 1)

    def test_mark_utxos_spent_empty_list_is_noop(self):
        wallet = Wallet.__new__(Wallet)
        wallet._session = MagicMock()
        wallet._mark_utxos_spent([])
        wallet.session.execute.assert_not_called()


class TestOwnedChangeKey(unittest.TestCase):
    def test_accepts_key_from_this_wallet(self):
        wallet = Wallet.__new__(Wallet)
        wallet.wallet_id = 7
        wallet._session = MagicMock()
        own_key = MagicMock(wallet_id=7)
        with patch("app.lib.wallets.WalletKey", return_value=own_key) as key_cls:
            result = wallet._owned_change_key(11)

        self.assertIs(result, own_key)
        key_cls.assert_called_once_with(11, wallet.session)

    def test_rejects_key_from_another_wallet(self):
        wallet = Wallet.__new__(Wallet)
        wallet.wallet_id = 7
        wallet._session = MagicMock()
        other_key = MagicMock(wallet_id=8)
        with patch("app.lib.wallets.WalletKey", return_value=other_key):
            with self.assertRaises(WalletError) as ctx:
                wallet._owned_change_key(99)
        self.assertIn("does not belong to this wallet", str(ctx.exception))


class TestPersistSentTransaction(unittest.TestCase):
    def _make_wallet_transaction(self):
        wt = WalletTransaction.__new__(WalletTransaction)
        wt.hdwallet = MagicMock()
        wt.hdwallet.session = MagicMock()
        wt.hdwallet.session.no_autoflush = MagicMock()
        wt.hdwallet.session.no_autoflush.__enter__ = MagicMock(return_value=None)
        wt.hdwallet.session.no_autoflush.__exit__ = MagicMock(return_value=False)
        inp = MagicMock()
        inp.prev_txid = bytes.fromhex("cd" * 32)
        inp.output_n_int = 0
        wt.inputs = [inp]
        wt.store = MagicMock()
        return wt

    def test_persist_calls_store_mark_commit_balance(self):
        wt = self._make_wallet_transaction()
        wt._persist_sent_transaction()

        wt.store.assert_called_once_with(commit=False)
        wt.hdwallet._mark_utxos_spent.assert_called_once_with(
            [(inp.prev_txid, inp.output_n_int) for inp in wt.inputs]
        )
        wt.hdwallet._commit.assert_called_once()
        wt.hdwallet._balance_update.assert_called_once()

    @patch("app.lib.wallets.time.sleep")
    def test_persist_retries_on_deadlock(self, mock_sleep):
        wt = self._make_wallet_transaction()
        orig = pymysql.err.OperationalError(
            1213, "Deadlock found when trying to get lock; try restarting transaction"
        )
        deadlock = OperationalError("stmt", {}, orig)
        wt.hdwallet._commit.side_effect = [deadlock, None]

        wt._persist_sent_transaction(max_retries=3)

        self.assertEqual(wt.hdwallet._commit.call_count, 2)
        wt.hdwallet.session.rollback.assert_called_once()
        mock_sleep.assert_called_once()

    @patch("app.lib.wallets.time.sleep")
    def test_persist_raises_after_max_retries(self, mock_sleep):
        wt = self._make_wallet_transaction()
        orig = pymysql.err.OperationalError(1213, "Deadlock")
        deadlock = OperationalError("stmt", {}, orig)
        wt.hdwallet._commit.side_effect = deadlock

        with self.assertRaises(OperationalError):
            wt._persist_sent_transaction(max_retries=2)

        self.assertEqual(wt.hdwallet._commit.call_count, 2)
        self.assertEqual(wt.hdwallet.session.rollback.call_count, 2)


class TestSendUsesPersistSentTransaction(unittest.TestCase):
    @patch.object(WalletTransaction, "_persist_sent_transaction")
    @patch("app.lib.wallets.Service")
    def test_send_persists_after_broadcast(self, mock_service_cls, mock_persist):
        wt = WalletTransaction.__new__(WalletTransaction)
        wt.verified = True
        wt.verify = MagicMock(return_value=True)
        wt.raw_hex = MagicMock(return_value="deadbeef")
        wt.network = MagicMock()
        wt.network.name = "main"
        wt.hdwallet = MagicMock()
        wt.hdwallet.name = "test-wallet"
        wt.hdwallet.providers = []
        wt.hdwallet.db_cache_uri = None
        wt.hdwallet.strict = True

        mock_service = mock_service_cls.return_value
        mock_service.sendrawtransaction.return_value = {"txid": "abc123"}

        result = WalletTransaction.send(wt, broadcast=True)

        self.assertIsNone(result)
        self.assertEqual(wt.txid, "abc123")
        self.assertTrue(wt.pushed)
        mock_persist.assert_called_once()


class TestPayoutLock(unittest.TestCase):
    @patch("app.payout_lock.redis.Redis")
    def test_payout_lock_acquires_and_releases(self, mock_redis_cls):
        from app.payout_lock import payout_lock

        mock_client = MagicMock()
        mock_lock = MagicMock()
        mock_lock.acquire.return_value = True
        mock_client.lock.return_value = mock_lock
        mock_redis_cls.from_url.return_value = mock_client

        with payout_lock(store_id=1, timeout=10, blocking_timeout=10):
            pass

        lock_args, lock_kwargs = mock_client.lock.call_args
        from app.config import COIN
        self.assertEqual(lock_args[0], f"{COIN}:payout_lock:1")
        self.assertEqual(lock_kwargs["timeout"], 10)
        self.assertFalse(lock_kwargs["thread_local"])
        mock_lock.acquire.assert_called_once_with(blocking=True)
        mock_lock.release.assert_called_once()

    @patch("app.payout_lock.redis.Redis")
    def test_payout_lock_is_scoped_by_store_id(self, mock_redis_cls):
        from app.config import COIN
        from app.payout_lock import payout_lock

        mock_client = MagicMock()
        mock_lock = MagicMock()
        mock_lock.acquire.return_value = True
        mock_client.lock.return_value = mock_lock
        mock_redis_cls.from_url.return_value = mock_client

        with payout_lock(store_id=2, timeout=10, blocking_timeout=10):
            pass

        lock_args, _ = mock_client.lock.call_args
        self.assertEqual(lock_args[0], f"{COIN}:payout_lock:2")

    def test_payout_lock_requires_store_id(self):
        from app.payout_lock import payout_lock

        with self.assertRaises(ValueError) as ctx:
            with payout_lock(timeout=10, blocking_timeout=10):
                pass
        self.assertIn("store_id is required", str(ctx.exception))

    def test_lock_heartbeat_extends_ttl_until_stopped(self):
        from app.payout_lock import _lock_heartbeat

        lock = MagicMock()
        lock.reacquire.return_value = True
        stop_event = MagicMock()
        stop_event.wait.side_effect = [False, True]

        _lock_heartbeat(lock, timeout=30, stop_event=stop_event)

        lock.reacquire.assert_called_once()
        stop_event.wait.assert_any_call(10)

    def test_lock_heartbeat_stops_if_reacquire_fails(self):
        from app.payout_lock import _lock_heartbeat

        lock = MagicMock()
        lock.reacquire.return_value = False
        stop_event = MagicMock()
        stop_event.wait.return_value = False

        _lock_heartbeat(lock, timeout=30, stop_event=stop_event)

        lock.reacquire.assert_called_once()
        self.assertEqual(stop_event.wait.call_count, 1)


class TestSplitScanHits(unittest.TestCase):
    def test_routes_tx_to_owning_wallets(self):
        from app.lib.wallets import split_scan_hits

        related = {"tx1": {"bc1qa", "bc1qb"}}
        addresses = {"bc1qa", "bc1qb", "bc1qc"}
        mapping = {
            "bc1qa": {1},
            "bc1qb": {2},
            "bc1qc": {1},
        }
        per_related, per_addrs = split_scan_hits(related, addresses, mapping)
        self.assertEqual(per_related[1], {"tx1": {"bc1qa"}})
        self.assertEqual(per_related[2], {"tx1": {"bc1qb"}})
        self.assertEqual(per_addrs[1], {"bc1qa", "bc1qc"})
        self.assertEqual(per_addrs[2], {"bc1qb"})

    def test_unknown_address_is_ignored(self):
        from app.lib.wallets import split_scan_hits

        per_related, per_addrs = split_scan_hits(
            {"tx1": {"bc1qunknown"}},
            {"bc1qunknown"},
            {},
        )
        self.assertEqual(per_related, {})
        self.assertEqual(per_addrs, {})


class TestScanBlock(unittest.TestCase):
    def _wallet(self, wallet_id, srv):
        wallet = Wallet.__new__(Wallet)
        wallet.wallet_id = wallet_id
        wallet.network = MagicMock()
        wallet.network.name = "bitcoin"
        wallet._build_service = MagicMock(return_value=srv)
        wallet._session = MagicMock()
        wallet._get_fixed_addresses_if_needed = MagicMock(return_value=None)
        wallet._process_transactions = MagicMock(return_value=(set(), {}, 0))
        wallet._update_db_transactions = MagicMock()
        wallet._store_related_block_txs = MagicMock()
        wallet._scan_keys_loop = MagicMock()
        wallet._finalize_scan = MagicMock()
        return wallet

    @patch("app.lib.wallets.COIN", "BTC")
    def test_fetches_block_once_for_many_wallets(self):
        srv = MagicMock()
        srv.getblocktransactions.return_value = {"tx": []}
        w1 = self._wallet(1, srv)
        w2 = self._wallet(2, srv)

        with patch.object(Wallet, "_load_addresses_by_wallet", return_value=({}, set())):
            Wallet.scan_block([w1, w2], block="hash", current_block_height=10)

        srv.getblocktransactions.assert_called_once_with("hash")
        w1._update_db_transactions.assert_called_once()
        w2._update_db_transactions.assert_called_once()
        w1._store_related_block_txs.assert_not_called()
        w2._store_related_block_txs.assert_not_called()
        w1._finalize_scan.assert_called_once()
        w2._finalize_scan.assert_not_called()

    @patch("app.lib.wallets.COIN", "BTC")
    def test_stores_related_txs_on_owning_wallet(self):
        srv = MagicMock()
        srv.getblocktransactions.return_value = {"tx": [{"txid": "tx1"}]}
        w1 = self._wallet(1, srv)
        w2 = self._wallet(2, srv)
        w1._process_transactions.return_value = (
            {"bc1qa"},
            {"tx1": {"bc1qa"}},
            1,
        )

        with patch.object(
            Wallet,
            "_load_addresses_by_wallet",
            return_value=({"bc1qa": {1}}, {"bc1qa"}),
        ):
            Wallet.scan_block([w1, w2], block="hash", current_block_height=10)

        w1._store_related_block_txs.assert_called_once()
        related = w1._store_related_block_txs.call_args[0][1]
        self.assertEqual(related, {"tx1": {"bc1qa"}})
        w2._store_related_block_txs.assert_not_called()

    @patch("app.lib.wallets.COIN", "LTC")
    def test_ltc_scans_when_only_fixed_addresses_match(self):
        srv = MagicMock()
        srv.getblocktransactions.return_value = {"tx": [{"txid": "tx1"}]}
        w1 = self._wallet(1, srv)
        w2 = self._wallet(2, srv)
        w1._get_fixed_addresses_if_needed.return_value = ["Lfixed"]
        w1._process_transactions.return_value = (set(), {}, 0)

        with patch.object(Wallet, "_load_addresses_by_wallet", return_value=({}, set())):
            Wallet.scan_block([w1, w2], block="hash", current_block_height=10)

        w1._scan_keys_loop.assert_called_once()
        w2._scan_keys_loop.assert_called_once()
        args, kwargs = w1._scan_keys_loop.call_args
        self.assertEqual(args[1], set())
        self.assertEqual(args[2], ["Lfixed"])
