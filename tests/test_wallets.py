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
