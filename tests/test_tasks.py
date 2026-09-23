from contextlib import contextmanager
from unittest.mock import MagicMock, patch

from app.tasks import make_multipayout, withdraw_to_external_wallet_task


@contextmanager
def _noop_lock(*args, **kwargs):
    yield


class TestMakeMultipayout:
    @patch("app.tasks.payout_lock", _noop_lock)
    @patch("app.tasks.post_payout_results")
    @patch("app.tasks.PayoutService")
    def test_native_coin_path(self, payout_cls, post_payout_results):
        payout_instance = payout_cls.return_value
        payout_instance.make_multipayout.return_value = [{"status": "success"}]
        post_payout_results.delay = MagicMock()

        result = make_multipayout.run(
            "BTC", [{"dest": "bc1q0", "amount": 1}], "0.00005", store_id=1
        )

        payout_instance.make_multipayout.assert_called_once_with(
            [{"dest": "bc1q0", "amount": 1}], "0.00005", store_id=1
        )
        post_payout_results.delay.assert_called_once_with(
            [{"status": "success"}], "BTC"
        )
        assert result == [{"status": "success"}]

    def test_unknown_symbol_returns_error(self):
        result = make_multipayout.run("UNKNOWN", [], "0.00005")
        assert result == [{"status": "error", "msg": "Symbol is not in config"}]

    @patch("app.tasks.payout_lock", _noop_lock)
    @patch("app.tasks.post_payout_results")
    @patch("app.tasks.PayoutService")
    def test_missing_store_id_is_rejected(self, payout_cls, post_payout_results):
        result = make_multipayout.run("BTC", [{"dest": "bc1q0", "amount": 1}], "0.00005")

        payout_cls.assert_not_called()
        post_payout_results.delay.assert_not_called()
        assert result == [{"status": "error", "msg": "store_id is required"}]

    @patch("app.tasks.payout_lock")
    @patch("app.tasks.post_payout_results")
    @patch("app.tasks.PayoutService")
    def test_uses_store_scoped_lock(self, payout_cls, post_payout_results, payout_lock):
        payout_instance = payout_cls.return_value
        payout_instance.make_multipayout.return_value = [{"status": "success"}]
        post_payout_results.delay = MagicMock()
        payout_lock.return_value.__enter__ = MagicMock()
        payout_lock.return_value.__exit__ = MagicMock(return_value=False)

        make_multipayout.run(
            "BTC", [{"dest": "bc1q0", "amount": 1}], "0.00005", store_id=2
        )

        payout_lock.assert_called_once_with(store_id=2)


class TestWithdrawToExternalWallet:
    @patch("app.tasks.payout_lock")
    @patch("app.tasks.post_payout_results")
    @patch("app.tasks.PayoutService")
    def test_uses_store_scoped_lock(self, payout_cls, post_payout_results, payout_lock):
        # unsafe: MagicMock treats assert_* as unittest assertions.
        payout_instance = MagicMock(unsafe=True)
        payout_cls.return_value = payout_instance
        payout_instance.withdraw_to_external_wallet_task.return_value = [{"status": "success"}]
        post_payout_results.delay = MagicMock()
        payout_lock.return_value.__enter__ = MagicMock()
        payout_lock.return_value.__exit__ = MagicMock(return_value=False)

        withdraw_to_external_wallet_task.run(
            "BTC", [{"source": "bc1qsrc", "dest": "bc1qdst"}], store_id=2
        )

        payout_instance.assert_sources_belong_to_store.assert_called_once_with(
            [{"source": "bc1qsrc", "dest": "bc1qdst"}], 2
        )
        payout_lock.assert_called_once_with(store_id=2)
        payout_instance.withdraw_to_external_wallet_task.assert_called_once_with(
            [{"source": "bc1qsrc", "dest": "bc1qdst"}], store_id=2
        )

    @patch("app.tasks.payout_lock")
    @patch("app.tasks.post_payout_results")
    @patch("app.tasks.PayoutService")
    def test_source_store_mismatch_skips_lock(
        self, payout_cls, post_payout_results, payout_lock
    ):
        payout_instance = MagicMock(unsafe=True)
        payout_cls.return_value = payout_instance
        payout_instance.assert_sources_belong_to_store.side_effect = Exception(
            "Source address 'bc1qsrc' does not belong to store_id=2"
        )

        try:
            withdraw_to_external_wallet_task.run(
                "BTC", [{"source": "bc1qsrc", "dest": "bc1qdst"}], store_id=2
            )
        except Exception as exc:
            assert "does not belong to store_id=2" in str(exc)
        else:
            raise AssertionError("expected source store mismatch to raise")

        payout_lock.assert_not_called()
        payout_instance.withdraw_to_external_wallet_task.assert_not_called()
        post_payout_results.delay.assert_not_called()
