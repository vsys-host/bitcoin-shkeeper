from unittest.mock import patch

from flask import Flask, g

from app.api.views import get_balance, get_transaction


class TestGetTransactionView:
    def test_requires_store_id(self):
        app = Flask(__name__)
        with app.test_request_context("/transaction/ab", method="POST", json={}):
            result = get_transaction("ab" * 32)
        assert result == ({"status": "error", "msg": "store_id is required"}, 400)

    @patch("app.api.views.TransactionLookupService")
    def test_returns_confirmation_placeholder_when_no_wallet_owned_outputs(self, lookup_cls):
        lookup_cls.return_value.get_transaction.return_value = {
            "confirmations": 5,
            "details": [],
        }
        app = Flask(__name__)
        with app.test_request_context(
            "/transaction/ab", method="POST", json={"store_id": 2}
        ):
            result = get_transaction("ab" * 32)

        assert result == [["", 0, 5, "change"]]
        lookup_cls.return_value.get_transaction.assert_called_once_with(
            "ab" * 32, store_id=2
        )


class TestGetBalanceView:
    def test_requires_store_id(self):
        app = Flask(__name__)
        with app.test_request_context("/balance", method="POST", json={}):
            result = get_balance()
        assert result == ({"status": "error", "msg": "store_id is required"}, 400)

    @patch("app.api.views.WalletService")
    def test_locked_wallet_is_503(self, wallet_cls):
        wallet_cls.return_value.get_store_balance.side_effect = PermissionError(
            "Wallet is locked or encryption password not available"
        )
        app = Flask(__name__)
        with app.test_request_context(
            "/balance", method="POST", json={"store_id": 1}
        ):
            g.symbol = "BTC"
            body, status = get_balance()
        assert status == 503
        assert body.get_json()["status"] == "error"
