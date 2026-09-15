from unittest.mock import patch

from flask import Flask

from app.api.views import get_transaction


class TestGetTransactionView:
    def test_requires_store_id(self):
        app = Flask(__name__)
        with app.test_request_context("/transaction/ab", method="POST", json={}):
            result = get_transaction("ab" * 32)
        assert result == ({"status": "error", "msg": "store_id is required"}, 400)

    @patch("app.api.views.TransactionLookupService")
    def test_returns_empty_when_no_wallet_owned_outputs(self, lookup_cls):
        lookup_cls.return_value.get_transaction.return_value = {
            "confirmations": 5,
            "details": [],
        }
        app = Flask(__name__)
        with app.test_request_context(
            "/transaction/ab", method="POST", json={"store_id": 2}
        ):
            result = get_transaction("ab" * 32)

        assert result == []
        lookup_cls.return_value.get_transaction.assert_called_once_with(
            "ab" * 32, store_id=2
        )
