from unittest.mock import MagicMock, patch

from app.services.transaction import TransactionLookupService


class TestGetTransactionCategories:
    def _lookup(self, txid, store_id=1):
        return TransactionLookupService().get_transaction(txid, store_id=store_id)

    @patch("app.services.transaction.NodeService")
    @patch.object(TransactionLookupService, "get_txs_by_txid")
    def test_external_outputs_are_send_without_change_receive(self, get_txs, node_cls):
        send_out = MagicMock(key_id=None, output_n=0, address="tb1qdest", value=99859)
        change_out = MagicMock(key_id=7, output_n=1, address="tb1qchange", value=1000)
        own_vin = MagicMock(key_id=3, address="tb1qvin")
        tx = MagicMock(confirmations=5, inputs=[own_vin], outputs=[change_out, send_out])
        get_txs.return_value = [tx]
        node_cls.return_value.get_confirmations.return_value = None

        result = self._lookup("ab" * 32)

        assert [d["address"] for d in result["details"]] == ["tb1qdest"]
        assert [d["category"] for d in result["details"]] == ["send"]
        assert result["confirmations"] == 5
        get_txs.assert_called_once_with("ab" * 32, 1)

    @patch("app.services.transaction.NodeService")
    @patch.object(TransactionLookupService, "get_txs_by_txid")
    def test_send_all_without_change_is_send(self, get_txs, node_cls):
        send_out = MagicMock(key_id=None, output_n=0, address="tb1qdest", value=99859)
        tx = MagicMock(confirmations=5, inputs=[], outputs=[send_out])
        get_txs.return_value = [tx]
        node_cls.return_value.get_confirmations.return_value = None

        result = self._lookup("cd" * 32)

        assert len(result["details"]) == 1
        assert result["details"][0]["address"] == "tb1qdest"
        assert result["details"][0]["category"] == "send"
        assert result["confirmations"] == 5

    @patch("app.services.transaction.NodeService")
    @patch.object(TransactionLookupService, "get_txs_by_txid")
    def test_incoming_payment_skips_payer_change(self, get_txs, node_cls):
        invoice_out = MagicMock(
            key_id=7, output_n=0, address="ltc1qinvoice", value=290000
        )
        payer_change = MagicMock(
            key_id=None, output_n=1, address="ltc1qpayerchange", value=137525391
        )
        foreign_vin = MagicMock(key_id=None, address="ltc1qpayer")
        tx = MagicMock(
            confirmations=5,
            wallet_id=2,
            inputs=[foreign_vin],
            outputs=[invoice_out, payer_change],
        )
        get_txs.return_value = [tx]
        node_cls.return_value.get_confirmations.return_value = None

        with patch("app.services.transaction.db") as db:
            db.session.query.return_value.scalar.return_value = False
            result = self._lookup("be" * 32)

        assert len(result["details"]) == 1
        assert result["details"][0]["address"] == "ltc1qinvoice"
        assert result["details"][0]["category"] == "receive"

    @patch("app.services.transaction.NodeService")
    @patch.object(TransactionLookupService, "get_txs_by_txid")
    def test_incoming_without_saved_vins_is_not_send(self, get_txs, node_cls):
        invoice_out = MagicMock(
            key_id=7, output_n=0, address="ltc1qinvoice", value=290000
        )
        payer_change = MagicMock(
            key_id=None, output_n=1, address="ltc1qpayerchange", value=137525391
        )
        tx = MagicMock(confirmations=5, wallet_id=2, inputs=[], outputs=[invoice_out, payer_change])
        get_txs.return_value = [tx]
        node_cls.return_value.get_confirmations.return_value = None

        result = self._lookup("cf" * 32)

        assert [d["category"] for d in result["details"]] == ["receive"]
        assert [d["address"] for d in result["details"]] == ["ltc1qinvoice"]

    @patch("app.services.transaction.NodeService")
    @patch.object(TransactionLookupService, "get_txs_by_txid")
    def test_vin_from_another_store_is_not_this_store_send(self, get_txs, node_cls):
        invoice_out = MagicMock(key_id=7, output_n=1, address="tb1qchange", value=1000)
        payer_change = MagicMock(key_id=None, output_n=0, address="tb1qdest", value=99859)
        other_store_vin = MagicMock(key_id=None, address="tb1qvinotherstore")
        tx = MagicMock(
            confirmations=5,
            wallet_id=2,
            inputs=[other_store_vin],
            outputs=[invoice_out, payer_change],
        )
        get_txs.return_value = [tx]
        node_cls.return_value.get_confirmations.return_value = None

        with patch("app.services.transaction.db") as db:
            db.session.query.return_value.scalar.return_value = False
            result = self._lookup("0b" * 32)

        assert [d["category"] for d in result["details"]] == ["receive"]
        assert [d["address"] for d in result["details"]] == ["tb1qchange"]

    @patch("app.services.transaction.NodeService")
    @patch.object(TransactionLookupService, "get_txs_by_txid")
    def test_vin_address_in_same_wallet_is_send(self, get_txs, node_cls):
        send_out = MagicMock(key_id=None, output_n=0, address="tb1qdest", value=99859)
        change_out = MagicMock(key_id=7, output_n=1, address="tb1qchange", value=1000)
        own_vin = MagicMock(key_id=None, address="tb1qvin")
        tx = MagicMock(
            confirmations=5,
            wallet_id=2,
            inputs=[own_vin],
            outputs=[change_out, send_out],
        )
        get_txs.return_value = [tx]
        node_cls.return_value.get_confirmations.return_value = None

        with patch("app.services.transaction.db") as db:
            db.session.query.return_value.scalar.return_value = True
            result = self._lookup("0c" * 32)

        assert [d["category"] for d in result["details"]] == ["send"]
        assert [d["address"] for d in result["details"]] == ["tb1qdest"]

    @patch("app.services.transaction.NodeService")
    @patch.object(TransactionLookupService, "get_txs_by_txid")
    def test_wallet_unconfirmed_uses_node_confirmations(self, get_txs, node_cls):
        send_out = MagicMock(key_id=None, output_n=0, address="tb1qdest", value=99859)
        tx = MagicMock(confirmations=0, outputs=[send_out])
        get_txs.return_value = [tx]
        node_cls.return_value.get_confirmations.return_value = 3

        result = self._lookup("11" * 32)

        assert result["confirmations"] == 3
        assert result["details"][0]["category"] == "send"

    @patch("app.services.transaction.NodeService")
    @patch.object(TransactionLookupService, "get_txs_by_txid")
    def test_reorg_prefers_node_confirmations(self, get_txs, node_cls):
        send_out = MagicMock(key_id=None, output_n=0, address="tb1qdest", value=99859)
        tx = MagicMock(confirmations=5, outputs=[send_out])
        get_txs.return_value = [tx]
        node_cls.return_value.get_confirmations.return_value = 1

        result = self._lookup("12" * 32)

        assert result["confirmations"] == 1

    @patch("app.services.transaction.NodeService")
    @patch.object(TransactionLookupService, "get_txs_by_txid")
    def test_missing_wallet_tx_uses_node_confirmations(self, get_txs, node_cls):
        get_txs.return_value = []
        node_cls.return_value.get_confirmations.return_value = 5

        result = self._lookup("ef" * 32)

        assert result["details"] == []
        assert result["confirmations"] == 5
        node_cls.return_value.get_confirmations.assert_called_once_with("ef" * 32)

    @patch("app.services.transaction.NodeService")
    @patch.object(TransactionLookupService, "get_txs_by_txid")
    def test_missing_wallet_tx_unknown_on_node(self, get_txs, node_cls):
        get_txs.return_value = []
        node_cls.return_value.get_confirmations.return_value = None

        assert self._lookup("aa" * 32) is None

    def test_get_transaction_requires_store_id(self):
        try:
            TransactionLookupService().get_transaction("ab" * 32, store_id=None)
        except ValueError as exc:
            assert "store_id is required" in str(exc)
        else:
            raise AssertionError("expected missing store_id to raise")

    @patch("app.services.transaction.store_service.parse_store_id", side_effect=lambda v, required=True: int(v))
    @patch("app.services.transaction.db")
    def test_get_txs_by_txid_joins_store_wallet(self, mock_db, _parse):
        txs = [MagicMock()]
        mock_db.session.query.return_value.join.return_value.filter.return_value.order_by.return_value.all.return_value = txs

        result = TransactionLookupService().get_txs_by_txid("ab" * 32, store_id=2)

        assert result == txs
        mock_db.session.query.return_value.join.assert_called_once()
        mock_db.session.query.return_value.join.return_value.filter.assert_called_once()
