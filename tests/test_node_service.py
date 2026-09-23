from unittest.mock import patch

from app.services.node import NodeService


class TestGetConfirmations:
    @patch.object(NodeService, "_build_service")
    def test_reads_confirmations_from_verbose_tx(self, build):
        build.return_value.getverbosetransaction.return_value = {"confirmations": 5}
        assert NodeService().get_confirmations("ab" * 32) == 5

    @patch.object(NodeService, "_build_service")
    def test_mempool_tx_is_zero(self, build):
        build.return_value.getverbosetransaction.return_value = {"txid": "ab"}
        assert NodeService().get_confirmations("ab" * 32) == 0

    @patch.object(NodeService, "_build_service")
    def test_rpc_error_returns_none(self, build):
        build.return_value.getverbosetransaction.side_effect = Exception("missing")
        assert NodeService().get_confirmations("ab" * 32) is None
