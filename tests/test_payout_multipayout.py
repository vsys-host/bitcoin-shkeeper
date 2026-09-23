from decimal import Decimal
from unittest.mock import MagicMock, patch

from app.services.payout import PayoutService, coin_fee_from_sat_per_vbyte, relay_dust_satoshi
from app.services.store import _leaf_address_keys, pick_change_key

FEE_ADDR = "tb1q9jrhnfe5neu720h2v8xjeu4gged0j37pem2x0x"
MERCHANT_ADDR = "tb1qxfsnwjyfucv4scm3eql0gm68exxp2zgd6ckwc9"


class _Key:
    def __init__(self, key_id, address="", change=0, used=False, path=""):
        self.id = key_id
        self.address = address
        self.change = change
        self.used = used
        self.path = path


def test_pick_change_key_prefers_unused_change():
    keys = [
        _Key(1, "bc1qrecv", change=0),
        _Key(2, "bc1qchg1", change=1, used=True),
        _Key(3, "bc1qchg2", change=1, used=False),
    ]
    assert pick_change_key(keys).id == 3


def test_pick_change_key_falls_back_to_receive():
    keys = [_Key(1, "bc1qrecv", change=0), _Key(2, "", change=0)]
    assert pick_change_key(keys).address == "bc1qrecv"


def test_pick_change_key_skips_hd_chain_node():
    keys = [
        _Key(1, "bc1qchain", change=1, path="m/84'/0'/0'/1"),
        _Key(2, "bc1qleaf", change=1, path="m/84'/0'/0'/1/3"),
    ]
    assert pick_change_key(keys).id == 2


def test_pick_change_key_skips_purpose0_chain_node():
    keys = [
        _Key(1, "bc1qchain", change=1, path="m/0'/1'"),
        _Key(2, "bc1qleaf", change=1, path="m/0'/1'/3'"),
    ]
    assert pick_change_key(keys).id == 2


def test_pick_change_key_returns_none_when_only_chain_nodes():
    keys = [_Key(1, "bc1qchain", change=1, path="m/84'/0'/0'/1")]
    assert pick_change_key(keys) is None


def test_leaf_address_keys_keeps_doge_single_and_drops_chain():
    keys = [
        _Key(1, "D7Y55gGczu2hTfxgAQvZybTh9fYpkN2p3z", path="m"),
        _Key(2, "bc1qchain", change=1, path="m/84'/0'/0'/0"),
        _Key(3, "bc1qleaf", change=0, path="m/84'/0'/0'/0/1"),
        _Key(4, "", path="m/84'/0'/0'/0/2"),
    ]
    assert [key.id for key in _leaf_address_keys(keys)] == [1, 3]


def test_relay_dust_p2wpkh_is_core_limit_not_networks_json():
    assert relay_dust_satoshi(FEE_ADDR, fallback=1000, coin="BTC") == 294
    assert relay_dust_satoshi(MERCHANT_ADDR, fallback=1000, coin="BTC") == 294


def test_relay_dust_unknown_address_uses_fallback():
    assert relay_dust_satoshi("bc1qfee", fallback=1000, coin="BTC") == 1000


def test_relay_dust_ltc_is_10x_bitcoin_core():
    assert relay_dust_satoshi(FEE_ADDR, fallback=1000, coin="LTC") == 2940


def test_relay_dust_doge_is_hard_dust():
    assert relay_dust_satoshi("D7Y55gGczu2hTfxgAQvZybTh9fYpkN2p3z", fallback=1000, coin="DOGE") == 100_000


def _store_keys(store_service):
    store_service.parse_store_id.side_effect = lambda v: int(v) if v is not None else 1
    key_a = MagicMock(id=10, change=0, address="bc1qa")
    key_change = MagicMock(id=11, change=1, address="bc1qc", used=False)
    store_service.store_address_keys.return_value = [key_a, key_change]
    store_service.pick_change_key.return_value = key_change
    return key_a, key_change


class TestMakeMultipayoutSingleTx:
    @patch("app.services.payout.decimal_value_to_satoshi", side_effect=lambda a: int(Decimal(str(a)) * 100_000_000))
    @patch("app.services.payout.store_service")
    def test_all_outputs_in_one_send(self, store_service, _to_sats):
        _store_keys(store_service)

        tx = MagicMock()
        tx.__str__ = MagicMock(return_value="txid-shared")
        wallet_hd = MagicMock()
        wallet_hd.send.return_value = tx
        wallet_hd.network.dust_amount = 1000

        wallet = MagicMock()
        wallet.is_valid_address.return_value = True
        wallet.current_wallet.return_value = wallet_hd

        node = MagicMock()
        node.get_transaction_price.return_value = Decimal("0.00001")

        svc = PayoutService(wallet_service=wallet, node_service=node)
        results = svc.make_multipayout(
            [
                {"dest": "bc1qfee", "amount": "0.1"},
                {"dest": "bc1qcold", "amount": "0.9"},
            ],
            coin_fee=Decimal("1"),
            store_id=2,
        )

        wallet_hd.send.assert_called_once()
        wallet.current_wallet.assert_called_once_with(store_id=2)
        output_arr = wallet_hd.send.call_args.args[0]
        assert output_arr == [
            ("bc1qfee", 10_000_000),
            ("bc1qcold", 90_000_000),
        ]
        assert wallet_hd.send.call_args.kwargs["input_key_id"] == [10, 11]
        assert wallet_hd.send.call_args.kwargs["change_key_id"] == 11
        tx.send.assert_called_once()

        assert len(results) == 2
        assert results[0]["txids"] == ["txid-shared"]
        assert results[1]["txids"] == ["txid-shared"]
        assert results[0]["status"] == "success"
        assert results[1]["dest"] == "bc1qcold"
        node.get_transaction_price.assert_called_once()

    @patch("app.services.payout.decimal_value_to_satoshi", side_effect=lambda a: int(Decimal(str(a)) * 100_000_000))
    @patch("app.services.payout.store_service")
    def test_coin_fee_is_converted_to_sat_per_kb(self, store_service, _to_sats):
        _store_keys(store_service)
        tx = MagicMock()
        tx.__str__ = MagicMock(return_value="txid-fee")
        wallet_hd = MagicMock()
        wallet_hd.send.return_value = tx
        wallet_hd.network.dust_amount = 1000
        wallet = MagicMock()
        wallet.is_valid_address.return_value = True
        wallet.current_wallet.return_value = wallet_hd
        svc = PayoutService(wallet_service=wallet, node_service=MagicMock())
        svc.node.get_transaction_price.return_value = Decimal("0.00001")

        svc.make_multipayout(
            [{"dest": "bc1qfee", "amount": "0.1"}],
            coin_fee=Decimal("0.00005"),
            store_id=2,
        )

        assert wallet_hd.send.call_args.kwargs["fee_per_kb"] == 5_000

    @patch("app.services.payout.decimal_value_to_satoshi", side_effect=lambda a: int(Decimal(str(a)) * 100_000_000))
    @patch("app.services.payout.store_service")
    def test_doge_clamps_fee_to_network_min(self, store_service, _to_sats):
        _store_keys(store_service)
        tx = MagicMock()
        tx.__str__ = MagicMock(return_value="txid-doge-fee")
        wallet_hd = MagicMock()
        wallet_hd.send.return_value = tx
        wallet_hd.network.dust_amount = 1000
        wallet_hd.network.fee_min = 1_000_000
        wallet = MagicMock()
        wallet.is_valid_address.return_value = True
        wallet.current_wallet.return_value = wallet_hd
        svc = PayoutService(wallet_service=wallet, node_service=MagicMock())
        svc.node.get_transaction_price.return_value = Decimal("0.00001")

        svc.make_multipayout(
            [{"dest": "D7Y55gGczu2hTfxgAQvZybTh9fYpkN2p3z", "amount": "1"}],
            coin_fee=Decimal("0.00005"),
            store_id=1,
        )

        assert wallet_hd.send.call_args.kwargs["fee_per_kb"] == 1_000_000

    @patch("app.services.payout.decimal_value_to_satoshi", side_effect=lambda a: int(Decimal(str(a)) * 100_000_000))
    @patch("app.services.payout.store_service")
    def test_zero_coin_fee_falls_back_to_node_sat_per_kb(self, store_service, _to_sats):
        _store_keys(store_service)
        tx = MagicMock()
        tx.__str__ = MagicMock(return_value="txid-node-fee")
        wallet_hd = MagicMock()
        wallet_hd.send.return_value = tx
        wallet_hd.network.dust_amount = 1000
        wallet = MagicMock()
        wallet.is_valid_address.return_value = True
        wallet.current_wallet.return_value = wallet_hd
        svc = PayoutService(wallet_service=wallet, node_service=MagicMock())
        svc.node.get_transaction_price.return_value = Decimal("0.00001")

        svc.make_multipayout(
            [{"dest": "bc1qfee", "amount": "0.1"}],
            coin_fee=Decimal("0"),
            store_id=2,
        )

        assert wallet_hd.send.call_args.kwargs["fee_per_kb"] == 1_000

    @patch("app.services.payout.decimal_value_to_satoshi", side_effect=lambda a: int(Decimal(str(a)) * 100_000_000))
    @patch("app.services.payout.store_service")
    def test_int_zero_coin_fee_from_celery_json_uses_node(self, store_service, _to_sats):
        _store_keys(store_service)
        tx = MagicMock()
        tx.__str__ = MagicMock(return_value="txid-int-zero")
        wallet_hd = MagicMock()
        wallet_hd.send.return_value = tx
        wallet_hd.network.dust_amount = 1000
        wallet = MagicMock()
        wallet.is_valid_address.return_value = True
        wallet.current_wallet.return_value = wallet_hd
        svc = PayoutService(wallet_service=wallet, node_service=MagicMock())
        svc.node.get_transaction_price.return_value = Decimal("0.00001")

        svc.make_multipayout(
            [{"dest": "bc1qfee", "amount": "0.1"}],
            coin_fee=0,
            store_id=2,
        )

        assert wallet_hd.send.call_args.kwargs["fee_per_kb"] == 1_000

    @patch("app.services.payout.decimal_value_to_satoshi", side_effect=lambda a: int(Decimal(str(a)) * 100_000_000))
    @patch("app.services.payout.store_service")
    def test_send_error_is_payout_failure(self, store_service, _to_sats):
        _store_keys(store_service)
        tx = MagicMock()
        tx.error = "Cannot send transaction. rpc down"
        wallet_hd = MagicMock()
        wallet_hd.send.return_value = tx
        wallet_hd.network.dust_amount = 1000
        wallet = MagicMock()
        wallet.is_valid_address.return_value = True
        wallet.current_wallet.return_value = wallet_hd
        svc = PayoutService(wallet_service=wallet, node_service=MagicMock())
        svc.node.get_transaction_price.return_value = Decimal("0.00001")

        results = svc.make_multipayout(
            [{"dest": "bc1qfee", "amount": "0.1"}],
            coin_fee=Decimal("1"),
            store_id=2,
        )

        tx.send.assert_called_once()
        assert results[0]["status"] == "error"
        assert results[0]["error"] == "Cannot send transaction. rpc down"
        assert "txids" not in results[0]

    @patch("app.services.payout.decimal_value_to_satoshi", side_effect=lambda a: int(Decimal(str(a)) * 100_000_000))
    @patch("app.services.payout.store_service")
    def test_sends_p2wpkh_fee_above_core_dust(self, store_service, _to_sats):
        _store_keys(store_service)
        tx = MagicMock()
        tx.__str__ = MagicMock(return_value="txid-ok")
        wallet_hd = MagicMock()
        wallet_hd.send.return_value = tx
        wallet_hd.network.dust_amount = 1000
        wallet = MagicMock()
        wallet.is_valid_address.return_value = True
        wallet.current_wallet.return_value = wallet_hd
        svc = PayoutService(wallet_service=wallet, node_service=MagicMock())
        svc.node.get_transaction_price.return_value = Decimal("0.00001")

        results = svc.make_multipayout(
            [
                {"dest": FEE_ADDR, "amount": "0.00000936"},
                {"dest": MERCHANT_ADDR, "amount": "0.00008419"},
            ],
            coin_fee=Decimal("1"),
            store_id=2,
        )

        output_arr = wallet_hd.send.call_args.args[0]
        assert output_arr == [
            (FEE_ADDR, 936),
            (MERCHANT_ADDR, 8419),
        ]
        assert [r["status"] for r in results] == ["success", "success"]

    @patch("app.services.payout.decimal_value_to_satoshi", side_effect=lambda a: int(Decimal(str(a)) * 100_000_000))
    @patch("app.services.payout.store_service")
    def test_skips_dust_fee_and_sends_merchant(self, store_service, _to_sats):
        _store_keys(store_service)
        tx = MagicMock()
        tx.__str__ = MagicMock(return_value="txid-merchant")
        wallet_hd = MagicMock()
        wallet_hd.send.return_value = tx
        wallet_hd.network.dust_amount = 1000
        wallet = MagicMock()
        wallet.is_valid_address.return_value = True
        wallet.current_wallet.return_value = wallet_hd
        svc = PayoutService(wallet_service=wallet, node_service=MagicMock())
        svc.node.get_transaction_price.return_value = Decimal("0.00001")

        results = svc.make_multipayout(
            [
                {"dest": FEE_ADDR, "amount": "0.00000036"},
                {"dest": MERCHANT_ADDR, "amount": "0.00000319"},
            ],
            coin_fee=Decimal("1"),
            store_id=2,
        )

        output_arr = wallet_hd.send.call_args.args[0]
        assert output_arr == [(MERCHANT_ADDR, 319)]
        assert results[0]["dest"] == MERCHANT_ADDR
        assert results[0]["status"] == "success"
        assert results[0]["txids"] == ["txid-merchant"]
        assert results[1]["dest"] == FEE_ADDR
        assert results[1]["status"] == "error"
        assert "below dust" in results[1]["error"]

    @patch("app.services.payout.decimal_value_to_satoshi", side_effect=lambda a: int(Decimal(str(a)) * 100_000_000))
    @patch("app.services.payout.store_service")
    def test_rejects_when_all_outputs_are_dust(self, store_service, _to_sats):
        _store_keys(store_service)
        wallet_hd = MagicMock()
        wallet_hd.network.dust_amount = 1000
        wallet = MagicMock()
        wallet.is_valid_address.return_value = True
        wallet.current_wallet.return_value = wallet_hd
        svc = PayoutService(wallet_service=wallet, node_service=MagicMock())

        try:
            svc.make_multipayout(
                [{"dest": FEE_ADDR, "amount": "0.00000036"}],
                coin_fee=Decimal("1"),
                store_id=2,
            )
        except Exception as exc:
            assert "below dust" in str(exc)
        else:
            raise AssertionError("expected dust output to raise")

    @patch("app.services.payout.COIN", "LTC")
    @patch("app.services.payout.decimal_value_to_satoshi", side_effect=lambda a: int(Decimal(str(a)) * 100_000_000))
    @patch("app.services.payout.store_service")
    def test_ltc_skips_fee_below_core_dust_and_sends_merchant(self, store_service, _to_sats):
        _store_keys(store_service)
        tx = MagicMock()
        tx.__str__ = MagicMock(return_value="txid-ltc")
        wallet_hd = MagicMock()
        wallet_hd.send.return_value = tx
        wallet_hd.network.dust_amount = 1000
        wallet = MagicMock()
        wallet.is_valid_address.return_value = True
        wallet.current_wallet.return_value = wallet_hd
        svc = PayoutService(wallet_service=wallet, node_service=MagicMock())
        svc.node.get_transaction_price.return_value = Decimal("0.00001")

        results = svc.make_multipayout(
            [
                {"dest": FEE_ADDR, "amount": "0.00002000"},
                {"dest": MERCHANT_ADDR, "amount": "0.00005000"},
            ],
            coin_fee=Decimal("1"),
            store_id=1,
        )

        output_arr = wallet_hd.send.call_args.args[0]
        assert output_arr == [(MERCHANT_ADDR, 5000)]
        assert results[0]["dest"] == MERCHANT_ADDR
        assert results[0]["status"] == "success"
        assert results[1]["dest"] == FEE_ADDR
        assert results[1]["status"] == "error"
        assert "2940 sat" in results[1]["error"]

    @patch("app.services.payout.COIN", "LTC")
    @patch("app.services.payout.decimal_value_to_satoshi", side_effect=lambda a: int(Decimal(str(a)) * 100_000_000))
    @patch("app.services.payout.store_service")
    def test_ltc_rejects_when_all_outputs_below_core_dust(self, store_service, _to_sats):
        _store_keys(store_service)
        wallet_hd = MagicMock()
        wallet_hd.network.dust_amount = 1000
        wallet = MagicMock()
        wallet.is_valid_address.return_value = True
        wallet.current_wallet.return_value = wallet_hd
        svc = PayoutService(wallet_service=wallet, node_service=MagicMock())

        try:
            svc.make_multipayout(
                [
                    {"dest": FEE_ADDR, "amount": "0.00000036"},
                    {"dest": MERCHANT_ADDR, "amount": "0.00000319"},
                ],
                coin_fee=Decimal("1"),
                store_id=1,
            )
        except Exception as exc:
            assert "below dust" in str(exc)
            assert "2940 sat" in str(exc)
        else:
            raise AssertionError("expected LTC dust outputs to raise")
        wallet_hd.send.assert_not_called()

    @patch("app.services.payout.COIN", "DOGE")
    @patch("app.services.payout.decimal_value_to_satoshi", side_effect=lambda a: int(Decimal(str(a)) * 100_000_000))
    @patch("app.services.payout.store_service")
    def test_doge_skips_fee_below_hard_dust_and_sends_merchant(self, store_service, _to_sats):
        _store_keys(store_service)
        tx = MagicMock()
        tx.__str__ = MagicMock(return_value="txid-doge")
        wallet_hd = MagicMock()
        wallet_hd.send.return_value = tx
        wallet_hd.network.dust_amount = 1000
        wallet = MagicMock()
        wallet.is_valid_address.return_value = True
        wallet.current_wallet.return_value = wallet_hd
        svc = PayoutService(wallet_service=wallet, node_service=MagicMock())
        svc.node.get_transaction_price.return_value = Decimal("0.00001")

        results = svc.make_multipayout(
            [
                {"dest": FEE_ADDR, "amount": "0.00050000"},
                {"dest": MERCHANT_ADDR, "amount": "0.00200000"},
            ],
            coin_fee=Decimal("1"),
            store_id=1,
        )

        output_arr = wallet_hd.send.call_args.args[0]
        assert output_arr == [(MERCHANT_ADDR, 200_000)]
        assert results[0]["status"] == "success"
        assert results[1]["status"] == "error"
        assert "100000 sat" in results[1]["error"]

    @patch("app.services.payout.COIN", "DOGE")
    @patch("app.services.payout.decimal_value_to_satoshi", side_effect=lambda a: int(Decimal(str(a)) * 100_000_000))
    @patch("app.services.payout.store_service")
    def test_doge_rejects_single_output_below_hard_dust(self, store_service, _to_sats):
        _store_keys(store_service)
        wallet_hd = MagicMock()
        wallet_hd.network.dust_amount = 1000
        wallet = MagicMock()
        wallet.is_valid_address.return_value = True
        wallet.current_wallet.return_value = wallet_hd
        svc = PayoutService(wallet_service=wallet, node_service=MagicMock())

        try:
            svc.make_multipayout(
                [{"dest": "D7Y55gGczu2hTfxgAQvZybTh9fYpkN2p3z", "amount": "0.00000700"}],
                coin_fee=Decimal("1"),
                store_id=1,
            )
        except Exception as exc:
            assert "below dust" in str(exc)
            assert "100000 sat" in str(exc)
        else:
            raise AssertionError("expected DOGE dust output to raise")
        wallet_hd.send.assert_not_called()


class TestAssertSourcesBelongToStore:
    def _key(self, store_id):
        key = MagicMock()
        key.wallet = MagicMock(store_id=store_id)
        return key

    @patch("app.services.payout.store_service")
    def test_accepts_matching_source_store(self, store_service):
        store_service.parse_store_id.side_effect = lambda v, required=True: int(v) if v is not None else 1
        store_service.store_key_by_address.return_value = self._key(2)

        PayoutService().assert_sources_belong_to_store(
            [{"source": "bc1qsrc", "dest": "bc1qdst"}], 2
        )
        store_service.store_key_by_address.assert_called_once_with(2, "bc1qsrc")
        store_service.address_is_known.assert_not_called()

    @patch("app.services.payout.store_service")
    def test_rejects_source_from_another_store(self, store_service):
        store_service.parse_store_id.side_effect = lambda v, required=True: int(v) if v is not None else 1
        store_service.store_key_by_address.return_value = None
        store_service.address_is_known.return_value = True

        try:
            PayoutService().assert_sources_belong_to_store(
                [{"source": "bc1qsrc", "dest": "bc1qdst"}], 2
            )
        except Exception as exc:
            assert str(exc) == "Source address 'bc1qsrc' does not belong to store_id=2"
        else:
            raise AssertionError("expected source store mismatch to raise")

    @patch("app.services.payout.store_service")
    def test_rejects_unassigned_legacy_wallet(self, store_service):
        store_service.parse_store_id.side_effect = lambda v, required=True: int(v) if v is not None else 1
        store_service.store_key_by_address.return_value = None
        store_service.address_is_known.return_value = True

        try:
            PayoutService().assert_sources_belong_to_store(
                [{"source": "bc1qlegacy", "dest": "bc1qdst"}], 1
            )
        except Exception as exc:
            assert str(exc) == "Source address 'bc1qlegacy' does not belong to store_id=1"
        else:
            raise AssertionError("expected unassigned wallet to raise")

    @patch("app.services.payout.store_service")
    def test_skips_missing_source_and_unknown_key(self, store_service):
        store_service.parse_store_id.side_effect = lambda v, required=True: int(v) if v is not None else 1
        store_service.store_key_by_address.return_value = None
        store_service.address_is_known.return_value = False

        PayoutService().assert_sources_belong_to_store(
            [{"dest": "bc1qdst"}, {"source": "bc1qunknown"}], 2
        )


class TestWithdrawToExternalWallet:
    @patch("app.services.payout.store_service")
    def test_sweeps_key_from_requested_store(self, store_service):
        store_service.parse_store_id.side_effect = lambda v, required=True: int(v) if v is not None else 1
        key = MagicMock(id=42)
        store_service.store_key_by_address.return_value = key
        tx = MagicMock()
        tx.__str__ = MagicMock(return_value="txid-sweep")
        wallet_hd = MagicMock()
        wallet_hd.sweep.return_value = tx
        wallet = MagicMock()
        wallet.is_valid_address.return_value = True
        wallet.current_wallet.return_value = wallet_hd
        svc = PayoutService(wallet_service=wallet)

        results = svc.withdraw_to_external_wallet_task(
            [{"source": "bc1qsrc", "dest": "bc1qdst"}],
            store_id=2,
        )

        store_service.store_key_by_address.assert_called_once_with(2, "bc1qsrc")
        wallet.current_wallet.assert_called_once_with(store_id=2)
        wallet_hd.sweep.assert_called_once_with("bc1qdst", input_key_id=42)
        tx.send.assert_called_once()
        assert results[0]["status"] == "success"
        assert results[0]["txids"] == ["txid-sweep"]

    @patch("app.services.payout.store_service")
    def test_send_error_is_withdraw_failure(self, store_service):
        store_service.parse_store_id.side_effect = lambda v, required=True: int(v) if v is not None else 1
        store_service.store_key_by_address.return_value = MagicMock(id=42)
        tx = MagicMock()
        tx.error = "Cannot verify transaction"
        wallet_hd = MagicMock()
        wallet_hd.sweep.return_value = tx
        wallet = MagicMock()
        wallet.is_valid_address.return_value = True
        wallet.current_wallet.return_value = wallet_hd
        svc = PayoutService(wallet_service=wallet)

        results = svc.withdraw_to_external_wallet_task(
            [{"source": "bc1qsrc", "dest": "bc1qdst"}],
            store_id=2,
        )

        tx.send.assert_called_once()
        assert results[0]["status"] == "error"
        assert results[0]["error"] == "Cannot verify transaction"

    @patch("app.services.payout.store_service")
    def test_rejects_source_missing_from_store(self, store_service):
        store_service.parse_store_id.side_effect = lambda v, required=True: int(v) if v is not None else 1
        store_service.store_key_by_address.return_value = None
        wallet = MagicMock()
        wallet.is_valid_address.return_value = True
        svc = PayoutService(wallet_service=wallet)

        try:
            svc.withdraw_to_external_wallet_task(
                [{"source": "bc1qsrc", "dest": "bc1qdst"}],
                store_id=2,
            )
        except Exception as exc:
            assert str(exc) == "Source address 'bc1qsrc' not found"
        else:
            raise AssertionError("expected missing store key to raise")
        wallet.current_wallet.assert_not_called()


class TestEstimateTxFee:
    @patch("app.services.payout.decimal_value_to_satoshi", side_effect=lambda a: int(Decimal(str(a)) * 100_000_000))
    @patch("app.services.payout.store_service")
    def test_uses_dry_run_fee_from_selected_utxos(self, store_service, _to_sats):
        _store_keys(store_service)
        tx = MagicMock(fee=12_345)
        wallet_hd = MagicMock(anti_fee_sniping=True)
        wallet_hd.transaction_create.return_value = tx
        wallet = MagicMock()
        wallet.current_wallet.return_value = wallet_hd
        wallet.is_valid_address.return_value = True
        node = MagicMock()
        node.get_transaction_price.return_value = Decimal("0.0005")

        result = PayoutService(wallet_service=wallet, node_service=node).estimate_tx_fee(
            Decimal("0.5"),
            store_id=2,
            dest="bc1qdestxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        )

        assert result["accounts_num"] == 1
        assert result["fee"] == 12_345
        assert result["fee_satoshi"] == 50
        wallet_hd.transaction_create.assert_called_once()
        outputs = wallet_hd.transaction_create.call_args.args[0]
        assert outputs == [("bc1qdestxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 50_000_000)]
        kwargs = wallet_hd.transaction_create.call_args.kwargs
        assert kwargs["input_key_id"] == [10, 11]
        assert kwargs["change_key_id"] == 11
        assert kwargs["fee_per_kb"] == 50_000
        assert kwargs["random_output_order"] is False
        assert wallet_hd.anti_fee_sniping is True

    @patch("app.services.payout.decimal_value_to_satoshi", side_effect=lambda a: int(Decimal(str(a)) * 100_000_000))
    @patch("app.services.payout.store_service")
    def test_retries_with_fee_subtracted_when_full_amount_does_not_fit(self, store_service, _to_sats):
        _store_keys(store_service)
        wallet_hd = MagicMock(anti_fee_sniping=True)
        wallet_hd.transaction_create.side_effect = [
            Exception("Not enough unspent transaction outputs found"),
            MagicMock(fee=9_000),
        ]
        wallet = MagicMock()
        wallet.current_wallet.return_value = wallet_hd
        wallet.is_valid_address.return_value = True
        node = MagicMock()
        node.get_transaction_price.return_value = Decimal("0.0005")

        result = PayoutService(wallet_service=wallet, node_service=node).estimate_tx_fee(
            Decimal("0.5"), store_id=2
        )

        assert result["fee"] == 9_000
        assert wallet_hd.transaction_create.call_count == 2
        first_dest_sats = wallet_hd.transaction_create.call_args_list[0].args[0][0][1]
        second_dest_sats = wallet_hd.transaction_create.call_args_list[1].args[0][0][1]
        assert first_dest_sats == 50_000_000
        assert second_dest_sats == 50_000_000 - 50_000

    @patch("app.services.payout.decimal_value_to_satoshi", side_effect=lambda a: int(Decimal(str(a)) * 100_000_000))
    @patch("app.services.payout.store_service")
    def test_falls_back_to_network_feerate_when_dry_run_fails(self, store_service, _to_sats):
        _store_keys(store_service)
        wallet_hd = MagicMock(anti_fee_sniping=True)
        wallet_hd.transaction_create.side_effect = Exception("Not enough unspent")
        wallet = MagicMock()
        wallet.current_wallet.return_value = wallet_hd
        wallet.is_valid_address.return_value = True
        node = MagicMock()
        node.get_transaction_price.return_value = Decimal("0.0005")

        result = PayoutService(wallet_service=wallet, node_service=node).estimate_tx_fee(
            Decimal("0.5"), store_id=2
        )

        assert result["fee"] == 50 * 226
        assert result["fee_satoshi"] == 50
        assert wallet_hd.anti_fee_sniping is True

    @patch("app.services.payout.decimal_value_to_satoshi", side_effect=lambda a: int(Decimal(str(a)) * 100_000_000))
    @patch("app.services.payout.store_service")
    def test_falls_back_when_wallet_is_missing(self, store_service, _to_sats):
        _store_keys(store_service)
        wallet = MagicMock()
        wallet.current_wallet.return_value = None
        node = MagicMock()
        node.get_transaction_price.return_value = Decimal("0.0005")

        result = PayoutService(wallet_service=wallet, node_service=node).estimate_tx_fee(
            Decimal("0.5"), store_id=2
        )

        assert result["fee"] == 50 * 226
        assert result["fee_satoshi"] == 50


class TestCoinFeeRate:
    def test_zero_means_use_node_feerate(self):
        assert coin_fee_from_sat_per_vbyte(0) == Decimal("0")
        assert coin_fee_from_sat_per_vbyte("0") == Decimal("0")
        assert coin_fee_from_sat_per_vbyte(None) == Decimal("0")

    def test_converts_fractional_sat_per_vb(self):
        assert coin_fee_from_sat_per_vbyte("0.5") == Decimal("0.000005")

    def test_converts_integer_sat_per_vb(self):
        assert coin_fee_from_sat_per_vbyte(50) == Decimal("0.0005")
