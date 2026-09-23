from unittest.mock import MagicMock, patch

import sqlalchemy

from app.lib.wallets import WalletError
from app.services.wallet import WalletService


class TestCreateWalletStoreConflict:
    @patch("app.services.wallet.Wallet")
    @patch("app.services.wallet.db")
    def test_integrity_error_returns_existing(self, mock_db, mock_wallet_cls):
        mock_wallet_cls.create.side_effect = sqlalchemy.exc.IntegrityError("INSERT", {}, None)
        winner = MagicMock()
        mock_wallet_cls.return_value = winner
        existing_row = MagicMock()
        existing_row.name = "winner-wallet"
        svc = WalletService()
        with patch.object(svc, "db_wallet", return_value=existing_row):
            wallet, created_flag = svc._create_wallet(store_id=2)

        assert created_flag is False
        assert wallet is winner
        mock_db.session.rollback.assert_called()
        mock_wallet_cls.assert_called_with("winner-wallet")

    @patch("app.services.wallet.Wallet")
    @patch("app.services.wallet.db")
    def test_wallet_error_already_exists_returns_existing(self, mock_db, mock_wallet_cls):
        mock_wallet_cls.create.side_effect = WalletError("Wallet with name 'store-2' already exists")
        winner = MagicMock()
        mock_wallet_cls.return_value = winner
        existing_row = MagicMock()
        existing_row.name = "winner-wallet"
        svc = WalletService()
        with patch.object(svc, "db_wallet", return_value=existing_row):
            wallet, created_flag = svc._create_wallet(store_id=2)

        assert created_flag is False
        assert wallet is winner
        mock_db.session.rollback.assert_called()
        mock_wallet_cls.assert_called_with("winner-wallet")

    @patch("app.services.wallet.Wallet")
    @patch("app.services.wallet.db")
    def test_other_wallet_error_is_reraised(self, mock_db, mock_wallet_cls):
        mock_wallet_cls.create.side_effect = WalletError("Please enter wallet name")
        svc = WalletService()
        try:
            svc._create_wallet(store_id=2)
        except WalletError as exc:
            assert "Please enter wallet name" in str(exc)
        else:
            raise AssertionError("expected unrelated WalletError to raise")

    @patch("app.services.wallet.Wallet")
    @patch("app.services.wallet.db")
    def test_create_writes_store_id_in_same_insert(self, mock_db, mock_wallet_cls):
        created = MagicMock(wallet_id=5)
        mock_wallet_cls.create.return_value = created
        svc = WalletService()

        wallet, created_flag = svc._create_wallet(store_id=2)

        assert created_flag is True
        assert wallet is created
        kwargs = mock_wallet_cls.create.call_args.kwargs
        assert kwargs["store_id"] == 2
        assert kwargs["generated_address_count"] == 1


class TestPrepareWalletForNewAddress:
    def test_new_wallet_uses_index_one(self):
        svc = WalletService()
        new_wallet = MagicMock()
        with patch.object(svc, "db_wallet", return_value=None):
            with patch.object(svc, "_create_wallet", return_value=(new_wallet, True)):
                wallet, idx = svc._prepare_wallet_for_new_address(2)

        assert wallet is new_wallet
        assert idx == 1

    @patch("app.services.wallet.Wallet")
    @patch("app.services.wallet.db")
    def test_lost_race_increments_winner_count(self, mock_db, mock_wallet_cls):
        svc = WalletService()
        winner_row = MagicMock()
        winner_row.name = "winner"
        winner_row.generated_address_count = 1
        winner_row.store_id = 2
        winner_row.migrated = False
        opened = MagicMock()
        mock_wallet_cls.return_value = opened

        with patch.object(svc, "db_wallet", side_effect=[None, winner_row]):
            with patch.object(svc, "_create_wallet", return_value=(MagicMock(), False)):
                wallet, idx = svc._prepare_wallet_for_new_address(2)

        assert wallet is opened
        assert idx == 2
        assert winner_row.generated_address_count == 2

    @patch("app.services.wallet.Wallet")
    @patch("app.services.wallet.db")
    def test_locks_wallet_row_before_increment(self, mock_db, mock_wallet_cls):
        svc = WalletService()
        row = MagicMock()
        row.name = "store-2"
        row.generated_address_count = 4
        row.store_id = 2
        row.migrated = False
        mock_wallet_cls.return_value = MagicMock()

        with patch.object(svc, "db_wallet", return_value=row) as db_wallet:
            wallet, idx = svc._prepare_wallet_for_new_address(2)

        db_wallet.assert_called_with(2, for_update=True)
        assert idx == 5
        assert row.generated_address_count == 5
        mock_db.session.commit.assert_called()
        assert wallet is mock_wallet_cls.return_value


class TestGetAllAccounts:
    @patch("app.services.wallet.get_account_password", return_value="pw")
    @patch("app.services.wallet.Wallet")
    def test_includes_purpose0_receive_paths(self, mock_wallet_cls, _pw):
        wallet = MagicMock()
        wallet.current_index_path.return_value = 1
        wallet.keys.return_value = [
            MagicMock(address="bc1qpurpose0", path="m/0'/0'/3'"),
            MagicMock(address="bc1qsegwit", path="m/84'/1'/0'/0/2"),
            MagicMock(address="bc1qchange", path="m/0'/1'/3'"),
            MagicMock(address="bc1qunexpanded", path="m/0'/0/3"),
            MagicMock(address="", path="m/0'/0'/4'"),
        ]
        mock_wallet_cls.return_value = wallet
        svc = WalletService()
        with patch.object(svc, "wallet_name", return_value="store-1"):
            accounts = svc.get_all_accounts(store_id=1)

        assert accounts == ["bc1qpurpose0", "bc1qsegwit"]


class TestGetDump:
    def _row(self, name, store_id):
        row = MagicMock()
        row.name = name
        row.store_id = store_id
        row.parent_id = None
        return row

    def _key(self, address, wif="wif", key_private=None, key_public=None):
        return MagicMock(
            address=address,
            wif=wif,
            key_private=key_private,
            key_public=key_public,
        )

    def _query_rows(self, mock_db, rows):
        mock_db.session.query.return_value.filter.return_value.order_by.return_value.all.return_value = rows

    def _wallets_by_name(self, mock_wallet_cls, wallets):
        mock_wallet_cls.side_effect = lambda name: wallets[name]

    @patch("app.services.wallet.get_account_password", return_value="pw")
    @patch("app.services.wallet.Wallet")
    @patch("app.services.wallet.db")
    def test_skips_keys_without_address(self, mock_db, mock_wallet_cls, _pw):
        self._query_rows(mock_db, [self._row("w1", 1)])
        wallet = MagicMock()
        wallet.keys.return_value = [
            self._key(""),
            self._key("bc1qok", wif=b"wif"),
        ]
        self._wallets_by_name(mock_wallet_cls, {"w1": wallet})

        dump = WalletService().get_dump(store_id=1, scoped=True)

        assert "" not in dump
        assert "bc1qok" in dump
        assert dump["bc1qok"]["wif"] == "wif"
        assert dump["bc1qok"]["private"] is None
        assert dump["bc1qok"]["public"] is None

    @patch("app.services.wallet.get_account_password", return_value="pw")
    @patch("app.services.wallet.Wallet")
    @patch("app.services.wallet.db")
    def test_dump_uses_walletkey_byte_fields(self, mock_db, mock_wallet_cls, _pw):
        self._query_rows(mock_db, [self._row("w1", 1)])
        wallet = MagicMock()
        wallet.keys.return_value = [
            self._key("bc1qok", key_private=b"\x01\x02", key_public=b"\x03\x04"),
        ]
        self._wallets_by_name(mock_wallet_cls, {"w1": wallet})

        dump = WalletService().get_dump(store_id=1, scoped=True)

        assert dump["bc1qok"]["private"] == "0102"
        assert dump["bc1qok"]["public"] == "0304"

    @patch("app.services.wallet.get_account_password", return_value="pw")
    @patch("app.services.wallet.Wallet")
    @patch("app.services.wallet.db")
    def test_scoped_dump_includes_only_store_wallet(self, mock_db, mock_wallet_cls, _pw):
        self._query_rows(mock_db, [self._row("w1", 1), self._row("w2", 2)])
        w1 = MagicMock()
        w1.keys.return_value = [self._key("bc1qone")]
        w2 = MagicMock()
        w2.keys.return_value = [self._key("bc1qtwo")]
        self._wallets_by_name(mock_wallet_cls, {"w1": w1, "w2": w2})

        dump = WalletService().get_dump(store_id=1, scoped=True)

        assert dump.keys() == {"bc1qone"}

    @patch("app.services.wallet.get_account_password", return_value="pw")
    @patch("app.services.wallet.Wallet")
    @patch("app.services.wallet.db")
    def test_unscoped_dump_includes_only_default_store(self, mock_db, mock_wallet_cls, _pw):
        self._query_rows(mock_db, [self._row("w1", 1), self._row("w2", 2)])
        w1 = MagicMock()
        w1.keys.return_value = [self._key("bc1qone")]
        w2 = MagicMock()
        w2.keys.return_value = [self._key("bc1qtwo")]
        self._wallets_by_name(mock_wallet_cls, {"w1": w1, "w2": w2})

        dump = WalletService().get_dump(store_id=1, scoped=False)

        assert dump.keys() == {"bc1qone"}

    @patch("app.services.wallet.get_account_password", return_value="pw")
    @patch("app.services.wallet.Wallet")
    @patch("app.services.wallet.db")
    def test_dump_rejects_non_default_store(self, mock_db, mock_wallet_cls, _pw):
        try:
            WalletService().get_dump(store_id=2, scoped=True)
        except PermissionError as exc:
            assert "default store" in str(exc)
        else:
            raise AssertionError("expected non-default dump to raise")
        mock_wallet_cls.assert_not_called()

    @patch("app.services.wallet.get_account_password", return_value="pw")
    @patch("app.services.wallet.Wallet")
    @patch("app.services.wallet.db")
    def test_dump_raises_on_wallet_load_failure(self, mock_db, mock_wallet_cls, _pw):
        self._query_rows(mock_db, [self._row("w1", 1)])
        mock_wallet_cls.side_effect = Exception("decrypt failed")

        try:
            WalletService().get_dump(store_id=1, scoped=True)
        except Exception as exc:
            assert str(exc) == "decrypt failed"
        else:
            raise AssertionError("expected dump load failure to raise")

    @patch("app.services.wallet.get_account_password", return_value=None)
    @patch("app.services.wallet.Wallet")
    @patch("app.services.wallet.db")
    def test_dump_requires_password(self, mock_db, mock_wallet_cls, _pw):
        try:
            WalletService().get_dump(store_id=1, scoped=True)
        except PermissionError as exc:
            assert "locked" in str(exc).lower()
        else:
            raise AssertionError("expected locked wallet dump to raise")
        mock_wallet_cls.assert_not_called()
        mock_db.session.query.assert_not_called()


class TestScanBlockService:
    @patch("app.services.wallet.Wallet")
    def test_raises_when_no_wallets(self, mock_wallet_cls):
        svc = WalletService()
        with patch.object(svc, "all_hd_wallets", return_value=[]):
            try:
                svc.scan_block("hash", 10)
                assert False, "expected RuntimeError"
            except RuntimeError as exc:
                assert "No HD wallets" in str(exc)
        mock_wallet_cls.scan_block.assert_not_called()

    @patch("app.services.wallet.Wallet")
    def test_scans_when_wallets_exist(self, mock_wallet_cls):
        svc = WalletService()
        wallets = [MagicMock()]
        with patch.object(svc, "all_hd_wallets", return_value=wallets):
            svc.scan_block("hash", 10)
        mock_wallet_cls.scan_block.assert_called_once_with(
            wallets, block="hash", current_block_height=10
        )


class TestGetStoreBalance:
    @patch("app.services.wallet.get_account_password", return_value=None)
    def test_locked_wallet_raises(self, _pw):
        try:
            WalletService().get_store_balance(store_id=1)
        except PermissionError as exc:
            assert "locked" in str(exc).lower()
        else:
            raise AssertionError("expected locked wallet balance to raise")

    @patch("app.services.wallet.get_account_password", return_value="pw")
    @patch("app.services.wallet.Wallet")
    def test_missing_wallet_is_zero(self, mock_wallet_cls, _pw):
        svc = WalletService()
        with patch.object(svc, "wallet_name", return_value=None):
            balance = svc.get_store_balance(store_id=2)
        assert balance == 0
        mock_wallet_cls.assert_not_called()


class TestAllHdWallets:
    @patch("app.services.wallet.get_account_password", return_value="pw")
    @patch("app.services.wallet.Wallet")
    @patch("app.services.wallet.db")
    def test_propagates_wallet_load_failure(self, mock_db, mock_wallet_cls, _pw):
        row = MagicMock()
        row.name = "broken-wallet"
        mock_db.session.query.return_value.filter.return_value.order_by.return_value.all.return_value = [
            row
        ]
        mock_wallet_cls.side_effect = Exception("decrypt failed")

        try:
            WalletService().all_hd_wallets()
        except Exception as exc:
            assert str(exc) == "decrypt failed"
        else:
            raise AssertionError("expected wallet load failure to raise")
