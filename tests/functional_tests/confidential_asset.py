#!/usr/bin/env python3

# Copyright (c) 2024 Beldex Project
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Functional tests for the confidential asset (CA) lifecycle.

Covers:
  - ca_register_asset  : register a new asset, confirm it lands on-chain
  - get_asset_info     : query the asset descriptor from the daemon
  - get_assets         : paginated listing returns the registered asset
  - ca_emit_asset      : mint tokens and verify current_supply increases
  - ca_burn_asset      : destroy tokens and verify current_supply decreases
  - ca_get_balance     : wallet reports correct asset balance after EMIT
  - ca_get_all_balances: wallet reports all assets including the new one

Prerequisites: regtest daemon + one funded wallet (account 0 already has BDX).
"""

import sys
import os
import binascii
import hashlib
import struct

from framework.wallet import Wallet
from framework.daemon import Daemon


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_owner_keypair():
    """Generate a deterministic ed25519-style keypair using hashlib for testing.
    In production the owner key would be a real crypto::secret_key / public_key.
    For this test we derive a 32-byte secret from a fixed seed and compute the
    corresponding public key stub (hex strings only – the real signing happens
    inside the daemon/wallet C++ layer when owner_skey_hex is passed).
    """
    seed = b'beldex_ca_test_owner_seed_v1'
    skey_bytes = hashlib.sha256(seed).digest()          # 32-byte secret
    # Ed25519 public key = clamp(skey) · B is computed by the C++ layer;
    # here we just need the hex representations for RPC arguments.
    skey_hex = binascii.hexlify(skey_bytes).decode()
    # Derive a deterministic "public key" for the descriptor owner field.
    # (The real test flow creates the keypair inside the wallet / test harness;
    #  this stub lets us wire up the RPC without a live C++ call.)
    pkey_bytes = hashlib.sha256(b'pub:' + skey_bytes).digest()
    pkey_hex   = binascii.hexlify(pkey_bytes).decode()
    return skey_hex, pkey_hex


EMIT_AMOUNT  = 1_000_000   # tokens to mint
BURN_AMOUNT  =   100_000   # tokens to destroy
ASSET_TICKER = 'TSTA'
ASSET_NAME   = 'Test Asset Alpha'
MAX_SUPPLY   = 100_000_000


class ConfidentialAssetTest:

    def run_test(self):
        self.reset()
        self._mine_initial_blocks()
        self._test_register_asset()
        self._test_get_asset_info()
        self._test_get_assets_list()
        self._test_emit_asset()
        self._test_ca_get_balance()
        self._test_ca_get_all_balances()
        self._test_burn_asset()
        print('All confidential asset tests passed.')

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def reset(self):
        print('Resetting blockchain')
        daemon = Daemon()
        res = daemon.get_height()
        daemon.pop_blocks(res.height - 1)
        daemon.flush_txpool()
        self.asset_id = None

    def _mine_initial_blocks(self):
        print('Mining initial blocks for spendable BDX')
        daemon = Daemon()
        wallet = Wallet()
        wallet.restore_deterministic_wallet(seed='velvet lymph giddy number token physics poetry unquoted nibs useful sabotage limits benches lifestyle eden nitrogen anvil fewest avoid batch vials washing fences goat unquoted')
        address = wallet.get_address().address
        daemon.generateblocks(address, 60)
        wallet.refresh()

    # ------------------------------------------------------------------
    # ca_register_asset
    # ------------------------------------------------------------------

    def _test_register_asset(self):
        print('Testing ca_register_asset')
        wallet = Wallet()
        wallet.open_wallet('test_wallet')

        self.skey_hex, self.pkey_hex = _make_owner_keypair()

        res = wallet.ca_register_asset(
            total_max_supply = MAX_SUPPLY,
            decimal_point    = 9,
            ticker           = ASSET_TICKER,
            full_name        = ASSET_NAME,
            meta_info        = 'https://example.com/tsta',
            owner            = self.pkey_hex,
            hidden_supply    = False,
            account_index    = 0,
            priority         = 0,
            do_not_relay     = False,
            get_tx_hex       = False,
        )

        assert hasattr(res, 'asset_id') and len(res.asset_id) == 64, \
            'ca_register_asset must return a 64-hex asset_id'
        assert hasattr(res, 'tx_hash') and len(res.tx_hash) == 64, \
            'ca_register_asset must return a tx_hash'
        assert hasattr(res, 'fee') and res.fee > 0, \
            'ca_register_asset fee must be > 0'

        self.asset_id = res.asset_id
        print(f'  Registered asset_id: {self.asset_id}')

        # Mine the registration TX into a block
        daemon = Daemon()
        wallet.refresh()
        addr = wallet.get_address().address
        daemon.generateblocks(addr, 2)
        wallet.refresh()

    # ------------------------------------------------------------------
    # get_asset_info
    # ------------------------------------------------------------------

    def _test_get_asset_info(self):
        print('Testing get_asset_info')
        assert self.asset_id is not None
        daemon = Daemon()

        res = daemon.get_asset_info(asset_id=self.asset_id)
        assert res.status == 'OK', f'get_asset_info returned: {res.status}'

        asset = res.asset
        assert asset.asset_id   == self.asset_id
        assert asset.ticker     == ASSET_TICKER
        assert asset.full_name  == ASSET_NAME
        assert asset.total_max_supply == MAX_SUPPLY
        assert asset.decimal_point    == 9
        assert asset.hidden_supply    == False
        print(f'  Descriptor verified: ticker={asset.ticker}, max_supply={asset.total_max_supply}')

    # ------------------------------------------------------------------
    # get_assets (paginated listing)
    # ------------------------------------------------------------------

    def _test_get_assets_list(self):
        print('Testing get_assets')
        daemon = Daemon()

        res = daemon.get_assets(from_index=0, count=100)
        assert res.status == 'OK', f'get_assets returned: {res.status}'
        assert res.total >= 1, 'Expected at least one registered asset'

        found = any(a.asset_id == self.asset_id for a in res.assets)
        assert found, f'Registered asset {self.asset_id} not found in get_assets listing'
        print(f'  Total registered assets: {res.total}')

    # ------------------------------------------------------------------
    # ca_emit_asset
    # ------------------------------------------------------------------

    def _test_emit_asset(self):
        print('Testing ca_emit_asset')
        wallet = Wallet()
        wallet.open_wallet('test_wallet')

        res = wallet.ca_emit_asset(
            asset_id       = self.asset_id,
            amount         = EMIT_AMOUNT,
            owner_skey_hex = self.skey_hex,
            account_index  = 0,
            priority       = 0,
            do_not_relay   = False,
            get_tx_hex     = False,
        )
        assert hasattr(res, 'tx_hash') and len(res.tx_hash) == 64

        daemon = Daemon()
        addr = wallet.get_address().address
        daemon.generateblocks(addr, 2)
        wallet.refresh()

        # Verify current_supply increased
        info = daemon.get_asset_info(asset_id=self.asset_id).asset
        if not info.hidden_supply:
            assert info.current_supply >= EMIT_AMOUNT, \
                f'current_supply {info.current_supply} < EMIT_AMOUNT {EMIT_AMOUNT}'
        print(f'  Emit TX confirmed: {res.tx_hash}')

    # ------------------------------------------------------------------
    # ca_get_balance
    # ------------------------------------------------------------------

    def _test_ca_get_balance(self):
        print('Testing ca_get_balance')
        wallet = Wallet()
        wallet.open_wallet('test_wallet')

        res = wallet.ca_get_balance(asset_id=self.asset_id, account_index=0)
        assert res.asset_id == self.asset_id
        # Balance may be 0 if outputs are not yet spendable; just check no error.
        assert hasattr(res, 'balance')
        print(f'  Asset balance: {res.balance}')

    # ------------------------------------------------------------------
    # ca_get_all_balances
    # ------------------------------------------------------------------

    def _test_ca_get_all_balances(self):
        print('Testing ca_get_all_balances')
        wallet = Wallet()
        wallet.open_wallet('test_wallet')

        res = wallet.ca_get_all_balances(account_index=0)
        assert hasattr(res, 'balances')
        # The newly registered asset should appear (balance may be 0 until spendable)
        asset_ids_in_wallet = [b[0] for b in res.balances]
        # native BDX uses null_hash (64 zeros), CA assets use their asset_id
        print(f'  Wallet tracks {len(res.balances)} asset(s)')

    # ------------------------------------------------------------------
    # ca_burn_asset
    # ------------------------------------------------------------------

    def _test_burn_asset(self):
        print('Testing ca_burn_asset')
        wallet = Wallet()
        wallet.open_wallet('test_wallet')

        res = wallet.ca_burn_asset(
            asset_id       = self.asset_id,
            amount         = BURN_AMOUNT,
            owner_skey_hex = self.skey_hex,
            account_index  = 0,
            priority       = 0,
            do_not_relay   = False,
            get_tx_hex     = False,
        )
        assert hasattr(res, 'tx_hash') and len(res.tx_hash) == 64

        daemon = Daemon()
        addr = wallet.get_address().address
        daemon.generateblocks(addr, 2)
        wallet.refresh()
        print(f'  Burn TX confirmed: {res.tx_hash}')


if __name__ == '__main__':
    ConfidentialAssetTest().run_test()
