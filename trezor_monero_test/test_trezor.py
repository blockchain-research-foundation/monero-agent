#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import binascii
import os
import unittest
import zlib

import pkg_resources
from monero_serialize import xmrboost, xmrserialize, xmrtypes

from monero_glue.agent import agent_lite
from monero_glue.hwtoken import token
from monero_glue.xmr import crypto, monero, wallet
from monero_glue.xmr.sub.seed import SeedDerivation
from monero_glue_test.base_tx_test import BaseTxTest
from monero_glue.trezor import manager as tmanager


class TrezorTest(BaseTxTest):
    def __init__(self, *args, **kwargs):
        super(TrezorTest, self).__init__(*args, **kwargs)
        self.trezor_proxy = None  # type: tmanager.Trezor
        self.agent = None  # type: agent_lite.Agent
        self.creds = None

    def get_trezor_path(self):
        tpath = os.getenv('TREZOR_PATH')
        return tpath if tpath is not None else 'udp:127.0.0.1:21324'

    def reinit_trezor(self):
        self.deinit()
        path = self.get_trezor_path()
        self.creds = self.get_trezor_creds(0)
        self.trezor_proxy = tmanager.Trezor(path=path, debug=True)
        self.agent = agent_lite.Agent(self.trezor_proxy, network_type=monero.NetworkTypes.TESTNET)

        client = self.trezor_proxy.client
        client.transport.session_begin()
        client.wipe_device()
        client.load_device_by_mnemonic(
            mnemonic=self.get_trezor_mnemonics()[0],
            pin="",
            passphrase_protection=False,
            label="ph4test",
            language="english",
        )
        client.transport.session_end()

    def deinit(self):
        try:
            if self.trezor_proxy and self.trezor_proxy.client:
                self.trezor_proxy.client.close()
        except Exception as e:
            pass

    def setUp(self):
        super().setUp()
        self.reinit_trezor()

    def tearDown(self):
        self.deinit()
        super().tearDown()

    async def test_ping(self):
        await self.trezor_proxy.ping()

    async def test_get_address(self):
        res = await self.agent.get_address()
        self.assertIsNotNone(res)
        self.assertEqual(res.address, self.creds.address)

    async def test_get_watch(self):
        res = await self.agent.get_watch_only()
        self.assertIsNotNone(res)
        self.assertEqual(res.watch_key, crypto.encodeint(self.creds.view_key_private))
        self.assertEqual(res.address, self.creds.address)

    async def test_ki_sync(self):
        ki_data = self.get_data_file("ki_sync_01.txt")
        ki_loaded = await wallet.load_exported_outputs(
            self.creds.view_key_private, ki_data
        )

        self.assertEqual(ki_loaded.m_spend_public_key, crypto.encodepoint(self.creds.spend_key_public))
        self.assertEqual(ki_loaded.m_view_public_key, crypto.encodepoint(self.creds.view_key_public))
        res = await self.agent.import_outputs(ki_loaded.tds)
        self.assertTrue(len(res) > 0)

    async def test_transactions(self):
        files = self.get_trezor_tsx_tests()
        creds = self.get_trezor_creds(0)
        all_creds = [self.get_trezor_creds(0), self.get_trezor_creds(1), self.get_trezor_creds(2)]

        for fl in files:
            with self.subTest(msg=fl):
                unsigned_tx_c = self.get_data_file(fl)
                unsigned_tx = await wallet.load_unsigned_tx(
                    creds.view_key_private, unsigned_tx_c
                )

                await self.tx_sign_test(self.agent, unsigned_tx, creds, all_creds, fl)
