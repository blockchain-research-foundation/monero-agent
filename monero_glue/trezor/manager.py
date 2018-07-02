#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


import os
from trezorlib import coins
from trezorlib import tx_api
from trezorlib.client import TrezorClientDebugLink, TrezorClient
from trezorlib.transport import get_transport
from trezorlib.tools import parse_path
from trezorlib import monero, protobuf
from trezorlib import messages as proto

from monero_serialize import xmrserialize
from monero_glue.protocol.messages import MessageConverter
from monero_glue.hwtoken import token, misc
from monero_glue.messages import MoneroExportedKeyImage, \
    MoneroKeyImageExportInit, MoneroKeyImageExportInitResp, \
    MoneroKeyImageSyncStep, MoneroKeyImageSyncStepResp, \
    MoneroKeyImageSyncFinalResp, \
    MoneroGetWatchKey, MoneroGetAddress, \
    MoneroGetKey, \
    MoneroRespError


class TrezorSession(object):
    def __init__(self, client, **kwargs):
        self.client = client

    def __enter__(self):
        self.client.transport.session_begin()
        return self.client

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.client.transport.session_end()


class Trezor(token.TokenLite):
    """
    Trezor proxy calls to the trezor
    """
    def __init__(self, path=None, debug=False, address_n=None, network_type=0, *args, **kwargs):
        super().__init__()
        if path is None:
            path = os.environ.get('TREZOR_PATH', 'udp:127.0.0.1:21324')

        self.debug = debug
        self.path = path
        self.msg_conv = MessageConverter(fix_bytes=True)
        self._connect()

    def _connect(self):
        self.wirelink = get_transport(self.path)
        self.client = TrezorClientDebugLink(self.wirelink) if self.debug else TrezorClient(self.wirelink)

        if self.debug:
            try:
                self.debuglink = self.wirelink.find_debug()
                self.client.set_debuglink(self.debuglink)
            except Exception as e:
                pass

    def _to_tlib(self, msg):
        return self.msg_conv.to_trezorlib(msg)

    def _from_tlib(self, msg):
        return self.msg_conv.to_phlib(msg)

    def reconnect(self):
        self._connect()

    def close(self):
        self.client.close()

    def session(self):
        return TrezorSession(self.client)

    async def call(self, msg, recode=True):
        with self.session():
            if recode:
                msg = self._to_tlib(msg)

            res = self.client.call(msg)

            if recode:
                res = self._from_tlib(res)
            return res

    async def ping(self, message=None, **kwargs):
        with self.session():
            return self.client.ping(message if message else 'monero', **kwargs)

    async def get_view_key(self, msg):
        with self.session():
            res = self.client.call(self._to_tlib(msg))
            return self._from_tlib(res)

    async def get_keys(self, msg):
        with self.session():
            res = self.client.call(self._to_tlib(msg))
            return self._from_tlib(res)

    async def tsx_sign(self, msg):
        with self.session():
            res = self.client.call(self._to_tlib(msg))
            return self._from_tlib(res)

    async def key_image_sync(self, msg, *args, **kwargs):
        with self.session():
            res = self.client.call(self._to_tlib(msg))
            return self._from_tlib(res)

