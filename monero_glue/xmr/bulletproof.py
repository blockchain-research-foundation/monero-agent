#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018
#
# Adapted from Monero C++ code
# Faster exponentiation uses Pippenger algorithm: https://cr.yp.to/papers/pippenger.pdf
#
#

import math

from monero_serialize.core.int_serialize import dump_uvarint_b, dump_uvarint_b_into, uvarint_size
from monero_serialize.xmrtypes import Bulletproof

from monero_glue.compat import gc
from monero_glue.compat import log
from monero_glue.compat.micropython import memcpy

from monero_glue.xmr import crypto


# Constants

BP_LOG_N = 6
BP_N = 1 << BP_LOG_N  # 64
BP_M = 16  # maximal number of bulletproofs

ZERO = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
ONE = b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
TWO = b"\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
EIGHT = b"\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
INV_EIGHT = b"\x79\x2f\xdc\xe2\x29\xe5\x06\x61\xd0\xda\x1c\x7d\xb3\x9d\xd3\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06"
MINUS_ONE = b"\xec\xd3\xf5\x5c\x1a\x63\x12\x58\xd6\x9c\xf7\xa2\xde\xf9\xde\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10"
MINUS_INV_EIGHT = b"\x74\xa4\x19\x7a\xf0\x7d\x0b\xf7\x05\xc2\xda\x25\x2b\x5c\x0b\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0a"

# Monero H point
XMR_H = b"\x8b\x65\x59\x70\x15\x37\x99\xaf\x2a\xea\xdc\x9f\xf1\xad\xd0\xea\x6c\x72\x51\xd5\x41\x54\xcf\xa9\x2c\x17\x3a\x0d\xd3\x9c\x1f\x94"
XMR_HP = crypto.gen_H()

# get_exponent(Gi[i], XMR_H, i * 2 + 1)
BP_GI_PRE = b"\x0b\x48\xbe\x50\xe4\x9c\xad\x13\xfb\x3e\x01\x4f\x3f\xa7\xd6\x8b\xac\xa7\xc8\xa9\x10\x83\xdc\x9c\x59\xb3\x79\xaa\xab\x21\x8f\x15\xdf\x01\xa5\xd6\x3b\x3e\x3a\x38\x38\x2a\xfb\xd7\xbc\x68\x5f\x34\x3d\x61\x92\xda\x16\xed\x4b\x45\x1f\x15\xfd\xda\xb1\x70\xe2\x2d\x73\x69\xc8\xd5\xa7\x45\x42\x3d\x26\x06\x23\xa1\xf7\x5f\xae\x1f\xb1\xf8\x1b\x16\x9d\x42\x2a\xcd\x85\x58\xe9\xd5\x74\x25\x48\xbd\x81\xc0\x7d\x2b\xd8\x77\x1e\xb4\xbd\x84\x15\x5d\x38\xd7\x05\x31\xfe\x66\x2b\x78\xf0\xc4\x4a\x9a\xea\xea\x2e\xd2\xd6\xf0\xeb\xe1\x08\x96\xc5\xc2\x2f\x00\x70\xeb\xf0\x55\xdf\xe8\xdc\x1c\xb2\x05\x42\xef\x29\x15\x1a\xa0\x77\x1e\x58\x1e\x68\xfe\x78\x18\xef\x42\x35\xc8\xdf\x1a\x32\xae\xce\xed\xef\xcb\xdf\x6d\x91\xd5\x24\x92\x9b\x84\x02\xa0\x26\xcb\x85\x74\xe0\xe3\xa3\x34\x2c\xe2\x11\xbc\xd9\x67\xbc\x14\xe7\xab\xda\x6c\x17\xc2\xf2\x2a\x38\x1b\x84\xc2\x49\x75\x78\x52\xe9\x9d\x62\xc4\x5f\x16\x0e\x89\x15\xec\x21\xd4\xc8\xa3\x83\x1d\x7c\x2f\x24\x58\x1e\xc9\xd1\x50\x13\xdf\xcc\xb5\xeb\xa6\x9d\xf6\x91\xa0\x80\x02\xb3\x3d\x4f\x2f\xb0\x6c\xa9\xf2\x9c\xfb\xc7\x0d\xb0\x23\xa4\x8e\x45\x35\xf5\x83\x8f\x5e\xa2\x7f\x70\x98\x0d\x11\xec\xd9\x35\xb4\x78\x25\x8e\x2a\x4f\x10\x06\xb3\x2d\xa6\x38\x72\x92\x25\x9e\x69\xac\x0a\x82\x9e\xf3\x47\x69\x98\x96\x72\x8c\x0c\xc0\xca\xdc\x74\x6d\xae\x46\xfb\x31\x86\x4a\x59\xa5\xb9\xa1\x54\x9c\x77\xe4\xcf\x8a\xb8\xb2\x55\xa3\xa0\xae\xfa\xa4\xca\xd1\x25\xd2\x19\x94\x9c\x0a\xef\xf0\xc3\x56\x0a\xb1\x58\xed\x67\x17\x48\xa1\x75\x56\x41\x9e\xc9\x42\xe1\x6b\x90\x1d\xbb\x2f\xc6\xdf\x96\x60\x32\x4f\xcb\xcd\x6e\x40\xf2\x35\xd7\x5b\x76\x4f\xaf\xf6\x1c\x19\x05\x22\x2b\xaf\x87\xd5\x1d\x45\xf3\x55\x81\x38\xc8\x7c\xe5\x4c\x46\x4c\xc6\x40\xb9\x55\xe7\xfa\x33\x10\xf8\x3b\x13\xdd\x7b\x24\x73\x19\xe1\x3c\xe6\x19\x95\xbc\x77\x1e\xe1\xed\xe7\x36\x35\x99\xf0\x8f\xc5\xcf\xda\x89\x0e\xa8\x03\xe0\xec\xa7\x0a\x97\x70\x7e\x90\x56\x29\xa5\xe0\x6d\x18\x6a\x96\x4f\x32\x2f\xff\xba\xa7\xed\x2e\x78\x1d\x4d\x3f\xed\xe0\x74\x61\xf4\x4b\x2d\x98\xdb\xcc\x0c\xaa\x20\x55\x14\x6e\x13\xf5\x0e\xcf\x75\x49\x1d\xad\xd3\x6a\xd2\xba\xac\x56\xbc\x08\x56\x2e\xc6\x6c\xe1\x10\xb5\x44\x83\x1d\xbd\x34\xc6\xc2\x52\x95\x81\x51\xc4\x9a\x73\x4c\x6e\x62\x5e\x42\x60\x8c\x00\x5e\x79\x7e\xdb\x6d\x0a\x89\x34\xb3\x24\xa0\xe4\xd3\x1c\xba\x01\x57\x83\x50\x1e\xcd\xfa\x7a\x8e\xba\xe3\xa6\xbf\xd3\x2e\x6d\x1a\x36\x14\xb1\x11\x83\xc8\x09\x80\xd4\x54\x6c\xc3\xee\x5d\xb4\x7b\xfe\x97\x05\xaa\x95\xe2\xda\x29\xf2\x28\x23\x03\x53\x91\x7e\x5d\x2b\x19\x32\xfe\x48\x2f\xbc\xfe\xd7\x13\x4d\x55\x6d\x0c\x27\xf6\xcc\x6b\xf3\x01\x5c\x06\x61\x16\x25\x73\x9d\x88\x9c\x57\x89\xfa\x75\xb3\xc8\x39\x69\xcb\x88\xb1\xdf\x01\xc0\xac\xa4\x70\xf6\x65\xeb\x71\x82\xe0\x72\xbc\xa8\x9b\xc6\x69\xff\xe5\xb0\x29\x6f\xe2\x13\x43\xa8\xc3\x27\xc8\xa8\x41\x75\x02\x85\x5a\x25\xcc\xb7\x5b\x2f\x8e\xea\xc5\xd1\xdb\x25\x04\x4b\x0a\xea\xd2\xcf\x77\x02\x1e\xd9\x4f\x79\xf3\x00\x1e\x7b\x8e\x9d\xb7\x31\x1d\xb2\x8c\x45\xc9\x0d\x80\xa1\xe3\xd5\xb2\x7b\x43\xf8\xe3\x80\x21\x4d\x6a\x2c\x40\x46\xc8\xd4\x0f\x52\x4d\x47\x83\x53\x20\x4d\x01\xa1\x7c\x4f\xb7\xb1\x8c\x2f\x48\x27\x01\x50\xdb\x67\xd4\xb0\xb9\xce\x87\x86\xe0\x3c\x95\x50\xc5\x47\xfb\x18\x02\x9e\xf1\x6e\x56\x29\xe9\xa1\xc6\x68\xe1\xaa\x79\xc7\x88\x73\x55\xf5\xf5\x1b\x0c\xbb\x1f\x08\x35\xe0\x4e\x7a\xcc\x53\xac\x55\xa3\x57\x41\x97\xb5\x4c\x5a\xaa\xad\x47\xbe\x24\xdb\xbc\x11\xc1\xbd\x3e\xeb\x62\x46\x54\x2d\x2f\x5a\xe5\xf4\x39\x8d\xd4\xa7\x60\x17\x03\xcb\xbf\xd5\x9b\xad\xdd\x3a\x7c\xe6\xe3\x75\xe7\xd9\x00\x50\xe2\x71\xb1\x3f\x13\x2d\xf8\x5e\x1c\x12\xbe\x54\xfe\x66\xde\x81\xf6\x8a\x1c\x8f\x69\x6f\x3e\x77\x3c\x7e\xef\x57\xac\x13\x89\xbd\x02\x80\xd5\x58\xea\x78\x62\xf0\x1b\x64\x1e\xc6\xda\x0e\xfe\xfb\xee\xd0\x50\x9c\x53\x8a\x8c\x36\x16\x68\x1d\x76\x1a\xe5\xc6\xf9\xd2\xaa\xde\xd7\x18\x90\xda\x24\x96\x15\x60\x43\x08\x21\x82\xec\x85\x9c\x3a\xe4\x86\x93\xf9\x13\x43\xd0\xa5\xf0\xec\xbb\x7d\xec\x9b\x97\x3b\xf2\x13\x67\x8a\x65\x3b\x0d\x9d\xf5\x10\x65\x2a\x23\xc0\xb8\x06\x53\x67\x92\x4a\x4c\xfc\x78\x60\x36\xc0\x66\xca\xa7\x38\x34\x9c\xf1\xcd\xa7\x0d\xbf\xa8\x5c\xce\xb4\xa0\x9f\x85\x03\x9b\x6f\x77\x27\x4f\xa6\xe2\x79\x35\xbf\x89\xae\x37\x3a\x3b\x5a\xda\x58\x24\xbd\x4b\x2a\xec\x22\x2a\xeb\xd7\xfe\xe7\xa4\x82\xe9\xc1\x33\x58\xea\xb2\x5f\x94\x22\x36\xf3\xf4\xb6\xeb\xaf\xe1\xc3\xee\xee\xf7\x93\x83\x66\x80\x66\x7c\x66\x94\x64\xc3\xd4\xa0\x84\x7d\xf3\x02\x4b\xd5\xdf\x2a\xa4\xaa\x4d\x19\xe5\x51\xed\xe9\x3d\xd0\x75\xf7\x95\x3a\xca\xe5\x3f\x0f\x9e\x8a\x38\x4e\x49\x6c\x52\x50\xb0\x7e\x76\x17\xe8\x9e\x28\xf9\x53\xd0\x96\xec\x29\x87\xeb\xd8\xf3\xe7\x4d\x93\x39\x63\xb8\x27\x73\xd3\x7a\xb1\xb7\xa3\x60\x1d\xc8\x97\x13\x34\x82\x5d\xd1\xd6\x7e\x4c\x48\x29\x72\x92\xa0\x7a\x40\x62\x96\x75\xb3\xe8\x78\x8e\xfc\x68\x73\x85\x30\x04\x81\xae\x69\x74\x06\xd2\x4e\xf8\x8e\xbf\x9c\xa1\x97\x2c\x1d\x52\x84\x78\x85\x8e\xad\x85\x78\x2e\xd4\x10\xeb\xbc\x1f\x3d\xa4\x8b\xa8\x07\x83\x62\x36\xaa\xc0\xa8\xf0\x8a\x50\x29\x11\x5d\x57\xe7\xef\x18\xcb\x27\xcc\xe8\xd2\xc1\x57\xa9\xf4\xf5\x61\x5d\xcc\x34\x8a\xea\xc8\x0d\x0f\x28\xdf\x33\xba\xbe\x39\xf6\xec\xbd\x19\xa4\xa6\xaf\xa8\x53\xaa\x4d\xa0\x3b\x6b\xd7\xa8\x06\x22\x9d\xed\x76\xd2\xc5\xb9\xde\x11\x76\xd5\x19\xa7\x93\x94\x67\x92\xb5\x41\x7e\xaf\x7d\x2d\x51\x26\x97\x7c\x57\x04\xfc\x0f\xcd\x8e\x1b\x2f\x58\x9b\x1d\x41\x8d\x19\xdd\x28\xf7\xe9\x4c\x51\xa1\x78\x2d\x32\x2e\x03\xcb\xa4\x78\x85\x74\x24\x49\x7b\x4a\x37\x3f\xde\x0f\xba\xe4\xcc\xd9\x38\xcb\xbf\xa0\xf4\xad\x23\x97\xee\xd7\xf7\x6d\xc3\xcd\xb6\xb0\x6a\x36\x66\x0c\x07\x75\xd3\x91\xca\x47\x21\x33\x41\xf6\x59\xe9\x01\x4f\x70\x28\x4e\xfa\xa5\xfa\xab\xa4\xbb\x83\x79\xce\x02\x04\xf5\xae\xdc\x28\x26\x8d\x82\x43\x8b\x5b\x88\x1f\xdf\x2d\xee\x4a\xd7\xd4\x0e\xd1\x3d\xad\x57\xca\x92\x96\x14\xa6\x3a\x00\xfe\x3a\x78\xf3\x3b\x30\xb6\xfd\x5f\x39\xe4\x43\x70\x36\xdc\xed\x8d\x87\xaf\x43\x28\x2f\x43\xfa\x14\xab\xaf\x6c\x84\x15\xfc\x05\xee\x1a\xd1\x71\xd8\x1f\xaa\x46\x7d\xdf\xe5\xe0\x2e\xb6\x89\x5e\x56\x88\xde\xc0\x48\xf6\x66\x0e\x3a\x2f\xd8\xbd\xec\x60\x2a\xf5\x95\x90\xec\x4c\x6e\xab\x83\x4c\xc0\xde\xc8\x62\x1e\xb5\x10\xfb\xa6\xf7\xad\xf4\x76\x93\xc2\xfd\x57\x4d\x82\x20\xa2\xe7\x0e\x73\xad\x68\xe4\xc3\x32\x48\x8e\xb8\xe7\x31\xfe\x60\x0d\x1e\x9f\x6b\x8f\x5c\xbf\x69\x9c\x18\xd0\x6b\xcd\x73\xb7\xcf\xce\xf4\x2e\x68\xaf\x7a\xe6\x7f\xea\x46\xe9\x46\xde\x6a\x61\xfa\xa4\x2c\x53\x5c\xfc\xae\xaa\xd5\x33\x4f\xc1\xa9\xba\xd4\xa5\x3e\x57\xd1\x1c\x6a\xcc\xfc\xef\xd2\xe8\xab\x44\xcb\x12\xfb\x2e\x66\x4f\xcb\xdf\x5c\x82\xb2\x12\x89\x62\x6a\xc2\xa1\x40\x2b\xde\x7a\x86\x9e\xb9\xed\x78\x07\x33\x8d\xd3\xb2\xba\x82\x37\x84\x5d\xb9\x67\x71\xcc\x98\x80\x08\x1a\xcf\x05\x3d\x9b\xd5\x1c\x01\x01\x94\x1c\x4c\x26\xf6\x6a\xa5\xdb\xad\x3f\x53\x54\x60\x85\x77\xf9\xe5\x1a\xfe\x74\x3a\xdd\x50\xf1\xb5\x90\x1b\xea\x7b\xeb\x5a\xe7\x80\xb6\xec\xe9\x77\xf6\x5b\x9c\x62\x8e\x1d\xce\x0a\xd1\xe0\x78\xc7\x46\xc2\xf3\x8d\x0e\x7f\x06\xb0\x88\x70\x8a\xe9\xac\x11\x17\xe3\xa3\x79\x99\xc1\xd7\x5a\x62\xe9\xc9\xe0\x17\x01\x8e\x08\x8a\xeb\xfb\x37\x8d\xe2\x9c\x78\x93\xac\xf1\x09\x42\x58\x4b\xf5\x58\xa2\xd0\x2d\x75\x1e\x34\xf3\xf4\x84\xb0\x01\xe3\x19\x24\xcc\x21\x84\x8b\xf0\xdd\xaf\x1f\x3d\x8a\x31\x00\x49\x73\x6f\xf7\xf0\x49\x29\x4d\x8a\x59\x5f\x2c\xa7\x26\x3a\x36\x13\x84\x0c\x14\xb3\x3e\xf4\x83\xcd\xca\x5b\xbb\x8a\x4c\x70\x04\xcc\xb8\xf6\x71\x56\x26\x7e\xe3\x5f\x28\x0d\xb1\x26\x45\xde\x8e\x55\x2a\x93\x12\xdf\x57\x69\xa0\x30\xa6\xb4\x6d\x80\xdb\x2e\x6c\x06\xb3\xc7\x6c\x1a\xda\x42\x37\x3b\x29\xa0\x59\x1f\x39\x85\x67\x49\xdf\xdf\xb2\x66\x81\x16\x6a\x28\x6f\xb4\xf2\x09\x7a\x3b\x6f\x8f\xeb\xdb\xe4\x41\x3b\x67\xb5\x58\x68\x9c\x2e\x7c\x1d\x6d\x64\x08\xf4\x6a\x60\x94\xc7\x4b\x22\x81\xe7\x96\xe1\xd9\x00\xcc\x83\x53\x37\xa3\x1b\x53\x50\xca\xa9\xc4\x44\xc6\x70\xf7\x8f\x86\x6e\x03\xef\x6e\xc2\xcb\xcb\xc1\x79\x97\x41\x45\xb2\x39\xb9\x09\x12\xbb\xee\xf8\xf5\x76\x96\x1b\x5e\xfc\x69\x64\x1f\x7a\x71\x51\x70\x87\x75\xb6\x7c\x9e\x65\xed\x9b\xb9\xf5\xa8\x7b\xb7\x90\xda\x20\x35\x57\xbe\xd2\x67\x40\x55\xe8\xa6\xab\x36\x46\xc4\xe1\xa8\x45\xea\x53\xd8\x61\x4a\xe4\x90\x06\x5d\xef\x75\x76\x15\xa2\x65\xf2\xab\x98\x38\x80\x29\xae\xc3\xaf\xb5\xcc\xa3\xa6\x66\xab\x29\xb6\xd2\xc0\x02\x97\x9c\x63\x6a\x3b\x41\xb8\x83\x7a\x43\x2a\x81\xd6\xdb\x55\xcf\x40\x6b\x1f\x58\x42\xb0\xa8\x87\xfe\x6b\x2b\xd8\x8e\x46\x29\x8e\xd3\xec\xc3\x87\x4c\x98\x37\x73\x46\x33\x1f\xde\x7a\x2f\xf7\xf1\x04\x26\x5b\xbd\x2d\x02\x74\xc0\x33\xc7\x58\x38\x51\x00\x1d\xcd\xb3\xde\xd9\x0a\x9c\x09\x77\xc1\xf8\x6d"

# get_exponent(Hi[i], XMR_H, i * 2)
BP_HI_PRE = b"\x42\xba\x66\x8a\x00\x7d\x0f\xcd\x6f\xea\x40\x09\xde\x8a\x64\x37\x24\x8f\x2d\x44\x52\x30\xaf\x00\x4a\x89\xfd\x04\x27\x9b\xc2\x97\xe5\x22\x4e\xf8\x71\xee\xb8\x72\x11\x51\x1d\x2a\x5c\xb8\x1e\xea\xa1\x60\xa8\xa5\x40\x8e\xab\x5d\xea\xeb\x9d\x45\x58\x78\x09\x47\x8f\xc5\x47\xc0\xc5\x2e\x90\xe0\x1e\xcd\x2c\xe4\x1b\xfc\x62\x40\x86\xf0\xec\xdc\x26\x0c\xf3\x0e\x1b\x9c\xae\x3b\x18\xed\x6b\x2c\x9f\x11\x04\x41\x45\xda\x98\xe3\x11\x1b\x40\xa1\x07\x8e\xa9\x04\x57\xb2\x8b\x01\x46\x2c\x90\xe3\xd8\x47\x94\x9e\xd8\xc1\xd3\x1d\x17\x96\x37\xec\x75\x65\xf7\x6f\xa2\x0a\xcc\x47\x1b\x16\x94\xb7\x95\xca\x44\x61\x8e\x4c\xc6\x8e\x0a\x46\xb2\x0f\x91\xe8\x67\x77\x25\x1d\xad\x91\xf0\xd5\xd4\x51\xd7\xe9\x4b\xfc\xd4\x13\x93\x4c\x1d\xa1\x73\xa9\x2d\xdc\x0d\x5e\x0e\x4c\x2c\xfb\xe5\x92\x5b\x0b\x88\x9c\x80\x22\xf3\xa7\xe4\x2f\xcf\xd4\xea\xcd\x06\x31\x63\x15\xc8\xc0\x6c\xb6\x67\x17\x6e\x8f\xd6\x75\xe1\x8a\x22\x96\x10\x0a\xd3\x42\x06\xfc\xf4\x44\x35\x7b\xe1\xe9\x87\x2f\x59\xd7\x1c\x4e\x66\xaf\xdf\x7c\x19\x6b\x6a\x59\x6b\xe2\x89\x0c\x0a\xea\x92\x8a\x9c\x69\xd2\xc4\xdf\x3b\x9c\x52\x8b\xce\x2c\x0c\x30\x6b\x62\x91\xde\xa2\x8d\xe1\xc0\x23\x32\x87\x19\xe9\xa1\xba\x1d\x84\x9c\x1b\xb4\x46\xbc\x0b\x0d\x37\x76\x25\x0d\xd6\x6d\x97\x27\xc2\x5d\x0e\xfe\xb0\xf9\x31\xfc\x53\x7a\xb2\xbd\x9f\x89\x78\x21\x6f\x6e\xb6\xe4\x23\xfa\xe0\xd3\x74\xd3\x4a\x20\x69\x4e\x39\x7a\x70\xb8\x4b\x75\xe3\xbe\x14\xb2\xcf\x53\x01\xc7\xcb\xc6\x62\x50\x96\x71\xa5\xe5\x93\x73\x6f\x61\x13\xc3\xf2\x88\xec\x00\xa1\xcc\x2f\xc7\x15\x6f\x4f\xff\xa1\x74\x8e\x9b\x2c\x2d\xdf\x2f\x43\x03\xbb\xfe\x7f\xfc\xee\x5e\x57\xb3\xb8\x42\x06\xa9\x1b\xcf\x32\xf7\x12\xc7\x5e\x5f\xa5\x10\x87\x85\xb8\xcc\x24\x47\x99\x83\x12\xca\x31\xab\x85\x00\xc8\x2c\x62\x68\x45\x39\xa2\x70\x01\xfb\x17\xf2\xa5\x64\x9d\xb2\xe2\xd6\x4b\x6b\x88\xf0\xd6\x81\x00\x9a\xe7\x8e\xae\xce\x9c\x73\x57\x80\x2c\x6c\x1c\xd8\x1e\xf6\x24\x86\x89\x85\x40\x89\xaa\xd6\x94\x47\x33\x91\xba\xd6\x18\xef\x01\xdf\xd6\x80\x98\x1a\x78\x97\x18\xe9\xd7\xca\xef\x06\x3d\xeb\x2d\x67\x5f\xe8\x43\xea\x63\x4d\xcf\x96\x77\xc1\xd3\xee\x92\x51\x39\x71\xb7\x24\xc7\x88\xe4\x10\x7a\x42\x40\xfe\x26\xe5\xfb\x36\xcc\x00\x7e\x76\x58\x96\x48\x82\xf7\x69\xf1\x8c\x78\x6a\xb1\x52\xf2\x5c\x5d\x2a\xe4\x72\xf7\x1e\x40\x13\xc4\xb0\xc5\x78\x7d\xc1\xd7\x8b\xdc\x8d\x52\x33\x10\x39\xaf\x41\x24\x11\x2e\xe9\x34\x6f\x11\x0a\x4e\x81\x18\xe8\x64\x11\x5d\x49\xb0\x82\xc8\x38\x51\xd4\xd5\xe1\x10\xa4\xab\xda\xdd\xbd\xa9\xb0\x22\x7f\x5b\x26\xbf\x52\xd5\xa2\x25\x25\x23\x59\x72\x84\x3d\xe9\x1d\x99\xd0\x09\x1f\x17\xf4\x78\x2d\x4f\xeb\x2b\x76\x0c\xd5\x8b\x6f\x24\x76\xe8\xb0\x2d\x90\x8a\x15\x15\x07\x8a\xa8\x08\xaa\x3a\x56\x5e\xfc\xb7\x16\x9f\xe0\xcb\xf7\x2c\x12\xce\x17\x50\xf2\x86\x1f\xb6\xc6\x85\x16\x13\xcb\xe9\x74\xef\xc1\x68\x4a\xeb\xbe\x8b\x8a\x52\x2a\xbb\xe7\x82\x77\xd0\xda\xa7\x89\x2d\x9d\xa8\x7c\x27\xbe\xcd\x3e\xc0\x38\x95\x23\x3a\xd4\x66\x31\x8c\x44\x3c\x4d\x6d\x5c\xf1\x2e\xba\x7d\xbd\x3e\x84\x32\x9d\xf6\x1a\xfc\x9b\x7e\x08\xfc\x13\x32\xa6\x82\x34\x42\x73\x39\x6e\xc7\xdc\xdc\xbe\xae\x48\xff\x70\xa1\x9a\x31\xd6\x62\x44\x3c\xce\x57\xf7\x7a\xfe\x05\x0b\x81\x22\x48\x60\x25\x5b\xcb\xc8\xf4\x80\xc4\x3c\xfd\xeb\xb1\xb2\xa6\x89\x72\xb7\xd3\x32\x3b\x03\x61\xf3\xa1\x14\x2f\x8b\x45\x2e\x92\x98\x77\x3d\xef\x56\x35\xc2\xe2\xef\xa3\x70\x0e\x4c\xc9\xe5\xd8\xde\x78\x96\x7e\x57\x35\x82\xcf\x7c\x74\x97\x7c\x30\xb5\x46\x9b\x2c\x0b\xac\xe8\xec\x25\x9f\x71\xba\x25\xc8\xdd\x1c\x51\xe5\xb0\x24\x1c\xca\x7c\x86\xf7\x18\xb7\xd2\xc3\xd4\x57\xa6\xe5\xe0\xb3\x9f\x1f\x39\xeb\xaf\xbb\x08\x83\xd4\x27\xd9\x36\x47\x60\x15\xad\x88\xb7\x92\xa0\x31\xe4\xdd\x98\x37\x57\xc9\x9a\xea\x39\x12\xe8\xf8\xc2\xf6\x59\xde\x4b\xc1\xa2\x20\x4c\xea\x13\x2e\x4f\x9e\xf7\x17\x77\x11\x91\x53\x63\x9a\x71\xff\x24\x17\xf5\x22\xfe\x41\xb8\x7e\x9c\x1c\xb7\x66\x9f\x40\xf9\xd6\x85\x88\x7d\xff\x81\x92\x7a\xa4\x2e\xda\x7f\x2a\x69\x67\x89\x09\x10\x33\xcf\x5b\xe2\xfc\x1f\x5f\x3a\x2d\xe2\x27\x15\xeb\x33\xd6\x28\x28\x92\x2d\xac\x86\x2e\xfc\x7f\xc6\xd5\x4c\x99\xe6\xec\x6e\x58\xc0\xb6\x4d\xa9\x57\xe7\x36\xd3\x00\x93\xc8\x67\xa1\x20\xd5\xdb\xfc\x55\x03\xca\x27\x64\x05\xdf\x4b\x2d\xbe\x6c\xfe\x7c\x2c\x56\xbc\xd2\x66\x9f\x1b\x7d\x82\xc9\xf9\x29\x91\xbf\x41\x02\xaf\x61\x10\xbf\x1b\xf5\xbd\xae\x89\x7f\x9a\x06\x42\x09\xcf\x31\x29\x96\x53\x13\x7e\x86\x5f\x90\x5c\x89\x29\x44\x91\x39\x54\x5a\xc8\x25\x3c\x32\xbe\x19\xcc\x8b\xd8\x54\xca\x7c\xdb\x07\xc2\xae\xba\x12\xa1\x4c\xcf\xa3\x08\x5f\x9f\xfd\x9f\x75\x39\x80\xc9\xd4\x5b\x7b\x4e\x0f\x5b\xe4\x6d\xf3\xae\x5c\x10\xc1\x89\xf1\xdc\x9e\xd2\x59\x2e\x24\x6b\xd2\x44\x9a\xa0\xda\xae\x45\x8a\xe8\xbf\xbd\x52\xf9\x83\xc3\xde\x44\x12\x37\x26\x71\x9c\x08\xd4\xc3\x7c\x8c\x9b\x0b\xe1\x7b\x6b\x49\x82\x61\x36\xaa\x7b\x90\x85\x31\xbc\x91\x73\x2b\x08\x7a\x41\x36\x03\x0b\xad\x7b\x5b\x1c\xfa\x7d\x9c\x98\xa9\xdc\x34\x7a\x92\x65\x1f\x29\xc2\xe1\x10\xaf\xf8\x89\x7f\x26\x7c\x04\x22\x10\xa6\xb7\x0a\x31\x3c\xc0\x6a\xfa\x2b\xd9\xc2\x91\x15\x37\xd6\x09\xd6\x8b\xec\x94\x32\xe8\x4b\x96\x79\x52\x7d\x6a\xbb\x58\x8b\xa7\x2b\xb2\x14\x98\x70\x69\xd8\x0b\x0a\xbc\x2b\xbd\x68\xeb\xa0\x33\x1e\x3a\xe5\xf4\x10\x6f\x7f\xc1\xe2\xe7\xb8\xd6\xe5\x37\x0e\x32\x01\xcc\xe2\xa0\x36\xb6\x8e\xd3\x54\x31\x63\x39\xf0\x92\xde\xc7\x66\x2b\xce\xbd\xd2\x06\x61\x11\xd1\x6c\xe5\x5a\x93\x7e\x2c\x61\x90\x7b\xc3\x66\xc8\x85\xda\xa3\x74\x95\xbe\x67\x1e\xf6\xc2\xf2\xe5\x54\xed\xe3\xb5\x3c\xe2\x80\xcb\xe8\x8a\x48\xb9\xd9\x74\x0e\x98\x0c\xea\xf8\x04\xed\xcd\x8c\x96\x85\x81\x93\xe6\xd5\x17\x8b\xf6\x04\xcc\x73\xbd\x8f\xaa\xd5\x0d\x53\x15\x49\x99\x31\x97\xcc\x27\x28\x27\x21\x6d\x1a\xf9\xdc\xc6\xe9\x86\x2a\x6e\x53\xa0\xa2\xc7\x32\x98\xe1\xfa\xdc\x0f\x91\x48\xcb\xc8\x5e\xc0\x56\x7c\x38\x76\x9c\x27\x65\xd6\x54\xc4\x26\x9f\x6e\xf1\x39\x47\xf1\x3c\x23\x9c\xbb\x08\xb7\xcf\x67\xa2\x5b\xac\x03\x0a\xd1\xb8\x92\xc4\x34\x79\x24\x64\x49\xf5\x32\x8d\xac\x31\x41\xd3\xd7\xc8\xa9\xa2\x54\x0d\xca\xc2\xcb\xc9\x8e\x27\x84\x31\x43\xe7\xd4\xb9\x6d\xde\x75\x21\xfc\x70\xb3\x28\x0a\x2a\x4c\x5f\x39\x28\x7f\x5d\x24\xd7\xa7\x59\xea\x03\x7b\x11\x44\x87\x39\xee\x2a\x28\xfc\x4b\x16\x0e\xac\x40\x61\x08\xae\xe6\xb5\x80\x62\x13\x11\xfe\x03\x0b\xf0\x8b\x4f\x6e\xed\x3d\x7d\x3d\x86\x93\xd3\xac\x52\x4d\xa2\xb4\xeb\xf1\x9e\x25\x59\xdc\x50\xff\x35\xe6\x2d\xa6\x20\xdc\x0a\x02\xed\xcb\xe4\xf3\x98\xb1\xbd\x86\xea\x15\x4b\x6a\x94\x00\x57\x9e\x3f\x1c\xd5\x7f\xdc\x2f\x10\xbd\x8c\xdb\x16\x7c\x0b\x28\x3f\x90\x07\xe6\x20\xd9\xca\x28\x06\x7f\xe2\xb0\x15\xed\x65\x7c\x91\x53\xb8\x44\x3d\x77\xe8\xe2\x5f\xf3\x48\xf4\xdf\x78\xbb\xc1\xce\x20\xa7\xba\xbd\xe4\x0e\xd2\xbd\xbe\xaf\x2b\x5c\xd9\x8e\x52\x02\xba\xf7\xe3\xdc\xf1\x8b\xa1\x15\x62\x0c\x51\xae\x8b\x58\xb4\x92\x3b\x9a\x86\x94\xc9\x3d\xf6\x4b\x17\x8c\x4c\xd2\xf9\xf6\xef\xc5\x1f\x45\x8b\x0c\x5e\xe8\x60\xa4\x0a\xc8\xce\xc3\x50\x6e\xc8\x5b\x99\xdc\x71\x6b\x95\xcb\xb3\x42\xdb\x91\xad\xe4\xb6\x1e\x17\x7f\x60\xf9\xfa\xbb\xff\x2c\x9b\xad\xee\x04\xcf\xd7\x41\xd6\x6d\x2f\x26\x32\x1e\x2c\xf5\x0a\x3c\xd0\x21\xf6\x28\x88\x63\xde\x2d\xad\xf8\xd5\x2d\x1f\x8b\x9f\x51\x42\x43\x05\xa3\xd4\x07\x96\x29\x63\xc1\xd0\xbe\xeb\x81\x13\xf8\x03\x07\xec\xc2\x19\x23\x94\x7f\xe8\xcb\xaf\x5c\x2c\x05\xae\x63\x69\x85\x21\x99\xc5\x2a\x17\x97\xb9\xaf\xf2\xa9\x24\x5d\x7a\x8b\x91\x72\xd5\x72\xb4\x43\x2f\x63\x44\x1f\xf5\x1c\x4a\x4e\x27\x0e\x3b\x61\xea\xe6\xe1\x3e\xef\xe3\x5e\x85\x42\x7b\xc7\x58\xef\x4a\xf4\xc0\x0f\x9c\x77\x52\x1c\x03\x61\xd2\x99\x43\x1f\x9d\x8e\x29\x8c\x13\x41\x4c\x46\x17\x0a\x1d\x82\xa1\x38\x0f\xba\xfe\x53\x1c\xa7\x01\x84\xab\x89\x65\xc4\xc8\x07\x06\x0e\x80\x39\xfe\xc4\x61\x5e\x59\x09\xd2\x7a\xc5\xca\x80\x41\xe3\xf9\x5b\x27\xf1\xc3\xd4\xd4\x06\xa2\x04\x8b\x1e\x6c\xe1\xe6\x37\xcb\x87\xc0\xf9\x7d\x36\x17\xd4\x6a\xef\xfd\xd1\xe8\x13\xc2\x55\xfb\x8b\x3e\xf9\x39\xa2\xc5\xfa\xd4\xd1\x09\x73\xc0\x8c\x05\x5f\x79\x13\xc5\x16\x64\x58\x9d\xa5\x14\x5a\x9c\x59\x72\xf4\xb2\x12\xeb\xf5\x11\x71\xd9\x23\x43\x83\x3a\x08\x95\x3c\xd8\x0c\xd0\xd9\x08\x90\x4c\x56\x3e\xdc\x34\x29\x42\x21\x86\x56\x33\xd8\xcf\x6f\xf5\x04\x44\xb9\xd2\x9b\xeb\x05\xa4\x7b\x8b\xb1\x21\xcb\x11\x8d\x6c\xb1\x6b\x24\xc4\x45\x09\x8a\xa9\x0e\x6d\x5a\x10\xea\xe0\xa0\xf3\x97\x7a\x28\x08\xf7\x9c\xaf\xe8\xf8\x70\x52\x97\xbd\x91\xeb\xbf\x27\x92\xa1\x89\x2c\xb0\x09\xdb\x0b\x7a\xc3\x51\xd0\x35\x3f\x43\xfe\x3a\xa9\x71\x92\xe8\xb9\xd7\xfe\xf5\xba\xec\x41\x5b\x0c\xa4\x8c\x92\x0e\x7c\xdd\x78\xf9\x24\x6a\xd2\x54\xe8\x7e\xe1\xb0\x65\x84\xb8\x60\xb0\xb8\x80\x0a\xae\xe1\x78\x96\xf0\x29\x0c\xb7\x89\xb0\xd7"

# oneN = vector_powers(rct::identity(), BP_N);
# BP_ONE_N = None  # Eval vector to save memory

# twoN = vector_powers(TWO, BP_N);
BP_TWO_N = b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

# ip12 = inner_product(oneN, twoN);
BP_IP12 = b"\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


#
# Rct keys operation
#

tmp_bf_1 = bytearray(32)
tmp_bf_2 = bytearray(32)

tmp_pt_1 = crypto.new_point()
tmp_pt_2 = crypto.new_point()
tmp_pt_3 = crypto.new_point()
tmp_pt_4 = crypto.new_point()

tmp_sc_1 = crypto.new_scalar()
tmp_sc_2 = crypto.new_scalar()
tmp_sc_3 = crypto.new_scalar()
tmp_sc_4 = crypto.new_scalar()


def _ensure_dst_key(dst=None):
    if dst is None:
        dst = bytearray(32)
    return dst


def copy_key(dst, src):
    for i in range(32):
        dst[i] = src[i]
    return dst


def copy_vector(dst, src):
    for i in range(len(src)):
        copy_key(dst[i], src[i])
    return dst


def init_key(val, dst=None):
    dst = _ensure_dst_key(dst)
    return copy_key(dst, val)


def invert(dst, x):
    """
    Modular inversion mod curve order.

    Naive approach using large arithmetics in Python.
    Should be moved to the crypto provider later.
    :param x: 32byte contracted
    :param dst:
    :return:
    """
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(tmp_sc_1, x)
    crypto.sc_inv_into(tmp_sc_2, tmp_sc_1)
    crypto.encodeint_into(tmp_sc_2, dst)
    return dst


def scalarmult_key(dst, P, s):
    dst = _ensure_dst_key(dst)
    crypto.decodepoint_into(tmp_pt_1, P)
    crypto.decodeint_into_noreduce(tmp_sc_1, s)
    crypto.scalarmult_into(tmp_pt_2, tmp_pt_1, tmp_sc_1)
    crypto.encodepoint_into(tmp_pt_2, dst)
    return dst


def scalarmult8(dst, P):
    dst = _ensure_dst_key(dst)
    crypto.decodepoint_into(tmp_pt_1, P)
    crypto.ge_mul8_into(tmp_pt_2, tmp_pt_1)
    crypto.encodepoint_into(tmp_pt_2, dst)
    return dst


def scalarmultH(dst, x):
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into(tmp_sc_1, x)
    crypto.scalarmult_into(tmp_pt_1, XMR_HP, tmp_sc_1)
    crypto.encodepoint_into(tmp_pt_1, dst)
    return dst


def scalarmult_base(dst, x):
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(tmp_sc_1, x)
    crypto.scalarmult_base_into(tmp_pt_1, tmp_sc_1)
    crypto.encodepoint_into(tmp_pt_1, dst)
    return dst


def sc_gen(dst=None):
    dst = _ensure_dst_key(dst)
    crypto.random_scalar_into(tmp_sc_1)
    crypto.encodeint_into(tmp_sc_1, dst)
    return dst


def full_gen(dst=None):
    dst = _ensure_dst_key(dst)
    b = crypto.random_bytes(32)
    copy_key(dst, b)
    return dst


def sc_add(dst, a, b):
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(tmp_sc_1, a)
    crypto.decodeint_into_noreduce(tmp_sc_2, b)
    crypto.sc_add_into(tmp_sc_3, tmp_sc_1, tmp_sc_2)
    crypto.encodeint_into(tmp_sc_3, dst)
    return dst


def sc_sub(dst, a, b):
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(tmp_sc_1, a)
    crypto.decodeint_into_noreduce(tmp_sc_2, b)
    crypto.sc_sub_into(tmp_sc_3, tmp_sc_1, tmp_sc_2)
    crypto.encodeint_into(tmp_sc_3, dst)
    return dst


def sc_mul(dst, a, b):
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(tmp_sc_1, a)
    crypto.decodeint_into_noreduce(tmp_sc_2, b)
    crypto.sc_mul_into(tmp_sc_3, tmp_sc_1, tmp_sc_2)
    crypto.encodeint_into(tmp_sc_3, dst)
    return dst


def sc_muladd(dst, a, b, c):
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(tmp_sc_1, a)
    crypto.decodeint_into_noreduce(tmp_sc_2, b)
    crypto.decodeint_into_noreduce(tmp_sc_3, c)
    crypto.sc_muladd_into(tmp_sc_4, tmp_sc_1, tmp_sc_2, tmp_sc_3)
    crypto.encodeint_into(tmp_sc_4, dst)
    return dst


def sc_mulsub(dst, a, b, c):
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(tmp_sc_1, a)
    crypto.decodeint_into_noreduce(tmp_sc_2, b)
    crypto.decodeint_into_noreduce(tmp_sc_3, c)
    crypto.sc_mulsub_into(tmp_sc_4, tmp_sc_1, tmp_sc_2, tmp_sc_3)
    crypto.encodeint_into(tmp_sc_4, dst)
    return dst


def add_keys(dst, A, B):
    dst = _ensure_dst_key(dst)
    crypto.decodepoint_into(tmp_pt_1, A)
    crypto.decodepoint_into(tmp_pt_2, B)
    crypto.point_add_into(tmp_pt_3, tmp_pt_1, tmp_pt_2)
    crypto.encodepoint_into(tmp_pt_3, dst)
    return dst


def sub_keys(dst, A, B):
    dst = _ensure_dst_key(dst)
    crypto.decodepoint_into(tmp_pt_1, A)
    crypto.decodepoint_into(tmp_pt_2, B)
    crypto.point_sub_into(tmp_pt_3, tmp_pt_1, tmp_pt_2)
    crypto.encodepoint_into(tmp_pt_3, dst)
    return dst


def add_keys2(dst, a, b, B):
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(tmp_sc_1, a)
    crypto.decodeint_into_noreduce(tmp_sc_2, b)
    crypto.decodepoint_into(tmp_pt_1, B)
    crypto.add_keys2_into(tmp_pt_2, tmp_sc_1, tmp_sc_2, tmp_pt_1)
    crypto.encodepoint_into(tmp_pt_2, dst)
    return dst


def add_keys3(dst, a, A, b, B):
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(tmp_sc_1, a)
    crypto.decodeint_into_noreduce(tmp_sc_2, b)
    crypto.decodepoint_into(tmp_pt_1, A)
    crypto.decodepoint_into(tmp_pt_2, B)
    crypto.add_keys3_into(tmp_pt_3, tmp_sc_1, tmp_pt_1, tmp_sc_2, tmp_pt_2)
    crypto.encodepoint_into(tmp_pt_3, dst)
    return dst


def hash_to_scalar(dst, data):
    dst = _ensure_dst_key(dst)
    crypto.hash_to_scalar_into(tmp_sc_1, data)
    crypto.encodeint_into(tmp_sc_1, dst)
    return dst


def hash_vct_to_scalar(dst, data):  # TODO: frag-optim
    dst = _ensure_dst_key(dst)
    ctx = crypto.get_keccak()
    for x in data:
        ctx.update(x)
    crypto.encodeint_into(crypto.decodeint(ctx.digest()), dst)
    return dst


def get_exponent(dst, base, idx):
    dst = _ensure_dst_key(dst)
    salt = b"bulletproof"
    buff = bytearray(len(salt) + 32 + 1)  # assume varint occupies 1 B
    memcpy(buff, 0, base, 0, 32)
    memcpy(buff, 32, salt, 0, len(salt))
    dump_uvarint_b_into(idx, buff, 32 + len(salt))
    h1 = crypto.cn_fast_hash(buff)
    pt = crypto.hash_to_ec(h1)
    crypto.encodepoint_into(pt, dst)
    return dst


#
#
#


class KeyV(object):
    """
    KeyVector abstraction
    Constant precomputed buffers = bytes, frozen. Same operation as normal.
    """

    def __init__(self, elems=64, src=None, buffer=None, const=False):
        self.current_idx = 0
        self.d = None
        self.mv = None
        self.size = elems
        self.const = const
        if src:
            self.d = bytearray(src.d)
            self.size = src.size
        elif buffer:
            self.d = buffer  # can be immutable (bytes)
            self.size = len(buffer) // 32
        else:
            self.d = bytearray(32 * elems)
        self._set_mv()

    def _set_mv(self):
        self.mv = memoryview(self.d)

    def __getitem__(self, item):
        """
        Returns corresponding 32 byte array
        :param item:
        :return:
        """
        return self.mv[item * 32 : (item + 1) * 32]

    def __setitem__(self, key, value):
        """
        Sets given key to the particular place
        :param key:
        :param value:
        :return:
        """
        if self.const:
            raise ValueError("Constant KeyV")
        ck = self[key]
        for i in range(32):
            ck[i] = value[i]

    def __iter__(self):
        self.current_idx = 0
        return self

    def __next__(self):
        if self.current_idx >= self.size:
            raise StopIteration
        else:
            self.current_idx += 1
            return self[self.current_idx - 1]

    def __len__(self):
        return self.size

    def slice(self, res, start, stop):
        for i in range(start, stop):
            res[i - start] = self[i]
        return res

    def slice_r(self, start, stop):
        res = KeyV(stop - start)
        return self.slice(res, start, stop)

    def copy_from(self, src):
        self.size = self.size
        self.d = bytearray(self.d)
        self._set_mv()

    def copy(self, dst=None):
        if dst:
            dst.copy_from(self)
        else:
            dst = KeyV(src=self)
        return dst

    def resize(self, nsize, chop=False):
        if self.size == nsize:
            return self
        elif self.size > nsize and not chop:
            self.d = self.d[: nsize * 32]
        else:
            self.d = bytearray(nsize * 32)
        self.size = nsize
        self._set_mv()


class KeyVEval(KeyV):
    """
    KeyVector computed / evaluated on demand
    """

    def __init__(self, elems=64, src=None):
        super().__init__(elems)
        self.size = elems
        self.fnc = src
        self.buff = _ensure_dst_key()
        self.mv = memoryview(self.buff)

    def __getitem__(self, item):
        return self.fnc(item, self.mv)

    def __setitem__(self, key, value):
        raise ValueError("Constant vector")

    def slice(self, res, start, stop):
        raise ValueError("Not supported")

    def slice_r(self, start, stop):
        raise ValueError("Not supported")

    def copy(self, dst=None):
        raise ValueError("Not supported")

    def resize(self, nsize, chop=False):
        raise ValueError("Not supported")


class KeyVSized(KeyV):
    """
    Resized vector, wrapping possibly larger vector
    (e.g., precomputed, but has to have exact size for further computations)
    """
    def __init__(self, wrapped, new_size):
        super().__init__(wrapped)
        self.size = new_size
        self.wrapped = wrapped

    def __getitem__(self, item):
        return self.wrapped[item]

    def __setitem__(self, key, value):
        self.wrapped[key] = value

    def resize(self, nsize, chop=False):
        raise ValueError('Not supported')


class KeyVPrecomp(KeyV):
    """
    Vector with possibly large size and some precomputed prefix.
    Usable for Gi vector with precomputed usual sizes (i.e., 2 output transactions)
    but possible to compute further
    """
    def __init__(self, size, precomp_prefix, aux_comp_fnc):
        super().__init__(size)
        self.size = size
        self.precomp_prefix = precomp_prefix
        self.aux_comp_fnc = aux_comp_fnc

    def __getitem__(self, item):
        if item < len(self.precomp_prefix):
            return self.precomp_prefix[item]
        return self.aux_comp_fnc(item, None)

    def __setitem__(self, key, value):
        raise ValueError('Not supported')

    def resize(self, nsize, chop=False):
        raise ValueError('Not supported')


def _ensure_dst_keyvect(dst=None, size=None):
    if dst is None:
        dst = KeyV(elems=size)
    if size is not None:
        dst.resize(size)
    return dst


def const_vector(val, elems=BP_N):
    return KeyVEval(elems=elems, src=lambda x, d: copy_key(d, val))


def consume_vct(vct):
    for i in range(64):
        vct[i]


def vector_exponent_custom(A, B, a, b, dst=None):
    dst = _ensure_dst_key(dst)

    crypto.identity_into(tmp_pt_1)
    crypto.identity_into(tmp_pt_2)

    for i in range(len(a)):
        crypto.decodeint_into_noreduce(tmp_sc_1, a[i])
        crypto.decodepoint_into(tmp_pt_3, A[i])
        crypto.decodeint_into_noreduce(tmp_sc_2, b[i])
        crypto.decodepoint_into(tmp_pt_4, B[i])
        crypto.add_keys3_into(tmp_pt_1, tmp_sc_1, tmp_pt_3, tmp_sc_2, tmp_pt_4)
        crypto.point_add_into(tmp_pt_2, tmp_pt_2, tmp_pt_1)
    crypto.encodepoint_into(tmp_pt_2, dst)
    return dst


def vector_powers(x, n, dst=None):
    dst = _ensure_dst_keyvect(dst, n)
    if n == 0:
        return dst
    dst[0] = ONE
    if n == 1:
        return dst
    dst[1] = x
    for i in range(2, n):
        sc_mul(dst[i], dst[i - 1], x)
    return dst


def vector_power_sum(x, n, dst=None):  # TODO: frag-optim
    dst = _ensure_dst_key(dst)
    if n == 0:
        return copy_key(dst, ZERO)

    copy_key(dst, ONE)
    if n == 1:
        return dst

    prev = init_key(x)
    for i in range(1, n):
        if i > 1:
            sc_mul(prev, prev, x)
        sc_add(dst, dst, prev)
    return dst


def inner_product(a, b, dst=None):
    if len(a) != len(b):
        raise ValueError("Incompatible sizes of a and b")
    dst = _ensure_dst_key(dst)
    crypto.sc_init_into(tmp_sc_1, 0)

    for i in range(len(a)):
        crypto.decodeint_into_noreduce(tmp_sc_2, a[i])
        crypto.decodeint_into_noreduce(tmp_sc_3, b[i])
        crypto.sc_muladd_into(tmp_sc_1, tmp_sc_2, tmp_sc_3, tmp_sc_1)
    crypto.encodeint_into(tmp_sc_1, dst)
    return dst


def hadamard(a, b, dst=None):
    dst = _ensure_dst_keyvect(dst, len(a))
    for i in range(len(a)):
        sc_mul(dst[i], a[i], b[i])
    return dst


def hadamard2(a, b, dst=None):
    dst = _ensure_dst_keyvect(dst, len(a))
    for i in range(len(a)):
        add_keys(dst[i], a[i], b[i])
    return dst


def vector_add(a, b, dst=None):
    dst = _ensure_dst_keyvect(dst, len(a))
    for i in range(len(a)):
        sc_add(dst[i], a[i], b[i])
    return dst


def vector_subtract(a, b, dst=None):
    dst = _ensure_dst_keyvect(dst, len(a))
    for i in range(len(a)):
        sc_sub(dst[i], a[i], b[i])
    return dst


def vector_scalar(a, x, dst=None):
    dst = _ensure_dst_keyvect(dst, len(a))
    for i in range(len(a)):
        sc_mul(dst[i], a[i], x)
    return dst


def vector_scalar2(a, x, dst=None):
    dst = _ensure_dst_keyvect(dst, len(a))
    for i in range(len(a)):
        scalarmult_key(dst[i], a[i], x)
    return dst


def vector_dup(x, n, dst=None):
    dst = _ensure_dst_keyvect(dst, n)
    for i in range(n):
        dst[i] = x
    return dst


def vector_sum(a, dst=None):
    dst = _ensure_dst_key(dst)
    copy_key(dst, ZERO)
    for i in range(len(a)):
        sc_add(dst, dst, a[i])
    return dst


def hash_cache_mash(dst, hash_cache, *args):
    dst = _ensure_dst_key(dst)
    ctx = crypto.get_keccak()
    ctx.update(hash_cache)

    for x in args:
        if x is None:
            break
        ctx.update(x)
    hsh = ctx.digest()

    crypto.decodeint_into(tmp_sc_1, hsh)
    crypto.encodeint_into(tmp_sc_1, tmp_bf_1)

    copy_key(dst, tmp_bf_1)
    copy_key(hash_cache, tmp_bf_1)
    return dst


def init_exponents():
    Gi = KeyV()
    Hi = KeyV()
    for i in range(64):
        get_exponent(Hi[i], XMR_H, i * 2)
        get_exponent(Gi[i], XMR_H, i * 2 + 1)
    return Gi, Hi


def vect2buff(vect):
    buff = b""
    for i in range(len(vect)):
        cur = vect[i]
        for j in range(32):
            buff += b"\\x%02x" % cur[j]
    return buff


def key2buff(hx):
    hxs = b""
    for i in hx:
        hxs += b"\\x%02x" % i
    return hxs


def is_reduced(sc):
    return crypto.encodeint(crypto.decodeint(sc)) == sc


def init_constants():
    Gi, Hi = init_exponents()
    GiB = vect2buff(Gi)
    HiB = vect2buff(Hi)
    oneN = vector_powers(ONE, 64)
    oneNB = vect2buff(oneN)
    twoN = vector_powers(TWO, 64)
    twoNB = vect2buff(twoN)
    ip12 = inner_product(oneN, twoN)
    ip12B = key2buff(ip12)
    return Gi, GiB, Hi, HiB, oneN, oneNB, twoN, twoNB, ip12, ip12B


class MultiExp(object):
    def __init__(self, size=None, scalars=None, points=None, scalar_fnc=None, point_fnc=None):
        self.size = size if size else None
        self.current_idx = 0

        self.scalars = scalars if scalars else []
        self.points = points if points else []
        self.scalar_fnc = scalar_fnc
        self.point_fnc = point_fnc
        if (scalars or points) and size is None:
            self.size = max(len(scalars) if scalars else 0, len(points) if points else 0)

    def add_pair(self, scalar, point):
        self.scalars.append(scalar)
        self.points.append(point)
        self.size = len(self.points)

    def add_scalar(self, scalar):
        self.scalars.append(init_key(scalar))
        self.size = len(self.scalars)

    def get_idx(self, idx):
        dst_scalar = None
        dst_point = None

        if idx >= len(self.scalars):
            dst_scalar = self.scalar_fnc(idx, None)
        else:
            dst_scalar = self.scalars[idx]

        if idx >= len(self.points):
            dst_point = self.point_fnc(idx, None)
        else:
            dst_point = self.points[idx]

        return dst_scalar, dst_point

    def __getitem__(self, item):
        return self.get_idx(item)

    def __setitem__(self, key, value):
        raise ValueError('Not supported')

    def __iter__(self):
        self.current_idx = 0
        return self

    def __next__(self):
        if self.current_idx >= self.size:
            raise StopIteration
        else:
            self.current_idx += 1
            return self[self.current_idx - 1]

    def __len__(self):
        return self.size


class MergedMultiExp(object):
    def __init__(self, *args):
        self.current_idx = 0
        self.exps = args if len(args) > 0 else []
        self.size = 0
        self.bnds = [0]
        for x in args:
            self.size += len(x)
            self.bnds.append(self.bnds[-1] + len(x))

    def add(self, exp):
        self.exps.append(exp)
        self.size += len(exp)
        self.bnds.append(self.bnds[-1] + len(exp))
        return self

    def _get_chunk(self, idx):
        if idx >= self.size:
            raise ValueError('Out of bounds')
        x = 0
        while self.bnds[x] < idx and x < len(self.exps):
            x += 1
        return x - 1

    def get_idx(self, idx):
        ch_idx = self._get_chunk(idx)
        acc_idx = self.bnds[ch_idx]
        return self.exps[ch_idx].get_idx(idx - acc_idx)

    def __getitem__(self, item):
        return self.get_idx(item)

    def __setitem__(self, key, value):
        raise ValueError('Not supported')

    def __iter__(self):
        self.current_idx = 0
        return self

    def __next__(self):
        if self.current_idx >= self.size:
            raise StopIteration
        else:
            self.current_idx += 1
            return self[self.current_idx - 1]

    def __len__(self):
        return self.size


def multiexp(dst=None, data=None, GiHi=False):
    dst = _ensure_dst_key(dst)
    crypto.identity_into(tmp_pt_1)
    for i in range(len(data)):
        sci, pti = data[i]
        crypto.decodeint_into_noreduce(tmp_sc_1, sci)
        crypto.decodepoint_into(tmp_pt_2, pti)
        crypto.scalarmult_into(tmp_pt_3, tmp_pt_2, tmp_sc_1)
        crypto.point_add_into(tmp_pt_1, tmp_pt_1, tmp_pt_3)
    crypto.encodepoint_into(tmp_pt_1, dst)
    return dst


class BulletProofBuilder(object):
    def __init__(self):
        self.use_det_masks = True
        self.value = None
        self.value_enc = None
        self.gamma = None
        self.gamma_enc = None
        self.proof_sec = None
        self.Gprec = KeyV(buffer=BP_GI_PRE, const=True)
        self.Hprec = KeyV(buffer=BP_HI_PRE, const=True)
        self.oneN = const_vector(ONE, 64)
        self.twoN = KeyV(buffer=BP_TWO_N, const=True)
        self.ip12 = BP_IP12
        self.v_aL = None
        self.v_aR = None
        self.v_sL = None
        self.v_sR = None
        self.tmp_sc_1 = crypto.new_scalar()
        self.tmp_det_buff = bytearray(64 + 1 + 1)
        self.tmp_h_buff1 = bytearray(32)
        self.gc_fnc = gc.collect
        self.gc_trace = None

    def gc(self, *args):
        if self.gc_trace:
            self.gc_trace(*args)
        if self.gc_fnc:
            self.gc_fnc()

    def assrt(self, cond, msg=None, *args, **kwargs):
        if not cond:
            raise ValueError(msg)

    def set_input(self, value=None, mask=None):
        self.value = value
        self.value_enc = crypto.encodeint(value)
        self.gamma = mask
        self.gamma_enc = crypto.encodeint(mask)
        self.proof_sec = crypto.random_bytes(64)

    def aL(self, i, dst=None):
        dst = _ensure_dst_key(dst)
        if self.value_enc[i // 8] & (1 << (i % 8)):
            copy_key(dst, ONE)
        else:
            copy_key(dst, ZERO)
        return dst

    def aR(self, i, dst=None):
        dst = _ensure_dst_key(dst)
        self.aL(i, tmp_bf_1)
        sc_sub(dst, tmp_bf_1, ONE)
        return dst

    def aL_vct(self):
        return KeyVEval(64, lambda x, r: self.aL(x, r))

    def aR_vct(self):
        return KeyVEval(64, lambda x, r: self.aR(x, r))

    def _det_mask(self, i, is_sL=True, dst=None):
        dst = _ensure_dst_key(dst)
        self.tmp_det_buff[0] = int(is_sL)
        memcpy(self.tmp_det_buff, 1, self.proof_sec, 0, len(self.proof_sec))
        dump_uvarint_b_into(i, self.tmp_det_buff, 65)
        crypto.keccak_hash_into(self.tmp_h_buff1, self.tmp_det_buff)
        crypto.keccak_hash_into(self.tmp_h_buff1, self.tmp_h_buff1)
        crypto.decodeint_into(self.tmp_sc_1, self.tmp_h_buff1)
        crypto.encodeint_into(self.tmp_sc_1, dst)
        return dst

    def sL(self, i, dst=None):
        return self._det_mask(i, True, dst)

    def sR(self, i, dst=None):
        return self._det_mask(i, False, dst)

    def sL_vct(self, ln=64):
        return (
            KeyVEval(ln, lambda x, r: self.sL(x, r))
            if self.use_det_masks
            else self.sX_gen(ln)
        )

    def sR_vct(self, ln=64):
        return (
            KeyVEval(ln, lambda x, r: self.sR(x, r))
            if self.use_det_masks
            else self.sX_gen(ln)
        )

    def sX_gen(self, ln=64):
        buff = bytearray(ln * 32)
        buff_mv = memoryview(buff)
        sc = crypto.new_scalar()
            crypto.random_scalar_into(sc)
        for i in range(ln):
            crypto.encodeint_into(sc, buff_mv[i * 32 : (i + 1) * 32])
        return KeyV(buffer=buff)

    def vector_exponent(self, a, b, dst=None):
        return vector_exponent_custom(self.Gprec, self.Hprec, a, b, dst)

    def prove_s1(self, V, A, S, T1, T2, taux, mu, t, x_ip, y, hash_cache, l, r):
        add_keys2(V, self.gamma_enc, self.value_enc, XMR_H)
        hash_to_scalar(hash_cache, V)

        # PAPER LINES 38-39
        alpha = sc_gen()
        ve = _ensure_dst_key()
        self.vector_exponent(self.v_aL, self.v_aR, ve)
        add_keys(A, ve, scalarmult_base(tmp_bf_1, alpha))

        # PAPER LINES 40-42
        rho = sc_gen()
        self.vector_exponent(self.v_sL, self.v_sR, ve)
        add_keys(S, ve, scalarmult_base(tmp_bf_1, rho))

        # PAPER LINES 43-45
        z = _ensure_dst_key()
        hash_cache_mash(y, hash_cache, A, S)
        hash_to_scalar(hash_cache, y)
        copy_key(z, hash_cache)
        self.gc(1)

        # Polynomial construction before PAPER LINE 46
        t0 = _ensure_dst_key()
        t1 = _ensure_dst_key()
        t2 = _ensure_dst_key()

        yN = vector_powers(y, BP_N)
        self.gc(2)

        ip1y = inner_product(self.oneN, yN)
        sc_muladd(t0, z, ip1y, t0)

        zsq = _ensure_dst_key()
        sc_mul(zsq, z, z)
        sc_muladd(t0, zsq, self.value_enc, t0)

        k = _ensure_dst_key()
        copy_key(k, ZERO)
        sc_mulsub(k, zsq, ip1y, k)

        zcu = _ensure_dst_key()
        sc_mul(zcu, zsq, z)
        sc_mulsub(k, zcu, self.ip12, k)
        sc_add(t0, t0, k)
        self.gc(3)

        # step 2, tmp_vct = vpIz
        tmp_vct = _ensure_dst_keyvect(None, BP_N)
        vector_scalar(self.oneN, z, tmp_vct)
        aL_vpIz = vector_subtract(self.v_aL, tmp_vct)
        aR_vpIz = vector_add(self.v_aR, tmp_vct)
        self.v_aL = None
        self.v_aR = None
        self.gc(4)

        # tmp_vct = HyNsR
        hadamard(yN, self.v_sR, tmp_vct)
        ip1 = inner_product(aL_vpIz, tmp_vct)
        ip3 = inner_product(self.v_sL, tmp_vct)
        self.gc(5)

        sc_add(t1, t1, ip1)

        vp2zsq = vector_scalar(self.twoN, zsq)

        # Originally:
        # ip2 = inner_product(self.v_sL, vector_add(hadamard(yN, aR_vpIz), vp2zsq))
        hadamard(yN, aR_vpIz, tmp_vct)
        self.gc(6)

        vector_add(tmp_vct, vp2zsq, tmp_vct)
        ip2 = inner_product(self.v_sL, tmp_vct)

        self.gc(6)
        sc_add(t1, t1, ip2)
        sc_add(t2, t2, ip3)

        # PAPER LINES 47-48
        tau1 = sc_gen()
        tau2 = sc_gen()

        add_keys(
            T1, scalarmult_key(tmp_bf_1, XMR_H, t1), scalarmult_base(tmp_bf_2, tau1)
        )
        add_keys(
            T2, scalarmult_key(tmp_bf_1, XMR_H, t2), scalarmult_base(tmp_bf_2, tau2)
        )

        # PAPER LINES 49-51
        x = _ensure_dst_key()
        hash_cache_mash(x, hash_cache, z, T1, T2)

        # PAPER LINES 52-53
        copy_key(taux, ZERO)
        sc_mul(taux, tau1, x)
        xsq = _ensure_dst_key()
        sc_mul(xsq, x, x)
        sc_muladd(taux, tau2, xsq, taux)
        sc_muladd(taux, self.gamma_enc, zsq, taux)
        sc_muladd(mu, x, rho, alpha)
        self.gc(7)

        # PAPER LINES 54-57
        vector_scalar(self.v_sL, x, tmp_vct)
        vector_add(aL_vpIz, tmp_vct, l)
        self.v_sL = None
        del aL_vpIz
        self.gc(8)

        # Originally:
        # vector_add(hadamard(yN, vector_add(aR_vpIz, vector_scalar(self.v_sR, x))), vp2zsq, r)
        vector_scalar(self.v_sR, x, tmp_vct)
        vector_add(aR_vpIz, tmp_vct, tmp_vct)
        del aR_vpIz
        self.gc(9)

        hadamard(yN, tmp_vct, tmp_vct)
        del yN
        self.gc(10)

        vector_add(tmp_vct, vp2zsq, r)
        self.v_sR = None
        del vp2zsq
        del tmp_vct
        self.gc(11)

        inner_product(l, r, t)
        hash_cache_mash(x_ip, hash_cache, x, taux, mu, t)

    def prove_s2(self, x_ip, y, hash_cache, l, r, L, R, aprime0, bprime0):
        Gprime = _ensure_dst_keyvect(None, BP_N)
        Hprime = _ensure_dst_keyvect(None, BP_N)

        aprime = l
        bprime = r

        yinv = invert(None, y)
        self.gc(20)

        yinvpow = _ensure_dst_key()
        copy_key(yinvpow, ONE)
        for i in range(BP_N):
            Gprime[i] = self.Gprec[i]
            scalarmult_key(Hprime[i], self.Hprec[i], yinvpow)
            sc_mul(yinvpow, yinvpow, yinv)
        self.gc(21)

        round = 0
        nprime = BP_N

        _tmp_k_1 = _ensure_dst_key()
        _tmp_vct_1 = _ensure_dst_keyvect(None, nprime // 2)
        _tmp_vct_2 = _ensure_dst_keyvect(None, nprime // 2)
        _tmp_vct_3 = _ensure_dst_keyvect(None, nprime // 2)
        _tmp_vct_4 = _ensure_dst_keyvect(None, nprime // 2)

        tmp = _ensure_dst_key()
        winv = _ensure_dst_key()
        w = _ensure_dst_keyvect(None, BP_LOG_N)
        cL = _ensure_dst_key()
        cR = _ensure_dst_key()

        # PAPER LINE 13
        while nprime > 1:
            # PAPER LINE 15
            nprime >>= 1
            _tmp_vct_1.resize(nprime, chop=True)
            _tmp_vct_2.resize(nprime, chop=True)
            _tmp_vct_3.resize(nprime, chop=True)
            _tmp_vct_4.resize(nprime, chop=True)
            self.gc(22)

            # PAPER LINES 16-17
            inner_product(
                aprime.slice(_tmp_vct_1, 0, nprime),
                bprime.slice(_tmp_vct_2, nprime, bprime.size),
                cL,
            )

            inner_product(
                aprime.slice(_tmp_vct_1, nprime, aprime.size),
                bprime.slice(_tmp_vct_2, 0, nprime),
                cR,
            )

            self.gc(23)

            # PAPER LINES 18-19
            vector_exponent_custom(
                Gprime.slice(_tmp_vct_1, nprime, len(Gprime)),
                Hprime.slice(_tmp_vct_2, 0, nprime),
                aprime.slice(_tmp_vct_3, 0, nprime),
                bprime.slice(_tmp_vct_4, nprime, len(bprime)),
                L[round],
            )

            sc_mul(tmp, cL, x_ip)
            add_keys(L[round], L[round], scalarmult_key(_tmp_k_1, XMR_H, tmp))
            self.gc(24)

            vector_exponent_custom(
                Gprime.slice(_tmp_vct_1, 0, nprime),
                Hprime.slice(_tmp_vct_2, nprime, len(Hprime)),
                aprime.slice(_tmp_vct_3, nprime, len(aprime)),
                bprime.slice(_tmp_vct_4, 0, nprime),
                R[round],
            )

            sc_mul(tmp, cR, x_ip)
            add_keys(R[round], R[round], scalarmult_key(_tmp_k_1, XMR_H, tmp))
            self.gc(25)

            # PAPER LINES 21-22
            hash_cache_mash(w[round], hash_cache, L[round], R[round])

            # PAPER LINES 24-25
            invert(winv, w[round])
            self.gc(26)

            vector_scalar2(Gprime.slice(_tmp_vct_1, 0, nprime), winv, _tmp_vct_3)
            vector_scalar2(
                Gprime.slice(_tmp_vct_2, nprime, len(Gprime)), w[round], _tmp_vct_4
            )
            hadamard2(_tmp_vct_3, _tmp_vct_4, Gprime)
            self.gc(27)

            vector_scalar2(Hprime.slice(_tmp_vct_1, 0, nprime), w[round], _tmp_vct_3)
            vector_scalar2(
                Hprime.slice(_tmp_vct_2, nprime, len(Hprime)), winv, _tmp_vct_4
            )
            hadamard2(_tmp_vct_3, _tmp_vct_4, Hprime)
            self.gc(28)

            # PAPER LINES 28-29
            vector_scalar(aprime.slice(_tmp_vct_1, 0, nprime), w[round], _tmp_vct_3)
            vector_scalar(
                aprime.slice(_tmp_vct_2, nprime, len(aprime)), winv, _tmp_vct_4
            )
            vector_add(_tmp_vct_3, _tmp_vct_4, aprime)
            self.gc(29)

            vector_scalar(bprime.slice(_tmp_vct_1, 0, nprime), winv, _tmp_vct_3)
            vector_scalar(
                bprime.slice(_tmp_vct_2, nprime, len(bprime)), w[round], _tmp_vct_4
            )
            vector_add(_tmp_vct_3, _tmp_vct_4, bprime)

            round += 1
            self.gc(30)

        copy_key(aprime0, aprime[0])
        copy_key(bprime0, bprime[0])

    def init_vct(self):
        self.v_aL = self.aL_vct()
        self.v_aR = self.aR_vct()
        self.v_sL = self.sL_vct()
        self.v_sR = self.sR_vct()

    def prove(self):
        # Prover state
        V = _ensure_dst_key()
        A = _ensure_dst_key()
        S = _ensure_dst_key()
        T1 = _ensure_dst_key()
        T2 = _ensure_dst_key()
        taux = _ensure_dst_key()
        mu = _ensure_dst_key()
        t = _ensure_dst_key()
        x_ip = _ensure_dst_key()
        y = _ensure_dst_key()
        hash_cache = _ensure_dst_key()
        aprime0 = _ensure_dst_key()
        bprime0 = _ensure_dst_key()

        L = _ensure_dst_keyvect(None, BP_LOG_N)
        R = _ensure_dst_keyvect(None, BP_LOG_N)
        l = _ensure_dst_keyvect(None, BP_N)
        r = _ensure_dst_keyvect(None, BP_N)

        self.init_vct()
        self.gc(50)

        self.prove_s1(V, A, S, T1, T2, taux, mu, t, x_ip, y, hash_cache, l, r)
        self.gc(51)

        self.prove_s2(x_ip, y, hash_cache, l, r, L, R, aprime0, bprime0)
        self.gc(52)

        return Bulletproof(
            V=[V],
            A=A,
            S=S,
            T1=T1,
            T2=T2,
            taux=taux,
            mu=mu,
            L=L,
            R=R,
            a=aprime0,
            b=bprime0,
            t=t,
        )

    def verify(self, proof):
        if len(proof.V) != 1:
            raise ValueError("len(V) != 1")
        if len(proof.L) != len(proof.R):
            raise ValueError("|L| != |R|")
        if len(proof.L) == 0:
            raise ValueError("Empty proof")
        if len(proof.L) != 6:
            raise ValueError("Proof is not for 64 bits")

        hash_cache = _ensure_dst_key()
        hash_to_scalar(hash_cache, proof.V[0])

        x = _ensure_dst_key()
        y = _ensure_dst_key()
        z = _ensure_dst_key()

        # Reconstruct the challenges
        hash_cache_mash(y, hash_cache, proof.A, proof.S)
        hash_to_scalar(hash_cache, y)
        copy_key(z, hash_cache)
        hash_cache_mash(x, hash_cache, z, proof.T1, proof.T2)

        # Reconstruct the challenges
        x_ip = _ensure_dst_key()
        hash_cache_mash(x_ip, hash_cache, x, proof.taux, proof.mu, proof.t)

        # PAPER LINE 61
        _tmp_k_1 = _ensure_dst_key()
        _tmp_k_2 = _ensure_dst_key()
        L61Left = _ensure_dst_key()
        add_keys(
            L61Left,
            scalarmult_base(_tmp_k_1, proof.taux),
            scalarmult_key(_tmp_k_2, XMR_H, proof.t),
        )

        k = _ensure_dst_key()
        yN = vector_powers(y, BP_N)
        ip1y = inner_product(self.oneN, yN)
        del yN

        zsq = _ensure_dst_key()
        sc_mul(zsq, z, z)

        zcu = _ensure_dst_key()
        tmp = _ensure_dst_key()
        tmp2 = _ensure_dst_key()
        sc_mulsub(k, zsq, ip1y, k)
        sc_mul(zcu, zsq, z)
        sc_mulsub(k, zcu, self.ip12, k)
        sc_muladd(tmp, z, ip1y, k)

        L61Right = _ensure_dst_key()
        scalarmult_key(L61Right, XMR_H, tmp)
        scalarmult_key(tmp, proof.V[0], zsq)
        add_keys(L61Right, L61Right, tmp)

        scalarmult_key(tmp, proof.T1, x)
        add_keys(L61Right, L61Right, tmp)

        xsq = _ensure_dst_key()
        sc_mul(xsq, x, x)
        scalarmult_key(tmp, proof.T2, xsq)
        add_keys(L61Right, L61Right, tmp)
        self.gc(60)

        if L61Right != L61Left:
            raise ValueError("Verification failure 1")

        del k
        del ip1y
        del zcu
        del L61Left
        del L61Right

        # PAPER LINE 62
        P = _ensure_dst_key()
        add_keys(P, proof.A, scalarmult_key(_tmp_k_1, proof.S, x))

        # Compute the number of rounds for the inner product
        rounds = len(proof.L)

        # PAPER LINES 21-22
        w = _ensure_dst_keyvect(None, rounds)
        for i in range(rounds):
            hash_cache_mash(w[i], hash_cache, proof.L[i], proof.R[i])

        # Basically PAPER LINES 24-25
        # Compute the curvepoints from G[i] and H[i]
        inner_prod = init_key(ONE)
        yinvpow = init_key(ONE)
        ypow = init_key(ONE)
        yinv = invert(None, y)
        self.gc(61)

        winv = _ensure_dst_keyvect(None, rounds)
        for i in range(rounds):
            invert(winv[i], w[i])
            self.gc(62)

        g_scalar = _ensure_dst_key()
        h_scalar = _ensure_dst_key()
        for i in range(BP_N):
            copy_key(g_scalar, proof.a)
            sc_mul(h_scalar, proof.b, yinvpow)

            for j in range(rounds - 1, -1, -1):
                J = len(w) - j - 1

                if (i & (1 << j)) == 0:
                    sc_mul(g_scalar, g_scalar, winv[J])
                    sc_mul(h_scalar, h_scalar, w[J])
                else:
                    sc_mul(g_scalar, g_scalar, w[J])
                    sc_mul(h_scalar, h_scalar, winv[J])

            # Adjust the scalars using the exponents from PAPER LINE 62
            sc_add(g_scalar, g_scalar, z)
            sc_mul(tmp, zsq, self.twoN[i])
            sc_muladd(tmp, z, ypow, tmp)
            sc_mulsub(h_scalar, tmp, yinvpow, h_scalar)

            # Now compute the basepoint's scalar multiplication
            # Each of these could be written as a multiexp operation instead
            add_keys3(tmp, g_scalar, self.Gprec[i], h_scalar, self.Hprec[i])
            add_keys(inner_prod, inner_prod, tmp)

            if i != BP_N - 1:
                sc_mul(yinvpow, yinvpow, yinv)
                sc_mul(ypow, ypow, y)
            self.gc(62)

        del g_scalar
        del h_scalar
        self.gc(63)

        # PAPER LINE 26
        pprime = _ensure_dst_key()
        sc_sub(tmp, ZERO, proof.mu)
        add_keys(pprime, P, scalarmult_base(_tmp_k_1, tmp))

        for i in range(rounds):
            sc_mul(tmp, w[i], w[i])
            sc_mul(tmp2, winv[i], winv[i])

            add_keys3(tmp, tmp, proof.L[i], tmp2, proof.R[i])
            add_keys(pprime, pprime, tmp)

        sc_mul(tmp, proof.t, x_ip)
        add_keys(pprime, pprime, scalarmult_key(_tmp_k_1, XMR_H, tmp))

        sc_mul(tmp, proof.a, proof.b)
        sc_mul(tmp, tmp, x_ip)
        scalarmult_key(tmp, XMR_H, tmp)
        add_keys(tmp, tmp, inner_prod)
        self.gc(64)

        if pprime != tmp:
            raise ValueError("Verification failure step 2")
        return True

    def verify_batch(self, proofs):
        """
        BP batch verification
        :param proofs:
        :return:
        """
        max_length = 0
        for proof in proofs:
            self.assrt(is_reduced(proof.taux), "Input scalar not in range")
            self.assrt(is_reduced(proof.mu), "Input scalar not in range")
            self.assrt(is_reduced(proof.a), "Input scalar not in range")
            self.assrt(is_reduced(proof.b), "Input scalar not in range")
            self.assrt(is_reduced(proof.t), "Input scalar not in range")
            self.assrt(len(proof.V) >= 1, "V does not have at least one element")
            self.assrt(len(proof.L) == len(proof.R), "|L| != |R|")
            self.assrt(len(proof.L) > 0, "Empty proof")
            max_length = max(max_length, len(proof.L))

        self.assrt(max_length < 32, "At least one proof is too large")

        maxMN = 1 << max_length
        logN = 6
        N = 1 << logN
        tmp = _ensure_dst_key()

        # setup weighted aggregates
        Z0 = init_key(ONE)
        z1 = init_key(ZERO)
        Z2 = init_key(ONE)
        z3 = init_key(ZERO)
        z4 = vector_dup(ZERO, maxMN)
        z5 = vector_dup(ZERO, maxMN)
        Y2 = init_key(ONE)
        Y3 = init_key(ONE)
        Y4 = init_key(ONE)
        y0 = init_key(ZERO)
        y1 = init_key(ZERO)

        for proof in proofs:
            M = 0
            logM = 0
            while True:
                M = 1 << logM
                if M > BP_M or M >= len(proof.V):
                    break
                logM += 1

            self.assrt(len(proof.L) == 6 + logM, "Proof is not the expected size")
            MN = M*N
            weight = crypto.encodeint(crypto.random_scalar())

            # Reconstruct the challenges
            hash_cache = hash_vct_to_scalar(None, proof.V)
            y = hash_cache_mash(None, hash_cache, proof.A, proof.S)
            self.assrt(y != ZERO, "y == 0")
            z = hash_to_scalar(None, y)
            copy_key(hash_cache, z)
            self.assrt(z != ZERO, "z == 0")

            x = hash_cache_mash(None, hash_cache, z, proof.T1, proof.T2)
            self.assrt(x != ZERO, "x == 0")
            x_ip = hash_cache_mash(None, hash_cache, x, proof.taux, proof.mu, proof.t)
            self.assrt(x_ip != ZERO, "x_ip == 0")

            # PAPER LINE 61
            sc_muladd(y0, proof.taux, weight, y0)
            zpow = vector_powers(z, M+3)

            k = _ensure_dst_key()
            ip1y = vector_power_sum(y, MN)
            sc_mulsub(k, zpow[2], ip1y, ZERO)
            for j in range(1, M + 1):
                self.assrt(j + 2 < len(zpow), "invalid zpow index")
                sc_mulsub(k, zpow[j + 2], BP_IP12, k)

            # VERIFY_line_61rl_new
            sc_muladd(tmp, z, ip1y, k)
            sc_sub(tmp, proof.t, tmp)
            sc_muladd(y1, tmp, weight, y1)

            muex = MultiExp(point_fnc=lambda i, d: proof.V[i])
            for j in range(len(proof.V)):
                sc_mul(tmp, zpow[j+2], EIGHT)
                muex.add_scalar(tmp)

            add_keys(Y2, Y2, scalarmult_key(None, multiexp(None, muex, False), weight))
            weight8 = _ensure_dst_key()
            sc_mul(weight8, weight, EIGHT)
            sc_mul(tmp, x, weight8)
            add_keys(Y3, Y3, scalarmult_key(None, proof.T1, tmp))
            xsq = _ensure_dst_key()
            sc_mul(xsq, x, x)
            sc_mul(tmp, xsq, weight8)
            add_keys(Y4, Y4, scalarmult_key(None, proof.T2, tmp))
            del weight8

            # PAPER LINE 62
            sc_mul(tmp, x, EIGHT)
            add_keys(Z0, Z0,
                     scalarmult_key(None,
                                    add_keys(None,
                                             scalarmult8(None, proof.A),
                                             scalarmult_key(None, proof.S, tmp)),
                                    weight))

            # Compute the number of rounds for the inner product
            rounds = logM + logN
            self.assrt(rounds > 0, "Zero rounds")

            # PAPER LINES 21-22
            # The inner product challenges are computed per round
            w = _ensure_dst_keyvect(None, rounds)
            for i in range(rounds):
                hash_cache_mash(w[i], hash_cache, proof.L[i], proof.R[i])
                self.assrt(w[i] != ZERO, "w[i] == 0")

            # Basically PAPER LINES 24-25
            # Compute the curvepoints from G[i] and H[i]
            yinvpow = init_key(ONE)
            ypow = init_key(ONE)
            yinv = invert(None, y)
            self.gc(61)

            winv = _ensure_dst_keyvect(None, rounds)
            for i in range(rounds):
                invert(winv[i], w[i])
                self.gc(62)

            g_scalar = _ensure_dst_key()
            h_scalar = _ensure_dst_key()
            for i in range(MN):
                copy_key(g_scalar, proof.a)
                sc_mul(h_scalar, proof.b, yinvpow)

                for j in range(rounds - 1, -1, -1):
                    J = len(w) - j - 1

                    if (i & (1 << j)) == 0:
                        sc_mul(g_scalar, g_scalar, winv[J])
                        sc_mul(h_scalar, h_scalar, w[J])
                    else:
                        sc_mul(g_scalar, g_scalar, w[J])
                        sc_mul(h_scalar, h_scalar, winv[J])

                # Adjust the scalars using the exponents from PAPER LINE 62
                sc_add(g_scalar, g_scalar, z)
                self.assrt(2+i//N < len(zpow), "invalid zpow index")
                self.assrt(i % N < len(self.twoN), "invalid twoN index")
                sc_mul(tmp, zpow[2+i//N], self.twoN[i % N])
                sc_muladd(tmp, z, ypow, tmp)
                sc_mulsub(h_scalar, tmp, yinvpow, h_scalar)

                sc_muladd(z4[i], g_scalar, weight, z4[i])
                sc_muladd(z5[i], h_scalar, weight, z5[i])

                if i != MN - 1:
                    sc_mul(yinvpow, yinvpow, yinv)
                    sc_mul(ypow, ypow, y)
                self.gc(62)

            del g_scalar
            del h_scalar
            self.gc(63)

            sc_muladd(z1, proof.mu, weight, z1)
            muex = MultiExp(point_fnc=lambda i, d: proof.L[i//2] if i&1 == 0 else proof.R[i//2])
            for i in range(rounds):
                sc_mul(tmp, w[i], w[i])
                sc_mul(tmp, tmp, EIGHT)
                muex.add_scalar(tmp)
                sc_mul(tmp, winv[i], winv[i])
                sc_mul(tmp, tmp, EIGHT)
                muex.add_scalar(tmp)

            acc = multiexp(None, muex, False)
            add_keys(Z2, Z2, scalarmult_key(None, acc, weight))
            sc_mulsub(tmp, proof.a, proof.b, proof.t)
            sc_mul(tmp, tmp, x_ip)
            sc_muladd(z3, tmp, weight, z3)

        # now check all proofs at once
        check1 = _ensure_dst_key()
        scalarmult_base(check1, y0)
        add_keys(check1, check1, scalarmult_key(None, XMR_H, y1))
        sub_keys(check1, check1, Y2)
        sub_keys(check1, check1, Y3)
        sub_keys(check1, check1, Y4)
        if check1 != ONE:
            raise ValueError('Verification failure at step 1')

        sc_sub(tmp, ZERO, z1)
        check2 = crypto.ge_double_scalarmult_base_vartime(crypto.decodeint(z3), crypto.gen_H(), crypto.decodeint(tmp))
        crypto.point_add_into(check2, check2, crypto.decodepoint(Z0))
        crypto.point_add_into(check2, check2, crypto.decodepoint(Z2))

        muex = MultiExp(point_fnc=lambda i, d: self.Gprec[i // 2] if i & 1 == 0 else self.Hprec[i // 2])
        for i in range(maxMN):
            sc_sub(tmp, ZERO, z4[i])
            muex.add_scalar(tmp)
            sc_sub(tmp, ZERO, z5[i])
            muex.add_scalar(tmp)

        crypto.point_add_into(check2, check2, crypto.decodepoint(multiexp(None, muex, True)))
        check2_enc = crypto.encodepoint(check2)
        if check2_enc != ONE:
            raise ValueError('Verification failure at step 2')
        return True
