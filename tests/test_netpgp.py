# -*- coding: utf-8 -*-
#
#   netpgp-cffi: netpgp cffi binding
#   Copyright (C) 2015-2017 mete0r <mete0r@sarangbang.or.kr>
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU Affero General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Affero General Public License for more details.
#
#   You should have received a copy of the GNU Affero General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals
from unittest import TestCase
import os
import shutil


class NetPGPTest(TestCase):

    def setUp(self):
        home = os.environ['HOME']
        gnupgdir = os.path.join(home, '.gnupg')
        if os.path.exists(gnupgdir):
            shutil.rmtree(gnupgdir)
        os.mkdir(gnupgdir)

    def test_generate_key(self):
        from netpgp_cffi.netpgp import NetPGP

        netpgp = NetPGP.create()

        key_id = netpgp.generate_key('foo', 4096)
        self.assertTrue(len(key_id) == 16)

        keys = netpgp.list_keys()
        self.assertEquals(1, len(keys))
        key = keys[0]
        self.assertEquals(key_id, key.id)
        self.assertEquals(0, key.duration)
        self.assertEquals(4096, key.bits)
        self.assertEquals('signature', key.header)
        self.assertTrue('RSA' in key.pka, key.pka)
        self.assertEquals(('foo', ''), key.uid)

        self.assertTrue(netpgp.find_key(key_id))
        self.assertTrue(netpgp.find_key('foo'))
        self.assertFalse(netpgp.find_key('bar'))

        netpgp.list_packets(
            filename=os.path.join(netpgp.homedir, 'secring.gpg'),
            armored=False,
        )

        encrypted = netpgp.encrypt(key_id, b'hello world')
        decrypted = netpgp.decrypt(encrypted)
        self.assertEquals(b'hello world', decrypted)
