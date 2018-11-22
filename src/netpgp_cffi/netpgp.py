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
from contextlib import contextmanager
from datetime import datetime
from shutil import copyfileobj
import io
import os
import json

from attr import attrs
from attr import attrib

from ._netpgp import ffi
from ._netpgp import lib
from .exceptions import InitializeError
from .exceptions import KeyGenerationError
from .exceptions import EncryptError
from .exceptions import DecryptError
from .exceptions import SignError


@attrs(slots=True, frozen=True)
class Key(object):
    birthtime = attrib()
    duration = attrib()
    fingerprint = attrib()
    header = attrib()
    bits = attrib()
    id = attrib()
    pka = attrib()
    uid = attrib()


class KeyFormat(object):

    def parse(self, d):
        birthtime = d['birthtime']
        birthtime = datetime.utcfromtimestamp(birthtime)
        duration = d['duration']
        fingerprint = d['fingerprint'].strip()
        header = d['header'].strip()
        bits = d['key bits']
        id = d['key id']
        pka = d['pka']
        uid = tuple(d['uid'])
        return Key(
            birthtime=birthtime,
            duration=duration,
            fingerprint=fingerprint,
            header=header,
            bits=bits,
            id=id,
            pka=pka,
            uid=uid,
        )


class NetPGP(object):

    @classmethod
    def create(cls, home=None, subdir='.gnupg'):
        home = home or os.environ['HOME']
        if not home.endswith('/'):
            home += '/'
        homedir = os.path.join(home, subdir)

        pubring = os.path.join(homedir, 'pubring.gpg')
        secring = os.path.join(homedir, 'secring.gpg')
        if not os.path.exists(pubring):
            with io.open(pubring, 'wb'):
                pass
        if not os.path.exists(secring):
            with io.open(secring, 'wb'):
                pass

        return cls(homedir)

    def __init__(self, homedir):
        self.homedir = homedir

    def list_packets(self, filename, armored=False):
        if armored:
            armored = 1
        else:
            armored = 0

        if not isinstance(filename, bytes):
            filename = filename.encode('utf-8')

        pubring = os.path.join(self.homedir, 'pubring.gpg')
        pubring = pubring.encode('utf-8')
        with _create(self.homedir) as _netpgp:
            return lib.netpgp_list_packets(_netpgp, filename, armored, pubring)

    def generate_key(self, id, numbits):
        homedir = self.homedir

        # file descriptor for passphrase
        passfd = os.open(os.devnull, os.O_RDONLY)
        try:
            with _create(homedir, passfd=passfd) as _netpgp:
                if not isinstance(id, bytes):
                    id = id.encode('utf-8')
                ret = lib.netpgp_generate_key(_netpgp, id, numbits)
                if ret == 0:
                    raise KeyGenerationError()
                keyid = _getvar(_netpgp, 'generated userid')
        finally:
            os.close(passfd)

        generated_pubring = os.path.join(homedir, keyid, 'pubring.gpg')
        generated_secring = os.path.join(homedir, keyid, 'secring.gpg')
        try:
            pubring = os.path.join(homedir, 'pubring.gpg')
            secring = os.path.join(homedir, 'secring.gpg')
            with io.open(generated_pubring, 'rb') as fpr:
                with io.open(pubring, 'ab') as fpw:
                    copyfileobj(fpr, fpw)
            with io.open(generated_secring, 'rb') as fpr:
                with io.open(secring, 'ab') as fpw:
                    copyfileobj(fpr, fpw)
            return keyid
        finally:
            os.unlink(generated_pubring)
            os.unlink(generated_secring)
            os.rmdir(os.path.join(homedir, keyid))

    def list_keys(self):
        homedir = self.homedir
        keyformat = KeyFormat()

        # no sig field
        psigs = 0

        with _create(homedir) as _netpgp:
            outptr = ffi.new('char **')
            lib.netpgp_list_keys_json(_netpgp, outptr, psigs)
            if outptr[0] != ffi.NULL:
                try:
                    result = ffi.string(outptr[0])
                    result = result.decode('utf-8')
                    result = json.loads(result)
                    return [keyformat.parse(key) for key in result]
                finally:
                    lib.free(outptr[0])
            return []

    def find_key(self, id):

        if not isinstance(id, bytes):
            id = id.encode('utf-8')

        with _create(self.homedir) as _netpgp:
            ret = lib.netpgp_find_key(_netpgp, id)
        return ret != 0

    def encrypt(self, userid, data, armored=False):
        if not isinstance(userid, bytes):
            userid = userid.encode('utf-8')

        if armored:
            armored = 1
        else:
            armored = 0

        # file descriptor for passphrase
        passfd = os.open(os.devnull, os.O_RDONLY)
        with _create(self.homedir, passfd=passfd) as _netpgp:
            _setvar(_netpgp, 'hash', 'SHA256')
            outsize = 4 * 1024 * 1024  # 4 MiB
            outbuf = ffi.new('char[{}]'.format(outsize))
            ret = lib.netpgp_encrypt_memory(
                _netpgp,
                userid,
                data,
                len(data),
                outbuf,
                outsize,
                armored,
            )
        if ret == 0:
            raise EncryptError()
        return ffi.string(outbuf[0:ret])

    def decrypt(self, encrypted, armored=False):
        if armored:
            armored = 1
        else:
            armored = 0

        # file descriptor for passphrase
        passfd = os.open(os.devnull, os.O_RDONLY)
        with _create(self.homedir, passfd=passfd) as _netpgp:
            _setvar(_netpgp, 'hash', 'SHA256')
            outsize = 4 * 1024 * 1024  # 4 MiB
            outbuf = ffi.new('char[{}]'.format(outsize))
            ret = lib.netpgp_decrypt_memory(
                _netpgp,
                encrypted,
                len(encrypted),
                outbuf,
                outsize,
                armored,
            )
        if ret == 0:
            raise DecryptError()
        return ffi.string(outbuf[0:ret])

    def sign(self, userid, data):

        if not isinstance(userid, bytes):
            userid = userid.encode('utf-8')

        armored = 1
        cleartext = 1

        # file descriptor for passphrase
        passfd = os.open(os.devnull, os.O_RDONLY)
        with _create(self.homedir, passfd=passfd) as _netpgp:
            _setvar(_netpgp, 'hash', 'SHA256')
            outsize = 4 * 1024 * 1024  # 4 MiB
            outbuf = ffi.new('char[{}]'.format(outsize))
            ret = lib.netpgp_sign_memory(
                _netpgp,
                userid,
                data,
                len(data),
                outbuf,
                outsize,
                armored,
                cleartext,
            )
        if ret == 0:
            raise SignError()
        return ffi.string(outbuf[:ret])


@contextmanager
def _create(homedir, passfd=None):
    _netpgp = ffi.new('netpgp_t *')

    _setvar(_netpgp, 'homedir', homedir)

    # file descriptor for passphrase
    if passfd is not None:
        passfd = int(passfd)
        _setvar(_netpgp, 'pass-fd', '{}'.format(passfd))

    ret = lib.netpgp_init(_netpgp)
    if ret == 0:
        raise InitializeError()
    try:
        yield _netpgp
    finally:
        lib.netpgp_end(_netpgp)


def _getvar(_netpgp, name):
    name = name.encode('utf-8')
    cdata = lib.netpgp_getvar(_netpgp, name)
    if cdata != ffi.NULL:
        return ffi.string(cdata).decode('utf-8')


def _setvar(_netpgp, name, value):
    name = name.encode('utf-8')
    if value is None:
        lib.netpgp_unsetvar(_netpgp, name)
    else:
        value = value.encode('utf-8')
        lib.netpgp_setvar(_netpgp, name, value)
