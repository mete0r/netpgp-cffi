# -*- coding: utf-8 -*-
#
#   netpgp-cffi: netpgp cffi binding
#   Copyright (C) 2015-2018 mete0r <mete0r@sarangbang.or.kr>
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
from io import BytesIO
from unittest import TestCase


class WsgiAppTest(TestCase):

    def test_app_factory(self):
        from netpgp_cffi.wsgi import app_factory
        app = app_factory({}, **{})

        environ = {
            'HTTP_ACCEPT': '*/*',
            'PATH_INFO': '/',
            'QUERY_STRING': '',
            'REMOTE_ADDR': '127.0.0.1',
            'REMOTE_HOST': 'localhost',
            'REQUEST_METHOD': 'GET',
            'SCRIPT_NAME': '',
            'SERVER_NAME': 'localhost',
            'SERVER_PORT': '8080',
            'SERVER_PROTOCOL': 'HTTP/1.1',
            'SERVER_SOFTWARE': 'WSGIServer/0.1',
            'wsgi.error': BytesIO(),
            'wsgi.input': BytesIO(),
            'wsgi.multiprocess': False,
            'wsgi.multithread': False,
            'wsgi.run_once': False,
            'wsgi.url_scheme': 'http',
            'wsgi.version': (1, 0),
        }
        result = dispatch(app, environ)
        self.assertEquals({
            'status': b'200 OK',
            'headers': [(b'Content-Type', b'application/json')],
            'body': b'null',
        }, result)


def dispatch(app, environ):
    result = {
    }

    def start_response(status, headers):
        result['status'] = status
        result['headers'] = headers
    result['body'] = b''.join(app(environ, start_response))
    return result
