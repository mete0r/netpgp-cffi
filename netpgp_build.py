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

from cffi import FFI

ffi = FFI()

ffi.cdef(
    '''
typedef struct netpgp_t {
        unsigned	  c;		/* # of elements used */
        unsigned	  size;		/* size of array */
        char		**name;		/* key names */
        char		**value;	/* value information */
        void		 *pubring;	/* public key ring */
        void		 *secring;	/* s3kr1t key ring */
        void		 *io;		/* the io struct for results/errs */
        void		 *passfp;	/* file pointer for password input */
} netpgp_t;
    '''
)

ffi.cdef(
    '''
/* begin and end */
int netpgp_init(netpgp_t *netpgp);
int netpgp_end(netpgp_t *netpgp);

/* debugging, reflection and information */
int netpgp_set_debug(const char *);
int netpgp_get_debug(const char *);
const char *netpgp_get_info(const char *type);
int netpgp_list_packets(netpgp_t *netpgp, char *f, int armor, char *pubringname);

/* variables */
int netpgp_setvar(netpgp_t *netpgp, const char *name, const char *value);
char *netpgp_getvar(netpgp_t *netpgp, const char *name);
int netpgp_incvar(netpgp_t *netpgp, const char *name, const int delta);
int netpgp_unsetvar(netpgp_t *netpgp, const char *name);

/* set home directory information */
int netpgp_set_homedir(netpgp_t *netpgp, char *home, const char *subdir, const int quiet);

/* key management */
int netpgp_list_keys(netpgp_t *netpgp, const int psigs);
int netpgp_list_keys_json(netpgp_t *netpgp, char **json, const int psigs);
int netpgp_find_key(netpgp_t *netpgp, char *id);
char *netpgp_get_key(netpgp_t *netpgp, const char *name, const char *fmt);
char *netpgp_export_key(netpgp_t *netpgp, char *name);
int netpgp_import_key(netpgp_t *netpgp, char *f);
int netpgp_generate_key(netpgp_t *netpgp, char *id, int numbits);

/* file management */
int netpgp_encrypt_file(netpgp_t *netpgp, const char *userid, const char *f, char *out, int armored);
int netpgp_decrypt_file(netpgp_t *netpgp, const char *f, char *out, int armored);
int netpgp_sign_file(netpgp_t *netpgp, const char *userid, const char *f, char *out, int armored, int cleartext, int detached);
int netpgp_verify_file(netpgp_t *netpgp, const char *in, const char *out, int armored);

/* memory signing and encryption */
int netpgp_sign_memory(netpgp_t *netpgp, const char *userid, char *mem, size_t size, char *out, size_t outsize, const unsigned armored, const unsigned cleartext);
int netpgp_verify_memory(netpgp_t *netpgp, const void *in, const size_t size, void *out, size_t outsize, const int armored);
int netpgp_encrypt_memory(netpgp_t *netpgp, const char *userid, void *in, const size_t insize, char *out, size_t outsize, int armored);
int netpgp_decrypt_memory(netpgp_t *netpgp, const void *input, const size_t insize, char *out, size_t outsize, const int armored);

/* match and hkp-related functions */
int netpgp_match_keys_json(netpgp_t *netpgp, char **json, char *name, const char *fmt, const int psigs);
int netpgp_match_keys(netpgp_t *netpgp, char *name, const char *fmt, void *vp, const int psigs);
int netpgp_match_pubkeys(netpgp_t *netpgp, char *name, void *vp);
int netpgp_format_json(void *vp, const char *json, const int psigs);

int netpgp_validate_sigs(netpgp_t *netpgp);

/* save pgp key in ssh format */
int netpgp_write_sshkey(netpgp_t *netpgp, char *s, const char *userid, char *out, size_t size);
    '''  # noqa
)

ffi.cdef('void free(void *);')

ffi.set_source(
    'netpgp_cffi._netpgp',
    '#include <netpgp.h>',
    include_dirs=[
        'include',
    ],
    libraries=[
        'bz2',
        'crypto',
    ],
    extra_objects=[
        'lib/libnetpgp.a',
        'lib/libmj.a',
    ],
)
