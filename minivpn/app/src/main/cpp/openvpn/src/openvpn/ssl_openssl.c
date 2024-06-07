/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2022 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2010-2021 Fox Crypto B.V. <openvpn@foxcrypto.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file Control Channel OpenSSL Backend
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_CRYPTO_OPENSSL)

#include "errlevel.h"
#include "buffer.h"
#include "misc.h"
#include "manage.h"
#include "memdbg.h"
#include "ssl_backend.h"
#include "ssl_common.h"
#include "base64.h"
#include "openssl_compat.h"

#ifdef ENABLE_CRYPTOAPI
#include "cryptoapi.h"
#endif


#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#endif


OSSL_LIB_CTX *tls_libctx; /* Global */

static void unload_xkey_provider(void);

/*
 * Allocate space in SSL objects in which to store a struct tls_session
 * pointer back to parent.
 *
 */

int mydata_index; /* GLOBAL */

void
tls_init_lib(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
#ifndef ENABLE_SMALL
    SSL_load_error_strings();
#endif
    OpenSSL_add_all_algorithms();
#endif
    mydata_index = SSL_get_ex_new_index(0, "struct session *", NULL, NULL, NULL);
    ASSERT(mydata_index >= 0);
}

void
tls_free_lib(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_cleanup();
#ifndef ENABLE_SMALL
    ERR_free_strings();
#endif
#endif
}


#endif /* defined(ENABLE_CRYPTO_OPENSSL) */
