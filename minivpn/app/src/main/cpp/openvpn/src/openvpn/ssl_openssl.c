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

#if defined(_MSC_VER) && !defined(_M_ARM64)
#include <openssl/applink.c>
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

void
tls_ctx_server_new(struct tls_root_ctx *ctx)
{
    ASSERT(NULL != ctx);

    ctx->ctx = SSL_CTX_new_ex(tls_libctx, NULL, SSLv23_server_method());

    if (ctx->ctx == NULL)
    {
        crypto_msg(M_FATAL, "SSL_CTX_new SSLv23_server_method");
    }
    if (ERR_peek_error() != 0)
    {
        crypto_msg(M_WARN, "Warning: TLS server context initialisation "
                   "has warnings.");
    }
}

void
tls_ctx_client_new(struct tls_root_ctx *ctx)
{
    ASSERT(NULL != ctx);

    ctx->ctx = SSL_CTX_new_ex(tls_libctx, NULL, SSLv23_client_method());

    if (ctx->ctx == NULL)
    {
        crypto_msg(M_FATAL, "SSL_CTX_new SSLv23_client_method");
    }
    if (ERR_peek_error() != 0)
    {
        crypto_msg(M_WARN, "Warning: TLS client context initialisation "
                   "has warnings.");
    }
}

void
tls_ctx_free(struct tls_root_ctx *ctx)
{
    ASSERT(NULL != ctx);
    SSL_CTX_free(ctx->ctx);
    ctx->ctx = NULL;
    unload_xkey_provider(); /* in case it is loaded */
}

bool
tls_ctx_initialised(struct tls_root_ctx *ctx)
{
    ASSERT(NULL != ctx);
    return NULL != ctx->ctx;
}


bool
tls_ctx_set_options(struct tls_root_ctx *ctx, unsigned int ssl_flags)
{
    ASSERT(NULL != ctx);

    /* process SSL options */
    long sslopt = SSL_OP_SINGLE_DH_USE | SSL_OP_NO_TICKET;
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
    sslopt |= SSL_OP_CIPHER_SERVER_PREFERENCE;
#endif
    sslopt |= SSL_OP_NO_COMPRESSION;
    /* Disable TLS renegotiations. OpenVPN's renegotiation creates new SSL
     * session and does not depend on this feature. And TLS renegotiations have
     * been problematic in the past */
#ifdef SSL_OP_NO_RENEGOTIATION
    sslopt |= SSL_OP_NO_RENEGOTIATION;
#endif

    SSL_CTX_set_options(ctx->ctx, sslopt);

#ifdef SSL_MODE_RELEASE_BUFFERS
    SSL_CTX_set_mode(ctx->ctx, SSL_MODE_RELEASE_BUFFERS);
#endif
    SSL_CTX_set_session_cache_mode(ctx->ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_default_passwd_cb(ctx->ctx, pem_password_callback);

    return true;
}

const char *
get_ssl_library_version(void)
{
    return "OpenSSL_version(OPENSSL_VERSION)";
}

/**
 * Setup ovpn.xey provider for signing with external keys.
 * It is loaded into a custom library context so as not to pollute
 * the default context. Alternatively we could override any
 * system-wide property query set on the default context. But we
 * want to avoid that.
 */
void
load_xkey_provider(void)
{
#ifdef HAVE_XKEY_PROVIDER

    /* Make a new library context for use in TLS context */
    if (!tls_libctx)
    {
        tls_libctx = OSSL_LIB_CTX_new();
        check_malloc_return(tls_libctx);

        /* Load all providers in default LIBCTX into this libctx.
         * OpenSSL has a child libctx functionality to automate this,
         * but currently that is usable only from within providers.
         * So we do something close to it manually here.
         */
        OSSL_PROVIDER_do_all(NULL, provider_load, tls_libctx);
    }

    if (!OSSL_PROVIDER_available(tls_libctx, "ovpn.xkey"))
    {
        OSSL_PROVIDER_add_builtin(tls_libctx, "ovpn.xkey", xkey_provider_init);
        if (!OSSL_PROVIDER_load(tls_libctx, "ovpn.xkey"))
        {
            msg(M_NONFATAL, "ERROR: failed loading external key provider: "
                "Signing with external keys will not work.");
        }
    }

    /* We only implement minimal functionality in ovpn.xkey, so we do not want
     * methods in xkey to be picked unless absolutely required (i.e, when the key
     * is external). Ensure this by setting a default propquery for the custom
     * libctx that unprefers, but does not forbid, ovpn.xkey. See also man page
     * of "property" in OpenSSL 3.0.
     */
    EVP_set_default_properties(tls_libctx, "?provider!=ovpn.xkey");

#endif /* HAVE_XKEY_PROVIDER */
}

/**
 * Undo steps in load_xkey_provider
 */
static void
unload_xkey_provider(void)
{
#ifdef HAVE_XKEY_PROVIDER
    if (tls_libctx)
    {
        OSSL_PROVIDER_do_all(tls_libctx, provider_unload, NULL);
        OSSL_LIB_CTX_free(tls_libctx);
    }
#endif /* HAVE_XKEY_PROVIDER */
    tls_libctx = NULL;
}

#endif /* defined(ENABLE_CRYPTO_OPENSSL) */
