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
 * @file Control Channel SSL library backend module
 */


#ifndef SSL_BACKEND_H_
#define SSL_BACKEND_H_

#include "buffer.h"

#ifdef ENABLE_CRYPTO_OPENSSL
#include "ssl_openssl.h"
#define SSLAPI SSLAPI_OPENSSL
#endif
#ifdef ENABLE_CRYPTO_MBEDTLS
#include "ssl_mbedtls.h"
#include "ssl_verify_mbedtls.h"
#define SSLAPI SSLAPI_MBEDTLS
#endif

/* Ensure that SSLAPI got a sane value if SSL is disabled or unknown */
#ifndef SSLAPI
#define SSLAPI SSLAPI_NONE
#endif

/**
 *  prototype for struct tls_session from ssl_common.h
 */
struct tls_session;

/**
 * Get a tls_cipher_name_pair containing OpenSSL and IANA names for supplied TLS cipher name
 *
 * @param cipher_name   Can be either OpenSSL or IANA cipher name
 * @return              tls_cipher_name_pair* if found, NULL otherwise
 */
typedef struct { const char *openssl_name; const char *iana_name; } tls_cipher_name_pair;
const tls_cipher_name_pair *tls_get_cipher_name_pair(const char *cipher_name, size_t len);

void tls_init_lib(void);

/**
 * Free any global SSL library-specific data structures.
 */
void tls_free_lib(void);

/**
 * Clear the underlying SSL library's error state.
 */
void tls_clear_error(void);

#endif /* SSL_BACKEND_H_ */
