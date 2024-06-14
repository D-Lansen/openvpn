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
 * @file Data Channel Cryptography SSL library-specific backend interface
 */

#ifndef CRYPTO_BACKEND_H_
#define CRYPTO_BACKEND_H_

#ifdef ENABLE_CRYPTO_OPENSSL
#include "crypto_openssl.h"
#endif
#ifdef ENABLE_CRYPTO_MBEDTLS
#include "crypto_mbedtls.h"
#endif
#include "basic.h"
#include "buffer.h"

/* TLS uses a tag of 128 bytes, let's do the same for OpenVPN */
#define OPENVPN_AEAD_TAG_LENGTH 16

/* Maximum cipher block size (bytes) */
#define OPENVPN_MAX_CIPHER_BLOCK_SIZE 32

/* Maximum HMAC digest size (bytes) */
#define OPENVPN_MAX_HMAC_SIZE   64
/*
 *
 * Random number functions, used in cases where we want
 * reasonably strong cryptographic random number generation
 * without depleting our entropy pool.  Used for random
 * IV values and a number of other miscellaneous tasks.
 *
 */

/**
 * Wrapper for secure random number generator. Retrieves len bytes of random
 * data, and places it in output.
 *
 * @param output        Output buffer
 * @param len           Length of the output buffer, in bytes
 *
 * @return              \c 1 on success, \c 0 on failure
 */
int rand_bytes(uint8_t *output, int len);

/*
 *
 * Generic cipher key type functions
 *
 */
/*
 * Max size in bytes of any cipher key that might conceivably be used.
 *
 * This value is checked at compile time in crypto.c to make sure
 * it is always at least EVP_MAX_KEY_LENGTH.
 *
 * We define our own value, since this parameter
 * is used to control the size of static key files.
 * If the OpenSSL library increases EVP_MAX_KEY_LENGTH,
 * we don't want our key files to be suddenly rendered
 * unusable.
 */
#define MAX_CIPHER_KEY_LENGTH 64

/**
 * Returns the block size of the cipher, in bytes.
 *
 * @param ciphername    cipher name
 *
 * @return              Block size, in bytes.
 */
int cipher_kt_block_size(const char *ciphername);

/**
 * Check if the supplied cipher is a supported CBC mode cipher.
 *
 * @param ciphername    cipher name
 *
 * @return              true iff the cipher is a CBC mode cipher.
 */
bool cipher_kt_mode_cbc(const char *ciphername);

#define MAX_HMAC_KEY_LENGTH 64

#endif /* CRYPTO_BACKEND_H_ */
