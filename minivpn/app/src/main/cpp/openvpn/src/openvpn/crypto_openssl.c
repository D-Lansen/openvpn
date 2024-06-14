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
 * @file Data Channel Cryptography OpenSSL-specific backend interface
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_CRYPTO_OPENSSL)

#include "basic.h"
#include "buffer.h"
#include "integer.h"
#include "crypto.h"
#include "crypto_backend.h"
#include "openssl_compat.h"

//#include <openssl/conf.h>
//#include <openssl/des.h>
//#include <openssl/err.h>
//#include <openssl/evp.h>
//#include <openssl/objects.h>
//#include <openssl/rand.h>
//#include <openssl/ssl.h>

//#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
//#include <openssl/kdf.h>
//#endif
//#if OPENSSL_VERSION_NUMBER >= 0x30000000L
//#include <openssl/provider.h>
//#endif

int
rand_bytes(uint8_t *output, int len)
{
    if (len < 0)
    {
        return 0;
    }
    else
    {
        for (int i = 0; i < len; i++)
        {
            int min = 0, max = 0xff;
            int range = max - min + 1;
            uint8_t rnd = min + rand() % range;
            memset(output+i, rnd, 1);
        }
        return 1;
    }
}

int
cipher_kt_block_size(const char *ciphername)
{
    return 16;
}

bool
cipher_kt_mode_cbc(const char *ciphername)
{
    return true;
}

#endif /* ENABLE_CRYPTO_OPENSSL */
