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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "crypto.h"
#include "error.h"
#include "integer.h"
#include "platform.h"


/*
 * Encryption and Compression Routines.
 *
 * On entry, buf contains the input data and length.
 * On exit, it should be set to the output data and length.
 *
 * If buf->len is <= 0 we should return
 * If buf->len is set to 0 on exit it tells the caller to ignore the packet.
 *
 * work is a workspace buffer we are given of size BUF_SIZE.
 * work may be used to return output data, or the input buffer
 * may be modified and returned as output.  If output data is
 * returned in work, the data should start after buf.headroom bytes
 * of padding to leave room for downstream routines to prepend.
 *
 * Up to a total of buf.headroom bytes may be prepended to the input buf
 * by all routines (encryption, decryption, compression, and decompression).
 *
 * Note that the buf_prepend return will assert if we try to
 * make a header bigger than buf.headroom.  This should not
 * happen unless the frame parameters are wrong.
 */

static void
openvpn_encrypt_v0(struct buffer *buf, struct buffer work, struct crypto_options *opt)
{
    if (buf->len > 0 && opt)
    {
        {
            if (packet_id_initialized(&opt->packet_id)
                && !packet_id_write(&opt->packet_id.send, buf, false, true))
            {
                msg(D_CRYPT_ERRORS, "ENCRYPT ERROR: packet ID roll over");
                goto err;
            }
            if (BLEN(&work))
            {
                buf_write_prepend(buf, BPTR(&work), BLEN(&work));
            }
            work = *buf;
        }
        *buf = work;
    }
    return;
    err:
    buf->len = 0;
    return;
}


void
openvpn_encrypt(struct buffer *buf, struct buffer work,
                struct crypto_options *opt)
{
    if (buf->len > 0 && opt)
    {
        openvpn_encrypt_v0(buf, work, opt);
    }
}


static bool
openvpn_decrypt_v0(struct buffer *buf, struct buffer work,
                   struct crypto_options *opt, const struct frame *frame)
{
    if (buf->len > 0 && opt)
    {
        work = *buf;
        if (packet_id_initialized(&opt->packet_id))
        {
            struct packet_id_net pin;
            if (!packet_id_read(&pin, &work, false))
            {
                msg(D_CRYPT_ERRORS,"error reading packet-id");
                goto error_exit;
            }
        }
        *buf = work;
    }
    return true;
    error_exit:
    buf->len = 0;
    return false;
}

bool
openvpn_decrypt(struct buffer *buf, struct buffer work,
                struct crypto_options *opt, const struct frame *frame,
                const uint8_t *ad_start)
{
    bool ret = false;
    if (buf->len > 0 && opt)
    {
        ret = openvpn_decrypt_v0(buf, work, opt, frame);
    }
    else
    {
        ret = true;
    }
    return ret;
}

unsigned int
calculate_crypto_overhead(const struct key_type *kt,
                          unsigned int pkt_id_size,
                          bool occ)
{
    unsigned int crypto_overhead = 0;
    crypto_overhead = 80;
    msg(M_INFO,"crypto_overhead_header_size:%d   pkt_id_size:%d  occ:%s",crypto_overhead,pkt_id_size,occ?"true":"false");

    return crypto_overhead;
}

unsigned int
crypto_max_overhead(void)
{
    return packet_id_size(true) + OPENVPN_MAX_IV_LENGTH
           +OPENVPN_MAX_CIPHER_BLOCK_SIZE
           +max_int(OPENVPN_MAX_HMAC_SIZE, OPENVPN_AEAD_TAG_LENGTH);
}

void
init_key_type(struct key_type *kt, const char *ciphername,
              const char *authname, bool tls_mode, bool warn)
{
    bool aead_cipher = false;
    ASSERT(ciphername);
    ASSERT(authname);
    CLEAR(*kt);
    kt->cipher = ciphername;
    kt->digest = authname;
}


void
check_replay_consistency(const struct key_type *kt, bool packet_id)
{
    ASSERT(kt);
}

void
prng_bytes(uint8_t *output, int len)
{
    ASSERT(rand_bytes(output, len));
    msg(M_INFO,"rnd_size:%d",len);
    if (len==8){
        msg(M_INFO,"rnd:%ld",(long)output);
    } else {
        msg(M_INFO,"=============rnd==========");
    }
}

long int
get_random(void)
{
    long int l;
    prng_bytes((unsigned char *)&l, sizeof(l));
    if (l < 0)
    {
        l = -l;
    }
    msg(M_INFO,"rnd:%ld",l);
    return l;
}
