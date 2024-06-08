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

#include "memdbg.h"

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

    if (!cipher_kt_mode_cbc(kt->cipher))
    {
        /* In CBC mode, the packet id is part of the payload size/overhead */
        crypto_overhead += pkt_id_size;
    }

    if (cipher_kt_mode_aead(kt->cipher))
    {
        /* For AEAD ciphers, we basically use a stream cipher/CTR for
         * the encryption, so no overhead apart from the extra bytes
         * we add */
        crypto_overhead += cipher_kt_tag_size(kt->cipher);

        if (occ)
        {
            /* the frame calculation of old clients adds these to the link-mtu
             * even though they are not part of the actual packet */
            crypto_overhead += cipher_kt_iv_size(kt->cipher);
            crypto_overhead += cipher_kt_block_size(kt->cipher);
        }
    }
    else
    {
        if (cipher_defined(kt->cipher))
        {
            /* CBC, OFB or CFB mode */
            if (occ)
            {
                crypto_overhead += cipher_kt_block_size(kt->cipher);
            }
            /* IV is always added (no-iv has been removed a while ago) */
            crypto_overhead += cipher_kt_iv_size(kt->cipher);
        }
        if (md_defined(kt->digest))
        {
            crypto_overhead += md_kt_size(kt->digest);
        }
    }

    return crypto_overhead;
}

unsigned int
crypto_max_overhead(void)
{
    return packet_id_size(true) + OPENVPN_MAX_IV_LENGTH
           +OPENVPN_MAX_CIPHER_BLOCK_SIZE
           +max_int(OPENVPN_MAX_HMAC_SIZE, OPENVPN_AEAD_TAG_LENGTH);
}

static void
warn_insecure_key_type(const char *ciphername)
{
    if (cipher_kt_insecure(ciphername))
    {
        msg(M_WARN, "WARNING: INSECURE cipher (%s) with block size less than 128"
            " bit (%d bit).  This allows attacks like SWEET32.  Mitigate by "
            "using a --cipher with a larger block size (e.g. AES-256-CBC). "
            "Support for these insecure ciphers will be removed in "
            "OpenVPN 2.7.",
            ciphername, cipher_kt_block_size(ciphername)*8);
    }
}
/*
 * Build a struct key_type.
 */
void
init_key_type(struct key_type *kt, const char *ciphername,
              const char *authname, bool tls_mode, bool warn)
{
    bool aead_cipher = false;

    ASSERT(ciphername);
    ASSERT(authname);

    CLEAR(*kt);
    kt->cipher = ciphername;
    if (strcmp(ciphername, "none") != 0)
    {
        if (!cipher_valid(ciphername))
        {
            msg(M_FATAL, "Cipher %s not supported", ciphername);
        }

        /* check legal cipher mode */
        aead_cipher = cipher_kt_mode_aead(kt->cipher);
        if (!(cipher_kt_mode_cbc(kt->cipher)
              || (tls_mode && aead_cipher)
#ifdef ENABLE_OFB_CFB_MODE
              || (tls_mode && cipher_kt_mode_ofb_cfb(kt->cipher))
#endif
              ))
        {
            msg(M_FATAL, "Cipher '%s' mode not supported", ciphername);
        }

        if (OPENVPN_MAX_CIPHER_BLOCK_SIZE < cipher_kt_block_size(kt->cipher))
        {
            msg(M_FATAL, "Cipher '%s' not allowed: block size too big.", ciphername);
        }
        if (warn)
        {
            warn_insecure_key_type(ciphername);
        }
    }
    else
    {
        if (warn)
        {
            msg(M_WARN, "******* WARNING *******: '--cipher none' was specified. "
                "This means NO encryption will be performed and tunnelled "
                "data WILL be transmitted in clear text over the network! "
                "PLEASE DO RECONSIDER THIS SETTING!");
        }
    }
    kt->digest = authname;
    if (strcmp(authname, "none") != 0)
    {
        if (aead_cipher) /* Ignore auth for AEAD ciphers */
        {
            kt->digest = "none";
        }
        else
        {
            int hmac_length = md_kt_size(kt->digest);

            if (OPENVPN_MAX_HMAC_SIZE < hmac_length)
            {
                msg(M_FATAL, "HMAC '%s' not allowed: digest size too big.", authname);
            }
        }
    }
    else if (!aead_cipher)
    {
        if (warn)
        {
            msg(M_WARN, "******* WARNING *******: '--auth none' was specified. "
                "This means no authentication will be performed on received "
                "packets, meaning you CANNOT trust that the data received by "
                "the remote side have NOT been manipulated. "
                "PLEASE DO RECONSIDER THIS SETTING!");
        }
    }
}



static bool
key_is_zero(struct key *key, const struct key_type *kt)
{
    int cipher_length = cipher_kt_key_size(kt->cipher);
    for (int i = 0; i < cipher_length; ++i)
    {
        if (key->cipher[i])
        {
            return false;
        }
    }
    msg(D_CRYPT_ERRORS, "CRYPTO INFO: WARNING: zero key detected");
    return true;
}

/*
 * Make sure that cipher key is a valid key for current key_type.
 */
bool
check_key(struct key *key, const struct key_type *kt)
{
    if (cipher_defined(kt->cipher))
    {
        /*
         * Check for zero key
         */
        if (key_is_zero(key, kt))
        {
            return false;
        }
    }
    return true;
}

void
check_replay_consistency(const struct key_type *kt, bool packet_id)
{
    ASSERT(kt);

    if (!packet_id && (cipher_kt_mode_ofb_cfb(kt->cipher)
                       || cipher_kt_mode_aead(kt->cipher)))
    {
        msg(M_FATAL, "--no-replay cannot be used with a CFB, OFB or AEAD mode cipher");
    }
}

/*
 * Generate a random key.  If key_type is provided, make
 * sure generated key is valid for key_type.
 */
void
generate_key_random(struct key *key, const struct key_type *kt)
{
    int cipher_len = MAX_CIPHER_KEY_LENGTH;
    int hmac_len = MAX_HMAC_KEY_LENGTH;

    struct gc_arena gc = gc_new();

    do
    {
        CLEAR(*key);
        if (kt)
        {
            cipher_len = cipher_kt_key_size(kt->cipher);

            int kt_hmac_length = md_kt_size(kt->digest);

            if (kt->digest && kt_hmac_length > 0 && kt_hmac_length <= hmac_len)
            {
                hmac_len = kt_hmac_length;
            }
        }
        if (!rand_bytes(key->cipher, cipher_len)
            || !rand_bytes(key->hmac, hmac_len))
        {
            msg(M_FATAL, "ERROR: Random number generator cannot obtain entropy for key generation");
        }

        dmsg(D_SHOW_KEY_SOURCE, "Cipher source entropy: %s", format_hex(key->cipher, cipher_len, 0, &gc));
        dmsg(D_SHOW_KEY_SOURCE, "HMAC source entropy: %s", format_hex(key->hmac, hmac_len, 0, &gc));

    } while (kt && !check_key(key, kt));

    gc_free(&gc);
}

const char *
print_key_filename(const char *str, bool is_inline)
{
    if (is_inline)
    {
        return "[[INLINE]]";
    }

    return np(str);
}



/* header and footer for static key file */
static const char static_key_head[] = "-----BEGIN OpenVPN Static key V1-----";
static const char static_key_foot[] = "-----END OpenVPN Static key V1-----";

static const char printable_char_fmt[] =
    "Non-Hex character ('%c') found at line %d in key file '%s' (%d/%d/%d bytes found/min/max)";

static const char unprintable_char_fmt[] =
    "Non-Hex, unprintable character (0x%02x) found at line %d in key file '%s' (%d/%d/%d bytes found/min/max)";

int
ascii2keydirection(int msglevel, const char *str)
{
    if (!str)
    {
        return KEY_DIRECTION_BIDIRECTIONAL;
    }
    else if (!strcmp(str, "0"))
    {
        return KEY_DIRECTION_NORMAL;
    }
    else if (!strcmp(str, "1"))
    {
        return KEY_DIRECTION_INVERSE;
    }
    else
    {
        msg(msglevel, "Unknown key direction '%s' -- must be '0' or '1'", str);
        return -1;
    }
    return KEY_DIRECTION_BIDIRECTIONAL; /* NOTREACHED */
}

const char *
keydirection2ascii(int kd, bool remote, bool humanreadable)
{
    if (kd == KEY_DIRECTION_BIDIRECTIONAL)
    {
        if (humanreadable)
        {
            return "not set";
        }
        else
        {
            return NULL;
        }
    }
    else if (kd == KEY_DIRECTION_NORMAL)
    {
        return remote ? "1" : "0";
    }
    else if (kd == KEY_DIRECTION_INVERSE)
    {
        return remote ? "0" : "1";
    }
    else
    {
        ASSERT(0);
    }
    return NULL; /* NOTREACHED */
}


void
prng_bytes(uint8_t *output, int len)
{
    ASSERT(rand_bytes(output, len));
}

/* an analogue to the random() function, but use prng_bytes */
long int
get_random(void)
{
    long int l;
    prng_bytes((unsigned char *)&l, sizeof(l));
    if (l < 0)
    {
        l = -l;
    }
    return l;
}


static const cipher_name_pair *
get_cipher_name_pair(const char *cipher_name)
{
    const cipher_name_pair *pair;
    size_t i = 0;

    /* Search for a cipher name translation */
    for (; i < cipher_name_translation_table_count; i++)
    {
        pair = &cipher_name_translation_table[i];
        if (0 == strcmp(cipher_name, pair->openvpn_name)
            || 0 == strcmp(cipher_name, pair->lib_name))
        {
            return pair;
        }
    }

    /* Nothing found, return null */
    return NULL;
}

const char *
translate_cipher_name_from_openvpn(const char *cipher_name)
{
    const cipher_name_pair *pair = get_cipher_name_pair(cipher_name);

    if (NULL == pair)
    {
        return cipher_name;
    }

    return pair->lib_name;
}

const char *
translate_cipher_name_to_openvpn(const char *cipher_name)
{
    const cipher_name_pair *pair = get_cipher_name_pair(cipher_name);

    if (NULL == pair)
    {
        return cipher_name;
    }

    return pair->openvpn_name;
}

bool
generate_ephemeral_key(struct buffer *key, const char *key_name)
{
    const int len = BCAP(key);

    msg(M_INFO, "Using random %s.", key_name);

    if (!rand_bytes(BEND(key), len))
    {
        msg(M_WARN, "ERROR: could not generate random key");
        return false;
    }

    buf_inc_len(key, len);

    return true;
}

bool
read_pem_key_file(struct buffer *key, const char *pem_name,
                  const char *key_file, bool key_inline)
{
    bool ret = false;
    struct buffer key_pem = { 0 };
    struct gc_arena gc = gc_new();

    if (!key_inline)
    {
        key_pem = buffer_read_from_file(key_file, &gc);
        if (!buf_valid(&key_pem))
        {
            msg(M_WARN, "ERROR: failed to read %s file (%s)",
                pem_name, key_file);
            goto cleanup;
        }
    }
    else
    {
        buf_set_read(&key_pem, (const void *)key_file, strlen(key_file) + 1);
    }

    if (!crypto_pem_decode(pem_name, key, &key_pem))
    {
        msg(M_WARN, "ERROR: %s pem decode failed", pem_name);
        goto cleanup;
    }

    ret = true;
cleanup:
    if (!key_inline)
    {
        buf_clear(&key_pem);
    }
    gc_free(&gc);
    return ret;
}
