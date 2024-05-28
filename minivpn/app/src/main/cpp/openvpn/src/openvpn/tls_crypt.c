/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2016-2021 Fox Crypto B.V. <openvpn@foxcrypto.com>
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

#include "argv.h"
#include "base64.h"
#include "crypto.h"
#include "platform.h"
#include "run_command.h"
#include "session_id.h"
#include "ssl.h"

#include "tls_crypt.h"

const char *tls_crypt_v2_cli_pem_name = "OpenVPN tls-crypt-v2 client key";
const char *tls_crypt_v2_srv_pem_name = "OpenVPN tls-crypt-v2 server key";

/** Metadata contains user-specified data */
static const uint8_t TLS_CRYPT_METADATA_TYPE_USER           = 0x00;
/** Metadata contains a 64-bit unix timestamp in network byte order */
static const uint8_t TLS_CRYPT_METADATA_TYPE_TIMESTAMP      = 0x01;

static struct key_type
tls_crypt_kt(void)
{
    return create_kt("AES-256-CTR", "SHA256", "tls-crypt");
}

int
tls_crypt_buf_overhead(void)
{
    return packet_id_size(true) + TLS_CRYPT_TAG_SIZE + TLS_CRYPT_BLOCK_SIZE;
}

void
tls_crypt_init_key(struct key_ctx_bi *key, const char *key_file,
                   bool key_inline, bool tls_server)
{
    const int key_direction = tls_server ?
                              KEY_DIRECTION_NORMAL : KEY_DIRECTION_INVERSE;
    struct key_type kt = tls_crypt_kt();
    if (!kt.cipher || !kt.digest)
    {
        msg(M_FATAL, "ERROR: --tls-crypt not supported");
    }
    crypto_read_openvpn_key(&kt, key, key_file, key_inline, key_direction,
                            "Control Channel Encryption", "tls-crypt");
}


static inline void
tls_crypt_v2_load_client_key(struct key_ctx_bi *key, const struct key2 *key2,
                             bool tls_server)
{
    const int key_direction = tls_server ?
                              KEY_DIRECTION_NORMAL : KEY_DIRECTION_INVERSE;
    struct key_type kt = tls_crypt_kt();
    if (!kt.cipher || !kt.digest)
    {
        msg(M_FATAL, "ERROR: --tls-crypt-v2 not supported");
    }
    init_key_ctx_bi(key, key2, key_direction, &kt,
                    "Control Channel Encryption");
}

void
tls_crypt_v2_init_client_key(struct key_ctx_bi *key, struct buffer *wkc_buf,
                             const char *key_file, bool key_inline)
{
    struct buffer client_key = alloc_buf(TLS_CRYPT_V2_CLIENT_KEY_LEN
                                         + TLS_CRYPT_V2_MAX_WKC_LEN);

    if (!read_pem_key_file(&client_key, tls_crypt_v2_cli_pem_name,
                           key_file, key_inline))
    {
        msg(M_FATAL, "ERROR: invalid tls-crypt-v2 client key format");
    }

    struct key2 key2;
    if (!buf_read(&client_key, &key2.keys, sizeof(key2.keys)))
    {
        msg(M_FATAL, "ERROR: not enough data in tls-crypt-v2 client key");
    }

    tls_crypt_v2_load_client_key(key, &key2, false);
    secure_memzero(&key2, sizeof(key2));

    *wkc_buf = client_key;
}

void
tls_crypt_v2_init_server_key(struct key_ctx *key_ctx, bool encrypt,
                             const char *key_file, bool key_inline)
{
    struct key srv_key;
    struct buffer srv_key_buf;

    buf_set_write(&srv_key_buf, (void *)&srv_key, sizeof(srv_key));
    if (!read_pem_key_file(&srv_key_buf, tls_crypt_v2_srv_pem_name,
                           key_file, key_inline))
    {
        msg(M_FATAL, "ERROR: invalid tls-crypt-v2 server key format");
    }

    struct key_type kt = tls_crypt_kt();
    if (!kt.cipher || !kt.digest)
    {
        msg(M_FATAL, "ERROR: --tls-crypt-v2 not supported");
    }
    init_key_ctx(key_ctx, &srv_key, &kt, encrypt, "tls-crypt-v2 server key");
    secure_memzero(&srv_key, sizeof(srv_key));
}

static bool
tls_crypt_v2_unwrap_client_key(struct key2 *client_key, struct buffer *metadata,
                               struct buffer wrapped_client_key,
                               struct key_ctx *server_key)
{
    const char *error_prefix = __func__;
    bool ret = false;
    struct gc_arena gc = gc_new();
    /* The crypto API requires one extra cipher block of buffer head room when
     * decrypting, which nicely matches the tag size of WKc.  So
     * TLS_CRYPT_V2_MAX_WKC_LEN is always large enough for the plaintext. */
    uint8_t plaintext_buf_data[TLS_CRYPT_V2_MAX_WKC_LEN] = { 0 };
    struct buffer plaintext = { 0 };

    dmsg(D_TLS_DEBUG_MED, "%s: unwrapping client key (len=%d): %s", __func__,
         BLEN(&wrapped_client_key), format_hex(BPTR(&wrapped_client_key),
                                               BLEN(&wrapped_client_key),
                                               0, &gc));

    if (TLS_CRYPT_V2_MAX_WKC_LEN < BLEN(&wrapped_client_key))
    {
        CRYPT_ERROR("wrapped client key too big");
    }

    /* Decrypt client key and metadata */
    uint16_t net_len = 0;
    const uint8_t *tag = BPTR(&wrapped_client_key);

    if (BLEN(&wrapped_client_key) < sizeof(net_len))
    {
        CRYPT_ERROR("failed to read length");
    }
    memcpy(&net_len, BEND(&wrapped_client_key) - sizeof(net_len),
           sizeof(net_len));

    if (ntohs(net_len) != BLEN(&wrapped_client_key))
    {
        dmsg(D_TLS_DEBUG_LOW, "%s: net_len=%u, BLEN=%i", __func__,
             ntohs(net_len), BLEN(&wrapped_client_key));
        CRYPT_ERROR("invalid length");
    }

    buf_inc_len(&wrapped_client_key, -(int)sizeof(net_len));

    if (!buf_advance(&wrapped_client_key, TLS_CRYPT_TAG_SIZE))
    {
        CRYPT_ERROR("failed to read tag");
    }

    if (!cipher_ctx_reset(server_key->cipher, tag))
    {
        CRYPT_ERROR("failed to initialize IV");
    }
    buf_set_write(&plaintext, plaintext_buf_data, sizeof(plaintext_buf_data));
    int outlen = 0;
    if (!cipher_ctx_update(server_key->cipher, BPTR(&plaintext), &outlen,
                           BPTR(&wrapped_client_key),
                           BLEN(&wrapped_client_key)))
    {
        CRYPT_ERROR("could not decrypt client key");
    }
    ASSERT(buf_inc_len(&plaintext, outlen));

    if (!cipher_ctx_final(server_key->cipher, BEND(&plaintext), &outlen))
    {
        CRYPT_ERROR("cipher final failed");
    }
    ASSERT(buf_inc_len(&plaintext, outlen));

    /* Check authentication */
    uint8_t tag_check[TLS_CRYPT_TAG_SIZE] = { 0 };
    hmac_ctx_reset(server_key->hmac);
    hmac_ctx_update(server_key->hmac, (void *)&net_len, sizeof(net_len));
    hmac_ctx_update(server_key->hmac, BPTR(&plaintext),
                    BLEN(&plaintext));
    hmac_ctx_final(server_key->hmac, tag_check);

    if (memcmp_constant_time(tag, tag_check, sizeof(tag_check)))
    {
        dmsg(D_CRYPTO_DEBUG, "tag      : %s",
             format_hex(tag, sizeof(tag_check), 0, &gc));
        dmsg(D_CRYPTO_DEBUG, "tag_check: %s",
             format_hex(tag_check, sizeof(tag_check), 0, &gc));
        CRYPT_ERROR("client key authentication error");
    }

    if (buf_len(&plaintext) < sizeof(client_key->keys))
    {
        CRYPT_ERROR("failed to read client key");
    }
    memcpy(&client_key->keys, BPTR(&plaintext), sizeof(client_key->keys));
    ASSERT(buf_advance(&plaintext, sizeof(client_key->keys)));

    if (!buf_copy(metadata, &plaintext))
    {
        CRYPT_ERROR("metadata too large for supplied buffer");
    }

    ret = true;
error_exit:
    if (!ret)
    {
        secure_memzero(client_key, sizeof(*client_key));
    }
    buf_clear(&plaintext);
    gc_free(&gc);
    return ret;
}

static bool
tls_crypt_v2_verify_metadata(const struct tls_wrap_ctx *ctx,
                             const struct tls_options *opt)
{
    bool ret = false;
    struct gc_arena gc = gc_new();
    const char *tmp_file = NULL;
    struct buffer metadata = ctx->tls_crypt_v2_metadata;
    int metadata_type = buf_read_u8(&metadata);
    if (metadata_type < 0)
    {
        msg(M_WARN, "ERROR: no metadata type");
        goto cleanup;
    }

    tmp_file = platform_create_temp_file(opt->tmp_dir, "tls_crypt_v2_metadata_",
                                         &gc);
    if (!tmp_file || !buffer_write_file(tmp_file, &metadata))
    {
        msg(M_WARN, "ERROR: could not write metadata to file");
        goto cleanup;
    }

    char metadata_type_str[4] = { 0 }; /* Max value: 255 */
    openvpn_snprintf(metadata_type_str, sizeof(metadata_type_str),
                     "%i", metadata_type);
    struct env_set *es = env_set_create(NULL);
    setenv_str(es, "script_type", "tls-crypt-v2-verify");
    setenv_str(es, "metadata_type", metadata_type_str);
    setenv_str(es, "metadata_file", tmp_file);

    struct argv argv = argv_new();
    argv_parse_cmd(&argv, opt->tls_crypt_v2_verify_script);
    argv_msg_prefix(D_TLS_DEBUG, &argv, "Executing tls-crypt-v2-verify");

    ret = openvpn_run_script(&argv, es, 0, "--tls-crypt-v2-verify");

    argv_free(&argv);
    env_set_destroy(es);

    if (!platform_unlink(tmp_file))
    {
        msg(M_WARN, "WARNING: failed to remove temp file '%s", tmp_file);
    }

    if (ret)
    {
        msg(D_HANDSHAKE, "TLS CRYPT V2 VERIFY SCRIPT OK");
    }
    else
    {
        msg(D_HANDSHAKE, "TLS CRYPT V2 VERIFY SCRIPT ERROR");
    }

cleanup:
    gc_free(&gc);
    return ret;
}

bool
tls_crypt_v2_extract_client_key(struct buffer *buf,
                                struct tls_wrap_ctx *ctx,
                                const struct tls_options *opt)
{
    if (!ctx->tls_crypt_v2_server_key.cipher)
    {
        msg(D_TLS_ERRORS,
            "Client wants tls-crypt-v2, but no server key present.");
        return false;
    }

    msg(D_HANDSHAKE, "Control Channel: using tls-crypt-v2 key");

    struct buffer wrapped_client_key = *buf;
    uint16_t net_len = 0;

    if (BLEN(&wrapped_client_key) < sizeof(net_len))
    {
        msg(D_TLS_ERRORS, "Can not read tls-crypt-v2 client key length");
        return false;
    }
    memcpy(&net_len, BEND(&wrapped_client_key) - sizeof(net_len),
           sizeof(net_len));

    size_t wkc_len = ntohs(net_len);
    if (!buf_advance(&wrapped_client_key, BLEN(&wrapped_client_key) - wkc_len))
    {
        msg(D_TLS_ERRORS, "Can not locate tls-crypt-v2 client key");
        return false;
    }

    struct key2 client_key = { 0 };
    ctx->tls_crypt_v2_metadata = alloc_buf(TLS_CRYPT_V2_MAX_METADATA_LEN);
    if (!tls_crypt_v2_unwrap_client_key(&client_key,
                                        &ctx->tls_crypt_v2_metadata,
                                        wrapped_client_key,
                                        &ctx->tls_crypt_v2_server_key))
    {
        msg(D_TLS_ERRORS, "Can not unwrap tls-crypt-v2 client key");
        secure_memzero(&client_key, sizeof(client_key));
        return false;
    }

    /* Load the decrypted key */
    ctx->mode = TLS_WRAP_NONE;
    ctx->cleanup_key_ctx = true;
    ctx->opt.flags |= CO_PACKET_ID_LONG_FORM;
    memset(&ctx->opt.key_ctx_bi, 0, sizeof(ctx->opt.key_ctx_bi));
    tls_crypt_v2_load_client_key(&ctx->opt.key_ctx_bi, &client_key, true);
    secure_memzero(&client_key, sizeof(client_key));

    /* Remove client key from buffer so tls-crypt code can unwrap message */
    ASSERT(buf_inc_len(buf, -(BLEN(&wrapped_client_key))));

    if (opt && opt->tls_crypt_v2_verify_script)
    {
        return tls_crypt_v2_verify_metadata(ctx, opt);
    }

    return true;
}

