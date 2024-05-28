/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2021 OpenVPN Inc <sales@openvpn.net>
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

#include "ssl_util.h"
#include "ssl_pkt.h"
#include "ssl_common.h"
#include "crypto.h"
#include "session_id.h"
#include "reliable.h"
#include "tls_crypt.h"


void
write_control_auth(struct tls_session *session,
                   struct key_state *ks,
                   struct buffer *buf,
                   struct link_socket_actual **to_link_addr,
                   int opcode,
                   int max_ack,
                   bool prepend_ack)
{
    uint8_t header = ks->key_id | (opcode << P_OPCODE_SHIFT);

    ASSERT(link_socket_actual_defined(&ks->remote_addr));
    ASSERT(reliable_ack_write
               (ks->rec_ack, ks->lru_acks, buf, &ks->session_id_remote,
               max_ack, prepend_ack));

    msg(D_TLS_DEBUG, "%s(): %s", __func__, packet_opcode_name(opcode));

    ASSERT(session_id_write_prepend(&session->session_id, buf));
    ASSERT(buf_write_prepend(buf, &header, sizeof(header)));

    *to_link_addr = &ks->remote_addr;
}

bool
read_control_auth(struct buffer *buf,
                  struct tls_wrap_ctx *ctx,
                  const struct link_socket_actual *from,
                  const struct tls_options *opt)
{
    struct gc_arena gc = gc_new();
    bool ret = false;

    const uint8_t opcode = *(BPTR(buf)) >> P_OPCODE_SHIFT;
    if ((opcode == P_CONTROL_HARD_RESET_CLIENT_V3
         || opcode == P_CONTROL_WKC_V1)
        && !tls_crypt_v2_extract_client_key(buf, ctx, opt))
    {
        msg(D_TLS_ERRORS,
            "TLS Error: can not extract tls-crypt-v2 client key from %s",
            print_link_socket_actual(from, &gc));
        goto cleanup;
    }

    if (ctx->tls_crypt_v2_server_key.cipher)
    {
        /* If tls-crypt-v2 is enabled, require *some* wrapping */
        msg(D_TLS_ERRORS, "TLS Error: could not determine wrapping from %s",
            print_link_socket_actual(from, &gc));
        /* TODO Do we want to support using tls-crypt-v2 and no control channel
         * wrapping at all simultaneously?  That would allow server admins to
         * upgrade clients one-by-one without running a second instance, but we
         * should not enable it by default because it breaks DoS-protection.
         * So, add something like --tls-crypt-v2-allow-insecure-fallback ? */
        goto cleanup;
    }

    buf_advance(buf, SID_SIZE + 1);
    ret = true;
cleanup:
    gc_free(&gc);
    return ret;
}


hmac_ctx_t *
session_id_hmac_init(void)
{
    /* We assume that SHA256 is always available */
    ASSERT(md_valid("SHA256"));
    hmac_ctx_t *hmac_ctx = hmac_ctx_new();

    uint8_t key[SHA256_DIGEST_LENGTH];
    ASSERT(rand_bytes(key, sizeof(key)));

    hmac_ctx_init(hmac_ctx, key, "SHA256");
    return hmac_ctx;
}
