/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2022 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2010-2021 Fox Crypto B.V. <openvpn@foxcrypto.com>
 *  Copyright (C) 2008-2022 David Sommerseth <dazo@eurephia.org>
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
 * @file Control Channel SSL/Data dynamic negotion Module
 * This file is split from ssl.c to be able to unit test it.
 */

/*
 * The routines in this file deal with dynamically negotiating
 * the data channel HMAC and cipher keys through a TLS session.
 *
 * Both the TLS session and the data channel are multiplexed
 * over the same TCP/UDP port.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "error.h"
#include "common.h"

#include "ssl_ncp.h"
#include "ssl_util.h"
#include "openvpn.h"

/**
 * Return the Negotiable Crypto Parameters version advertised in the peer info
 * string, or 0 if none specified.
 */
static int
tls_peer_info_ncp_ver(const char *peer_info)
{
    const char *ncpstr = peer_info ? strstr(peer_info, "IV_NCP=") : NULL;
    if (ncpstr)
    {
        int ncp = 0;
        int r = sscanf(ncpstr, "IV_NCP=%d", &ncp);
        if (r == 1)
        {
            return ncp;
        }
    }
    return 0;
}


char *
mutate_ncp_cipher_list(const char *list, struct gc_arena *gc)
{
    bool error_found = false;

    struct buffer new_list  = alloc_buf(MAX_NCP_CIPHERS_LENGTH);

    char *const tmp_ciphers = string_alloc(list, NULL);
    const char *token = strtok(tmp_ciphers, ":");
    while (token)
    {
        /*
         * Going cipher_kt_name (and translate_cipher_name_from_openvpn/
         * translate_cipher_name_to_openvpn) also normalises the cipher name,
         * e.g. replacing AeS-128-gCm with AES-128-GCM
         *
         * ciphers that have ? in front of them are considered optional and
         * OpenVPN will only warn if they are not found (and remove them from
         * the list)
         */
        bool optional = false;
        if (token[0] == '?')
        {
            token++;
            optional = true;
        }

        const bool nonecipher = (strcmp(token, "none") == 0);

        if (nonecipher)
        {
            msg(M_WARN, "WARNING: cipher 'none' specified for --data-ciphers. "
                "This allows negotiation of NO encryption and "
                "tunnelled data WILL then be transmitted in clear text "
                "over the network! "
                "PLEASE DO RECONSIDER THIS SETTING!");
        }
        if (!nonecipher && !cipher_valid(token))
        {
            const char *optstr = optional ? "optional " : "";
            msg(M_WARN, "Unsupported %scipher in --data-ciphers: %s", optstr, token);
            error_found = error_found || !optional;
        }
        else
        {
            const char *ovpn_cipher_name = cipher_kt_name(token);
            if (nonecipher)
            {
                /* NULL resolves to [null-cipher] but we need none for
                 * data-ciphers */
                ovpn_cipher_name = "none";
            }

            if (buf_len(&new_list)> 0)
            {
                /* The next if condition ensure there is always space for
                 * a :
                 */
                buf_puts(&new_list, ":");
            }

            /* Ensure buffer has capacity for cipher name + : + \0 */
            if (!(buf_forward_capacity(&new_list) >
                  strlen(ovpn_cipher_name) + 2))
            {
                msg(M_WARN, "Length of --data-ciphers is over the "
                    "limit of 127 chars");
                error_found = true;
            }
            else
            {
                buf_puts(&new_list, ovpn_cipher_name);
            }
        }
        token = strtok(NULL, ":");
    }



    char *ret = NULL;
    if (!error_found && buf_len(&new_list) > 0)
    {
        buf_null_terminate(&new_list);
        ret = string_alloc(buf_str(&new_list), gc);
    }
    free(tmp_ciphers);
    free_buf(&new_list);

    return ret;
}

void
append_cipher_to_ncp_list(struct options *o, const char *ciphername)
{
    /* Append the --cipher to ncp_ciphers to allow it in NCP */
    size_t newlen = strlen(o->ncp_ciphers) + 1 + strlen(ciphername) + 1;
    char *ncp_ciphers = gc_malloc(newlen, false, &o->gc);

    ASSERT(openvpn_snprintf(ncp_ciphers, newlen, "%s:%s", o->ncp_ciphers,
                            ciphername));
    o->ncp_ciphers = ncp_ciphers;
}

bool
tls_item_in_cipher_list(const char *item, const char *list)
{
    char *tmp_ciphers = string_alloc(list, NULL);
    char *tmp_ciphers_orig = tmp_ciphers;

    const char *token = strtok(tmp_ciphers, ":");
    while (token)
    {
        if (0 == strcmp(token, item))
        {
            break;
        }
        token = strtok(NULL, ":");
    }
    free(tmp_ciphers_orig);

    return token != NULL;
}

const char *
get_p2p_ncp_cipher(struct tls_session *session, const char *peer_info,
                   struct gc_arena *gc)
{
    /* we use a local gc arena to keep the temporary strings needed by strsep */
    struct gc_arena gc_local = gc_new();
    const char *peer_ciphers = extract_var_peer_info(peer_info, "IV_CIPHERS=", &gc_local);

    if (!peer_ciphers)
    {
        gc_free(&gc_local);
        return NULL;
    }

    const char *server_ciphers;
    const char *client_ciphers;

    if (session->opt->server)
    {
        server_ciphers = session->opt->config_ncp_ciphers;
        client_ciphers = peer_ciphers;
    }
    else
    {
        client_ciphers = session->opt->config_ncp_ciphers;
        server_ciphers = peer_ciphers;
    }

    /* Find the first common cipher from TLS server and TLS client. We
     * use the preference of the server here to make it deterministic */
    char *tmp_ciphers = string_alloc(server_ciphers, &gc_local);

    const char *token;
    while ((token = strsep(&tmp_ciphers, ":")))
    {
        if (tls_item_in_cipher_list(token, client_ciphers))
        {
            break;
        }
    }

    const char *ret = NULL;
    if (token != NULL)
    {
        ret = string_alloc(token, gc);
    }
    gc_free(&gc_local);

    return ret;
}
