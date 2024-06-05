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
 * @file Control Channel Verification Module
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "base64.h"
#include "manage.h"
#include "otime.h"
#include "run_command.h"
#include "ssl_verify.h"

#include "auth_token.h"
#include "push.h"
#include "ssl_util.h"

/*
 * Retrieve the common name for the given tunnel's active session. If the
 * common name is NULL or empty, return NULL if null is true, or "UNDEF" if
 * null is false.
 */
const char *
tls_common_name(const struct tls_multi *multi, const bool null)
{
    const char *ret = NULL;
    if (multi)
    {
        ret = multi->session[TM_ACTIVE].common_name;
    }
    if (ret && strlen(ret))
    {
        return ret;
    }
    else if (null)
    {
        return NULL;
    }
    else
    {
        return "UNDEF";
    }
}

/*
 * Lock the common name for the given tunnel.
 */
void
tls_lock_common_name(struct tls_multi *multi)
{
    const char *cn = multi->session[TM_ACTIVE].common_name;
    if (cn && !multi->locked_cn)
    {
        multi->locked_cn = string_alloc(cn, NULL);
    }
}

const char *
tls_username(const struct tls_multi *multi, const bool null)
{
    const char *ret = NULL;
    if (multi)
    {
        ret = multi->locked_username;
    }
    if (ret && strlen(ret))
    {
        return ret;
    }
    else if (null)
    {
        return NULL;
    }
    else
    {
        return "UNDEF";
    }
}

void
cert_hash_free(struct cert_hash_set *chs)
{
    if (chs)
    {
        int i;
        for (i = 0; i < MAX_CERT_DEPTH; ++i)
        {
            free(chs->ch[i]);
        }
        free(chs);
    }
}

bool
cert_hash_compare(const struct cert_hash_set *chs1, const struct cert_hash_set *chs2)
{
    if (chs1 && chs2)
    {
        int i;
        for (i = 0; i < MAX_CERT_DEPTH; ++i)
        {
            const struct cert_hash *ch1 = chs1->ch[i];
            const struct cert_hash *ch2 = chs2->ch[i];

            if (!ch1 && !ch2)
            {
                continue;
            }
            else if (ch1 && ch2 && !memcmp(ch1->sha256_hash, ch2->sha256_hash,
                                           sizeof(ch1->sha256_hash)))
            {
                continue;
            }
            else
            {
                return false;
            }
        }
        return true;
    }
    else if (!chs1 && !chs2)
    {
        return true;
    }
    else
    {
        return false;
    }
}

static struct cert_hash_set *
cert_hash_copy(const struct cert_hash_set *chs)
{
    struct cert_hash_set *dest = NULL;
    if (chs)
    {
        int i;
        ALLOC_OBJ_CLEAR(dest, struct cert_hash_set);
        for (i = 0; i < MAX_CERT_DEPTH; ++i)
        {
            const struct cert_hash *ch = chs->ch[i];
            if (ch)
            {
                ALLOC_OBJ(dest->ch[i], struct cert_hash);
                memcpy(dest->ch[i]->sha256_hash, ch->sha256_hash,
                       sizeof(dest->ch[i]->sha256_hash));
            }
        }
    }
    return dest;
}
void
tls_lock_cert_hash_set(struct tls_multi *multi)
{
    const struct cert_hash_set *chs = multi->session[TM_ACTIVE].cert_hash_set;
    if (chs && !multi->locked_cert_hash_set)
    {
        multi->locked_cert_hash_set = cert_hash_copy(chs);
    }
}

void
auth_set_client_reason(struct tls_multi *multi, const char *client_reason)
{
    free(multi->client_reason);
    multi->client_reason = NULL;

    if (client_reason && strlen(client_reason))
    {
        multi->client_reason = string_alloc(client_reason, NULL);
    }
}

#ifdef ENABLE_MANAGEMENT

static inline enum auth_deferred_result
man_def_auth_test(const struct key_state *ks)
{
    if (management_enable_def_auth(management))
    {
        return ks->mda_status;
    }
    else
    {
        return ACF_DISABLED;
    }
}
#endif /* ifdef ENABLE_MANAGEMENT */

/**
 *  Removes auth_pending file from the file system
 *  and key_state structure
 */
static void
key_state_rm_auth_pending_file(struct auth_deferred_status *ads)
{
    if (ads && ads->auth_pending_file)
    {
        platform_unlink(ads->auth_pending_file);
        free(ads->auth_pending_file);
        ads->auth_pending_file = NULL;
    }
}

/**
 *  Removes auth_pending and auth_control files from file system
 *  and key_state structure
 */
void
key_state_rm_auth_control_files(struct auth_deferred_status *ads)
{
    if (ads->auth_control_file)
    {
        platform_unlink(ads->auth_control_file);
        free(ads->auth_control_file);
        ads->auth_control_file = NULL;
    }
    key_state_rm_auth_pending_file(ads);
}

enum tls_auth_status
tls_authentication_status(struct tls_multi *multi)
{
    return TLS_AUTHENTICATION_SUCCEEDED;
}

#ifdef ENABLE_MANAGEMENT
/*
 * For deferred auth, this is where the management interface calls (on server)
 * to indicate auth failure/success.
 */
bool
tls_authenticate_key(struct tls_multi *multi, const unsigned int mda_key_id, const bool auth, const char *client_reason)
{
    bool ret = false;
    if (multi)
    {
        int i;
        auth_set_client_reason(multi, client_reason);
        for (i = 0; i < KEY_SCAN_SIZE; ++i)
        {
            struct key_state *ks = get_key_scan(multi, i);
            if (ks->mda_key_id == mda_key_id)
            {
                ks->mda_status = auth ? ACF_SUCCEEDED : ACF_FAILED;
                ret = true;
            }
        }
    }
    return ret;
}
#endif /* ifdef ENABLE_MANAGEMENT */
