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
 * @file Control Channel SSL/Data channel negotiation Module
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
#include "socket.h"
#include "misc.h"
#include "interval.h"
#include "perf.h"
#include "gremlin.h"
#include "route.h"
#include "tls_crypt.h"

#include "ssl.h"
#include "ssl_verify.h"
#include "ssl_backend.h"
#include "ssl_ncp.h"
#include "ssl_util.h"
#include "auth_token.h"
#include "mss.h"

#ifdef MEASURE_TLS_HANDSHAKE_STATS

static int tls_handshake_success; /* GLOBAL */
static int tls_handshake_error;   /* GLOBAL */
static int tls_packets_generated; /* GLOBAL */
static int tls_packets_sent;      /* GLOBAL */

#define INCR_SENT       ++tls_packets_sent
#define INCR_GENERATED  ++tls_packets_generated
#define INCR_SUCCESS    ++tls_handshake_success
#define INCR_ERROR      ++tls_handshake_error

void
show_tls_performance_stats(void)
{
    msg(D_TLS_DEBUG_LOW, "TLS Handshakes, success=%f%% (good=%d, bad=%d), retransmits=%f%%",
        (double) tls_handshake_success / (tls_handshake_success + tls_handshake_error) * 100.0,
        tls_handshake_success, tls_handshake_error,
        (double) (tls_packets_sent - tls_packets_generated) / tls_packets_generated * 100.0);
}
#else  /* ifdef MEASURE_TLS_HANDSHAKE_STATS */

#define INCR_SENT
#define INCR_GENERATED
#define INCR_SUCCESS
#define INCR_ERROR

#endif /* ifdef MEASURE_TLS_HANDSHAKE_STATS */

/**
 * SSL/TLS Cipher suite name translation table
 */
static const tls_cipher_name_pair tls_cipher_name_translation_table[] = {
        {"ADH-SEED-SHA", "TLS-DH-anon-WITH-SEED-CBC-SHA"},
        {"AES128-GCM-SHA256", "TLS-RSA-WITH-AES-128-GCM-SHA256"},
        {"AES128-SHA256", "TLS-RSA-WITH-AES-128-CBC-SHA256"},
        {"AES128-SHA", "TLS-RSA-WITH-AES-128-CBC-SHA"},
        {"AES256-GCM-SHA384", "TLS-RSA-WITH-AES-256-GCM-SHA384"},
        {"AES256-SHA256", "TLS-RSA-WITH-AES-256-CBC-SHA256"},
        {"AES256-SHA", "TLS-RSA-WITH-AES-256-CBC-SHA"},
        {"CAMELLIA128-SHA256", "TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256"},
        {"CAMELLIA128-SHA", "TLS-RSA-WITH-CAMELLIA-128-CBC-SHA"},
        {"CAMELLIA256-SHA256", "TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256"},
        {"CAMELLIA256-SHA", "TLS-RSA-WITH-CAMELLIA-256-CBC-SHA"},
        {"DES-CBC3-SHA", "TLS-RSA-WITH-3DES-EDE-CBC-SHA"},
        {"DES-CBC-SHA", "TLS-RSA-WITH-DES-CBC-SHA"},
        {"DH-DSS-SEED-SHA", "TLS-DH-DSS-WITH-SEED-CBC-SHA"},
        {"DHE-DSS-AES128-GCM-SHA256", "TLS-DHE-DSS-WITH-AES-128-GCM-SHA256"},
        {"DHE-DSS-AES128-SHA256", "TLS-DHE-DSS-WITH-AES-128-CBC-SHA256"},
        {"DHE-DSS-AES128-SHA", "TLS-DHE-DSS-WITH-AES-128-CBC-SHA"},
        {"DHE-DSS-AES256-GCM-SHA384", "TLS-DHE-DSS-WITH-AES-256-GCM-SHA384"},
        {"DHE-DSS-AES256-SHA256", "TLS-DHE-DSS-WITH-AES-256-CBC-SHA256"},
        {"DHE-DSS-AES256-SHA", "TLS-DHE-DSS-WITH-AES-256-CBC-SHA"},
        {"DHE-DSS-CAMELLIA128-SHA256", "TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256"},
        {"DHE-DSS-CAMELLIA128-SHA", "TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA"},
        {"DHE-DSS-CAMELLIA256-SHA256", "TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256"},
        {"DHE-DSS-CAMELLIA256-SHA", "TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA"},
        {"DHE-DSS-SEED-SHA", "TLS-DHE-DSS-WITH-SEED-CBC-SHA"},
        {"DHE-RSA-AES128-GCM-SHA256", "TLS-DHE-RSA-WITH-AES-128-GCM-SHA256"},
        {"DHE-RSA-AES128-SHA256", "TLS-DHE-RSA-WITH-AES-128-CBC-SHA256"},
        {"DHE-RSA-AES128-SHA", "TLS-DHE-RSA-WITH-AES-128-CBC-SHA"},
        {"DHE-RSA-AES256-GCM-SHA384", "TLS-DHE-RSA-WITH-AES-256-GCM-SHA384"},
        {"DHE-RSA-AES256-SHA256", "TLS-DHE-RSA-WITH-AES-256-CBC-SHA256"},
        {"DHE-RSA-AES256-SHA", "TLS-DHE-RSA-WITH-AES-256-CBC-SHA"},
        {"DHE-RSA-CAMELLIA128-SHA256", "TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256"},
        {"DHE-RSA-CAMELLIA128-SHA", "TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA"},
        {"DHE-RSA-CAMELLIA256-SHA256", "TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256"},
        {"DHE-RSA-CAMELLIA256-SHA", "TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA"},
        {"DHE-RSA-CHACHA20-POLY1305", "TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256"},
        {"DHE-RSA-SEED-SHA", "TLS-DHE-RSA-WITH-SEED-CBC-SHA"},
        {"DH-RSA-SEED-SHA", "TLS-DH-RSA-WITH-SEED-CBC-SHA"},
        {"ECDH-ECDSA-AES128-GCM-SHA256", "TLS-ECDH-ECDSA-WITH-AES-128-GCM-SHA256"},
        {"ECDH-ECDSA-AES128-SHA256", "TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA256"},
        {"ECDH-ECDSA-AES128-SHA", "TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA"},
        {"ECDH-ECDSA-AES256-GCM-SHA384", "TLS-ECDH-ECDSA-WITH-AES-256-GCM-SHA384"},
        {"ECDH-ECDSA-AES256-SHA256", "TLS-ECDH-ECDSA-WITH-AES-256-CBC-SHA256"},
        {"ECDH-ECDSA-AES256-SHA384", "TLS-ECDH-ECDSA-WITH-AES-256-CBC-SHA384"},
        {"ECDH-ECDSA-AES256-SHA", "TLS-ECDH-ECDSA-WITH-AES-256-CBC-SHA"},
        {"ECDH-ECDSA-CAMELLIA128-SHA256", "TLS-ECDH-ECDSA-WITH-CAMELLIA-128-CBC-SHA256"},
        {"ECDH-ECDSA-CAMELLIA128-SHA", "TLS-ECDH-ECDSA-WITH-CAMELLIA-128-CBC-SHA"},
        {"ECDH-ECDSA-CAMELLIA256-SHA256", "TLS-ECDH-ECDSA-WITH-CAMELLIA-256-CBC-SHA256"},
        {"ECDH-ECDSA-CAMELLIA256-SHA", "TLS-ECDH-ECDSA-WITH-CAMELLIA-256-CBC-SHA"},
        {"ECDH-ECDSA-DES-CBC3-SHA", "TLS-ECDH-ECDSA-WITH-3DES-EDE-CBC-SHA"},
        {"ECDH-ECDSA-DES-CBC-SHA", "TLS-ECDH-ECDSA-WITH-DES-CBC-SHA"},
        {"ECDH-ECDSA-RC4-SHA", "TLS-ECDH-ECDSA-WITH-RC4-128-SHA"},
        {"ECDHE-ECDSA-AES128-GCM-SHA256", "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"},
        {"ECDHE-ECDSA-AES128-SHA256", "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256"},
        {"ECDHE-ECDSA-AES128-SHA384", "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA384"},
        {"ECDHE-ECDSA-AES128-SHA", "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA"},
        {"ECDHE-ECDSA-AES256-GCM-SHA384", "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"},
        {"ECDHE-ECDSA-AES256-SHA256", "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA256"},
        {"ECDHE-ECDSA-AES256-SHA384", "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384"},
        {"ECDHE-ECDSA-AES256-SHA", "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA"},
        {"ECDHE-ECDSA-CAMELLIA128-SHA256", "TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-CBC-SHA256"},
        {"ECDHE-ECDSA-CAMELLIA128-SHA", "TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-CBC-SHA"},
        {"ECDHE-ECDSA-CAMELLIA256-SHA256", "TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-CBC-SHA256"},
        {"ECDHE-ECDSA-CAMELLIA256-SHA", "TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-CBC-SHA"},
        {"ECDHE-ECDSA-CHACHA20-POLY1305", "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256"},
        {"ECDHE-ECDSA-DES-CBC3-SHA", "TLS-ECDHE-ECDSA-WITH-3DES-EDE-CBC-SHA"},
        {"ECDHE-ECDSA-DES-CBC-SHA", "TLS-ECDHE-ECDSA-WITH-DES-CBC-SHA"},
        {"ECDHE-ECDSA-RC4-SHA", "TLS-ECDHE-ECDSA-WITH-RC4-128-SHA"},
        {"ECDHE-RSA-AES128-GCM-SHA256", "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"},
        {"ECDHE-RSA-AES128-SHA256", "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256"},
        {"ECDHE-RSA-AES128-SHA384", "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA384"},
        {"ECDHE-RSA-AES128-SHA", "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA"},
        {"ECDHE-RSA-AES256-GCM-SHA384", "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"},
        {"ECDHE-RSA-AES256-SHA256", "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA256"},
        {"ECDHE-RSA-AES256-SHA384", "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384"},
        {"ECDHE-RSA-AES256-SHA", "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA"},
        {"ECDHE-RSA-CAMELLIA128-SHA256", "TLS-ECDHE-RSA-WITH-CAMELLIA-128-CBC-SHA256"},
        {"ECDHE-RSA-CAMELLIA128-SHA", "TLS-ECDHE-RSA-WITH-CAMELLIA-128-CBC-SHA"},
        {"ECDHE-RSA-CAMELLIA256-SHA256", "TLS-ECDHE-RSA-WITH-CAMELLIA-256-CBC-SHA256"},
        {"ECDHE-RSA-CAMELLIA256-SHA", "TLS-ECDHE-RSA-WITH-CAMELLIA-256-CBC-SHA"},
        {"ECDHE-RSA-CHACHA20-POLY1305", "TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256"},
        {"ECDHE-RSA-DES-CBC3-SHA", "TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA"},
        {"ECDHE-RSA-DES-CBC-SHA", "TLS-ECDHE-RSA-WITH-DES-CBC-SHA"},
        {"ECDHE-RSA-RC4-SHA", "TLS-ECDHE-RSA-WITH-RC4-128-SHA"},
        {"ECDH-RSA-AES128-GCM-SHA256", "TLS-ECDH-RSA-WITH-AES-128-GCM-SHA256"},
        {"ECDH-RSA-AES128-SHA256", "TLS-ECDH-RSA-WITH-AES-128-CBC-SHA256"},
        {"ECDH-RSA-AES128-SHA384", "TLS-ECDH-RSA-WITH-AES-128-CBC-SHA384"},
        {"ECDH-RSA-AES128-SHA", "TLS-ECDH-RSA-WITH-AES-128-CBC-SHA"},
        {"ECDH-RSA-AES256-GCM-SHA384", "TLS-ECDH-RSA-WITH-AES-256-GCM-SHA384"},
        {"ECDH-RSA-AES256-SHA256", "TLS-ECDH-RSA-WITH-AES-256-CBC-SHA256"},
        {"ECDH-RSA-AES256-SHA384", "TLS-ECDH-RSA-WITH-AES-256-CBC-SHA384"},
        {"ECDH-RSA-AES256-SHA", "TLS-ECDH-RSA-WITH-AES-256-CBC-SHA"},
        {"ECDH-RSA-CAMELLIA128-SHA256", "TLS-ECDH-RSA-WITH-CAMELLIA-128-CBC-SHA256"},
        {"ECDH-RSA-CAMELLIA128-SHA", "TLS-ECDH-RSA-WITH-CAMELLIA-128-CBC-SHA"},
        {"ECDH-RSA-CAMELLIA256-SHA256", "TLS-ECDH-RSA-WITH-CAMELLIA-256-CBC-SHA256"},
        {"ECDH-RSA-CAMELLIA256-SHA", "TLS-ECDH-RSA-WITH-CAMELLIA-256-CBC-SHA"},
        {"ECDH-RSA-DES-CBC3-SHA", "TLS-ECDH-RSA-WITH-3DES-EDE-CBC-SHA"},
        {"ECDH-RSA-DES-CBC-SHA", "TLS-ECDH-RSA-WITH-DES-CBC-SHA"},
        {"ECDH-RSA-RC4-SHA", "TLS-ECDH-RSA-WITH-RC4-128-SHA"},
        {"EDH-DSS-DES-CBC3-SHA", "TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA"},
        {"EDH-DSS-DES-CBC-SHA", "TLS-DHE-DSS-WITH-DES-CBC-SHA"},
        {"EDH-RSA-DES-CBC3-SHA", "TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA"},
        {"EDH-RSA-DES-CBC-SHA", "TLS-DHE-RSA-WITH-DES-CBC-SHA"},
        {"EXP-DES-CBC-SHA", "TLS-RSA-EXPORT-WITH-DES40-CBC-SHA"},
        {"EXP-EDH-DSS-DES-CBC-SHA", "TLS-DH-DSS-EXPORT-WITH-DES40-CBC-SHA"},
        {"EXP-EDH-RSA-DES-CBC-SHA", "TLS-DH-RSA-EXPORT-WITH-DES40-CBC-SHA"},
        {"EXP-RC2-CBC-MD5", "TLS-RSA-EXPORT-WITH-RC2-CBC-40-MD5"},
        {"EXP-RC4-MD5", "TLS-RSA-EXPORT-WITH-RC4-40-MD5"},
        {"NULL-MD5", "TLS-RSA-WITH-NULL-MD5"},
        {"NULL-SHA256", "TLS-RSA-WITH-NULL-SHA256"},
        {"NULL-SHA", "TLS-RSA-WITH-NULL-SHA"},
        {"PSK-3DES-EDE-CBC-SHA", "TLS-PSK-WITH-3DES-EDE-CBC-SHA"},
        {"PSK-AES128-CBC-SHA", "TLS-PSK-WITH-AES-128-CBC-SHA"},
        {"PSK-AES256-CBC-SHA", "TLS-PSK-WITH-AES-256-CBC-SHA"},
        {"PSK-RC4-SHA", "TLS-PSK-WITH-RC4-128-SHA"},
        {"RC4-MD5", "TLS-RSA-WITH-RC4-128-MD5"},
        {"RC4-SHA", "TLS-RSA-WITH-RC4-128-SHA"},
        {"SEED-SHA", "TLS-RSA-WITH-SEED-CBC-SHA"},
        {"SRP-DSS-3DES-EDE-CBC-SHA", "TLS-SRP-SHA-DSS-WITH-3DES-EDE-CBC-SHA"},
        {"SRP-DSS-AES-128-CBC-SHA", "TLS-SRP-SHA-DSS-WITH-AES-128-CBC-SHA"},
        {"SRP-DSS-AES-256-CBC-SHA", "TLS-SRP-SHA-DSS-WITH-AES-256-CBC-SHA"},
        {"SRP-RSA-3DES-EDE-CBC-SHA", "TLS-SRP-SHA-RSA-WITH-3DES-EDE-CBC-SHA"},
        {"SRP-RSA-AES-128-CBC-SHA", "TLS-SRP-SHA-RSA-WITH-AES-128-CBC-SHA"},
        {"SRP-RSA-AES-256-CBC-SHA", "TLS-SRP-SHA-RSA-WITH-AES-256-CBC-SHA"},
#ifdef ENABLE_CRYPTO_OPENSSL
        /* OpenSSL-specific group names */
        {"DEFAULT", "DEFAULT"},
        {"ALL", "ALL"},
        {"HIGH", "HIGH"}, {"!HIGH", "!HIGH"},
        {"MEDIUM", "MEDIUM"}, {"!MEDIUM", "!MEDIUM"},
        {"LOW", "LOW"}, {"!LOW", "!LOW"},
        {"ECDH", "ECDH"}, {"!ECDH", "!ECDH"},
        {"ECDSA", "ECDSA"}, {"!ECDSA", "!ECDSA"},
        {"EDH", "EDH"}, {"!EDH", "!EDH"},
        {"EXP", "EXP"}, {"!EXP", "!EXP"},
        {"RSA", "RSA"}, {"!RSA", "!RSA"},
        {"kRSA", "kRSA"}, {"!kRSA", "!kRSA"},
        {"SRP", "SRP"}, {"!SRP", "!SRP"},
#endif
        {NULL, NULL}
};


const tls_cipher_name_pair *
tls_get_cipher_name_pair(const char *cipher_name, size_t len)
{
    const tls_cipher_name_pair *pair = tls_cipher_name_translation_table;

    while (pair->openssl_name != NULL)
    {
        if ((strlen(pair->openssl_name) == len && 0 == memcmp(cipher_name, pair->openssl_name, len))
            || (strlen(pair->iana_name) == len && 0 == memcmp(cipher_name, pair->iana_name, len)))
        {
            return pair;
        }
        pair++;
    }

    /* No entry found, return NULL */
    return NULL;
}

void
tls_init_control_channel_frame_parameters(struct frame *frame, int tls_mtu)
{
    /*
     * frame->extra_frame is already initialized with tls_auth buffer requirements,
     * if --tls-auth is enabled.
     */

    /* calculate the maximum overhead that control channel frames may have */
    int overhead = 0;

    /* Socks */
    overhead += 10;

    /* tls-auth and tls-crypt */
    overhead += max_int(packet_id_size(true) + TLS_CRYPT_TAG_SIZE + TLS_CRYPT_BLOCK_SIZE,
                        packet_id_size(true) + OPENVPN_MAX_HMAC_SIZE);

    /* TCP length field and opcode */
    overhead += 3;

    /* ACK array and remote SESSION ID (part of the ACK array) */
    overhead += ACK_SIZE(RELIABLE_ACK_SIZE);

    /* Previous OpenVPN version calculated the maximum size and buffer of a
     * control frame depending on the overhead of the data channel frame
     * overhead and limited its maximum size to 1250. Since control frame
     * frames also need to fit into data channel buffer we have the same
     * default of 1500 + 100 as data channel buffers have. Increasing
     * tls-mtu beyond this limit also the data channel buffers */
    frame->buf.payload_size = max_int(1500, tls_mtu) + 100;

    frame->buf.headroom = overhead;
    frame->buf.tailroom = overhead;

    frame->tun_mtu = tls_mtu;

    /* Ensure the tun-mtu stays in a valid range */
    frame->tun_mtu = min_int(frame->tun_mtu, TLS_CHANNEL_BUF_SIZE);
    frame->tun_mtu = max_int(frame->tun_mtu, 512);
}

/**
 * calculate the maximum overhead that control channel frames have
 * This includes header, op code and everything apart from the
 * payload itself. This method is a bit pessmistic and might give higher
 * overhead that we actually have */
static int
calc_control_channel_frame_overhead(const struct tls_session *session)
{
    const struct key_state *ks = &session->key[KS_PRIMARY];
    int overhead = 0;

    /* TCP length field and opcode */
    overhead += 3;

    /* our own session id */
    overhead += SID_SIZE;

    /* ACK array and remote SESSION ID (part of the ACK array) */
    int ackstosend = reliable_ack_outstanding(ks->rec_ack) + ks->lru_acks->len;
    overhead += ACK_SIZE(min_int(ackstosend, CONTROL_SEND_ACK_MAX));

    /* Message packet id */
    overhead += sizeof(packet_id_type);

    /* Add the typical UDP overhead for an IPv6 UDP packet. TCP+IPv6 has a
     * larger overhead but the risk of a TCP connection getting dropped because
     * we try to send a too large packet is basically zero */
    overhead += datagram_overhead(AF_INET6, PROTO_UDP);

    return overhead;
}

static struct user_pass passbuf; /* GLOBAL */

void
pem_password_setup(const char *auth_file)
{
    if (!strlen(passbuf.password))
    {
        get_user_pass(&passbuf, auth_file, UP_TYPE_PRIVATE_KEY, GET_USER_PASS_MANAGEMENT|GET_USER_PASS_PASSWORD_ONLY);
    }
}

/*
 * Auth username/password handling
 */
static bool auth_user_pass_enabled;     /* GLOBAL */
static struct user_pass auth_user_pass; /* GLOBAL */
static struct user_pass auth_token;     /* GLOBAL */

#ifdef ENABLE_MANAGEMENT
static char *auth_challenge; /* GLOBAL */
#endif

void
enable_auth_user_pass()
{
    auth_user_pass_enabled = true;
}

void
auth_user_pass_setup(const char *auth_file, const struct static_challenge_info *sci)
{
    if (!auth_user_pass.defined && !auth_token.defined)
    {
#ifdef ENABLE_MANAGEMENT
        if (auth_challenge) /* dynamic challenge/response */
        {
            get_user_pass_cr(&auth_user_pass,
                             auth_file,
                             UP_TYPE_AUTH,
                             GET_USER_PASS_MANAGEMENT|GET_USER_PASS_DYNAMIC_CHALLENGE,
                             auth_challenge);
        }
        else if (sci) /* static challenge response */
        {
            int flags = GET_USER_PASS_MANAGEMENT|GET_USER_PASS_STATIC_CHALLENGE;
            if (sci->flags & SC_ECHO)
            {
                flags |= GET_USER_PASS_STATIC_CHALLENGE_ECHO;
            }
            get_user_pass_cr(&auth_user_pass,
                             auth_file,
                             UP_TYPE_AUTH,
                             flags,
                             sci->challenge_text);
        }
        else
#endif /* ifdef ENABLE_MANAGEMENT */
        get_user_pass(&auth_user_pass, auth_file, UP_TYPE_AUTH, GET_USER_PASS_MANAGEMENT);
    }
}

/*
 * Disable password caching
 */
void
ssl_set_auth_nocache(void)
{
    passbuf.nocache = true;
    auth_user_pass.nocache = true;
}

/*
 * Set an authentication token
 */
void
ssl_set_auth_token(const char *token)
{
    set_auth_token(&auth_user_pass, &auth_token, token);
}

void
ssl_set_auth_token_user(const char *username)
{
    set_auth_token_user(&auth_token, username);
}

/*
 * Cleans an auth token and checks if it was active
 */
bool
ssl_clean_auth_token(void)
{
    bool wasdefined = auth_token.defined;
    purge_user_pass(&auth_token, true);
    return wasdefined;
}

/*
 * Forget private key password AND auth-user-pass username/password.
 */
void
ssl_purge_auth(const bool auth_user_pass_only)
{
    if (!auth_user_pass_only)
    {
#ifdef ENABLE_PKCS11
        pkcs11_logout();
#endif
        purge_user_pass(&passbuf, true);
    }
    purge_user_pass(&auth_user_pass, true);
#ifdef ENABLE_MANAGEMENT
    ssl_purge_auth_challenge();
#endif
}

#ifdef ENABLE_MANAGEMENT

void
ssl_purge_auth_challenge(void)
{
    free(auth_challenge);
    auth_challenge = NULL;
}

void
ssl_put_auth_challenge(const char *cr_str)
{
    ssl_purge_auth_challenge();
    auth_challenge = string_alloc(cr_str, NULL);
}

#endif


/*
 * Map internal constants to ascii names.
 */
static const char *
state_name(int state)
{
    switch (state)
    {
        case S_UNDEF:
            return "S_UNDEF";

        case S_INITIAL:
            return "S_INITIAL";

        case S_PRE_START:
            return "S_PRE_START";

        case S_START:
            return "S_START";

        case S_SENT_KEY:
            return "S_SENT_KEY";

        case S_GOT_KEY:
            return "S_GOT_KEY";

        case S_ACTIVE:
            return "S_ACTIVE";

        case S_ERROR:
            return "S_ERROR";

        case S_GENERATED_KEYS:
            return "S_GENERATED_KEYS";

        default:
            return "S_???";
    }
}

static const char *
ks_auth_name(enum ks_auth_state auth)
{
    switch (auth)
    {
        case KS_AUTH_TRUE:
            return "KS_AUTH_TRUE";

        case KS_AUTH_DEFERRED:
            return "KS_AUTH_DEFERRED";

        case KS_AUTH_FALSE:
            return "KS_AUTH_FALSE";

        default:
            return "KS_????";
    }
}

static const char *
session_index_name(int index)
{
    switch (index)
    {
        case TM_ACTIVE:
            return "TM_ACTIVE";

        case TM_UNTRUSTED:
            return "TM_UNTRUSTED";

        case TM_LAME_DUCK:
            return "TM_LAME_DUCK";

        default:
            return "TM_???";
    }
}

/*
 * For debugging.
 */
static const char *
print_key_id(struct tls_multi *multi, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(256, gc);

    for (int i = 0; i < KEY_SCAN_SIZE; ++i)
    {
        struct key_state *ks = get_key_scan(multi, i);
        buf_printf(&out, " [key#%d state=%s auth=%s id=%d sid=%s]", i,
                   state_name(ks->state), ks_auth_name(ks->authenticated),
                   ks->key_id,
                   session_id_print(&ks->session_id_remote, gc));
    }

    return BSTR(&out);
}

bool
is_hard_reset_method2(int op)
{
    if (op == P_CONTROL_HARD_RESET_CLIENT_V2 || op == P_CONTROL_HARD_RESET_SERVER_V2
        || op == P_CONTROL_HARD_RESET_CLIENT_V3)
    {
        return true;
    }
    return false;
}

/** @addtogroup control_processor
 *  @{ */

/** @name Functions for initialization and cleanup of key_state structures
 *  @{ */

/**
 * Initialize a \c key_state structure.
 * @ingroup control_processor
 *
 * This function initializes a \c key_state structure associated with a \c
 * tls_session.  It sets up the structure's SSL-BIO, sets the object's \c
 * key_state.state to \c S_INITIAL, and sets the session ID and key ID two
 * appropriate values based on the \c tls_session's internal state.  It
 * also initializes a new set of structures for the \link reliable
 * Reliability Layer\endlink.
 *
 * @param session      - A pointer to the \c tls_session structure
 *                       associated with the \a ks argument.
 * @param ks           - A pointer to the \c key_state structure to be
 *                       initialized.  This structure should already have
 *                       been allocated before calling this function.
 */
static void
key_state_init(struct tls_session *session, struct key_state *ks)
{
    update_time();

    CLEAR(*ks);


    /* Set control-channel initiation mode */
    ks->initial_opcode = session->initial_opcode;
    session->initial_opcode = P_CONTROL_SOFT_RESET_V1;
    ks->state = S_INITIAL;
    ks->key_id = session->key_id;

    /*
     * key_id increments to KEY_ID_MASK then recycles back to 1.
     * This way you know that if key_id is 0, it is the first key.
     */
    ++session->key_id;
    session->key_id &= P_KEY_ID_MASK;
    if (!session->key_id)
    {
        session->key_id = 1;
    }

    /* allocate key source material object */
    ALLOC_OBJ_CLEAR(ks->key_src, struct key_source2);

    /* allocate reliability objects */
    ALLOC_OBJ_CLEAR(ks->send_reliable, struct reliable);
    ALLOC_OBJ_CLEAR(ks->rec_reliable, struct reliable);
    ALLOC_OBJ_CLEAR(ks->rec_ack, struct reliable_ack);
    ALLOC_OBJ_CLEAR(ks->lru_acks, struct reliable_ack);

    /* allocate buffers */
    ks->plaintext_read_buf = alloc_buf(TLS_CHANNEL_BUF_SIZE);
    ks->plaintext_write_buf = alloc_buf(TLS_CHANNEL_BUF_SIZE);
    ks->ack_write_buf = alloc_buf(BUF_SIZE(&session->opt->frame));
    reliable_init(ks->send_reliable, BUF_SIZE(&session->opt->frame),
                  session->opt->frame.buf.headroom, TLS_RELIABLE_N_SEND_BUFFERS,
                  ks->key_id ? false : session->opt->xmit_hold);
    reliable_init(ks->rec_reliable, BUF_SIZE(&session->opt->frame),
                  session->opt->frame.buf.headroom, TLS_RELIABLE_N_REC_BUFFERS,
                  false);
    reliable_set_timeout(ks->send_reliable, session->opt->packet_timeout);

    /* init packet ID tracker */
    if (session->opt->replay)
    {
        packet_id_init(&ks->crypto_options.packet_id,
                       session->opt->replay_window, session->opt->replay_time, "SSL",
                       ks->key_id);
    }

    ks->crypto_options.pid_persist = NULL;

#ifdef ENABLE_MANAGEMENT
    ks->mda_key_id = session->opt->mda_context->mda_key_id_counter++;
#endif

}


/**
 * Cleanup a \c key_state structure.
 * @ingroup control_processor
 *
 * This function cleans up a \c key_state structure.  It frees the
 * associated SSL-BIO, and the structures allocated for the \link reliable
 * Reliability Layer\endlink.
 *
 * @param ks           - A pointer to the \c key_state structure to be
 *                       cleaned up.
 * @param clear        - Whether the memory allocated for the \a ks object
 *                       should be overwritten with 0s.
 */
static void
key_state_free(struct key_state *ks, bool clear)
{
    ks->state = S_UNDEF;

    free_buf(&ks->plaintext_read_buf);
    free_buf(&ks->plaintext_write_buf);
    free_buf(&ks->ack_write_buf);
    buffer_list_free(ks->paybuf);

    reliable_free(ks->send_reliable);
    reliable_free(ks->rec_reliable);

    free(ks->rec_ack);
    free(ks->lru_acks);
    free(ks->key_src);

    packet_id_free(&ks->crypto_options.packet_id);

    key_state_rm_auth_control_files(&ks->plugin_auth);
    key_state_rm_auth_control_files(&ks->script_auth);

    if (clear)
    {
        secure_memzero(ks, sizeof(*ks));
    }
}


/** @addtogroup control_processor
 *  @{ */

/** @name Functions for initialization and cleanup of tls_session structures
 *  @{ */

/**
 * Initialize a \c tls_session structure.
 * @ingroup control_processor
 *
 * This function initializes a \c tls_session structure.  This includes
 * generating a random session ID, and initializing the \c KS_PRIMARY \c
 * key_state in the \c tls_session.key array.
 *
 * @param multi        - A pointer to the \c tls_multi structure
 *                       associated with the \a session argument.
 * @param session      - A pointer to the \c tls_session structure to be
 *                       initialized.  This structure should already have
 *                       been allocated before calling this function.
 */
static void
tls_session_init(struct tls_multi *multi, struct tls_session *session)
{
    struct gc_arena gc = gc_new();

    dmsg(D_TLS_DEBUG, "TLS: tls_session_init: entry");

    CLEAR(*session);

    /* Set options data to point to parent's option structure */
    session->opt = &multi->opt;

    /* Randomize session # if it is 0 */
    while (!session_id_defined(&session->session_id))
    {
        session_id_random(&session->session_id);
    }

    /* Are we a TLS server or client? */
    if (session->opt->server)
    {
        session->initial_opcode = P_CONTROL_HARD_RESET_SERVER_V2;
    }
    else
    {
        session->initial_opcode = session->opt->tls_crypt_v2 ?
                                  P_CONTROL_HARD_RESET_CLIENT_V3 : P_CONTROL_HARD_RESET_CLIENT_V2;
    }

    /* Initialize control channel authentication parameters */
    session->tls_wrap = session->opt->tls_wrap;
    session->tls_wrap.work = alloc_buf(BUF_SIZE(&session->opt->frame));

    /* initialize packet ID replay window for --tls-auth */
    packet_id_init(&session->tls_wrap.opt.packet_id,
                   session->opt->replay_window,
                   session->opt->replay_time,
                   "TLS_WRAP", session->key_id);

    /* If we are using tls-crypt-v2 we manipulate the packet id to be (ab)used
     * to indicate early protocol negotiation */
    if (session->opt->tls_crypt_v2)
    {
        session->tls_wrap.opt.packet_id.send.time = now;
        session->tls_wrap.opt.packet_id.send.id = EARLY_NEG_START;
    }

    /* load most recent packet-id to replay protect on --tls-auth */
    packet_id_persist_load_obj(session->tls_wrap.opt.pid_persist,
                               &session->tls_wrap.opt.packet_id);

    key_state_init(session, &session->key[KS_PRIMARY]);

    dmsg(D_TLS_DEBUG, "TLS: tls_session_init: new session object, sid=%s",
         session_id_print(&session->session_id, &gc));

    gc_free(&gc);
}

/**
 * Clean up a \c tls_session structure.
 * @ingroup control_processor
 *
 * This function cleans up a \c tls_session structure.  This includes
 * cleaning up all associated \c key_state structures.
 *
 * @param session      - A pointer to the \c tls_session structure to be
 *                       cleaned up.
 * @param clear        - Whether the memory allocated for the \a session
 *                       object should be overwritten with 0s. This
 *                       implicitly sets many states to 0/false,
 *                       e.g. the validity of the keys in the structure
 *
 */
static void
tls_session_free(struct tls_session *session, bool clear)
{
    tls_wrap_free(&session->tls_wrap);

    for (size_t i = 0; i < KS_SIZE; ++i)
    {
        /* we don't need clear=true for this call since
         * the structs are part of session and get cleared
         * as part of session */
        key_state_free(&session->key[i], false);
    }

    free(session->common_name);

    cert_hash_free(session->cert_hash_set);

    if (clear)
    {
        secure_memzero(session, sizeof(*session));
    }
}

/** @} name Functions for initialization and cleanup of tls_session structures */

/** @} addtogroup control_processor */


static void
move_session(struct tls_multi *multi, int dest, int src, bool reinit_src)
{
    msg(D_TLS_DEBUG_LOW, "TLS: move_session: dest=%s src=%s reinit_src=%d",
        session_index_name(dest),
        session_index_name(src),
        reinit_src);
    ASSERT(src != dest);
    ASSERT(src >= 0 && src < TM_SIZE);
    ASSERT(dest >= 0 && dest < TM_SIZE);
    tls_session_free(&multi->session[dest], false);
    multi->session[dest] = multi->session[src];

    if (reinit_src)
    {
        tls_session_init(multi, &multi->session[src]);
    }
    else
    {
        secure_memzero(&multi->session[src], sizeof(multi->session[src]));
    }

    dmsg(D_TLS_DEBUG, "TLS: move_session: exit");
}

static void
reset_session(struct tls_multi *multi, struct tls_session *session)
{
    tls_session_free(session, false);
    tls_session_init(multi, session);
}

/*
 * Used to determine in how many seconds we should be
 * called again.
 */
static inline void
compute_earliest_wakeup(interval_t *earliest, interval_t seconds_from_now)
{
    if (seconds_from_now < *earliest)
    {
        *earliest = seconds_from_now;
    }
    if (*earliest < 0)
    {
        *earliest = 0;
    }
}

/*
 * Return true if "lame duck" or retiring key has expired and can
 * no longer be used.
 */
static inline bool
lame_duck_must_die(const struct tls_session *session, interval_t *wakeup)
{
    const struct key_state *lame = &session->key[KS_LAME_DUCK];
    if (lame->state >= S_INITIAL)
    {
        ASSERT(lame->must_die); /* a lame duck key must always have an expiration */
        if (now < lame->must_die)
        {
            compute_earliest_wakeup(wakeup, lame->must_die - now);
            return false;
        }
        else
        {
            return true;
        }
    }
    else if (lame->state == S_ERROR)
    {
        return true;
    }
    else
    {
        return false;
    }
}

struct tls_multi *
tls_multi_init(struct tls_options *tls_options)
{
    struct tls_multi *ret;

    ALLOC_OBJ_CLEAR(ret, struct tls_multi);

    /* get command line derived options */
    ret->opt = *tls_options;

    return ret;
}

void
tls_multi_init_finalize(struct tls_multi *multi, int tls_mtu)
{
    tls_init_control_channel_frame_parameters(&multi->opt.frame, tls_mtu);
    /* initialize the active and untrusted sessions */

    tls_session_init(multi, &multi->session[TM_ACTIVE]);

    if (!multi->opt.single_session)
    {
        tls_session_init(multi, &multi->session[TM_UNTRUSTED]);
    }
}

/*
 * Initialize and finalize a standalone tls-auth verification object.
 */

struct tls_auth_standalone *
tls_auth_standalone_init(struct tls_options *tls_options,
                         struct gc_arena *gc)
{
    struct tls_auth_standalone *tas;

    ALLOC_OBJ_CLEAR_GC(tas, struct tls_auth_standalone, gc);

    tas->tls_wrap = tls_options->tls_wrap;

    /*
     * Standalone tls-auth is in read-only mode with respect to TLS
     * control channel state.  After we build a new client instance
     * object, we will process this session-initiating packet for real.
     */
    tas->tls_wrap.opt.flags |= CO_IGNORE_PACKET_ID;

    /* get initial frame parms, still need to finalize */
    tas->frame = tls_options->frame;

    packet_id_init(&tas->tls_wrap.opt.packet_id, tls_options->replay_window,
                   tls_options->replay_time, "TAS", 0);

    return tas;
}

/*
 * Set local and remote option compatibility strings.
 * Used to verify compatibility of local and remote option
 * sets.
 */
void
tls_multi_init_set_options(struct tls_multi *multi,
                           const char *local,
                           const char *remote)
{
    /* initialize options string */
    multi->opt.local_options = local;
    multi->opt.remote_options = remote;
}

/*
 * Cleanup a tls_multi structure and free associated memory allocations.
 */
void
tls_multi_free(struct tls_multi *multi, bool clear)
{
    ASSERT(multi);

    auth_set_client_reason(multi, NULL);

    free(multi->peer_info);
    free(multi->locked_cn);
    free(multi->locked_username);

    cert_hash_free(multi->locked_cert_hash_set);

    wipe_auth_token(multi);

    free(multi->remote_ciphername);

    for (int i = 0; i < TM_SIZE; ++i)
    {
        tls_session_free(&multi->session[i], false);
    }

    if (clear)
    {
        secure_memzero(multi, sizeof(*multi));
    }

    free(multi);
}

/**
 * Generate data channel keys for the supplied TLS session.
 *
 * This erases the source material used to generate the data channel keys, and
 * can thus be called only once per session.
 */
bool
tls_session_generate_data_channel_keys(struct tls_multi *multi,
                                       struct tls_session *session)
{
    struct key_state *ks = &session->key[KS_PRIMARY];   /* primary key */
    ks->crypto_options.flags = session->opt->crypto_flags;
    ks->crypto_options.key_ctx_bi.initialized = true;
    ks->state = S_GENERATED_KEYS;
    return true;
}

bool
tls_session_update_crypto_params_do_work(struct tls_multi *multi,
                                         struct tls_session *session,
                                         struct options *options,
                                         struct frame *frame,
                                         struct frame *frame_fragment,
                                         struct link_socket_info *lsi)
{
    if (session->key[KS_PRIMARY].crypto_options.key_ctx_bi.initialized)
    {
        /* keys already generated, nothing to do */
        return true;
    }

    bool packet_id_long_form = cipher_kt_mode_ofb_cfb(session->opt->key_type.cipher);
    session->opt->crypto_flags &= ~(CO_PACKET_ID_LONG_FORM);
    if (packet_id_long_form)
    {
        session->opt->crypto_flags |= CO_PACKET_ID_LONG_FORM;
    }

    frame_calculate_dynamic(frame, &session->opt->key_type, options, lsi);

    frame_print(frame, D_MTU_INFO, "Data Channel MTU parms");

    /*
     * mssfix uses data channel framing, which at this point contains
     * actual overhead. Fragmentation logic uses frame_fragment, which
     * still contains worst case overhead. Replace it with actual overhead
     * to prevent unneeded fragmentation.
     */

    if (frame_fragment)
    {
        frame_calculate_dynamic(frame_fragment, &session->opt->key_type, options, lsi);
        frame_print(frame_fragment, D_MTU_INFO, "Fragmentation MTU parms");
    }

    return tls_session_generate_data_channel_keys(multi, session);
}

bool
tls_session_update_crypto_params(struct tls_multi *multi,
                                 struct tls_session *session,
                                 struct options *options, struct frame *frame,
                                 struct frame *frame_fragment,
                                 struct link_socket_info *lsi)
{
    /* Import crypto settings that might be set by pull/push */
    session->opt->crypto_flags |= options->data_channel_crypto_flags;
    return tls_session_update_crypto_params_do_work(multi, session, options,
                                                    frame, frame_fragment, lsi);
}

/*
 * Move the active key to the lame duck key and reinitialize the
 * active key.
 */
static void
key_state_soft_reset(struct tls_session *session)
{
    struct key_state *ks = &session->key[KS_PRIMARY];      /* primary key */
    struct key_state *ks_lame = &session->key[KS_LAME_DUCK]; /* retiring key */

    ks->must_die = now + session->opt->transition_window; /* remaining lifetime of old key */
    key_state_free(ks_lame, false);
    *ks_lame = *ks;

    key_state_init(session, ks);
    ks->session_id_remote = ks_lame->session_id_remote;
    ks->remote_addr = ks_lame->remote_addr;
}


static int
auth_deferred_expire_window(const struct tls_options *o)
{
    int ret = o->handshake_window;
    const int r2 = o->renegotiate_seconds / 2;

    if (o->renegotiate_seconds && r2 < ret)
    {
        ret = r2;
    }
    return ret;
}

/**
 * Move the session from S_INITIAL to S_PRE_START. This will also generate
 * the initial message based on ks->initial_opcode
 *
 * @return if the state change was succesful
 */
static bool
session_move_pre_start(const struct tls_session *session,
                       struct key_state *ks, bool skip_initial_send)
{
    struct buffer *buf = reliable_get_buf_output_sequenced(ks->send_reliable);
    if (!buf)
    {
        return false;
    }

    ks->initial = now;
    ks->must_negotiate = now + session->opt->handshake_window;
    ks->auth_deferred_expire = now + auth_deferred_expire_window(session->opt);

    /* null buffer */
    char* l_string = "l_string";
    buf_write(buf, l_string,strlen(l_string) + 1);

    reliable_mark_active_outgoing(ks->send_reliable, buf, ks->initial_opcode);

    /* If we want to skip sending the initial handshake packet we still generate
     * it to increase internal counters etc. but immediately mark it as done */
    if (skip_initial_send)
    {
        reliable_mark_deleted(ks->send_reliable, buf);
    }
    INCR_GENERATED;

    ks->state = S_PRE_START;

    struct gc_arena gc = gc_new();
    dmsg(D_TLS_DEBUG, "TLS: Initial Handshake, sid=%s",
         session_id_print(&session->session_id, &gc));
    gc_free(&gc);

#ifdef ENABLE_MANAGEMENT
    if (management && ks->initial_opcode != P_CONTROL_SOFT_RESET_V1)
    {
        management_set_state(management,
                             OPENVPN_STATE_WAIT,
                             NULL,
                             NULL,
                             NULL,
                             NULL,
                             NULL);
    }
#endif
    return true;

}

/**
 * Moves the key to state to S_ACTIVE and also advances the multi_state state
 * machine if this is the initial connection.
 */
static void
session_move_active(struct tls_multi *multi, struct tls_session *session,
                    struct link_socket_info *to_link_socket_info,
                    struct key_state *ks)
{
    dmsg(D_TLS_DEBUG_MED, "STATE S_ACTIVE");

    ks->established = now;
    if (check_debug_level(D_HANDSHAKE))
    {
        //print_details(&ks->ks_ssl, "Control Channel:");
    }
    ks->state = S_ACTIVE;
    /* Cancel negotiation timeout */
    ks->must_negotiate = 0;
    INCR_SUCCESS;

    /* Set outgoing address for data channel packets */
    link_socket_set_outgoing_addr(to_link_socket_info, &ks->remote_addr,
                                  session->common_name, session->opt->es);

    /* Check if we need to advance the tls_multi state machine */
    if (multi->multi_state == CAS_NOT_CONNECTED)
    {
        if (session->opt->mode == MODE_SERVER)
        {
            /* On a server we continue with running connect scripts next */
            multi->multi_state = CAS_WAITING_AUTH;
        }
        else
        {
            /* Skip the connect script related states */
            multi->multi_state = CAS_WAITING_OPTIONS_IMPORT;
        }
    }

}


static bool
tls_process_state(struct tls_multi *multi,
                     struct tls_session *session,
                     struct buffer *to_link,
                     struct link_socket_actual **to_link_addr,
                     struct link_socket_info *to_link_socket_info,
                     interval_t *wakeup)
{
    bool state_change = false;
    struct key_state *ks = &session->key[KS_PRIMARY];      /* primary key */

    /* Initial handshake */
    if (ks->state == S_INITIAL)
    {
        state_change = session_move_pre_start(session, ks, false);
        msg(M_INFO, "lichen1 session_move_pre_start status:%d",ks->state);
    }

    /* Are we timed out on receive? */
    if (now >= ks->must_negotiate && ks->state < S_ACTIVE)
    {
        msg(D_TLS_ERRORS,
            "TLS Error: TLS key negotiation failed to occur within %d seconds (check your network connectivity)",
            session->opt->handshake_window);
        goto error;
    }

    /* Check if the initial three-way Handshake is complete.
     * We consider the handshake to be complete when our own initial
     * packet has been successfully ACKed. */
    if (ks->state == S_PRE_START && reliable_empty(ks->send_reliable))
    {
        ks->state = S_START;
        state_change = true;
    }

    /* Wait for ACK */
    if (((ks->state == S_START && !session->opt->server)
         || (ks->state == S_START && session->opt->server))
        && reliable_empty(ks->send_reliable))
    {
        session_move_active(multi, session, to_link_socket_info, ks);
        state_change = true;

        multi->remote_ciphername = NULL;
        ks->authenticated = KS_AUTH_TRUE;

        msg(M_INFO,"lichen5 Wait for ACK status:%d",ks->state);
    }

    if (!to_link->len && reliable_can_send(ks->send_reliable))
    {
        int opcode;

        struct buffer *buf = reliable_send(ks->send_reliable, &opcode);
        ASSERT(buf);
        struct buffer b = *buf;

        write_control_auth(session, ks, &b, to_link_addr, opcode,
                           CONTROL_SEND_ACK_MAX, true);
        *to_link = b;
        msg(M_INFO, "lichen_sed to_link.len:%d status:%d",to_link->len,ks->state);

        return true;
    }


    struct reliable_entry *entry = reliable_get_entry_sequenced(ks->rec_reliable);
//    if (entry && ks->state< S_ACTIVE)
    if (entry)
    {
        /* The first packet from the peer (the reset packet) is special and
         * contains early protocol negotiation */
        msg(M_INFO,"lichen_rec  packet_id:%d  buf.len:%d  status:%d",entry->packet_id, entry->buf.len, ks->state);

        if (entry->packet_id == 0 && is_hard_reset_method2(entry->opcode))
        {

            if (entry->buf.len >0){
                char *str = (char *) malloc(entry->buf.len);
                buf_read(&entry->buf, str, entry->buf.len);
                msg(M_INFO,"%s",str);
            }

            reliable_mark_deleted(ks->rec_reliable, &entry->buf);
        }
        else
        {
            struct buffer *buf = &ks->plaintext_read_buf;
            if (!buf->len) {
                ASSERT(buf_init(buf, 0));
                buf_copy(buf, &entry->buf);
                reliable_mark_deleted(ks->rec_reliable, &entry->buf);
                state_change = true;
            }
        }

    }


    struct buffer *buf = &ks->plaintext_write_buf;
    if (buf->len)
    {

        struct buffer *b = reliable_get_buf_output_sequenced(ks->send_reliable);
        if (b){
            buf_copy_n(b, buf, buf->len);
            reliable_mark_active_outgoing(ks->send_reliable, b, P_CONTROL_V1);
        }
        memset(BPTR(buf), 0, BLEN(buf));  /* erase data just written */
        buf->len = 0;
        state_change = true;

//        int status = key_state_write_plaintext(&ks->ks_ssl, buf);

    }

    return state_change;
    error:
    ks->state = S_ERROR;
    msg(D_TLS_ERRORS, "TLS Error: TLS handshake failed");
    return false;

}


/*
 * This is the primary routine for processing TLS stuff inside the
 * the main event loop.  When this routine exits
 * with non-error status, it will set *wakeup to the number of seconds
 * when it wants to be called again.
 *
 * Return value is true if we have placed a packet in *to_link which we
 * want to send to our peer.
 */
static bool
tls_process(struct tls_multi *multi,
            struct tls_session *session,
            struct buffer *to_link,
            struct link_socket_actual **to_link_addr,
            struct link_socket_info *to_link_socket_info,
            interval_t *wakeup)
{
    struct key_state *ks = &session->key[KS_PRIMARY];      /* primary key */
    struct key_state *ks_lame = &session->key[KS_LAME_DUCK]; /* retiring key */

    /* Make sure we were initialized and that we're not in an error state */
    ASSERT(ks->state != S_UNDEF);
    ASSERT(ks->state != S_ERROR);
    ASSERT(session_id_defined(&session->session_id));

    /* Should we trigger a soft reset? -- new key, keeps old key for a while */
    if (ks->state >= S_ACTIVE
        && ((session->opt->renegotiate_seconds
             && now >= ks->established + session->opt->renegotiate_seconds)
            || (session->opt->renegotiate_bytes > 0
                && ks->n_bytes >= session->opt->renegotiate_bytes)
            || (session->opt->renegotiate_packets
                && ks->n_packets >= session->opt->renegotiate_packets)
            || (packet_id_close_to_wrapping(&ks->crypto_options.packet_id.send))))
    {
        msg(D_TLS_DEBUG_LOW, "TLS: soft reset sec=%d/%d bytes=" counter_format
                "/%d pkts=" counter_format "/%d",
            (int) (now - ks->established), session->opt->renegotiate_seconds,
            ks->n_bytes, session->opt->renegotiate_bytes,
            ks->n_packets, session->opt->renegotiate_packets);
        key_state_soft_reset(session);
    }

    /* Kill lame duck key transition_window seconds after primary key negotiation */
    if (lame_duck_must_die(session, wakeup))
    {
        key_state_free(ks_lame, true);
        msg(D_TLS_DEBUG_LOW, "TLS: tls_process: killed expiring key");
    }

    bool state_change = true;
    while (state_change)
    {
        update_time();

        dmsg(D_TLS_DEBUG, "TLS: tls_process: chg=%d ks=%s lame=%s to_link->len=%d wakeup=%d",
             state_change,
             state_name(ks->state),
             state_name(ks_lame->state),
             to_link->len,
             *wakeup);
        state_change = tls_process_state(multi, session, to_link, to_link_addr,
                                            to_link_socket_info, wakeup);

        if (ks->state == S_ERROR)
        {
            return false;
        }

    }

    update_time();

    /* We often send acks back to back to a following control packet. This
     * normally does not create a problem (apart from an extra packet).
     * However, with the P_CONTROL_WKC_V1 we need to ensure that the packet
     * gets resent if not received by remote, so instead we use an empty
     * control packet in this special case */

    /* Send 1 or more ACKs (each received control packet gets one ACK) */
    if (!to_link->len && !reliable_ack_empty(ks->rec_ack))
    {
        struct buffer buf = ks->ack_write_buf;
        ASSERT(buf_init(&buf, multi->opt.frame.buf.headroom));
        write_control_auth(session, ks, &buf, to_link_addr, P_ACK_V1,
                           RELIABLE_ACK_SIZE, false);
        *to_link = buf;
        msg(M_INFO,"lichen send 1 or more ACKs");
    }

    /* When should we wake up again? */
    if (ks->state >= S_INITIAL)
    {
        compute_earliest_wakeup(wakeup,reliable_send_timeout(ks->send_reliable));

        if (ks->must_negotiate)
        {
            compute_earliest_wakeup(wakeup, ks->must_negotiate - now);
        }
    }

    if (ks->established && session->opt->renegotiate_seconds)
    {
        compute_earliest_wakeup(wakeup, ks->established + session->opt->renegotiate_seconds - now);
    }

    dmsg(D_TLS_DEBUG, "TLS: tls_process: timeout set to %d", *wakeup);

    /* prevent event-loop spinning by setting minimum wakeup of 1 second */
    if (*wakeup <= 0)
    {
        *wakeup = 1;
        /* if we had something to send to remote, but to_link was busy,
         * let caller know we need to be called again soon */
        return true;
    }


    /* If any of the state changes resulted in the to_link buffer being
     * set, we are also active */
    if (to_link->len)
    {
        return true;
    }

    return false;
}

/*
 * Called by the top-level event loop.
 *
 * Basically decides if we should call tls_process for
 * the active or untrusted sessions.
 */

int
tls_multi_process(struct tls_multi *multi,
                  struct buffer *to_link,
                  struct link_socket_actual **to_link_addr,
                  struct link_socket_info *to_link_socket_info,
                  interval_t *wakeup)
{
    struct gc_arena gc = gc_new();
    int active = TLSMP_INACTIVE;
    bool error = false;

    perf_push(PERF_TLS_MULTI_PROCESS);

    /*
     * Process each session object having state of S_INITIAL or greater,
     * and which has a defined remote IP addr.
     */
    for (int i = 0; i < TM_SIZE; ++i)
    {
        struct tls_session *session = &multi->session[i];
        struct key_state *ks = &session->key[KS_PRIMARY];
        struct key_state *ks_lame = &session->key[KS_LAME_DUCK];

        /* set initial remote address */
        if (i == TM_ACTIVE && ks->state == S_INITIAL
            && link_socket_actual_defined(&to_link_socket_info->lsa->actual))
        {
            ks->remote_addr = to_link_socket_info->lsa->actual;
        }

        dmsg(D_TLS_DEBUG,
             "TLS: tls_multi_process: i=%d state=%s, mysid=%s, stored-sid=%s, stored-ip=%s",
             i,
             state_name(ks->state),
             session_id_print(&session->session_id, &gc),
             session_id_print(&ks->session_id_remote, &gc),
             print_link_socket_actual(&ks->remote_addr, &gc));

        if (ks->state >= S_INITIAL && link_socket_actual_defined(&ks->remote_addr))
        {
            struct link_socket_actual *tla = NULL;

            update_time();

            if (tls_process(multi, session, to_link, &tla,
                            to_link_socket_info, wakeup))
            {
                active = TLSMP_ACTIVE;
            }

            /*
             * If tls_process produced an outgoing packet,
             * return the link_socket_actual object (which
             * contains the outgoing address).
             */
            if (tla)
            {
                multi->to_link_addr = *tla;
                *to_link_addr = &multi->to_link_addr;
            }

            /*
             * If tls_process hits an error:
             * (1) If the session has an unexpired lame duck key, preserve it.
             * (2) Reinitialize the session.
             * (3) Increment soft error count
             */
            if (ks->state == S_ERROR)
            {
                ++multi->n_soft_errors;

                if (i == TM_ACTIVE)
                {
                    error = true;
                }

                if (i == TM_ACTIVE
                    && ks_lame->state >= S_ACTIVE
                    && !multi->opt.single_session)
                {
                    move_session(multi, TM_LAME_DUCK, TM_ACTIVE, true);
                }
                else
                {
                    reset_session(multi, session);
                }
            }
        }
    }

    update_time();

    enum tls_auth_status tas = tls_authentication_status(multi);

    tas = TLS_AUTHENTICATION_SUCCEEDED;

    /* If we have successfully authenticated and are still waiting for the authentication to finish
     * move the state machine for the multi context forward */

    if (multi->multi_state >= CAS_CONNECT_DONE)
    {
        for (int i = 0; i < TM_SIZE; ++i)
        {
            struct tls_session *session = &multi->session[i];
            struct key_state *ks = &session->key[KS_PRIMARY];

            if (ks->state == S_ACTIVE && ks->authenticated == KS_AUTH_TRUE)
            {
                tls_session_generate_data_channel_keys(multi, session);
                /* Update auth token on the client if needed */
                resend_auth_token_renegotiation(multi, session);
            }
        }
    }

    if (multi->multi_state == CAS_WAITING_AUTH && tas == TLS_AUTHENTICATION_SUCCEEDED)
    {
        multi->multi_state = CAS_PENDING;
    }

    /*
     * If lame duck session expires, kill it.
     */
    if (lame_duck_must_die(&multi->session[TM_LAME_DUCK], wakeup))
    {
        tls_session_free(&multi->session[TM_LAME_DUCK], true);
        msg(D_TLS_DEBUG_LOW, "TLS: tls_multi_process: killed expiring key");
    }

    /*
     * If untrusted session achieves TLS authentication,
     * move it to active session, usurping any prior session.
     *
     * A semi-trusted session is one in which the certificate authentication
     * succeeded (if cert verification is enabled) but the username/password
     * verification failed.  A semi-trusted session can forward data on the
     * TLS control channel but not on the tunnel channel.
     */
    if (TLS_AUTHENTICATED(multi, &multi->session[TM_UNTRUSTED].key[KS_PRIMARY]))
    {
        move_session(multi, TM_ACTIVE, TM_UNTRUSTED, true);
        msg(D_TLS_DEBUG_LOW, "TLS: tls_multi_process: untrusted session promoted to %strusted",
            tas == TLS_AUTHENTICATION_SUCCEEDED ? "" : "semi-");
    }

    /*
     * A hard error means that TM_ACTIVE hit an S_ERROR state and that no
     * other key state objects are S_ACTIVE or higher.
     */
    if (error)
    {
        for (int i = 0; i < KEY_SCAN_SIZE; ++i)
        {
            if (get_key_scan(multi, i)->state >= S_ACTIVE)
            {
                goto nohard;
            }
        }
        ++multi->n_hard_errors;
    }
    nohard:

#ifdef ENABLE_DEBUG
    /* DEBUGGING -- flood peer with repeating connection attempts */
    {
        const int throw_level = GREMLIN_CONNECTION_FLOOD_LEVEL(multi->opt.gremlin);
        if (throw_level)
        {
            for (int i = 0; i < KEY_SCAN_SIZE; ++i)
            {
                if (get_key_scan(multi, i)->state >= throw_level)
                {
                    ++multi->n_hard_errors;
                    ++multi->n_soft_errors;
                }
            }
        }
    }
#endif

    perf_pop();
    gc_free(&gc);

    return (tas == TLS_AUTHENTICATION_FAILED) ? TLSMP_KILL : active;
}

/*
 * Pre and post-process the encryption & decryption buffers in order
 * to implement a multiplexed TLS channel over the TCP/UDP port.
 */

static inline void
handle_data_channel_packet(struct tls_multi *multi,
                           const struct link_socket_actual *from,
                           struct buffer *buf,
                           struct crypto_options **opt,
                           bool floated,
                           const uint8_t **ad_start)
{
    struct gc_arena gc = gc_new();

    uint8_t c = *BPTR(buf);
    int op = c >> P_OPCODE_SHIFT;
    int key_id = c & P_KEY_ID_MASK;

    /* data channel packet */
    for (int i = 0; i < KEY_SCAN_SIZE; ++i)
    {
        struct key_state *ks = get_key_scan(multi, i);

        /*
         * This is the basic test of TLS state compatibility between a local OpenVPN
         * instance and its remote peer.
         *
         * If the test fails, it tells us that we are getting a packet from a source
         * which claims reference to a prior negotiated TLS session, but the local
         * OpenVPN instance has no memory of such a negotiation.
         *
         * It almost always occurs on UDP sessions when the passive side of the
         * connection is restarted without the active side restarting as well (the
         * passive side is the server which only listens for the connections, the
         * active side is the client which initiates connections).
         */
        if (ks->state >= S_GENERATED_KEYS && key_id == ks->key_id
            && ks->authenticated == KS_AUTH_TRUE
            && (floated || link_socket_actual_match(from, &ks->remote_addr)))
        {
            if (!ks->crypto_options.key_ctx_bi.initialized)
            {
                msg(D_MULTI_DROPPED,
                    "Key %s [%d] not initialized (yet), dropping packet.",
                    print_link_socket_actual(from, &gc), key_id);
                goto done;
            }

            /* return appropriate data channel decrypt key in opt */
            *opt = &ks->crypto_options;
            if (op == P_DATA_V2)
            {
                *ad_start = BPTR(buf);
            }
            ASSERT(buf_advance(buf, 1));
            if (op == P_DATA_V1)
            {
                *ad_start = BPTR(buf);
            }
            else if (op == P_DATA_V2)
            {
                if (buf->len < 4)
                {
                    msg(D_TLS_ERRORS, "Protocol error: received P_DATA_V2 from %s but length is < 4",
                        print_link_socket_actual(from, &gc));
                    ++multi->n_soft_errors;
                    goto done;
                }
                ASSERT(buf_advance(buf, 3));
            }

            ++ks->n_packets;
            ks->n_bytes += buf->len;
            dmsg(D_TLS_KEYSELECT,
                 "TLS: tls_pre_decrypt, key_id=%d, IP=%s",
                 key_id, print_link_socket_actual(from, &gc));
            gc_free(&gc);
            return;
        }
    }

    msg(D_TLS_ERRORS,
        "TLS Error: local/remote TLS keys are out of sync: %s "
        "(received key id: %d, known key ids: %s)",
        print_link_socket_actual(from, &gc), key_id,
        print_key_id(multi, &gc));

    done:
    buf->len = 0;
    *opt = NULL;
    gc_free(&gc);
}

/*
 *
 * When we are in TLS mode, this is the first routine which sees
 * an incoming packet.
 *
 * If it's a data packet, we set opt so that our caller can
 * decrypt it.  We also give our caller the appropriate decryption key.
 *
 * If it's a control packet, we authenticate it and process it,
 * possibly creating a new tls_session if it represents the
 * first packet of a new session.  For control packets, we will
 * also zero the size of *buf so that our caller ignores the
 * packet on our return.
 *
 * Note that openvpn only allows one active session at a time,
 * so a new session (once authenticated) will always usurp
 * an old session.
 *
 * Return true if input was an authenticated control channel
 * packet.
 *
 * If we are running in TLS thread mode, all public routines
 * below this point must be called with the L_TLS lock held.
 */

bool
tls_pre_decrypt(struct tls_multi *multi,
                const struct link_socket_actual *from,
                struct buffer *buf,
                struct crypto_options **opt,
                bool floated,
                const uint8_t **ad_start)
{

    if (buf->len <= 0)
    {
        buf->len = 0;
        *opt = NULL;
        return false;
    }

    struct gc_arena gc = gc_new();
    bool ret = false;

    /* get opcode  */
    uint8_t pkt_firstbyte = *BPTR(buf);
    int op = pkt_firstbyte >> P_OPCODE_SHIFT;

    if ((op == P_DATA_V1) || (op == P_DATA_V2))
    {
        handle_data_channel_packet(multi, from, buf, opt, floated, ad_start);
        return false;
    }

    /* get key_id */
    int key_id = pkt_firstbyte & P_KEY_ID_MASK;

    /* control channel packet */
    bool do_burst = false;
    bool new_link = false;
    struct session_id sid;         /* remote session ID */

    /* verify legal opcode */
    if (op < P_FIRST_OPCODE || op > P_LAST_OPCODE)
    {
        if (op == P_CONTROL_HARD_RESET_CLIENT_V1
            || op == P_CONTROL_HARD_RESET_SERVER_V1)
        {
            msg(D_TLS_ERRORS, "Peer tried unsupported key-method 1");
        }
        msg(D_TLS_ERRORS,
            "TLS Error: unknown opcode received from %s op=%d",
            print_link_socket_actual(from, &gc), op);
        goto error;
    }

    /* hard reset ? */
    if (is_hard_reset_method2(op))
    {
        /* verify client -> server or server -> client connection */
        if (((op == P_CONTROL_HARD_RESET_CLIENT_V2 || op == P_CONTROL_HARD_RESET_CLIENT_V3) && !multi->opt.server)
            || ((op == P_CONTROL_HARD_RESET_SERVER_V2) && multi->opt.server))
        {
            msg(D_TLS_ERRORS,
                "TLS Error: client->client or server->server connection attempted from %s",
                print_link_socket_actual(from, &gc));
            goto error;
        }
    }

    /*
     * Authenticate Packet
     */
    dmsg(D_TLS_DEBUG, "TLS: control channel, op=%s, IP=%s",
         packet_opcode_name(op), print_link_socket_actual(from, &gc));

    {
        struct buffer tmp = *buf;
        buf_advance(&tmp, 1);
        if (!session_id_read(&sid, &tmp) || !session_id_defined(&sid))
        {
            msg(D_TLS_ERRORS,
                "TLS Error: session-id not found in packet from %s",
                print_link_socket_actual(from, &gc));
            goto error;
        }
    }

    int i;
    /* use session ID to match up packet with appropriate tls_session object */
    for (i = 0; i < TM_SIZE; ++i)
    {
        struct tls_session *session = &multi->session[i];
        struct key_state *ks = &session->key[KS_PRIMARY];

        dmsg(D_TLS_DEBUG,
             "TLS: initial packet test, i=%d state=%s, mysid=%s, rec-sid=%s, rec-ip=%s, stored-sid=%s, stored-ip=%s",
             i,
             state_name(ks->state),
             session_id_print(&session->session_id, &gc),
             session_id_print(&sid, &gc),
             print_link_socket_actual(from, &gc),
             session_id_print(&ks->session_id_remote, &gc),
             print_link_socket_actual(&ks->remote_addr, &gc));

        if (session_id_equal(&ks->session_id_remote, &sid))
            /* found a match */
        {
            if (i == TM_LAME_DUCK)
            {
                msg(D_TLS_ERRORS,
                    "TLS ERROR: received control packet with stale session-id=%s",
                    session_id_print(&sid, &gc));
                goto error;
            }
            dmsg(D_TLS_DEBUG,
                 "TLS: found match, session[%d], sid=%s",
                 i, session_id_print(&sid, &gc));
            break;
        }
    }

    /*
     * Hard reset and session id does not match any session in
     * multi->session: Possible initial packet
     */
    if (i == TM_SIZE && is_hard_reset_method2(op))
    {
        struct tls_session *session = &multi->session[TM_ACTIVE];
        const struct key_state *ks = get_primary_key(multi);

        /*
         * If we have no session currently in progress, the initial packet will
         * open a new session in TM_ACTIVE rather than TM_UNTRUSTED.
         */
        if (!session_id_defined(&ks->session_id_remote))
        {
            if (multi->opt.single_session && multi->n_sessions)
            {
                msg(D_TLS_ERRORS,
                    "TLS Error: Cannot accept new session request from %s due to session context expire or --single-session [1]",
                    print_link_socket_actual(from, &gc));
                goto error;
            }

#ifdef ENABLE_MANAGEMENT
                if (management)
            {
                management_set_state(management,
                                     OPENVPN_STATE_AUTH,
                                     NULL,
                                     NULL,
                                     NULL,
                                     NULL,
                                     NULL);
            }
#endif

            msg(D_TLS_DEBUG_LOW,
                "TLS: Initial packet from %s, sid=%s",
                print_link_socket_actual(from, &gc),
                session_id_print(&sid, &gc));

            do_burst = true;
            new_link = true;
            i = TM_ACTIVE;
            session->untrusted_addr = *from;
        }
    }

    /*
     * If we detected new session in the last if block, variable i has
     * changed to TM_ACTIVE, so check the condition again.
     */
    if (i == TM_SIZE && is_hard_reset_method2(op))
    {
        /*
         * No match with existing sessions,
         * probably a new session.
         */
        struct tls_session *session = &multi->session[TM_UNTRUSTED];

        /*
         * If --single-session, don't allow any hard-reset connection request
         * unless it the first packet of the session.
         */
        if (multi->opt.single_session)
        {
            msg(D_TLS_ERRORS,
                "TLS Error: Cannot accept new session request from %s due to session context expire or --single-session [2]",
                print_link_socket_actual(from, &gc));
            goto error;
        }

        if (!read_control_auth(buf, &session->tls_wrap, from,
                               session->opt))
        {
            goto error;
        }

        /*
         * New session-initiating control packet is authenticated at this point,
         * assuming that the --tls-auth command line option was used.
         *
         * Without --tls-auth, we leave authentication entirely up to TLS.
         */
        msg(D_TLS_DEBUG_LOW,
            "TLS: new session incoming connection from %s",
            print_link_socket_actual(from, &gc));

        new_link = true;
        i = TM_UNTRUSTED;
        session->untrusted_addr = *from;
    }
    else
    {
        struct tls_session *session = &multi->session[i];
        struct key_state *ks = &session->key[KS_PRIMARY];

        /*
         * Packet must belong to an existing session.
         */
        if (i != TM_ACTIVE && i != TM_UNTRUSTED)
        {
            msg(D_TLS_ERRORS,
                "TLS Error: Unroutable control packet received from %s (si=%d op=%s)",
                print_link_socket_actual(from, &gc),
                i,
                packet_opcode_name(op));
            goto error;
        }

        /*
         * Verify remote IP address
         */
        if (!new_link && !link_socket_actual_match(&ks->remote_addr, from))
        {
            msg(D_TLS_ERRORS, "TLS Error: Received control packet from unexpected IP addr: %s",
                print_link_socket_actual(from, &gc));
            goto error;
        }

        /*
         * Remote is requesting a key renegotiation
         */
        if (op == P_CONTROL_SOFT_RESET_V1 && TLS_AUTHENTICATED(multi, ks))
        {
            if (!read_control_auth(buf, &session->tls_wrap, from,
                                   session->opt))
            {
                goto error;
            }

            key_state_soft_reset(session);

            dmsg(D_TLS_DEBUG,
                 "TLS: received P_CONTROL_SOFT_RESET_V1 s=%d sid=%s",
                 i, session_id_print(&sid, &gc));
        }
        else
        {
            /*
             * Remote responding to our key renegotiation request?
             */
            if (op == P_CONTROL_SOFT_RESET_V1)
            {
                do_burst = true;
            }

            if (!read_control_auth(buf, &session->tls_wrap, from,
                                   session->opt))
            {
                goto error;
            }

            dmsg(D_TLS_DEBUG,
                 "TLS: received control channel packet s#=%d sid=%s",
                 i, session_id_print(&sid, &gc));
        }
    }

    /*
     * We have an authenticated control channel packet (if --tls-auth/tls-crypt
     * or tls-crypt-v2 was set).
     * Now pass to our reliability layer which deals with
     * packet acknowledgements, retransmits, sequencing, etc.
     */
    struct tls_session *session = &multi->session[i];
    struct key_state *ks = &session->key[KS_PRIMARY];

    /* Make sure we were initialized and that we're not in an error state */
    ASSERT(ks->state != S_UNDEF);
    ASSERT(ks->state != S_ERROR);
    ASSERT(session_id_defined(&session->session_id));

    /* Let our caller know we processed a control channel packet */
    ret = true;

    /*
     * Set our remote address and remote session_id
     */
    if (new_link)
    {
        ks->session_id_remote = sid;
        ks->remote_addr = *from;
        ++multi->n_sessions;
    }
    else if (!link_socket_actual_match(&ks->remote_addr, from))
    {
        msg(D_TLS_ERRORS,
            "TLS Error: Existing session control channel packet from unknown IP address: %s",
            print_link_socket_actual(from, &gc));
        goto error;
    }

    /*
     * Should we do a retransmit of all unacknowledged packets in
     * the send buffer?  This improves the start-up efficiency of the
     * initial key negotiation after the 2nd peer comes online.
     */
    if (do_burst && !session->burst)
    {
        reliable_schedule_now(ks->send_reliable);
        session->burst = true;
    }

    /* Check key_id */
    if (ks->key_id != key_id)
    {
        msg(D_TLS_ERRORS,
            "TLS ERROR: local/remote key IDs out of sync (%d/%d) ID: %s",
            ks->key_id, key_id, print_key_id(multi, &gc));
        goto error;
    }

    /*
     * Process incoming ACKs for packets we can now
     * delete from reliable send buffer
     */
    {
        /* buffers all packet IDs to delete from send_reliable */
        struct reliable_ack send_ack;

        if (!reliable_ack_read(&send_ack, buf, &session->session_id))
        {
            msg(D_TLS_ERRORS,
                "TLS Error: reading acknowledgement record from packet");
            goto error;
        }
        reliable_send_purge(ks->send_reliable, &send_ack);
    }

    // lichen mark
    if (op != P_ACK_V1 && reliable_can_get(ks->rec_reliable))
    {
        packet_id_type id;

        /* Extract the packet ID from the packet */
        if (reliable_ack_read_packet_id(buf, &id))
        {
            /* Avoid deadlock by rejecting packet that would de-sequentialize receive buffer */
            if (reliable_wont_break_sequentiality(ks->rec_reliable, id))
            {
                if (reliable_not_replay(ks->rec_reliable, id))
                {
                    /* Save incoming ciphertext packet to reliable buffer */
                    struct buffer *in = reliable_get_buf(ks->rec_reliable);
                    ASSERT(in);
                    if (!buf_copy(in, buf))
                    {
                        msg(D_MULTI_DROPPED,
                            "Incoming control channel packet too big, dropping.");
                        goto error;
                    }
                    reliable_mark_active_incoming(ks->rec_reliable, in, id, op);
                }

                /* Process outgoing acknowledgment for packet just received, even if it's a replay */
                reliable_ack_acknowledge_packet_id(ks->rec_ack, id);
            }
        }
    }
    /* Remember that we received a valid control channel packet */
    ks->peer_last_packet = now;

    done:
    buf->len = 0;
    *opt = NULL;
    gc_free(&gc);
    return ret;

    error:
    ++multi->n_soft_errors;
    goto done;
}


struct key_state *
tls_select_encryption_key(struct tls_multi *multi)
{
    struct key_state *ks_select = NULL;
    for (int i = 0; i < KEY_SCAN_SIZE; ++i)
    {
        struct key_state *ks = get_key_scan(multi, i);
        if (ks->state >= S_GENERATED_KEYS && ks->authenticated == KS_AUTH_TRUE)
        {
            ASSERT(ks->crypto_options.key_ctx_bi.initialized);

            if (!ks_select)
            {
                ks_select = ks;
            }
            if (now >= ks->auth_deferred_expire)
            {
                ks_select = ks;
                break;
            }
        }
    }
    return ks_select;
}


/* Choose the key with which to encrypt a data packet */
void
tls_pre_encrypt(struct tls_multi *multi,
                struct buffer *buf, struct crypto_options **opt)
{
    multi->save_ks = NULL;
    if (buf->len <= 0)
    {
        buf->len = 0;
        *opt = NULL;
        return;
    }

    struct key_state *ks_select = tls_select_encryption_key(multi);

    if (ks_select)
    {
        *opt = &ks_select->crypto_options;
        multi->save_ks = ks_select;
        dmsg(D_TLS_KEYSELECT, "TLS: tls_pre_encrypt: key_id=%d", ks_select->key_id);
        return;
    }
    else
    {
        struct gc_arena gc = gc_new();
        dmsg(D_TLS_KEYSELECT, "TLS Warning: no data channel send key available: %s",
             print_key_id(multi, &gc));
        gc_free(&gc);

        *opt = NULL;
        buf->len = 0;
    }
}

void
tls_prepend_opcode_v1(const struct tls_multi *multi, struct buffer *buf)
{
    struct key_state *ks = multi->save_ks;
    uint8_t op;

    msg(D_TLS_DEBUG, __func__);

    ASSERT(ks);

    op = (P_DATA_V1 << P_OPCODE_SHIFT) | ks->key_id;
    ASSERT(buf_write_prepend(buf, &op, 1));
}

void
tls_prepend_opcode_v2(const struct tls_multi *multi, struct buffer *buf)
{
    struct key_state *ks = multi->save_ks;
    uint32_t peer;

    msg(D_TLS_DEBUG, __func__);

    ASSERT(ks);

    peer = htonl(((P_DATA_V2 << P_OPCODE_SHIFT) | ks->key_id) << 24
                 | (multi->peer_id & 0xFFFFFF));
    ASSERT(buf_write_prepend(buf, &peer, 4));
}

void
tls_post_encrypt(struct tls_multi *multi, struct buffer *buf)
{
    struct key_state *ks = multi->save_ks;
    multi->save_ks = NULL;

    if (buf->len > 0)
    {
        ASSERT(ks);

        ++ks->n_packets;
        ks->n_bytes += buf->len;
    }
}

bool
tls_send_payload(struct tls_multi *multi,
                 const uint8_t *data,
                 int size)
{
    struct key_state *ks;
    bool ret = false;

    ASSERT(multi);

    ks = get_key_scan(multi, 0);

    if (ks->state >= S_ACTIVE)
    {
        buf_write(&ks->plaintext_write_buf,data,size);
        ret = true;
    }
    else
    {
        if (!ks->paybuf)
        {
            ks->paybuf = buffer_list_new();
        }
        buffer_list_push_data(ks->paybuf, data, (size_t)size);
        ret = true;
    }


    return ret;
}


bool
tls_rec_payload(struct tls_multi *multi,
                struct buffer *buf)
{
    bool ret = false;

    ASSERT(multi);

    struct key_state *ks = get_key_scan(multi, 0);

    if (ks->state >= S_ACTIVE && BLEN(&ks->plaintext_read_buf))
    {
        if (buf_copy(buf, &ks->plaintext_read_buf))
        {
            ret = true;
        }
        ks->plaintext_read_buf.len = 0;
    }

    return ret;
}

void
tls_update_remote_addr(struct tls_multi *multi, const struct link_socket_actual *addr)
{
    struct gc_arena gc = gc_new();
    for (int i = 0; i < TM_SIZE; ++i)
    {
        struct tls_session *session = &multi->session[i];

        for (int j = 0; j < KS_SIZE; ++j)
        {
            struct key_state *ks = &session->key[j];

            if (!link_socket_actual_defined(&ks->remote_addr)
                || link_socket_actual_match(addr, &ks->remote_addr))
            {
                continue;
            }

            dmsg(D_TLS_KEYSELECT, "TLS: tls_update_remote_addr from IP=%s to IP=%s",
                 print_link_socket_actual(&ks->remote_addr, &gc),
                 print_link_socket_actual(addr, &gc));

            ks->remote_addr = *addr;
        }
    }
    gc_free(&gc);
}

/*
 * Dump a human-readable rendition of an openvpn packet
 * into a garbage collectable string which is returned.
 */
const char *
protocol_dump(struct buffer *buffer, unsigned int flags, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(256, gc);
    struct buffer buf = *buffer;

    uint8_t c;
    int op;
    int key_id;

    int tls_auth_hmac_size = (flags & PD_TLS_AUTH_HMAC_SIZE_MASK);

    if (buf.len <= 0)
    {
        buf_printf(&out, "DATA UNDEF len=%d", buf.len);
        goto done;
    }

    if (!(flags & PD_TLS))
    {
        goto print_data;
    }

    /*
     * Initial byte (opcode)
     */
    if (!buf_read(&buf, &c, sizeof(c)))
    {
        goto done;
    }
    op = (c >> P_OPCODE_SHIFT);
    key_id = c & P_KEY_ID_MASK;
    buf_printf(&out, "%s kid=%d", packet_opcode_name(op), key_id);

    if ((op == P_DATA_V1) || (op == P_DATA_V2))
    {
        goto print_data;
    }

    /*
     * Session ID
     */
    {
        struct session_id sid;

        if (!session_id_read(&sid, &buf))
        {
            goto done;
        }
        if (flags & PD_VERBOSE)
        {
            buf_printf(&out, " sid=%s", session_id_print(&sid, gc));
        }
    }

    /*
     * tls-auth hmac + packet_id
     */
    if (tls_auth_hmac_size)
    {
        struct packet_id_net pin;
        uint8_t tls_auth_hmac[MAX_HMAC_KEY_LENGTH];

        ASSERT(tls_auth_hmac_size <= MAX_HMAC_KEY_LENGTH);

        if (!buf_read(&buf, tls_auth_hmac, tls_auth_hmac_size))
        {
            goto done;
        }
        if (flags & PD_VERBOSE)
        {
            buf_printf(&out, " tls_hmac=%s", format_hex(tls_auth_hmac, tls_auth_hmac_size, 0, gc));
        }

        if (!packet_id_read(&pin, &buf, true))
        {
            goto done;
        }
        buf_printf(&out, " pid=%s", packet_id_net_print(&pin, (flags & PD_VERBOSE), gc));
    }

    /*
     * ACK list
     */
    buf_printf(&out, " %s", reliable_ack_print(&buf, (flags & PD_VERBOSE), gc));

    if (op == P_ACK_V1)
    {
        goto print_data;
    }

    /*
     * Packet ID
     */
    {
        packet_id_type l;
        if (!buf_read(&buf, &l, sizeof(l)))
        {
            goto done;
        }
        l = ntohpid(l);
        buf_printf(&out, " pid=" packet_id_format, (packet_id_print_type)l);
    }

    print_data:
    if (flags & PD_SHOW_DATA)
    {
        buf_printf(&out, " DATA %s", format_hex(BPTR(&buf), BLEN(&buf), 80, gc));
    }
    else
    {
        buf_printf(&out, " DATA len=%d", buf.len);
    }

    done:
    return BSTR(&out);
}

void
ssl_clean_user_pass(void)
{
    purge_user_pass(&auth_user_pass, false);
}
