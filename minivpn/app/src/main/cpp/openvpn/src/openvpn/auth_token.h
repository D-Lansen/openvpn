/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2022 OpenVPN Inc <sales@openvpn.net>
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
#ifndef AUTH_TOKEN_H
#define AUTH_TOKEN_H


/**
 * Wipes the authentication token out of the memory, frees and cleans up
 * related buffers and flags
 *
 *  @param multi  Pointer to a multi object holding the auth_token variables
 */
void wipe_auth_token(struct tls_multi *multi);

/**
 * The prefix given to auth tokens start with, this prefix is special
 * cased to not show up in log files in OpenVPN 2 and 3
 *
 * We also prefix this with _AT_ to only act on auth token generated by us.
 */
#define SESSION_ID_PREFIX "SESS_ID_AT_"

/**
 * Checks if a client should be sent a new auth token to update its
 * current auth-token
 * @param multi     Pointer the multi object of the TLS session
 * @param session   Pointer to the TLS session itself
 */
void
resend_auth_token_renegotiation(struct tls_multi *multi, struct tls_session *session);

#endif /* AUTH_TOKEN_H */
