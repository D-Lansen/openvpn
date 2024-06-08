#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "base64.h"
#include "buffer.h"
#include "crypto.h"
#include "openvpn.h"
#include "ssl_common.h"
#include "auth_token.h"
#include "push.h"
#include "integer.h"
#include "ssl.h"
#include "ssl_verify.h"
#include <inttypes.h>

const char *auth_token_pem_name = "OpenVPN auth-token server key";

#define AUTH_TOKEN_SESSION_ID_LEN 12
#define AUTH_TOKEN_SESSION_ID_BASE64_LEN (AUTH_TOKEN_SESSION_ID_LEN * 8 / 6)

#if AUTH_TOKEN_SESSION_ID_LEN % 3
#error AUTH_TOKEN_SESSION_ID_LEN needs to be multiple a 3
#endif

/* Size of the data of the token (not b64 encoded and without prefix) */
#define TOKEN_DATA_LEN (2 * sizeof(int64_t) + AUTH_TOKEN_SESSION_ID_LEN + 32)


void
wipe_auth_token(struct tls_multi *multi)
{
    if (multi)
    {
        if (multi->auth_token)
        {
            secure_memzero(multi->auth_token, strlen(multi->auth_token));
            free(multi->auth_token);
        }
        if (multi->auth_token_initial)
        {
            secure_memzero(multi->auth_token_initial,
                           strlen(multi->auth_token_initial));
            free(multi->auth_token_initial);
        }
        multi->auth_token = NULL;
        multi->auth_token_initial = NULL;
    }
}

void
resend_auth_token_renegotiation(struct tls_multi *multi, struct tls_session *session)
{
    /*
     * Auth token already sent to client, update auth-token on client.
     * The initial auth-token is sent as part of the push message, for this
     * update we need to schedule an extra push message.
     *
     * Otherwise the auth-token get pushed out as part of the "normal"
     * push-reply
     */
    bool is_renegotiation = session->key[KS_PRIMARY].key_id != 0;

    if (multi->auth_token_initial && is_renegotiation)
    {
        /*
         * We do not explicitly reschedule the sending of the
         * control message here. This might delay this reply
         * a few seconds but this message is not time critical
         */
        send_push_reply_auth_token(multi);
    }
}
