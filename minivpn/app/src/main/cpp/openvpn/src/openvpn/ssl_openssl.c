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
 * @file Control Channel OpenSSL Backend
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_CRYPTO_OPENSSL)

#include "errlevel.h"
#include "buffer.h"
#include "misc.h"
#include "manage.h"
#include "memdbg.h"
#include "ssl_backend.h"
#include "ssl_common.h"
#include "base64.h"
#include "openssl_compat.h"

#ifdef ENABLE_CRYPTOAPI
#include "cryptoapi.h"
#endif


#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#endif

#if defined(_MSC_VER) && !defined(_M_ARM64)
#include <openssl/applink.c>
#endif

OSSL_LIB_CTX *tls_libctx; /* Global */

static void unload_xkey_provider(void);

/*
 * Allocate space in SSL objects in which to store a struct tls_session
 * pointer back to parent.
 *
 */

int mydata_index; /* GLOBAL */

void
tls_init_lib(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
#ifndef ENABLE_SMALL
    SSL_load_error_strings();
#endif
    OpenSSL_add_all_algorithms();
#endif
    mydata_index = SSL_get_ex_new_index(0, "struct session *", NULL, NULL, NULL);
    ASSERT(mydata_index >= 0);
}

void
tls_free_lib(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_cleanup();
#ifndef ENABLE_SMALL
    ERR_free_strings();
#endif
#endif
}

void
tls_ctx_server_new(struct tls_root_ctx *ctx)
{
    ASSERT(NULL != ctx);

    ctx->ctx = SSL_CTX_new_ex(tls_libctx, NULL, SSLv23_server_method());

    if (ctx->ctx == NULL)
    {
        crypto_msg(M_FATAL, "SSL_CTX_new SSLv23_server_method");
    }
    if (ERR_peek_error() != 0)
    {
        crypto_msg(M_WARN, "Warning: TLS server context initialisation "
                   "has warnings.");
    }
}

void
tls_ctx_client_new(struct tls_root_ctx *ctx)
{
    ASSERT(NULL != ctx);

    ctx->ctx = SSL_CTX_new_ex(tls_libctx, NULL, SSLv23_client_method());

    if (ctx->ctx == NULL)
    {
        crypto_msg(M_FATAL, "SSL_CTX_new SSLv23_client_method");
    }
    if (ERR_peek_error() != 0)
    {
        crypto_msg(M_WARN, "Warning: TLS client context initialisation "
                   "has warnings.");
    }
}

void
tls_ctx_free(struct tls_root_ctx *ctx)
{
    ASSERT(NULL != ctx);
    SSL_CTX_free(ctx->ctx);
    ctx->ctx = NULL;
    unload_xkey_provider(); /* in case it is loaded */
}

bool
tls_ctx_initialised(struct tls_root_ctx *ctx)
{
    ASSERT(NULL != ctx);
    return NULL != ctx->ctx;
}

bool
key_state_export_keying_material(struct tls_session *session,
                                 const char *label, size_t label_size,
                                 void *ekm, size_t ekm_size)

{
    SSL *ssl = session->key[KS_PRIMARY].ks_ssl.ssl;

    if (SSL_export_keying_material(ssl, ekm, ekm_size, label,
                                   label_size, NULL, 0, 0) == 1)
    {
        return true;
    }
    else
    {
        secure_memzero(ekm, ekm_size);
        return false;
    }
}

bool
tls_ctx_set_options(struct tls_root_ctx *ctx, unsigned int ssl_flags)
{
    ASSERT(NULL != ctx);

    /* process SSL options */
    long sslopt = SSL_OP_SINGLE_DH_USE | SSL_OP_NO_TICKET;
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
    sslopt |= SSL_OP_CIPHER_SERVER_PREFERENCE;
#endif
    sslopt |= SSL_OP_NO_COMPRESSION;
    /* Disable TLS renegotiations. OpenVPN's renegotiation creates new SSL
     * session and does not depend on this feature. And TLS renegotiations have
     * been problematic in the past */
#ifdef SSL_OP_NO_RENEGOTIATION
    sslopt |= SSL_OP_NO_RENEGOTIATION;
#endif

    SSL_CTX_set_options(ctx->ctx, sslopt);

#ifdef SSL_MODE_RELEASE_BUFFERS
    SSL_CTX_set_mode(ctx->ctx, SSL_MODE_RELEASE_BUFFERS);
#endif
    SSL_CTX_set_session_cache_mode(ctx->ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_default_passwd_cb(ctx->ctx, pem_password_callback);

//    /* Require peer certificate verification */
//    int verify_flags = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
//    if (ssl_flags & SSLF_CLIENT_CERT_NOT_REQUIRED)
//    {
//        verify_flags = 0;
//    }
//    else if (ssl_flags & SSLF_CLIENT_CERT_OPTIONAL)
//    {
//        verify_flags = SSL_VERIFY_PEER;
//    }

    return true;
}

void
convert_tls_list_to_openssl(char *openssl_ciphers, size_t len, const char *ciphers)
{
    /* Parse supplied cipher list and pass on to OpenSSL */
    size_t begin_of_cipher, end_of_cipher;

    const char *current_cipher;
    size_t current_cipher_len;

    const tls_cipher_name_pair *cipher_pair;

    size_t openssl_ciphers_len = 0;
    openssl_ciphers[0] = '\0';

    /* Translate IANA cipher suite names to OpenSSL names */
    begin_of_cipher = end_of_cipher = 0;
    for (; begin_of_cipher < strlen(ciphers); begin_of_cipher = end_of_cipher)
    {
        end_of_cipher += strcspn(&ciphers[begin_of_cipher], ":");
        cipher_pair = tls_get_cipher_name_pair(&ciphers[begin_of_cipher], end_of_cipher - begin_of_cipher);

        if (NULL == cipher_pair)
        {
            /* No translation found, use original */
            current_cipher = &ciphers[begin_of_cipher];
            current_cipher_len = end_of_cipher - begin_of_cipher;

            /* Issue warning on missing translation */
            /* %.*s format specifier expects length of type int, so guarantee */
            /* that length is small enough and cast to int. */
            msg(D_LOW, "No valid translation found for TLS cipher '%.*s'",
                constrain_int(current_cipher_len, 0, 256), current_cipher);
        }
        else
        {
            /* Use OpenSSL name */
            current_cipher = cipher_pair->openssl_name;
            current_cipher_len = strlen(current_cipher);

            if (end_of_cipher - begin_of_cipher == current_cipher_len
                && 0 != memcmp(&ciphers[begin_of_cipher], cipher_pair->iana_name,
                               end_of_cipher - begin_of_cipher))
            {
                /* Non-IANA name used, show warning */
                msg(M_WARN, "Deprecated TLS cipher name '%s', please use IANA name '%s'", cipher_pair->openssl_name, cipher_pair->iana_name);
            }
        }

        /* Make sure new cipher name fits in cipher string */
        if ((SIZE_MAX - openssl_ciphers_len) < current_cipher_len
            || (len - 1) < (openssl_ciphers_len + current_cipher_len))
        {
            msg(M_FATAL,
                "Failed to set restricted TLS cipher list, too long (>%d).",
                (int)(len - 1));
        }

        /* Concatenate cipher name to OpenSSL cipher string */
        memcpy(&openssl_ciphers[openssl_ciphers_len], current_cipher, current_cipher_len);
        openssl_ciphers_len += current_cipher_len;
        openssl_ciphers[openssl_ciphers_len] = ':';
        openssl_ciphers_len++;

        end_of_cipher++;
    }

    if (openssl_ciphers_len > 0)
    {
        openssl_ciphers[openssl_ciphers_len-1] = '\0';
    }
}

void
tls_ctx_restrict_ciphers(struct tls_root_ctx *ctx, const char *ciphers)
{
    if (ciphers == NULL)
    {
        /* Use sane default TLS cipher list */
        if (!SSL_CTX_set_cipher_list(ctx->ctx,
                                     /* Use openssl's default list as a basis */
                                     "DEFAULT"
                                     /* Disable export ciphers and openssl's 'low' and 'medium' ciphers */
                                     ":!EXP:!LOW:!MEDIUM"
                                     /* Disable static (EC)DH keys (no forward secrecy) */
                                     ":!kDH:!kECDH"
                                     /* Disable DSA private keys */
                                     ":!DSS"
                                     /* Disable unsupported TLS modes */
                                     ":!PSK:!SRP:!kRSA"))
        {
            crypto_msg(M_FATAL, "Failed to set default TLS cipher list.");
        }
        return;
    }

    char openssl_ciphers[4096];
    convert_tls_list_to_openssl(openssl_ciphers, sizeof(openssl_ciphers), ciphers);

    ASSERT(NULL != ctx);

    /* Set OpenSSL cipher list */
    if (!SSL_CTX_set_cipher_list(ctx->ctx, openssl_ciphers))
    {
        crypto_msg(M_FATAL, "Failed to set restricted TLS cipher list: %s", openssl_ciphers);
    }
}

void
convert_tls13_list_to_openssl(char *openssl_ciphers, size_t len,
                              const char *ciphers)
{
    /*
     * OpenSSL (and official IANA) cipher names have _ in them. We
     * historically used names with - in them. Silently convert names
     * with - to names with _ to support both
     */
    if (strlen(ciphers) >= (len - 1))
    {
        msg(M_FATAL,
            "Failed to set restricted TLS 1.3 cipher list, too long (>%d).",
            (int) (len - 1));
    }

    strncpy(openssl_ciphers, ciphers, len);

    for (size_t i = 0; i < strlen(openssl_ciphers); i++)
    {
        if (openssl_ciphers[i] == '-')
        {
            openssl_ciphers[i] = '_';
        }
    }
}

void
tls_ctx_restrict_ciphers_tls13(struct tls_root_ctx *ctx, const char *ciphers)
{
    if (ciphers == NULL)
    {
        /* default cipher list of OpenSSL 1.1.1 is sane, do not set own
         * default as we do with tls-cipher */
        return;
    }

#if !defined(TLS1_3_VERSION)
    crypto_msg(M_WARN, "Not compiled with OpenSSL 1.1.1 or higher. "
               "Ignoring TLS 1.3 only tls-ciphersuites '%s' setting.",
               ciphers);
#else
    ASSERT(NULL != ctx);

    char openssl_ciphers[4096];
    convert_tls13_list_to_openssl(openssl_ciphers, sizeof(openssl_ciphers),
                                  ciphers);

    if (!SSL_CTX_set_ciphersuites(ctx->ctx, openssl_ciphers))
    {
        crypto_msg(M_FATAL, "Failed to set restricted TLS 1.3 cipher list: %s",
                   openssl_ciphers);
    }
#endif
}

void
tls_ctx_set_cert_profile(struct tls_root_ctx *ctx, const char *profile)
{
#if OPENSSL_VERSION_NUMBER > 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
    /* OpenSSL does not have certificate profiles, but a complex set of
     * callbacks that we could try to implement to achieve something similar.
     * For now, use OpenSSL's security levels to achieve similar (but not equal)
     * behaviour. */
    if (!profile || 0 == strcmp(profile, "legacy"))
    {
        SSL_CTX_set_security_level(ctx->ctx, 1);
    }
    else if (0 == strcmp(profile, "insecure"))
    {
        SSL_CTX_set_security_level(ctx->ctx, 0);
    }
    else if (0 == strcmp(profile, "preferred"))
    {
        SSL_CTX_set_security_level(ctx->ctx, 2);
    }
    else if (0 == strcmp(profile, "suiteb"))
    {
        SSL_CTX_set_security_level(ctx->ctx, 3);
        SSL_CTX_set_cipher_list(ctx->ctx, "SUITEB128");
    }
    else
    {
        msg(M_FATAL, "ERROR: Invalid cert profile: %s", profile);
    }
#else  /* if OPENSSL_VERSION_NUMBER > 0x10100000L */
    if (profile)
    {
        msg(M_WARN, "WARNING: OpenSSL 1.0.2 and LibreSSL do not support "
            "--tls-cert-profile, ignoring user-set profile: '%s'", profile);
    }
#endif /* if OPENSSL_VERSION_NUMBER > 0x10100000L */
}

void
tls_ctx_set_tls_groups(struct tls_root_ctx *ctx, const char *groups)
{
    ASSERT(ctx);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    struct gc_arena gc = gc_new();
    /* This method could be as easy as
     *  SSL_CTX_set1_groups_list(ctx->ctx, groups)
     * but OpenSSL (< 3.0) does not like the name secp256r1 for prime256v1
     * This is one of the important curves.
     * To support the same name for OpenSSL and mbedTLS, we do
     * this dance.
     * Also note that the code is wrong in the presence of OpenSSL3 providers.
     */

    int groups_count = get_num_elements(groups, ':');

    int *glist;
    /* Allocate an array for them */
    ALLOC_ARRAY_CLEAR_GC(glist, int, groups_count, &gc);

    /* Parse allowed ciphers, getting IDs */
    int glistlen = 0;
    char *tmp_groups = string_alloc(groups, &gc);

    const char *token;
    while ((token = strsep(&tmp_groups, ":")))
    {
        if (streq(token, "secp256r1"))
        {
            token = "prime256v1";
        }
        int nid = OBJ_sn2nid(token);

        if (nid == 0)
        {
            msg(M_WARN, "Warning unknown curve/group specified: %s", token);
        }
        else
        {
            glist[glistlen] = nid;
            glistlen++;
        }
    }

    if (!SSL_CTX_set1_groups(ctx->ctx, glist, glistlen))
    {
        crypto_msg(M_FATAL, "Failed to set allowed TLS group list: %s",
                   groups);
    }
    gc_free(&gc);
#else  /* if OPENSSL_VERSION_NUMBER < 0x30000000L */
    if (!SSL_CTX_set1_groups_list(ctx->ctx, groups))
    {
        crypto_msg(M_FATAL, "Failed to set allowed TLS group list: %s",
                   groups);
    }
#endif /* if OPENSSL_VERSION_NUMBER < 0x30000000L */
}


#ifdef ENABLE_CRYPTOAPI
void
tls_ctx_load_cryptoapi(struct tls_root_ctx *ctx, const char *cryptoapi_cert)
{
    ASSERT(NULL != ctx);

    /* Load Certificate and Private Key */
    if (!SSL_CTX_use_CryptoAPI_certificate(ctx->ctx, cryptoapi_cert))
    {
        crypto_msg(M_FATAL, "Cannot load certificate \"%s\" from Microsoft Certificate Store", cryptoapi_cert);
    }
}
#endif /* ENABLE_CRYPTOAPI */

static void
tls_ctx_add_extra_certs(struct tls_root_ctx *ctx, BIO *bio, bool optional)
{
    X509 *cert;
    while (true)
    {
        cert = NULL;
        if (!PEM_read_bio_X509(bio, &cert, NULL, NULL))
        {
            /*  a PEM_R_NO_START_LINE "Error" indicates that no certificate
             *  is found in the buffer.  If loading more certificates is
             *  optional, break without raising an error
             */
            if (optional
                && ERR_GET_REASON(ERR_peek_error()) == PEM_R_NO_START_LINE)
            {
                /* remove that error from error stack */
                (void)ERR_get_error();
                break;
            }

            /* Otherwise, bail out with error */
            crypto_msg(M_FATAL, "Error reading extra certificate");
        }
        /* takes ownership of cert like a set1 method */
        if (SSL_CTX_add_extra_chain_cert(ctx->ctx, cert) != 1)
        {
            crypto_msg(M_FATAL, "Error adding extra certificate");
        }
        /* We loaded at least one certificate, so loading more is optional */
        optional = true;
    }
}

void
tls_ctx_load_cert_file(struct tls_root_ctx *ctx, const char *cert_file,
                       bool cert_file_inline)
{
    BIO *in = NULL;
    X509 *x = NULL;
    int ret = 0;

    ASSERT(NULL != ctx);

    if (cert_file_inline)
    {
        in = BIO_new_mem_buf((char *) cert_file, -1);
    }
    else
    {
        in = BIO_new_file(cert_file, "r");
    }

    if (in == NULL)
    {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_SYS_LIB);
        goto end;
    }

    x = PEM_read_bio_X509(in, NULL,
                          SSL_CTX_get_default_passwd_cb(ctx->ctx),
                          SSL_CTX_get_default_passwd_cb_userdata(ctx->ctx));
    if (x == NULL)
    {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_PEM_LIB);
        goto end;
    }

    ret = SSL_CTX_use_certificate(ctx->ctx, x);
    if (ret)
    {
        tls_ctx_add_extra_certs(ctx, in, true);
    }

end:
    if (!ret)
    {
        if (cert_file_inline)
        {
            crypto_msg(M_FATAL, "Cannot load inline certificate file");
        }
        else
        {
            crypto_msg(M_FATAL, "Cannot load certificate file %s", cert_file);
        }
    }
    else
    {
        crypto_print_openssl_errors(M_DEBUG);
    }

    BIO_free(in);
    X509_free(x);
}

int
tls_ctx_load_priv_file(struct tls_root_ctx *ctx, const char *priv_key_file,
                       bool priv_key_file_inline)
{
    SSL_CTX *ssl_ctx = NULL;
    BIO *in = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 1;

    ASSERT(NULL != ctx);

    ssl_ctx = ctx->ctx;

    if (priv_key_file_inline)
    {
        in = BIO_new_mem_buf((char *) priv_key_file, -1);
    }
    else
    {
        in = BIO_new_file(priv_key_file, "r");
    }

    if (!in)
    {
        goto end;
    }

    pkey = PEM_read_bio_PrivateKey(in, NULL,
                                   SSL_CTX_get_default_passwd_cb(ctx->ctx),
                                   SSL_CTX_get_default_passwd_cb_userdata(ctx->ctx));
    if (!pkey)
    {
        pkey = engine_load_key(priv_key_file, ctx->ctx);
    }

    if (!pkey || !SSL_CTX_use_PrivateKey(ssl_ctx, pkey))
    {
#ifdef ENABLE_MANAGEMENT
        if (management && (ERR_GET_REASON(ERR_peek_error()) == EVP_R_BAD_DECRYPT))
        {
            management_auth_failure(management, UP_TYPE_PRIVATE_KEY, NULL);
        }
#endif
        crypto_msg(M_WARN, "Cannot load private key file %s",
                   print_key_filename(priv_key_file, priv_key_file_inline));
        goto end;
    }

    ret = 0;

end:
    EVP_PKEY_free(pkey);
    BIO_free(in);
    return ret;
}

void
backend_tls_ctx_reload_crl(struct tls_root_ctx *ssl_ctx, const char *crl_file,
                           bool crl_inline)
{
    BIO *in = NULL;

    X509_STORE *store = SSL_CTX_get_cert_store(ssl_ctx->ctx);
    if (!store)
    {
        crypto_msg(M_FATAL, "Cannot get certificate store");
    }

    /* Always start with a cleared CRL list, for that we
     * we need to manually find the CRL object from the stack
     * and remove it */
    STACK_OF(X509_OBJECT) *objs = X509_STORE_get0_objects(store);
    for (int i = 0; i < sk_X509_OBJECT_num(objs); i++)
    {
        X509_OBJECT *obj = sk_X509_OBJECT_value(objs, i);
        ASSERT(obj);
        if (X509_OBJECT_get_type(obj) == X509_LU_CRL)
        {
            sk_X509_OBJECT_delete(objs, i);
            X509_OBJECT_free(obj);
        }
    }

    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);

    if (crl_inline)
    {
        in = BIO_new_mem_buf((char *) crl_file, -1);
    }
    else
    {
        in = BIO_new_file(crl_file, "r");
    }

    if (in == NULL)
    {
        msg(M_WARN, "CRL: cannot read: %s",
            print_key_filename(crl_file, crl_inline));
        goto end;
    }

    int num_crls_loaded = 0;
    while (true)
    {
        X509_CRL *crl = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
        if (crl == NULL)
        {
            /*
             * PEM_R_NO_START_LINE can be considered equivalent to EOF.
             */
            bool eof = ERR_GET_REASON(ERR_peek_error()) == PEM_R_NO_START_LINE;
            /* but warn if no CRLs have been loaded */
            if (num_crls_loaded > 0 && eof)
            {
                /* remove that error from error stack */
                (void)ERR_get_error();
                break;
            }

            crypto_msg(M_WARN, "CRL: cannot read CRL from file %s",
                       print_key_filename(crl_file, crl_inline));
            break;
        }

        if (!X509_STORE_add_crl(store, crl))
        {
            X509_CRL_free(crl);
            crypto_msg(M_WARN, "CRL: cannot add %s to store",
                       print_key_filename(crl_file, crl_inline));
            break;
        }
        X509_CRL_free(crl);
        num_crls_loaded++;
    }
    msg(M_INFO, "CRL: loaded %d CRLs from file %s", num_crls_loaded, crl_file);
end:
    BIO_free(in);
}


#if defined(ENABLE_MANAGEMENT) && !defined(HAVE_XKEY_PROVIDER)
/* encrypt */
static int
rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    ASSERT(0);
    return -1;
}

/* verify arbitrary data */
static int
rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    ASSERT(0);
    return -1;
}

/* decrypt */
static int
rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    ASSERT(0);
    return -1;
}

/* called at RSA_free */
static int
openvpn_extkey_rsa_finish(RSA *rsa)
{
    /* meth was allocated in tls_ctx_use_management_external_key() ; since
     * this function is called when the parent RSA object is destroyed,
     * it is no longer used after this point so kill it. */
    const RSA_METHOD *meth = RSA_get_method(rsa);
    RSA_meth_free((RSA_METHOD *)meth);
    return 1;
}

/*
 * Convert OpenSSL's constant to the strings used in the management
 * interface query
 */
const char *
get_rsa_padding_name(const int padding)
{
    switch (padding)
    {
        case RSA_PKCS1_PADDING:
            return "RSA_PKCS1_PADDING";

        case RSA_NO_PADDING:
            return "RSA_NO_PADDING";

        default:
            return "UNKNOWN";
    }
}

/**
 * Pass the input hash in 'dgst' to management and get the signature back.
 *
 * @param dgst          hash to be signed
 * @param dgstlen       len of data in dgst
 * @param sig           On successful return signature is in sig.
 * @param siglen        length of buffer sig
 * @param algorithm     padding/hashing algorithm for the signature
 *
 * @return              signature length or -1 on error.
 */
static int
get_sig_from_man(const unsigned char *dgst, unsigned int dgstlen,
                 unsigned char *sig, unsigned int siglen,
                 const char *algorithm)
{
    char *in_b64 = NULL;
    char *out_b64 = NULL;
    int len = -1;

    int bencret = openvpn_base64_encode(dgst, dgstlen, &in_b64);

    if (management && bencret > 0)
    {
        out_b64 = management_query_pk_sig(management, in_b64, algorithm);

    }
    if (out_b64)
    {
        len = openvpn_base64_decode(out_b64, sig, siglen);
    }

    free(in_b64);
    free(out_b64);
    return len;
}

/* sign arbitrary data */
static int
rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa,
             int padding)
{
    unsigned int len = RSA_size(rsa);
    int ret = -1;

    if (padding != RSA_PKCS1_PADDING && padding != RSA_NO_PADDING)
    {
        RSAerr(RSA_F_RSA_OSSL_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
        return -1;
    }

    ret = get_sig_from_man(from, flen, to, len, get_rsa_padding_name(padding));

    return (ret == len) ? ret : -1;
}

static int
tls_ctx_use_external_rsa_key(struct tls_root_ctx *ctx, EVP_PKEY *pkey)
{
    RSA *rsa = NULL;
    RSA_METHOD *rsa_meth;

    ASSERT(NULL != ctx);

    const RSA *pub_rsa = EVP_PKEY_get0_RSA(pkey);
    ASSERT(NULL != pub_rsa);

    /* allocate custom RSA method object */
    rsa_meth = RSA_meth_new("OpenVPN external private key RSA Method",
                            RSA_METHOD_FLAG_NO_CHECK);
    check_malloc_return(rsa_meth);
    RSA_meth_set_pub_enc(rsa_meth, rsa_pub_enc);
    RSA_meth_set_pub_dec(rsa_meth, rsa_pub_dec);
    RSA_meth_set_priv_enc(rsa_meth, rsa_priv_enc);
    RSA_meth_set_priv_dec(rsa_meth, rsa_priv_dec);
    RSA_meth_set_init(rsa_meth, NULL);
    RSA_meth_set_finish(rsa_meth, openvpn_extkey_rsa_finish);
    RSA_meth_set0_app_data(rsa_meth, NULL);

    /* allocate RSA object */
    rsa = RSA_new();
    if (rsa == NULL)
    {
        SSLerr(SSL_F_SSL_USE_PRIVATEKEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* initialize RSA object */
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    RSA_get0_key(pub_rsa, &n, &e, NULL);
    RSA_set0_key(rsa, BN_dup(n), BN_dup(e), NULL);
    RSA_set_flags(rsa, RSA_flags(rsa) | RSA_FLAG_EXT_PKEY);
    if (!RSA_set_method(rsa, rsa_meth))
    {
        RSA_meth_free(rsa_meth);
        goto err;
    }
    /* from this point rsa_meth will get freed with rsa */

    /* bind our custom RSA object to ssl_ctx */
    if (!SSL_CTX_use_RSAPrivateKey(ctx->ctx, rsa))
    {
        goto err;
    }

    RSA_free(rsa); /* doesn't necessarily free, just decrements refcount */
    return 1;

err:
    if (rsa)
    {
        RSA_free(rsa);
    }
    else if (rsa_meth)
    {
        RSA_meth_free(rsa_meth);
    }
    return 0;
}

#if OPENSSL_VERSION_NUMBER > 0x10100000L && !defined(OPENSSL_NO_EC)

/* called when EC_KEY is destroyed */
static void
openvpn_extkey_ec_finish(EC_KEY *ec)
{
    /* release the method structure */
    const EC_KEY_METHOD *ec_meth = EC_KEY_get_method(ec);
    EC_KEY_METHOD_free((EC_KEY_METHOD *) ec_meth);
}

/* EC_KEY_METHOD callback: sign().
 * Sign the hash using EC key and return DER encoded signature in sig,
 * its length in siglen. Return value is 1 on success, 0 on error.
 */
static int
ecdsa_sign(int type, const unsigned char *dgst, int dgstlen, unsigned char *sig,
           unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r, EC_KEY *ec)
{
    int capacity = ECDSA_size(ec);
    /*
     * ECDSA does not seem to have proper constants for paddings since
     * there are only signatures without padding at the moment, use
     * a generic ECDSA for the moment
     */
    int len = get_sig_from_man(dgst, dgstlen, sig, capacity, "ECDSA");

    if (len > 0)
    {
        *siglen = len;
        return 1;
    }
    return 0;
}

/* EC_KEY_METHOD callback: sign_setup(). We do no precomputations */
static int
ecdsa_sign_setup(EC_KEY *ec, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp)
{
    return 1;
}

/* EC_KEY_METHOD callback: sign_sig().
 * Sign the hash and return the result as a newly allocated ECDS_SIG
 * struct or NULL on error.
 */
static ECDSA_SIG *
ecdsa_sign_sig(const unsigned char *dgst, int dgstlen, const BIGNUM *in_kinv,
               const BIGNUM *in_r, EC_KEY *ec)
{
    ECDSA_SIG *ecsig = NULL;
    unsigned int len = ECDSA_size(ec);
    struct gc_arena gc = gc_new();

    unsigned char *buf = gc_malloc(len, false, &gc);
    if (ecdsa_sign(0, dgst, dgstlen, buf, &len, NULL, NULL, ec) != 1)
    {
        goto out;
    }
    /* const char ** should be avoided: not up to us, so we cast our way through */
    ecsig = d2i_ECDSA_SIG(NULL, (const unsigned char **)&buf, len);

out:
    gc_free(&gc);
    return ecsig;
}

static int
tls_ctx_use_external_ec_key(struct tls_root_ctx *ctx, EVP_PKEY *pkey)
{
    EC_KEY *ec = NULL;
    EVP_PKEY *privkey = NULL;
    EC_KEY_METHOD *ec_method;

    ASSERT(ctx);

    ec_method = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
    if (!ec_method)
    {
        goto err;
    }

    /* Among init methods, we only need the finish method */
    EC_KEY_METHOD_set_init(ec_method, NULL, openvpn_extkey_ec_finish, NULL, NULL, NULL, NULL);
    EC_KEY_METHOD_set_sign(ec_method, ecdsa_sign, ecdsa_sign_setup, ecdsa_sign_sig);

    ec = EC_KEY_dup(EVP_PKEY_get0_EC_KEY(pkey));
    if (!ec)
    {
        EC_KEY_METHOD_free(ec_method);
        goto err;
    }
    if (!EC_KEY_set_method(ec, ec_method))
    {
        EC_KEY_METHOD_free(ec_method);
        goto err;
    }
    /* from this point ec_method will get freed when ec is freed */

    privkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(privkey, ec))
    {
        goto err;
    }
    /* from this point ec will get freed when privkey is freed */

    if (!SSL_CTX_use_PrivateKey(ctx->ctx, privkey))
    {
        ec = NULL; /* avoid double freeing it below */
        goto err;
    }

    EVP_PKEY_free(privkey); /* this will down ref privkey and ec */
    return 1;

err:
    /* Reach here only when ec and privkey can be independenly freed */
    EVP_PKEY_free(privkey);
    EC_KEY_free(ec);
    return 0;
}
#endif /* OPENSSL_VERSION_NUMBER > 1.1.0 dev && !defined(OPENSSL_NO_EC) */
#endif /* ENABLE_MANAGEMENT && !HAVE_XKEY_PROVIDER */

#ifdef ENABLE_MANAGEMENT
int
tls_ctx_use_management_external_key(struct tls_root_ctx *ctx)
{
    int ret = 1;

    ASSERT(NULL != ctx);

    X509 *cert = SSL_CTX_get0_certificate(ctx->ctx);

    ASSERT(NULL != cert);

    /* get the public key */
    EVP_PKEY *pkey = X509_get0_pubkey(cert);
    ASSERT(pkey); /* NULL before SSL_CTX_use_certificate() is called */

#ifdef HAVE_XKEY_PROVIDER
    EVP_PKEY *privkey = xkey_load_management_key(tls_libctx, pkey);
    if (!privkey
        || !SSL_CTX_use_PrivateKey(ctx->ctx, privkey))
    {
        EVP_PKEY_free(privkey);
        goto cleanup;
    }
    EVP_PKEY_free(privkey);
#else  /* ifdef HAVE_XKEY_PROVIDER */
    if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA)
    {
        if (!tls_ctx_use_external_rsa_key(ctx, pkey))
        {
            goto cleanup;
        }
    }
#if (OPENSSL_VERSION_NUMBER > 0x10100000L) && !defined(OPENSSL_NO_EC)
    else if (EVP_PKEY_id(pkey) == EVP_PKEY_EC)
    {
        if (!tls_ctx_use_external_ec_key(ctx, pkey))
        {
            goto cleanup;
        }
    }
    else
    {
        crypto_msg(M_WARN, "management-external-key requires an RSA or EC certificate");
        goto cleanup;
    }
#else  /* OPENSSL_VERSION_NUMBER > 1.1.0 dev && !defined(OPENSSL_NO_EC) */
    else
    {
        crypto_msg(M_WARN, "management-external-key requires an RSA certificate");
        goto cleanup;
    }
#endif /* OPENSSL_VERSION_NUMBER > 1.1.0 dev && !defined(OPENSSL_NO_EC) */

#endif /* HAVE_XKEY_PROVIDER */

    ret = 0;
cleanup:
    if (ret)
    {
        crypto_msg(M_FATAL, "Cannot enable SSL external private key capability");
    }
    return ret;
}
#endif /* ifdef ENABLE_MANAGEMENT */

/*
 * Write to an OpenSSL BIO in non-blocking mode.
 */
static int
bio_write(BIO *bio, const uint8_t *data, int size, const char *desc)
{
    int i;
    int ret = 0;
    ASSERT(size >= 0);
    if (size)
    {
        /*
         * Free the L_TLS lock prior to calling BIO routines
         * so that foreground thread can still call
         * tls_pre_decrypt or tls_pre_encrypt,
         * allowing tunnel packet forwarding to continue.
         */
#ifdef BIO_DEBUG
        bio_debug_data("write", bio, data, size, desc);
#endif
        i = BIO_write(bio, data, size);

        if (i < 0)
        {
            if (BIO_should_retry(bio))
            {
            }
            else
            {
                crypto_msg(D_TLS_ERRORS, "TLS ERROR: BIO write %s error", desc);
                ret = -1;
                ERR_clear_error();
            }
        }
        else if (i != size)
        {
            crypto_msg(D_TLS_ERRORS, "TLS ERROR: BIO write %s incomplete %d/%d",
                       desc, i, size);
            ret = -1;
            ERR_clear_error();
        }
        else
        {                       /* successful write */
            dmsg(D_HANDSHAKE_VERBOSE, "BIO write %s %d bytes", desc, i);
            ret = 1;
        }
    }
    return ret;
}

/*
 * Inline functions for reading from and writing
 * to BIOs.
 */

static void
bio_write_post(const int status, struct buffer *buf)
{
    if (status == 1) /* success status return from bio_write? */
    {
        memset(BPTR(buf), 0, BLEN(buf));  /* erase data just written */
        buf->len = 0;
    }
}

/*
 * Read from an OpenSSL BIO in non-blocking mode.
 */
static int
bio_read(BIO *bio, struct buffer *buf, const char *desc)
{
    int i;
    int ret = 0;
    ASSERT(buf->len >= 0);
    if (buf->len)
    {
    }
    else
    {
        int len = buf_forward_capacity(buf);

        /*
         * BIO_read brackets most of the serious RSA
         * key negotiation number crunching.
         */
        i = BIO_read(bio, BPTR(buf), len);

        VALGRIND_MAKE_READABLE((void *) &i, sizeof(i));

#ifdef BIO_DEBUG
        bio_debug_data("read", bio, BPTR(buf), i, desc);
#endif
        if (i < 0)
        {
            if (BIO_should_retry(bio))
            {
            }
            else
            {
                crypto_msg(D_TLS_ERRORS, "TLS_ERROR: BIO read %s error", desc);
                buf->len = 0;
                ret = -1;
                ERR_clear_error();
            }
        }
        else if (!i)
        {
            buf->len = 0;
        }
        else
        {                       /* successful read */
            dmsg(D_HANDSHAKE_VERBOSE, "BIO read %s %d bytes", desc, i);
            buf->len = i;
            ret = 1;
            VALGRIND_MAKE_READABLE((void *) BPTR(buf), BLEN(buf));
        }
    }
    return ret;
}

void
key_state_ssl_init(struct key_state_ssl *ks_ssl, const struct tls_root_ctx *ssl_ctx, bool is_server, struct tls_session *session)
{
    ASSERT(NULL != ssl_ctx);
    ASSERT(ks_ssl);
    CLEAR(*ks_ssl);

    ks_ssl->ssl = SSL_new(ssl_ctx->ctx);
    if (!ks_ssl->ssl)
    {
        crypto_msg(M_FATAL, "SSL_new failed");
    }

    /* put session * in ssl object so we can access it
     * from verify callback*/
    SSL_set_ex_data(ks_ssl->ssl, mydata_index, session);

    ASSERT((ks_ssl->ssl_bio = BIO_new(BIO_f_ssl())));
    ASSERT((ks_ssl->ct_in = BIO_new(BIO_s_mem())));
    ASSERT((ks_ssl->ct_out = BIO_new(BIO_s_mem())));

#ifdef BIO_DEBUG
    bio_debug_oc("open ssl_bio", ks_ssl->ssl_bio);
    bio_debug_oc("open ct_in", ks_ssl->ct_in);
    bio_debug_oc("open ct_out", ks_ssl->ct_out);
#endif

    if (is_server)
    {
        SSL_set_accept_state(ks_ssl->ssl);
    }
    else
    {
        SSL_set_connect_state(ks_ssl->ssl);
    }

    //lichen
    SSL_set_bio(ks_ssl->ssl, ks_ssl->ct_in, ks_ssl->ct_out);
    BIO_set_ssl(ks_ssl->ssl_bio, ks_ssl->ssl, BIO_NOCLOSE);
}

void
key_state_ssl_free(struct key_state_ssl *ks_ssl)
{
    if (ks_ssl->ssl)
    {
#ifdef BIO_DEBUG
        bio_debug_oc("close ssl_bio", ks_ssl->ssl_bio);
        bio_debug_oc("close ct_in", ks_ssl->ct_in);
        bio_debug_oc("close ct_out", ks_ssl->ct_out);
#endif
        BIO_free_all(ks_ssl->ssl_bio);
        SSL_free(ks_ssl->ssl);
    }
}

int
key_state_write_plaintext(struct key_state_ssl *ks_ssl, struct buffer *buf)
{
    int ret = 0;
    perf_push(PERF_BIO_WRITE_PLAINTEXT);

    ASSERT(NULL != ks_ssl);

    ret = bio_write(ks_ssl->ssl_bio, BPTR(buf), BLEN(buf),
                    "tls_write_plaintext");
    bio_write_post(ret, buf);

    perf_pop();
    return ret;
}

int
key_state_write_plaintext_const(struct key_state_ssl *ks_ssl, const uint8_t *data, int len)
{
    int ret = 0;
    perf_push(PERF_BIO_WRITE_PLAINTEXT);

    ASSERT(NULL != ks_ssl);

    ret = bio_write(ks_ssl->ssl_bio, data, len, "tls_write_plaintext_const");

    perf_pop();
    return ret;
}

int
key_state_read_ciphertext(struct key_state_ssl *ks_ssl, struct buffer *buf)
{
    int ret = 0;
    perf_push(PERF_BIO_READ_CIPHERTEXT);

    ASSERT(NULL != ks_ssl);

    ret = bio_read(ks_ssl->ct_out, buf, "tls_read_ciphertext");

    perf_pop();
    return ret;
}

int
key_state_write_ciphertext(struct key_state_ssl *ks_ssl, struct buffer *buf)
{
    int ret = 0;
    perf_push(PERF_BIO_WRITE_CIPHERTEXT);

    ASSERT(NULL != ks_ssl);

    ret = bio_write(ks_ssl->ct_in, BPTR(buf), BLEN(buf), "tls_write_ciphertext");
    bio_write_post(ret, buf);

    perf_pop();
    return ret;
}



//tls_multi_init() : tls_multi->tls_options
//tls_multi->tls_options
//tls_multi->tls_session->key[0]->ks_ssl->ssl_bio
int
key_state_read_plaintext(struct key_state_ssl *ks_ssl, struct buffer *buf)
{
    int ret = 0;
    perf_push(PERF_BIO_READ_PLAINTEXT);

    ASSERT(NULL != ks_ssl);

    ret = bio_read(ks_ssl->ssl_bio, buf, "tls_read_plaintext");

    perf_pop();
    return ret;
}

const char *
get_ssl_library_version(void)
{
    return "OpenSSL_version(OPENSSL_VERSION)";
}


/**
 * Setup ovpn.xey provider for signing with external keys.
 * It is loaded into a custom library context so as not to pollute
 * the default context. Alternatively we could override any
 * system-wide property query set on the default context. But we
 * want to avoid that.
 */
void
load_xkey_provider(void)
{
#ifdef HAVE_XKEY_PROVIDER

    /* Make a new library context for use in TLS context */
    if (!tls_libctx)
    {
        tls_libctx = OSSL_LIB_CTX_new();
        check_malloc_return(tls_libctx);

        /* Load all providers in default LIBCTX into this libctx.
         * OpenSSL has a child libctx functionality to automate this,
         * but currently that is usable only from within providers.
         * So we do something close to it manually here.
         */
        OSSL_PROVIDER_do_all(NULL, provider_load, tls_libctx);
    }

    if (!OSSL_PROVIDER_available(tls_libctx, "ovpn.xkey"))
    {
        OSSL_PROVIDER_add_builtin(tls_libctx, "ovpn.xkey", xkey_provider_init);
        if (!OSSL_PROVIDER_load(tls_libctx, "ovpn.xkey"))
        {
            msg(M_NONFATAL, "ERROR: failed loading external key provider: "
                "Signing with external keys will not work.");
        }
    }

    /* We only implement minimal functionality in ovpn.xkey, so we do not want
     * methods in xkey to be picked unless absolutely required (i.e, when the key
     * is external). Ensure this by setting a default propquery for the custom
     * libctx that unprefers, but does not forbid, ovpn.xkey. See also man page
     * of "property" in OpenSSL 3.0.
     */
    EVP_set_default_properties(tls_libctx, "?provider!=ovpn.xkey");

#endif /* HAVE_XKEY_PROVIDER */
}

/**
 * Undo steps in load_xkey_provider
 */
static void
unload_xkey_provider(void)
{
#ifdef HAVE_XKEY_PROVIDER
    if (tls_libctx)
    {
        OSSL_PROVIDER_do_all(tls_libctx, provider_unload, NULL);
        OSSL_LIB_CTX_free(tls_libctx);
    }
#endif /* HAVE_XKEY_PROVIDER */
    tls_libctx = NULL;
}

#endif /* defined(ENABLE_CRYPTO_OPENSSL) */
