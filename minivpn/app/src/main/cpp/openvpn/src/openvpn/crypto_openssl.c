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
 * @file Data Channel Cryptography OpenSSL-specific backend interface
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_CRYPTO_OPENSSL)

#include "basic.h"
#include "buffer.h"
#include "integer.h"
#include "crypto.h"
#include "crypto_backend.h"
#include "openssl_compat.h"

#include <openssl/conf.h>
#include <openssl/des.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
#include <openssl/kdf.h>
#endif
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

#if defined(_WIN32) && defined(OPENSSL_NO_EC)
#error Windows build with OPENSSL_NO_EC: disabling EC key is not supported.
#endif

#ifdef _MSC_VER
/* mute ossl3 deprecation warnings treated as errors in msvc */
#pragma warning(disable: 4996)
#endif

/*
 * Check for key size creepage.
 */

#if MAX_CIPHER_KEY_LENGTH < EVP_MAX_KEY_LENGTH
#warning Some OpenSSL EVP ciphers now support key lengths greater than MAX_CIPHER_KEY_LENGTH -- consider increasing MAX_CIPHER_KEY_LENGTH
#endif

#if MAX_HMAC_KEY_LENGTH < EVP_MAX_MD_SIZE
#warning Some OpenSSL HMAC message digests now support key lengths greater than MAX_HMAC_KEY_LENGTH -- consider increasing MAX_HMAC_KEY_LENGTH
#endif

#if HAVE_OPENSSL_ENGINE
#include <openssl/ui.h>
#include <openssl/engine.h>

static bool engine_initialized = false; /* GLOBAL */

static ENGINE *engine_persist = NULL;   /* GLOBAL */

/* Try to load an engine in a shareable library */
static ENGINE *
try_load_engine(const char *engine)
{
    ENGINE *e = ENGINE_by_id("dynamic");
    if (e)
    {
        if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", engine, 0)
            || !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0))
        {
            ENGINE_free(e);
            e = NULL;
        }
    }
    return e;
}

static ENGINE *
setup_engine(const char *engine)
{
    ENGINE *e = NULL;

    ENGINE_load_builtin_engines();

    if (engine)
    {
        if (strcmp(engine, "auto") == 0)
        {
            msg(M_INFO, "Initializing OpenSSL auto engine support");
            ENGINE_register_all_complete();
            return NULL;
        }
        if ((e = ENGINE_by_id(engine)) == NULL
            && (e = try_load_engine(engine)) == NULL)
        {
            crypto_msg(M_FATAL, "OpenSSL error: cannot load engine '%s'",
                       engine);
        }

        if (!ENGINE_set_default(e, ENGINE_METHOD_ALL))
        {
            crypto_msg(M_FATAL,
                       "OpenSSL error: ENGINE_set_default failed on engine '%s'",
                       engine);
        }

        msg(M_INFO, "Initializing OpenSSL support for engine '%s'",
            ENGINE_get_id(e));
    }
    return e;
}

#endif /* HAVE_OPENSSL_ENGINE */

void
crypto_init_lib_engine(const char *engine_name)
{
#if HAVE_OPENSSL_ENGINE
    if (!engine_initialized)
    {
        ASSERT(engine_name);
        ASSERT(!engine_persist);
        engine_persist = setup_engine(engine_name);
        engine_initialized = true;
    }
#else  /* if HAVE_OPENSSL_ENGINE */
    msg(M_WARN, "Note: OpenSSL hardware crypto engine functionality is not available");
#endif
}

provider_t *
crypto_load_provider(const char *provider)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    /* Load providers into the default (NULL) library context */
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, provider);
    if (!prov)
    {
        crypto_msg(M_FATAL, "failed to load provider '%s'", provider);
    }
    return prov;
#else  /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
    msg(M_WARN, "Note: OpenSSL provider functionality is not available");
    return NULL;
#endif
}

void
crypto_unload_provider(const char *provname, provider_t *provider)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (!OSSL_PROVIDER_unload(provider))
    {
        crypto_msg(M_FATAL, "failed to unload provider '%s'", provname);
    }
#endif
}

/*
 *
 * Functions related to the core crypto library
 *
 */

void
crypto_init_lib(void)
{
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
#else
    OPENSSL_config(NULL);
#endif
    /*
     * If you build the OpenSSL library and OpenVPN with
     * CRYPTO_MDEBUG, you will get a listing of OpenSSL
     * memory leaks on program termination.
     */

#ifdef CRYPTO_MDEBUG
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
#endif
}

void
crypto_uninit_lib(void)
{
#ifdef CRYPTO_MDEBUG
    FILE *fp = fopen("sdlog", "w");
    ASSERT(fp);
    CRYPTO_mem_leaks_fp(fp);
    fclose(fp);
#endif

#if HAVE_OPENSSL_ENGINE
    if (engine_initialized)
    {
        ENGINE_cleanup();
        engine_persist = NULL;
        engine_initialized = false;
    }
#endif
}

void
crypto_print_openssl_errors(const unsigned int flags)
{
    unsigned long err = 0;

    while ((err = ERR_get_error()))
    {
        /* Be more clear about frequently occurring "no shared cipher" error */
        if (ERR_GET_REASON(err) == SSL_R_NO_SHARED_CIPHER)
        {
            msg(D_CRYPT_ERRORS, "TLS error: The server has no TLS ciphersuites "
                "in common with the client. Your --tls-cipher setting might be "
                "too restrictive.");
        }
        else if (ERR_GET_REASON(err) == SSL_R_UNSUPPORTED_PROTOCOL)
        {
            msg(D_CRYPT_ERRORS, "TLS error: Unsupported protocol. This typically "
                "indicates that client and server have no common TLS version enabled. "
                "This can be caused by mismatched tls-version-min and tls-version-max "
                "options on client and server. "
                "If your OpenVPN client is between v2.3.6 and v2.3.2 try adding "
                "tls-version-min 1.0 to the client configuration to use TLS 1.0+ "
                "instead of TLS 1.0 only");
        }
        msg(flags, "OpenSSL: %s", ERR_error_string(err, NULL));
    }
}


/*
 *
 * OpenSSL memory debugging.  If dmalloc debugging is enabled, tell
 * OpenSSL to use our private malloc/realloc/free functions so that
 * we can dispatch them to dmalloc.
 *
 */

#ifdef DMALLOC
static void *
crypto_malloc(size_t size, const char *file, int line)
{
    return dmalloc_malloc(file, line, size, DMALLOC_FUNC_MALLOC, 0, 0);
}

static void *
crypto_realloc(void *ptr, size_t size, const char *file, int line)
{
    return dmalloc_realloc(file, line, ptr, size, DMALLOC_FUNC_REALLOC, 0);
}

static void
crypto_free(void *ptr)
{
    dmalloc_free(__FILE__, __LINE__, ptr, DMALLOC_FUNC_FREE);
}

void
crypto_init_dmalloc(void)
{
    CRYPTO_set_mem_ex_functions(crypto_malloc,
                                crypto_realloc,
                                crypto_free);
}
#endif /* DMALLOC */

const cipher_name_pair cipher_name_translation_table[] = {
    { "AES-128-GCM", "id-aes128-GCM" },
    { "AES-192-GCM", "id-aes192-GCM" },
    { "AES-256-GCM", "id-aes256-GCM" },
    { "CHACHA20-POLY1305", "ChaCha20-Poly1305" },
};
const size_t cipher_name_translation_table_count =
    sizeof(cipher_name_translation_table) / sizeof(*cipher_name_translation_table);


int
rand_bytes(uint8_t *output, int len)
{
    if (unlikely(1 != RAND_bytes(output, len)))
    {
        crypto_msg(D_CRYPT_ERRORS, "RAND_bytes() failed");
        return 0;
    }
    return 1;
}


static evp_cipher_type *
cipher_get(const char *ciphername)
{
    ASSERT(ciphername);
    ciphername = translate_cipher_name_from_openvpn(ciphername);
    return EVP_CIPHER_fetch(NULL, ciphername, NULL);
}

bool
cipher_valid_reason(const char *ciphername, const char **reason)
{
    bool ret = false;
    evp_cipher_type *cipher = cipher_get(ciphername);
    if (!cipher)
    {
        crypto_msg(D_LOW, "Cipher algorithm '%s' not found", ciphername);
        *reason = "disabled because unknown";
        goto out;
    }

#ifdef OPENSSL_FIPS
    /* Rhel 8/CentOS 8 have a patched OpenSSL version that return a cipher
     * here that is actually not usable if in FIPS mode */

    if (FIPS_mode() && !(EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_FIPS))
    {
        msg(D_LOW, "Cipher algorithm '%s' is known by OpenSSL library but "
            "currently disabled by running in FIPS mode.", ciphername);
        *reason = "disabled by FIPS mode";
        goto out;
    }
#endif
    if (EVP_CIPHER_key_length(cipher) > MAX_CIPHER_KEY_LENGTH)
    {
        msg(D_LOW, "Cipher algorithm '%s' uses a default key size (%d bytes) "
            "which is larger than " PACKAGE_NAME "'s current maximum key size "
            "(%d bytes)", ciphername, EVP_CIPHER_key_length(cipher),
            MAX_CIPHER_KEY_LENGTH);
        *reason = "disabled due to key size too large";
        goto out;
    }

    ret = true;
    *reason = NULL;
out:
    EVP_CIPHER_free(cipher);
    return ret;
}

const char *
cipher_kt_name(const char *ciphername)
{
    ASSERT(ciphername);
    if (strcmp("none", ciphername) == 0)
    {
        return "[null-cipher]";
    }

    evp_cipher_type *cipher_kt = cipher_get(ciphername);
    if (!cipher_kt)
    {
        return NULL;
    }

    const char *name = EVP_CIPHER_name(cipher_kt);
    EVP_CIPHER_free(cipher_kt);
    return translate_cipher_name_to_openvpn(name);
}

int
cipher_kt_key_size(const char *ciphername)
{
    evp_cipher_type *cipher = cipher_get(ciphername);
    int size = EVP_CIPHER_key_length(cipher);
    EVP_CIPHER_free(cipher);
    return size;
}

int
cipher_kt_iv_size(const char *ciphername)
{
    evp_cipher_type *cipher = cipher_get(ciphername);
    int ivsize = EVP_CIPHER_iv_length(cipher);
    EVP_CIPHER_free(cipher);
    return ivsize;
}

int
cipher_kt_block_size(const char *ciphername)
{
    /*
     * OpenSSL reports OFB/CFB/GCM cipher block sizes as '1 byte'.  To work
     * around that, try to replace the mode with 'CBC' and return the block size
     * reported for that cipher, if possible.  If that doesn't work, just return
     * the value reported by OpenSSL.
     */
    char *name = NULL;
    char *mode_str = NULL;
    const char *orig_name = NULL;
    evp_cipher_type *cbc_cipher = NULL;
    evp_cipher_type *cipher = cipher_get(ciphername);
    if (!cipher)
    {
        return 0;
    }

    int block_size = EVP_CIPHER_block_size(cipher);

    orig_name = EVP_CIPHER_name(cipher);
    if (!orig_name)
    {
        goto cleanup;
    }

    name = string_alloc(translate_cipher_name_to_openvpn(orig_name), NULL);
    mode_str = strrchr(name, '-');
    if (!mode_str || strlen(mode_str) < 4)
    {
        goto cleanup;
    }

    strcpy(mode_str, "-CBC");

    cbc_cipher = EVP_CIPHER_fetch(NULL, translate_cipher_name_from_openvpn(name), NULL);
    if (cbc_cipher)
    {
        block_size = EVP_CIPHER_block_size(cbc_cipher);
    }

cleanup:
    EVP_CIPHER_free(cbc_cipher);
    EVP_CIPHER_free(cipher);
    free(name);
    return block_size;
}

int
cipher_kt_tag_size(const char *ciphername)
{
    if (cipher_kt_mode_aead(ciphername))
    {
        return OPENVPN_AEAD_TAG_LENGTH;
    }
    else
    {
        return 0;
    }
}

bool
cipher_kt_insecure(const char *ciphername)
{

    if (cipher_kt_block_size(ciphername) >= 128 / 8)
    {
        return false;
    }
#ifdef NID_chacha20_poly1305
    evp_cipher_type *cipher = cipher_get(ciphername);
    if (cipher)
    {
        bool ischachapoly = (EVP_CIPHER_nid(cipher) == NID_chacha20_poly1305);
        EVP_CIPHER_free(cipher);
        if (ischachapoly)
        {
            return false;
        }
    }
#endif
    return true;
}

int
cipher_kt_mode(const EVP_CIPHER *cipher_kt)
{
    ASSERT(NULL != cipher_kt);
    return EVP_CIPHER_mode(cipher_kt);
}

bool
cipher_kt_mode_cbc(const char *ciphername)
{
    evp_cipher_type *cipher = cipher_get(ciphername);

    bool ret = cipher && (cipher_kt_mode(cipher) == OPENVPN_MODE_CBC
                          /* Exclude AEAD cipher modes, they require a different API */
#ifdef EVP_CIPH_FLAG_CTS
                          && !(EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_CTS)
#endif
                          && !(EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER));
    EVP_CIPHER_free(cipher);

    //msg(M_INFO,"%s is cbc:  %s",ciphername,ret?"true":"false"); true

    return ret;
}

bool
cipher_kt_mode_ofb_cfb(const char *ciphername)
{
    return false;
}

bool
cipher_kt_mode_aead(const char *ciphername)
{
    bool isaead = false;

    evp_cipher_type *cipher = cipher_get(ciphername);
    if (cipher)
    {
        if (EVP_CIPHER_mode(cipher) == OPENVPN_MODE_GCM)
        {
            isaead = true;
        }

#ifdef NID_chacha20_poly1305
        if (EVP_CIPHER_nid(cipher) == NID_chacha20_poly1305)
        {
            isaead =  true;
        }
#endif
    }

    EVP_CIPHER_free(cipher);

    // return false
    return isaead;
}

/*
 *
 * Generic message digest information functions
 *
 */

static evp_md_type *
md_get(const char *digest)
{
    evp_md_type *md = NULL;
    ASSERT(digest);
    md = EVP_MD_fetch(NULL, digest, NULL);
    if (!md)
    {
        crypto_msg(M_FATAL, "Message hash algorithm '%s' not found", digest);
    }
    if (EVP_MD_size(md) > MAX_HMAC_KEY_LENGTH)
    {
        crypto_msg(M_FATAL, "Message hash algorithm '%s' uses a default hash "
                   "size (%d bytes) which is larger than " PACKAGE_NAME "'s current "
                   "maximum hash size (%d bytes)",
                   digest, EVP_MD_size(md), MAX_HMAC_KEY_LENGTH);
    }
    return md;
}


bool
md_valid(const char *digest)
{
    evp_md_type *md = EVP_MD_fetch(NULL, digest, NULL);
    bool valid = (md != NULL);
    EVP_MD_free(md);
    return valid;
}


/* Since we used the OpenSSL <=1.1 names as part of our OCC message, they
 * are now unfortunately part of our wire protocol.
 *
 * OpenSSL 3.0 will still accept the "old" names so we do not need to use
 * this translation table for forward lookup, only for returning the name
 * with md_kt_name() */
const cipher_name_pair digest_name_translation_table[] = {
    { "BLAKE2s256", "BLAKE2S-256"},
    { "BLAKE2b512", "BLAKE2B-512"},
    { "RIPEMD160", "RIPEMD-160" },
    { "SHA224", "SHA2-224"},
    { "SHA256", "SHA2-256"},
    { "SHA384", "SHA2-384"},
    { "SHA512", "SHA2-512"},
    { "SHA512-224", "SHA2-512/224"},
    { "SHA512-256", "SHA2-512/256"},
    { "SHAKE128", "SHAKE-128"},
    { "SHAKE256", "SHAKE-256"},
};
const size_t digest_name_translation_table_count =
    sizeof(digest_name_translation_table) / sizeof(*digest_name_translation_table);

const char *
md_kt_name(const char *mdname)
{
    if (!strcmp("none", mdname))
    {
        return "[null-digest]";
    }
    evp_md_type *kt = md_get(mdname);
    const char *name = EVP_MD_get0_name(kt);

    /* Search for a digest name translation */
    for (size_t i = 0; i < digest_name_translation_table_count; i++)
    {
        const cipher_name_pair *pair = &digest_name_translation_table[i];
        if (!strcmp(name, pair->lib_name))
        {
            name = pair->openvpn_name;
        }
    }

    EVP_MD_free(kt);
    return name;
}

unsigned char
md_kt_size(const char *mdname)
{
    if (!strcmp("none", mdname))
    {
        return 0;
    }
    evp_md_type *kt = md_get(mdname);
    unsigned char size =  (unsigned char)EVP_MD_size(kt);
    EVP_MD_free(kt);
    msg(M_INFO,"md_kt_size:%s:%d",mdname,size);
    return size;
}




#endif /* ENABLE_CRYPTO_OPENSSL */
