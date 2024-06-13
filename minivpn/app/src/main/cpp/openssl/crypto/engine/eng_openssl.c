/*
 * Copyright 2001-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* We need to use some engine deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

/*
 * RC4 and SHA-1 low level APIs and EVP _meth_ APISs are deprecated for public
 * use, but still ok for internal use.
 */
#include "internal/deprecated.h"

#include <stdio.h>
#include <openssl/crypto.h>
#include "internal/cryptlib.h"
#include "crypto/engine.h"
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>

#include <openssl/hmac.h>
#include <openssl/x509v3.h>

/*
 * This testing gunk is implemented (and explained) lower down. It also
 * assumes the application explicitly calls "ENGINE_load_openssl()" because
 * this is no longer automatic in ENGINE_load_builtin_engines().
 */
#define TEST_ENG_OPENSSL_RC4
#ifndef OPENSSL_NO_STDIO
# define TEST_ENG_OPENSSL_PKEY
#endif
/* #define TEST_ENG_OPENSSL_HMAC */
/* #define TEST_ENG_OPENSSL_HMAC_INIT */
/* #define TEST_ENG_OPENSSL_RC4_OTHERS */
#ifndef OPENSSL_NO_STDIO
# define TEST_ENG_OPENSSL_RC4_P_INIT
#endif
/* #define TEST_ENG_OPENSSL_RC4_P_CIPHER */
#define TEST_ENG_OPENSSL_SHA
/* #define TEST_ENG_OPENSSL_SHA_OTHERS */
/* #define TEST_ENG_OPENSSL_SHA_P_INIT */
/* #define TEST_ENG_OPENSSL_SHA_P_UPDATE */
/* #define TEST_ENG_OPENSSL_SHA_P_FINAL */

/* Now check what of those algorithms are actually enabled */
#ifdef OPENSSL_NO_RC4
# undef TEST_ENG_OPENSSL_RC4
# undef TEST_ENG_OPENSSL_RC4_OTHERS
# undef TEST_ENG_OPENSSL_RC4_P_INIT
# undef TEST_ENG_OPENSSL_RC4_P_CIPHER
#endif

static int openssl_destroy(ENGINE *e);

#ifdef TEST_ENG_OPENSSL_RC4
static int openssl_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                           const int **nids, int nid);
#endif
#ifdef TEST_ENG_OPENSSL_SHA
static int openssl_digests(ENGINE *e, const EVP_MD **digest,
                           const int **nids, int nid);
#endif

#ifdef TEST_ENG_OPENSSL_PKEY
static EVP_PKEY *openssl_load_privkey(ENGINE *eng, const char *key_id,
                                      UI_METHOD *ui_method,
                                      void *callback_data);
#endif

#ifdef TEST_ENG_OPENSSL_HMAC
static int ossl_register_hmac_meth(void);
static int ossl_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                           const int **nids, int nid);
#endif

/* The constants used when creating the ENGINE */
static const char *engine_openssl_id = "openssl";
static const char *engine_openssl_name = "Software engine support";

/*
 * This internal function is used by ENGINE_openssl() and possibly by the
 * "dynamic" ENGINE support too
 */
static int bind_helper(ENGINE *e)
{
    if (!ENGINE_set_id(e, engine_openssl_id)
        || !ENGINE_set_name(e, engine_openssl_name)
        || !ENGINE_set_destroy_function(e, openssl_destroy)
#ifndef TEST_ENG_OPENSSL_NO_ALGORITHMS
        || !ENGINE_set_RSA(e, RSA_get_default_method())
# ifndef OPENSSL_NO_DSA
        || !ENGINE_set_DSA(e, DSA_get_default_method())
# endif
# ifndef OPENSSL_NO_EC
        || !ENGINE_set_EC(e, EC_KEY_OpenSSL())
# endif
# ifndef OPENSSL_NO_DH
        || !ENGINE_set_DH(e, DH_get_default_method())
# endif
        || !ENGINE_set_RAND(e, RAND_OpenSSL())
# ifdef TEST_ENG_OPENSSL_RC4
        || !ENGINE_set_ciphers(e, openssl_ciphers)
# endif
# ifdef TEST_ENG_OPENSSL_SHA
        || !ENGINE_set_digests(e, openssl_digests)
# endif
#endif
#ifdef TEST_ENG_OPENSSL_PKEY
        || !ENGINE_set_load_privkey_function(e, openssl_load_privkey)
#endif
#ifdef TEST_ENG_OPENSSL_HMAC
        || !ossl_register_hmac_meth()
        || !ENGINE_set_pkey_meths(e, ossl_pkey_meths)
#endif
        )
        return 0;
    /*
     * If we add errors to this ENGINE, ensure the error handling is setup
     * here
     */
    /* openssl_load_error_strings(); */
    return 1;
}

static ENGINE *engine_openssl(void)
{
    ENGINE *ret = ENGINE_new();
    if (ret == NULL)
        return NULL;
    if (!bind_helper(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void engine_load_openssl_int(void)
{
    ENGINE *toadd = engine_openssl();
    if (!toadd)
        return;

    ERR_set_mark();
    ENGINE_add(toadd);
    /*
     * If the "add" worked, it gets a structural reference. So either way, we
     * release our just-created reference.
     */
    ENGINE_free(toadd);
    /*
     * If the "add" didn't work, it was probably a conflict because it was
     * already added (eg. someone calling ENGINE_load_blah then calling
     * ENGINE_load_builtin_engines() perhaps).
     */
    ERR_pop_to_mark();
}

/*
 * This stuff is needed if this ENGINE is being compiled into a
 * self-contained shared-library.
 */
#ifdef ENGINE_DYNAMIC_SUPPORT
static int bind_fn(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_openssl_id) != 0))
        return 0;
    if (!bind_helper(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
#endif                          /* ENGINE_DYNAMIC_SUPPORT */
#ifdef TEST_ENG_OPENSSL_RC4
/*-
 * This section of code compiles an "alternative implementation" of two modes of
 * RC4 into this ENGINE. The result is that EVP_CIPHER operation for "rc4"
 * should under normal circumstances go via this support rather than the default
 * EVP support. There are other symbols to tweak the testing;
 *    TEST_ENC_OPENSSL_RC4_OTHERS - print a one line message to stderr each time
 *        we're asked for a cipher we don't support (should not happen).
 *    TEST_ENG_OPENSSL_RC4_P_INIT - print a one line message to stderr each time
 *        the "init_key" handler is called.
 *    TEST_ENG_OPENSSL_RC4_P_CIPHER - ditto for the "cipher" handler.
 */
# include <openssl/rc4.h>
# define TEST_RC4_KEY_SIZE               16
typedef struct {
    unsigned char key[TEST_RC4_KEY_SIZE];
    RC4_KEY ks;
} TEST_RC4_KEY;
# define test(ctx) ((TEST_RC4_KEY *)EVP_CIPHER_CTX_get_cipher_data(ctx))
static int test_rc4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    const int n = EVP_CIPHER_CTX_get_key_length(ctx);

# ifdef TEST_ENG_OPENSSL_RC4_P_INIT
    fprintf(stderr, "(TEST_ENG_OPENSSL_RC4) test_init_key() called\n");
# endif
    if (n <= 0)
        return n;
    memcpy(&test(ctx)->key[0], key, n);
    RC4_set_key(&test(ctx)->ks, n, test(ctx)->key);
    return 1;
}

static int test_rc4_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t inl)
{
# ifdef TEST_ENG_OPENSSL_RC4_P_CIPHER
    fprintf(stderr, "(TEST_ENG_OPENSSL_RC4) test_cipher() called\n");
# endif
    RC4(&test(ctx)->ks, inl, in, out);
    return 1;
}

static EVP_CIPHER *r4_cipher = NULL;
static const EVP_CIPHER *test_r4_cipher(void)
{
    if (r4_cipher == NULL) {
        EVP_CIPHER *cipher;

        if ((cipher = EVP_CIPHER_meth_new(NID_rc4, 1, TEST_RC4_KEY_SIZE)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(cipher, 0)
            || !EVP_CIPHER_meth_set_flags(cipher, EVP_CIPH_VARIABLE_LENGTH)
            || !EVP_CIPHER_meth_set_init(cipher, test_rc4_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(cipher, test_rc4_cipher)
            || !EVP_CIPHER_meth_set_impl_ctx_size(cipher, sizeof(TEST_RC4_KEY))) {
            EVP_CIPHER_meth_free(cipher);
            cipher = NULL;
        }
        r4_cipher = cipher;
    }
    return r4_cipher;
}
static void test_r4_cipher_destroy(void)
{
    EVP_CIPHER_meth_free(r4_cipher);
    r4_cipher = NULL;
}

static EVP_CIPHER *r4_40_cipher = NULL;
static const EVP_CIPHER *test_r4_40_cipher(void)
{
    if (r4_40_cipher == NULL) {
        EVP_CIPHER *cipher;

        if ((cipher = EVP_CIPHER_meth_new(NID_rc4, 1, 5 /* 40 bits */)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(cipher, 0)
            || !EVP_CIPHER_meth_set_flags(cipher, EVP_CIPH_VARIABLE_LENGTH)
            || !EVP_CIPHER_meth_set_init(cipher, test_rc4_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(cipher, test_rc4_cipher)
            || !EVP_CIPHER_meth_set_impl_ctx_size(cipher, sizeof(TEST_RC4_KEY))) {
            EVP_CIPHER_meth_free(cipher);
            cipher = NULL;
        }
        r4_40_cipher = cipher;
    }
    return r4_40_cipher;
}
static void test_r4_40_cipher_destroy(void)
{
    EVP_CIPHER_meth_free(r4_40_cipher);
    r4_40_cipher = NULL;
}
static int test_cipher_nids(const int **nids)
{
    static int cipher_nids[4] = { 0, 0, 0, 0 };
    static int pos = 0;
    static int init = 0;

    if (!init) {
        const EVP_CIPHER *cipher;
        if ((cipher = test_r4_cipher()) != NULL)
            cipher_nids[pos++] = EVP_CIPHER_get_nid(cipher);
        if ((cipher = test_r4_40_cipher()) != NULL)
            cipher_nids[pos++] = EVP_CIPHER_get_nid(cipher);
        cipher_nids[pos] = 0;
        init = 1;
    }
    *nids = cipher_nids;
    return pos;
}

static int openssl_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                           const int **nids, int nid)
{
    if (!cipher) {
        /* We are returning a list of supported nids */
        return test_cipher_nids(nids);
    }
    /* We are being asked for a specific cipher */
    if (nid == NID_rc4)
        *cipher = test_r4_cipher();
    else if (nid == NID_rc4_40)
        *cipher = test_r4_40_cipher();
    else {
# ifdef TEST_ENG_OPENSSL_RC4_OTHERS
        fprintf(stderr, "(TEST_ENG_OPENSSL_RC4) returning NULL for "
                "nid %d\n", nid);
# endif
        *cipher = NULL;
        return 0;
    }
    return 1;
}
#endif

#ifdef TEST_ENG_OPENSSL_SHA
/* Much the same sort of comment as for TEST_ENG_OPENSSL_RC4 */
# include <openssl/sha.h>

static int test_sha1_init(EVP_MD_CTX *ctx)
{
# ifdef TEST_ENG_OPENSSL_SHA_P_INIT
    fprintf(stderr, "(TEST_ENG_OPENSSL_SHA) test_sha1_init() called\n");
# endif
    return SHA1_Init(EVP_MD_CTX_get0_md_data(ctx));
}

static int test_sha1_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
# ifdef TEST_ENG_OPENSSL_SHA_P_UPDATE
    fprintf(stderr, "(TEST_ENG_OPENSSL_SHA) test_sha1_update() called\n");
# endif
    return SHA1_Update(EVP_MD_CTX_get0_md_data(ctx), data, count);
}

static int test_sha1_final(EVP_MD_CTX *ctx, unsigned char *md)
{
# ifdef TEST_ENG_OPENSSL_SHA_P_FINAL
    fprintf(stderr, "(TEST_ENG_OPENSSL_SHA) test_sha1_final() called\n");
# endif
    return SHA1_Final(md, EVP_MD_CTX_get0_md_data(ctx));
}

static EVP_MD *sha1_md = NULL;
static const EVP_MD *test_sha_md(void)
{
    if (sha1_md == NULL) {
        EVP_MD *md;

        if ((md = EVP_MD_meth_new(NID_sha1, NID_sha1WithRSAEncryption)) == NULL
            || !EVP_MD_meth_set_result_size(md, SHA_DIGEST_LENGTH)
            || !EVP_MD_meth_set_input_blocksize(md, SHA_CBLOCK)
            || !EVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVP_MD *) + sizeof(SHA_CTX))
            || !EVP_MD_meth_set_flags(md, 0)
            || !EVP_MD_meth_set_init(md, test_sha1_init)
            || !EVP_MD_meth_set_update(md, test_sha1_update)
            || !EVP_MD_meth_set_final(md, test_sha1_final)) {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        sha1_md = md;
    }
    return sha1_md;
}
static void test_sha_md_destroy(void)
{
    EVP_MD_meth_free(sha1_md);
    sha1_md = NULL;
}
static int test_digest_nids(const int **nids)
{
    static int digest_nids[2] = { 0, 0 };
    static int pos = 0;
    static int init = 0;

    if (!init) {
        const EVP_MD *md;
        if ((md = test_sha_md()) != NULL)
            digest_nids[pos++] = EVP_MD_get_type(md);
        digest_nids[pos] = 0;
        init = 1;
    }
    *nids = digest_nids;
    return pos;
}

static int openssl_digests(ENGINE *e, const EVP_MD **digest,
                           const int **nids, int nid)
{
    if (!digest) {
        /* We are returning a list of supported nids */
        return test_digest_nids(nids);
    }
    /* We are being asked for a specific digest */
    if (nid == NID_sha1)
        *digest = test_sha_md();
    else {
# ifdef TEST_ENG_OPENSSL_SHA_OTHERS
        fprintf(stderr, "(TEST_ENG_OPENSSL_SHA) returning NULL for "
                "nid %d\n", nid);
# endif
        *digest = NULL;
        return 0;
    }
    return 1;
}
#endif

#ifdef TEST_ENG_OPENSSL_PKEY
static EVP_PKEY *openssl_load_privkey(ENGINE *eng, const char *key_id,
                                      UI_METHOD *ui_method,
                                      void *callback_data)
{
    BIO *in;
    EVP_PKEY *key;
    fprintf(stderr, "(TEST_ENG_OPENSSL_PKEY)Loading Private key %s\n",
            key_id);
    in = BIO_new_file(key_id, "r");
    if (!in)
        return NULL;
    key = PEM_read_bio_PrivateKey(in, NULL, 0, NULL);
    BIO_free(in);
    return key;
}
#endif



int openssl_destroy(ENGINE *e)
{
    test_sha_md_destroy();
#ifdef TEST_ENG_OPENSSL_RC4
    test_r4_cipher_destroy();
    test_r4_40_cipher_destroy();
#endif
    return 1;
}

