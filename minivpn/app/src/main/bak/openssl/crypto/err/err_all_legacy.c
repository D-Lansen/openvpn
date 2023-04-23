/*
 * Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* This is the C source file where we include this header directly */
#include "../../include/openssl/cryptoerr_legacy.h"

#ifndef OPENSSL_NO_DEPRECATED_3_0

# include "../../include/crypto/err.h"
# include "../../include/crypto/asn1err.h"
# include "../../include/crypto/asyncerr.h"
# include "../../include/crypto/bnerr.h"
# include "../../include/crypto/buffererr.h"
# include "../../include/crypto/bioerr.h"
# include "../../include/crypto/cmserr.h"
# include "../../include/crypto/comperr.h"
# include "../../include/crypto/conferr.h"
# include "../../include/crypto/cryptoerr.h"
# include "../../include/crypto/cterr.h"
# include "../../include/crypto/dherr.h"
# include "../../include/crypto/dsaerr.h"
# include "../../include/internal/dsoerr.h"
# include "../../include/crypto/ecerr.h"
# include "../../include/crypto/engineerr.h"
# include "../../include/crypto/evperr.h"
# include "../../include/crypto/httperr.h"
# include "../../include/crypto/objectserr.h"
# include "../../include/crypto/ocsperr.h"
# include "../../include/crypto/pemerr.h"
# include "../../include/crypto/pkcs12err.h"
# include "../../include/crypto/pkcs7err.h"
# include "../../include/crypto/randerr.h"
# include "../../include/crypto/rsaerr.h"
# include "../../include/crypto/storeerr.h"
# include "../../include/crypto/tserr.h"
# include "../../include/crypto/uierr.h"
# include "../../include/crypto/x509err.h"
# include "../../include/crypto/x509v3err.h"

# ifdef OPENSSL_NO_ERR
#  define IMPLEMENT_LEGACY_ERR_LOAD(lib)        \
    int ERR_load_##lib##_strings(void)          \
    {                                           \
        return 1;                               \
    }
# else
#  define IMPLEMENT_LEGACY_ERR_LOAD(lib)        \
    int ERR_load_##lib##_strings(void)          \
    {                                           \
        return ossl_err_load_##lib##_strings(); \
    }
# endif

IMPLEMENT_LEGACY_ERR_LOAD(ASN1)
IMPLEMENT_LEGACY_ERR_LOAD(ASYNC)
IMPLEMENT_LEGACY_ERR_LOAD(BIO)
IMPLEMENT_LEGACY_ERR_LOAD(BN)
IMPLEMENT_LEGACY_ERR_LOAD(BUF)
# ifndef OPENSSL_NO_CMS
IMPLEMENT_LEGACY_ERR_LOAD(CMS)
# endif
# ifndef OPENSSL_NO_COMP
IMPLEMENT_LEGACY_ERR_LOAD(COMP)
# endif
IMPLEMENT_LEGACY_ERR_LOAD(CONF)
IMPLEMENT_LEGACY_ERR_LOAD(CRYPTO)
# ifndef OPENSSL_NO_CT
IMPLEMENT_LEGACY_ERR_LOAD(CT)
# endif
# ifndef OPENSSL_NO_DH
IMPLEMENT_LEGACY_ERR_LOAD(DH)
# endif
# ifndef OPENSSL_NO_DSA
IMPLEMENT_LEGACY_ERR_LOAD(DSA)
# endif
# ifndef OPENSSL_NO_EC
IMPLEMENT_LEGACY_ERR_LOAD(EC)
# endif
# ifndef OPENSSL_NO_ENGINE
IMPLEMENT_LEGACY_ERR_LOAD(ENGINE)
# endif
IMPLEMENT_LEGACY_ERR_LOAD(ERR)
IMPLEMENT_LEGACY_ERR_LOAD(EVP)
IMPLEMENT_LEGACY_ERR_LOAD(OBJ)
# ifndef OPENSSL_NO_OCSP
IMPLEMENT_LEGACY_ERR_LOAD(OCSP)
# endif
IMPLEMENT_LEGACY_ERR_LOAD(PEM)
IMPLEMENT_LEGACY_ERR_LOAD(PKCS12)
IMPLEMENT_LEGACY_ERR_LOAD(PKCS7)
IMPLEMENT_LEGACY_ERR_LOAD(RAND)
IMPLEMENT_LEGACY_ERR_LOAD(RSA)
IMPLEMENT_LEGACY_ERR_LOAD(OSSL_STORE)
# ifndef OPENSSL_NO_TS
IMPLEMENT_LEGACY_ERR_LOAD(TS)
# endif
IMPLEMENT_LEGACY_ERR_LOAD(UI)
IMPLEMENT_LEGACY_ERR_LOAD(X509)
IMPLEMENT_LEGACY_ERR_LOAD(X509V3)
#endif /* OPENSSL_NO_DEPRECATED_3_0 */
