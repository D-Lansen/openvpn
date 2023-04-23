/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "../../include/openssl/err.h"
#include "../../include/crypto/err.h"
#include "../../include/crypto/cryptoerr.h"
#include "../../include/crypto/asn1err.h"
#include "../../include/crypto/bnerr.h"
#include "../../include/crypto/ecerr.h"
#include "../../include/crypto/buffererr.h"
#include "../../include/crypto/bioerr.h"
#include "../../include/crypto/comperr.h"
#include "../../include/crypto/rsaerr.h"
#include "../../include/crypto/dherr.h"
#include "../../include/crypto/dsaerr.h"
#include "../../include/crypto/evperr.h"
#include "../../include/crypto/objectserr.h"
#include "../../include/crypto/pemerr.h"
#include "../../include/crypto/pkcs7err.h"
#include "../../include/crypto/x509err.h"
#include "../../include/crypto/x509v3err.h"
#include "../../include/crypto/conferr.h"
#include "../../include/crypto/pkcs12err.h"
#include "../../include/crypto/randerr.h"
#include "../../include/internal/dsoerr.h"
#include "../../include/crypto/engineerr.h"
#include "../../include/crypto/uierr.h"
#include "../../include/crypto/httperr.h"
#include "../../include/crypto/ocsperr.h"
#include "../../include/crypto/tserr.h"
#include "../../include/crypto/cmserr.h"
#include "../../include/crypto/crmferr.h"
#include "../../include/crypto/cmperr.h"
#include "../../include/crypto/cterr.h"
#include "../../include/crypto/asyncerr.h"
#include "../../include/crypto/storeerr.h"
#include "../../include/crypto/esserr.h"
#include "../../include/internal/propertyerr.h"
#include "../../providers/common/include/prov/proverr.h"

int ossl_err_load_crypto_strings(void)
{
    if (0
#ifndef OPENSSL_NO_ERR
        || ossl_err_load_ERR_strings() == 0 /* include error strings for SYSerr */
        || ossl_err_load_BN_strings() == 0
        || ossl_err_load_RSA_strings() == 0
# ifndef OPENSSL_NO_DH
        || ossl_err_load_DH_strings() == 0
# endif
        || ossl_err_load_EVP_strings() == 0
        || ossl_err_load_BUF_strings() == 0
        || ossl_err_load_OBJ_strings() == 0
        || ossl_err_load_PEM_strings() == 0
# ifndef OPENSSL_NO_DSA
        || ossl_err_load_DSA_strings() == 0
# endif
        || ossl_err_load_X509_strings() == 0
        || ossl_err_load_ASN1_strings() == 0
        || ossl_err_load_CONF_strings() == 0
        || ossl_err_load_CRYPTO_strings() == 0
# ifndef OPENSSL_NO_COMP
        || ossl_err_load_COMP_strings() == 0
# endif
# ifndef OPENSSL_NO_EC
        || ossl_err_load_EC_strings() == 0
# endif
        /* skip ossl_err_load_SSL_strings() because it is not in this library */
        || ossl_err_load_BIO_strings() == 0
        || ossl_err_load_PKCS7_strings() == 0
        || ossl_err_load_X509V3_strings() == 0
        || ossl_err_load_PKCS12_strings() == 0
        || ossl_err_load_RAND_strings() == 0
        || ossl_err_load_DSO_strings() == 0
# ifndef OPENSSL_NO_TS
        || ossl_err_load_TS_strings() == 0
# endif
# ifndef OPENSSL_NO_ENGINE
        || ossl_err_load_ENGINE_strings() == 0
# endif
        || ossl_err_load_HTTP_strings() == 0
# ifndef OPENSSL_NO_OCSP
        || ossl_err_load_OCSP_strings() == 0
# endif
        || ossl_err_load_UI_strings() == 0
# ifndef OPENSSL_NO_CMS
        || ossl_err_load_CMS_strings() == 0
# endif
# ifndef OPENSSL_NO_CRMF
        || ossl_err_load_CRMF_strings() == 0
        || ossl_err_load_CMP_strings() == 0
# endif
# ifndef OPENSSL_NO_CT
        || ossl_err_load_CT_strings() == 0
# endif
        || ossl_err_load_ESS_strings() == 0
        || ossl_err_load_ASYNC_strings() == 0
        || ossl_err_load_OSSL_STORE_strings() == 0
        || ossl_err_load_PROP_strings() == 0
        || ossl_err_load_PROV_strings() == 0
#endif
        )
        return 0;

    return 1;
}
