/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "../../include/internal/cryptlib.h"
#include "../../include/openssl/bio.h"
#include "../../include/openssl/evp.h"
#include "../../include/openssl/x509.h"
#include "../../include/openssl/pkcs7.h"
#include "../../include/openssl/pem.h"

IMPLEMENT_PEM_rw(X509_AUX, X509, PEM_STRING_X509_TRUSTED, X509_AUX)
