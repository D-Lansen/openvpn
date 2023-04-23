/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../../include/openssl/err.h"
#include "../../include/openssl/asyncerr.h"
#include "../../include/crypto/asyncerr.h"

#ifndef OPENSSL_NO_ERR

static const ERR_STRING_DATA ASYNC_str_reasons[] = {
    {ERR_PACK(ERR_LIB_ASYNC, 0, ASYNC_R_FAILED_TO_SET_POOL),
    "failed to set pool"},
    {ERR_PACK(ERR_LIB_ASYNC, 0, ASYNC_R_FAILED_TO_SWAP_CONTEXT),
    "failed to swap context"},
    {ERR_PACK(ERR_LIB_ASYNC, 0, ASYNC_R_INIT_FAILED), "init failed"},
    {ERR_PACK(ERR_LIB_ASYNC, 0, ASYNC_R_INVALID_POOL_SIZE),
    "invalid pool size"},
    {0, NULL}
};

#endif

int ossl_err_load_ASYNC_strings(void)
{
#ifndef OPENSSL_NO_ERR
    if (ERR_reason_error_string(ASYNC_str_reasons[0].error) == NULL)
        ERR_load_strings_const(ASYNC_str_reasons);
#endif
    return 1;
}
