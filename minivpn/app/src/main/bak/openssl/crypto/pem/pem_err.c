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
#include "../../include/openssl/pemerr.h"
#include "../../include/crypto/pemerr.h"

#ifndef OPENSSL_NO_ERR

static const ERR_STRING_DATA PEM_str_reasons[] = {
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_BAD_BASE64_DECODE), "bad base64 decode"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_BAD_DECRYPT), "bad decrypt"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_BAD_END_LINE), "bad end line"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_BAD_IV_CHARS), "bad iv chars"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_BAD_MAGIC_NUMBER), "bad magic number"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_BAD_PASSWORD_READ), "bad password read"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_BAD_VERSION_NUMBER), "bad version number"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_BIO_WRITE_FAILURE), "bio write failure"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_CIPHER_IS_NULL), "cipher is null"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_ERROR_CONVERTING_PRIVATE_KEY),
    "error converting private key"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_EXPECTING_DSS_KEY_BLOB),
    "expecting dss key blob"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_EXPECTING_PRIVATE_KEY_BLOB),
    "expecting private key blob"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_EXPECTING_PUBLIC_KEY_BLOB),
    "expecting public key blob"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_EXPECTING_RSA_KEY_BLOB),
    "expecting rsa key blob"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_HEADER_TOO_LONG), "header too long"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_INCONSISTENT_HEADER),
    "inconsistent header"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_KEYBLOB_HEADER_PARSE_ERROR),
    "keyblob header parse error"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_KEYBLOB_TOO_SHORT), "keyblob too short"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_MISSING_DEK_IV), "missing dek iv"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_NOT_DEK_INFO), "not dek info"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_NOT_ENCRYPTED), "not encrypted"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_NOT_PROC_TYPE), "not proc type"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_NO_START_LINE), "no start line"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_PROBLEMS_GETTING_PASSWORD),
    "problems getting password"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_PVK_DATA_TOO_SHORT), "pvk data too short"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_PVK_TOO_SHORT), "pvk too short"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_READ_KEY), "read key"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_SHORT_HEADER), "short header"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_UNEXPECTED_DEK_IV), "unexpected dek iv"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_UNSUPPORTED_CIPHER), "unsupported cipher"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_UNSUPPORTED_ENCRYPTION),
    "unsupported encryption"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_UNSUPPORTED_KEY_COMPONENTS),
    "unsupported key components"},
    {ERR_PACK(ERR_LIB_PEM, 0, PEM_R_UNSUPPORTED_PUBLIC_KEY_TYPE),
    "unsupported public key type"},
    {0, NULL}
};

#endif

int ossl_err_load_PEM_strings(void)
{
#ifndef OPENSSL_NO_ERR
    if (ERR_reason_error_string(PEM_str_reasons[0].error) == NULL)
        ERR_load_strings_const(PEM_str_reasons);
#endif
    return 1;
}
