/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_DSOERR_H
# define OSSL_INTERNAL_DSOERR_H
# pragma once

# include "../openssl/opensslconf.h"
# include "../openssl/symhacks.h"

# ifdef  __cplusplus
extern "C" {
# endif

int ossl_err_load_DSO_strings(void);

/*
 * DSO reason codes.
 */
# define DSO_R_CTRL_FAILED                                100
# define DSO_R_DSO_ALREADY_LOADED                         110
# define DSO_R_EMPTY_FILE_STRUCTURE                       113
# define DSO_R_FAILURE                                    114
# define DSO_R_FILENAME_TOO_BIG                           101
# define DSO_R_FINISH_FAILED                              102
# define DSO_R_INCORRECT_FILE_SYNTAX                      115
# define DSO_R_LOAD_FAILED                                103
# define DSO_R_NAME_TRANSLATION_FAILED                    109
# define DSO_R_NO_FILENAME                                111
# define DSO_R_NULL_HANDLE                                104
# define DSO_R_SET_FILENAME_FAILED                        112
# define DSO_R_STACK_ERROR                                105
# define DSO_R_SYM_FAILURE                                106
# define DSO_R_UNLOAD_FAILED                              107
# define DSO_R_UNSUPPORTED                                108


# ifdef  __cplusplus
}
# endif
#endif
