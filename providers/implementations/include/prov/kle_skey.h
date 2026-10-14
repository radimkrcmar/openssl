/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_PROV_KLE_SKEY_H
#define OSSL_PROV_KLE_SKEY_H

#include <stddef.h>

/*
 * kle provider: the key data of an AES EVP_SKEY is only its SCC, of an ECB
 * Machine, which fits KLE_SKEY_SCC_MAX; the GCM Machine's SCCs make
 * KLE_SCC_MAX larger.
 */
#define KLE_SKEY_SCC_MAX 80

typedef struct {
    unsigned char scc[KLE_SKEY_SCC_MAX];
    size_t scc_len;
} KLE_SKEY;

/* Parameter names of the kle provider's AES skeymgmt. */
#define OSSL_SKEY_PARAM_KLE_SCC "kle-scc"
#define OSSL_SKEY_PARAM_KLE_BINDING "kle-binding" /* "device", "process" */

#endif
