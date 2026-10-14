/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * The "kle" store of the kle provider (RISC-V Zkl lockers, prototype).
 *
 * A kle: URI names a file that holds a Sealed Cryptographic Context, as
 * "kle:scc" or "kle:/etc/kle-demo/scc" (or "kle:///etc/kle-demo/scc").  It
 * loads as one AES EVP_SKEY of the kle provider, the SCC its reference: the
 * SCC is all there is of the key outside the KLE unit.  The skeymgmt checks
 * the SCC on import, the unit unseals it when a cipher is set up with it.
 * So "openssl enc -provider kle -skeyuri kle:scc" needs no -skeymgmt,
 * -skeyopt or -propquery: the key brings its provider.
 */

#include <string.h>
#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include "prov/kle_skey.h"
#include "prov/providercommon.h"

static OSSL_FUNC_store_open_fn kle_store_open;
static OSSL_FUNC_store_load_fn kle_store_load;
static OSSL_FUNC_store_eof_fn kle_store_eof;
static OSSL_FUNC_store_close_fn kle_store_close;

typedef struct {
    /* One more byte than an SCC may have, to tell a longer file. */
    unsigned char scc[KLE_SKEY_SCC_MAX + 1];
    size_t scc_len;
    int loaded;
} KLE_STORE_CTX;

static void *kle_store_open(void *provctx, const char *uri)
{
    KLE_STORE_CTX *ctx;
    const char *path = uri + 4;
    BIO *in;
    int ok;

    if (!ossl_prov_is_running() || OPENSSL_strncasecmp(uri, "kle:", 4) != 0)
        return NULL;
    /* An authority, as in file: URIs, only if empty. */
    if (strncmp(path, "//", 2) == 0) {
        if (path[2] != '/') {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_URI_AUTHORITY_UNSUPPORTED,
                           "%s", uri);
            return NULL;
        }
        path += 2;
    }
    if ((in = BIO_new_file(path, "rb")) == NULL)
        return NULL;
    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL) {
        BIO_free(in);
        return NULL;
    }
    ok = BIO_read_ex(in, ctx->scc, sizeof(ctx->scc), &ctx->scc_len)
         && ctx->scc_len <= KLE_SKEY_SCC_MAX;
    BIO_free(in);
    if (!ok) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_KEY,
                       "%s does not hold an SCC", path);
        OPENSSL_free(ctx);
        return NULL;
    }
    return ctx;
}

static int kle_store_load(void *loaderctx,
                          OSSL_CALLBACK *object_cb, void *object_cbarg,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    KLE_STORE_CTX *ctx = loaderctx;
    int type = OSSL_OBJECT_SKEY;
    OSSL_PARAM params[4];

    if (ctx->loaded)
        return 0;
    ctx->loaded = 1;
    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                 (char *)"AES", 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                  ctx->scc, ctx->scc_len);
    params[3] = OSSL_PARAM_construct_end();
    return object_cb(params, object_cbarg);
}

static int kle_store_eof(void *loaderctx)
{
    KLE_STORE_CTX *ctx = loaderctx;

    return ctx->loaded;
}

static int kle_store_close(void *loaderctx)
{
    OPENSSL_clear_free(loaderctx, sizeof(KLE_STORE_CTX));
    return 1;
}

const OSSL_DISPATCH ossl_kle_store_functions[] = {
    { OSSL_FUNC_STORE_OPEN, (void (*)(void))kle_store_open },
    { OSSL_FUNC_STORE_LOAD, (void (*)(void))kle_store_load },
    { OSSL_FUNC_STORE_EOF, (void (*)(void))kle_store_eof },
    { OSSL_FUNC_STORE_CLOSE, (void (*)(void))kle_store_close },
    OSSL_DISPATCH_END
};
