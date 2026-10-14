/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * AES-{128,192,256}-{ECB,CBC,CTR} of the kle provider (RISC-V Zkl lockers,
 * prototype).  Besides raw keys, the ciphers take EVP_SKEY keys of the kle
 * provider's AES skeymgmt, whose key data is a Sealed Cryptographic Context.
 */

#include <openssl/proverr.h>
#include "cipher_aes.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/kle_skey.h"

#ifdef OSSL_AES_KLE

static OSSL_FUNC_cipher_freectx_fn kle_aes_freectx;
static OSSL_FUNC_cipher_dupctx_fn kle_aes_dupctx;
static OSSL_FUNC_cipher_encrypt_skey_init_fn kle_aes_skey_einit;
static OSSL_FUNC_cipher_decrypt_skey_init_fn kle_aes_skey_dinit;

static void kle_aes_freectx(void *vctx)
{
    PROV_AES_CTX *ctx = (PROV_AES_CTX *)vctx;

    ossl_cipher_aes_kle_release(&ctx->base);
    ossl_cipher_generic_reset_ctx((PROV_CIPHER_CTX *)vctx);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void *kle_aes_dupctx(void *vctx)
{
    PROV_AES_CTX *in = (PROV_AES_CTX *)vctx;
    PROV_AES_CTX *ret;

    if (!ossl_prov_is_running())
        return NULL;
    ret = OPENSSL_malloc(sizeof(*ret));
    if (ret == NULL)
        return NULL;
    in->base.hw->copyctx(&ret->base, &in->base);
    return ret;
}

static int kle_aes_skey_init(void *vctx, void *skeydata,
                              const unsigned char *iv, size_t ivlen,
                              const OSSL_PARAM params[], int enc)
{
    PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
    KLE_SKEY *key = skeydata;
    int ok = enc ? ossl_cipher_generic_einit(vctx, NULL, 0, iv, ivlen, params)
                 : ossl_cipher_generic_dinit(vctx, NULL, 0, iv, ivlen, params);

    if (!ok || key == NULL)
        return ok;
    if (kle_scc_keylen(key->scc) != ctx->keylen) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return 0;
    }
    if (!ossl_cipher_aes_kle_set_scc(ctx, key->scc, key->scc_len))
        return 0;
    ctx->key_set = 1;
    return 1;
}

static int kle_aes_skey_einit(void *vctx, void *skeydata,
                               const unsigned char *iv, size_t ivlen,
                               const OSSL_PARAM params[])
{
    return kle_aes_skey_init(vctx, skeydata, iv, ivlen, params, 1);
}

static int kle_aes_skey_dinit(void *vctx, void *skeydata,
                               const unsigned char *iv, size_t ivlen,
                               const OSSL_PARAM params[])
{
    return kle_aes_skey_init(vctx, skeydata, iv, ivlen, params, 0);
}

#define KLE_AES_CIPHER(kbits, lcmode, UCMODE, blkbits, ivbits, typ)            \
    static OSSL_FUNC_cipher_newctx_fn kle_aes##kbits##lcmode##_newctx;         \
    static void *kle_aes##kbits##lcmode##_newctx(void *provctx)                \
    {                                                                           \
        PROV_AES_CTX *ctx;                                                      \
                                                                                \
        if (!ossl_prov_is_running())                                            \
            return NULL;                                                        \
        ctx = OPENSSL_zalloc(sizeof(*ctx));                                     \
        if (ctx != NULL)                                                        \
            ossl_cipher_generic_initkey(ctx, kbits, blkbits, ivbits,            \
                EVP_CIPH_##UCMODE##_MODE, 0,                                    \
                ossl_prov_cipher_hw_aes_kle(EVP_CIPH_##UCMODE##_MODE),         \
                provctx);                                                       \
        return ctx;                                                             \
    }                                                                           \
    static OSSL_FUNC_cipher_get_params_fn kle_aes##kbits##lcmode##_get_params; \
    static int kle_aes##kbits##lcmode##_get_params(OSSL_PARAM params[])        \
    {                                                                           \
        return ossl_cipher_generic_get_params(params, EVP_CIPH_##UCMODE##_MODE, \
            0, kbits, blkbits, ivbits);                                         \
    }                                                                           \
    const OSSL_DISPATCH ossl_kle_aes##kbits##lcmode##_functions[] = {          \
        { OSSL_FUNC_CIPHER_NEWCTX,                                              \
            (void (*)(void))kle_aes##kbits##lcmode##_newctx },                 \
        { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))kle_aes_freectx },         \
        { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))kle_aes_dupctx },           \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT,                                        \
            (void (*)(void))ossl_cipher_generic_einit },                        \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT,                                        \
            (void (*)(void))ossl_cipher_generic_dinit },                        \
        { OSSL_FUNC_CIPHER_ENCRYPT_SKEY_INIT,                                   \
            (void (*)(void))kle_aes_skey_einit },                              \
        { OSSL_FUNC_CIPHER_DECRYPT_SKEY_INIT,                                   \
            (void (*)(void))kle_aes_skey_dinit },                              \
        { OSSL_FUNC_CIPHER_UPDATE,                                              \
            (void (*)(void))ossl_cipher_generic_##typ##_update },               \
        { OSSL_FUNC_CIPHER_FINAL,                                               \
            (void (*)(void))ossl_cipher_generic_##typ##_final },                \
        { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))ossl_cipher_generic_cipher },\
        { OSSL_FUNC_CIPHER_GET_PARAMS,                                          \
            (void (*)(void))kle_aes##kbits##lcmode##_get_params },             \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                      \
            (void (*)(void))ossl_cipher_generic_get_ctx_params },               \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                      \
            (void (*)(void))ossl_cipher_generic_set_ctx_params },               \
        { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                     \
            (void (*)(void))ossl_cipher_generic_gettable_params },              \
        { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                 \
            (void (*)(void))ossl_cipher_generic_gettable_ctx_params },          \
        { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                 \
            (void (*)(void))ossl_cipher_generic_settable_ctx_params },          \
        OSSL_DISPATCH_END                                                       \
    }

KLE_AES_CIPHER(256, ecb, ECB, 128, 0, block);
KLE_AES_CIPHER(192, ecb, ECB, 128, 0, block);
KLE_AES_CIPHER(128, ecb, ECB, 128, 0, block);
KLE_AES_CIPHER(256, cbc, CBC, 128, 128, block);
KLE_AES_CIPHER(192, cbc, CBC, 128, 128, block);
KLE_AES_CIPHER(128, cbc, CBC, 128, 128, block);
KLE_AES_CIPHER(256, ctr, CTR, 8, 128, stream);
KLE_AES_CIPHER(192, ctr, CTR, 8, 128, stream);
KLE_AES_CIPHER(128, ctr, CTR, 8, 128, stream);

#endif /* OSSL_AES_KLE */
