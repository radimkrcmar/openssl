/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * AES skeymgmt of the kle provider (RISC-V Zkl lockers, prototype).
 *
 * The key data is a Sealed Cryptographic Context (SCC) and nothing else:
 *  - import of "raw-bytes" provisions the key into a locker, exports it as
 *    an SCC and forgets the raw key;
 *  - import of "kle-scc" adopts an SCC exported earlier, as does import
 *    of a "reference", the form an SCC from a kle: URI takes (kle_store.c);
 *  - generate creates the key inside the KLE unit (all-ones SKID): its
 *    value is never visible to software;
 *  - export yields only "kle-scc", never raw bytes.
 * "kle-binding" selects the Locality the SCC is bound to: "device"
 * (DevScrt, the default: usable by any process on this device and boot)
 * or "process" (SLocality: this process only).
 * The CC may only be used in U-mode (UsagePolicy) and for encryption and
 * decryption.
 */

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include "prov/implementations.h"
#include "prov/kle_skey.h"
#include "prov/providercommon.h"
#include "crypto/riscv_kle.h"

#ifdef OSSL_RISCV_KLE

static OSSL_FUNC_skeymgmt_free_fn kle_skey_free;
static OSSL_FUNC_skeymgmt_import_fn kle_skey_import;
static OSSL_FUNC_skeymgmt_export_fn kle_skey_export;
static OSSL_FUNC_skeymgmt_generate_fn kle_skey_generate;
static OSSL_FUNC_skeymgmt_imp_settable_params_fn kle_skey_imp_settable;
static OSSL_FUNC_skeymgmt_gen_settable_params_fn kle_skey_gen_settable;

static int binding(const OSSL_PARAM params[], int *loc)
{
    const OSSL_PARAM *p;
    const char *s = "device";

    p = OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_KLE_BINDING);
    if (p != NULL && !OSSL_PARAM_get_utf8_string_ptr(p, &s))
        return 0;
    if (strcmp(s, "device") == 0)
        *loc = KLE_LOC_DEVICE;
    else if (strcmp(s, "process") == 0)
        *loc = KLE_LOC_PROCESS;
    else
        return 0;
    return 1;
}

static void *kle_skey_from(const KLE_KEY *k)
{
    KLE_SKEY *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret != NULL) {
        memcpy(ret->scc, k->scc, k->scc_len);
        ret->scc_len = k->scc_len;
    }
    return ret;
}

static void kle_skey_free(void *keydata)
{
    OPENSSL_clear_free(keydata, sizeof(KLE_SKEY));
}

static void *kle_skey_import(void *provctx, int selection,
                              const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    KLE_KEY k = { .locker = -1 };
    void *ret = NULL;
    const void *data;
    size_t len;
    int loc;

    if (!ossl_prov_is_running()
        || (selection & OSSL_SKEYMGMT_SELECT_SECRET_KEY) == 0)
        return NULL;

    p = OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_KLE_SCC);
    if (p == NULL)
        p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_REFERENCE);
    if (p != NULL) {
        /*
         * kle_key_from_scc() checks the length before the MDH is read,
         * against KLE_SCC_MAX, which GCM SCCs make larger than an ECB
         * SCC, all that a KLE_SKEY holds.
         */
        if (!OSSL_PARAM_get_octet_string_ptr(p, &data, &len)
            || len > KLE_SKEY_SCC_MAX
            || !kle_key_from_scc(&k, data, len)
            || kle_scc_keylen(k.scc) == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
            return NULL;
        }
        return kle_skey_from(&k);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_RAW_BYTES);
    if (p == NULL || !OSSL_PARAM_get_octet_string_ptr(p, &data, &len)
        || !binding(params, &loc)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return NULL;
    }
    if (kle_key_from_raw(&k, data, len, KLE_MODE_ECB,
                          KLE_POLICY_ENC | KLE_POLICY_DEC, loc))
        ret = kle_skey_from(&k);
    else
        ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SETUP_FAILED);
    kle_key_release(&k);
    OPENSSL_cleanse(&k, sizeof(k));
    return ret;
}

static void *kle_skey_generate(void *provctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    KLE_KEY k = { .locker = -1 };
    size_t len = 32;
    void *ret = NULL;
    int loc;

    if (!ossl_prov_is_running())
        return NULL;
    p = OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_KEY_LENGTH);
    if ((p != NULL && !OSSL_PARAM_get_size_t(p, &len)) || !binding(params, &loc)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return NULL;
    }
    if (kle_key_generate(&k, len, KLE_POLICY_ENC | KLE_POLICY_DEC, loc))
        ret = kle_skey_from(&k);
    else
        ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SETUP_FAILED);
    kle_key_release(&k);
    return ret;
}

static int kle_skey_export(void *keydata, int selection,
                            OSSL_CALLBACK *param_cb, void *cbarg)
{
    KLE_SKEY *key = keydata;
    OSSL_PARAM params[2];

    if (!ossl_prov_is_running() || key == NULL
        || (selection & OSSL_SKEYMGMT_SELECT_SECRET_KEY) == 0)
        return 0;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_SKEY_PARAM_KLE_SCC,
                                                  key->scc, key->scc_len);
    params[1] = OSSL_PARAM_construct_end();
    return param_cb(params, cbarg);
}

static const OSSL_PARAM kle_imp_params[] = {
    OSSL_PARAM_octet_string(OSSL_SKEY_PARAM_RAW_BYTES, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_SKEY_PARAM_KLE_SCC, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SKEY_PARAM_KLE_BINDING, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM kle_gen_params[] = {
    OSSL_PARAM_size_t(OSSL_SKEY_PARAM_KEY_LENGTH, NULL),
    OSSL_PARAM_utf8_string(OSSL_SKEY_PARAM_KLE_BINDING, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *kle_skey_imp_settable(void *provctx)
{
    return kle_imp_params;
}

static const OSSL_PARAM *kle_skey_gen_settable(void *provctx)
{
    return kle_gen_params;
}

const OSSL_DISPATCH ossl_kle_aes_skeymgmt_functions[] = {
    { OSSL_FUNC_SKEYMGMT_FREE, (void (*)(void))kle_skey_free },
    { OSSL_FUNC_SKEYMGMT_IMPORT, (void (*)(void))kle_skey_import },
    { OSSL_FUNC_SKEYMGMT_EXPORT, (void (*)(void))kle_skey_export },
    { OSSL_FUNC_SKEYMGMT_GENERATE, (void (*)(void))kle_skey_generate },
    { OSSL_FUNC_SKEYMGMT_IMP_SETTABLE_PARAMS,
        (void (*)(void))kle_skey_imp_settable },
    { OSSL_FUNC_SKEYMGMT_GEN_SETTABLE_PARAMS,
        (void (*)(void))kle_skey_gen_settable },
    OSSL_DISPATCH_END
};

#endif /* OSSL_RISCV_KLE */
