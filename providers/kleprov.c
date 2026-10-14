/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * The kle provider: AES in RISC-V Zkl (KLE) cryptographic lockers
 * (prototype).  Loading fails unless the kernel reports Zkl via hwprobe.
 */

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include "prov/provider_ctx.h"
#include "prov/names.h"
#include "prov/providercommon.h"
#include "crypto/riscv_kle.h"

extern const OSSL_DISPATCH ossl_kle_aes256gcm_functions[];
extern const OSSL_DISPATCH ossl_kle_aes192gcm_functions[];
extern const OSSL_DISPATCH ossl_kle_aes128gcm_functions[];
extern const OSSL_DISPATCH ossl_kle_aes256ecb_functions[];
extern const OSSL_DISPATCH ossl_kle_aes192ecb_functions[];
extern const OSSL_DISPATCH ossl_kle_aes128ecb_functions[];
extern const OSSL_DISPATCH ossl_kle_aes256cbc_functions[];
extern const OSSL_DISPATCH ossl_kle_aes192cbc_functions[];
extern const OSSL_DISPATCH ossl_kle_aes128cbc_functions[];
extern const OSSL_DISPATCH ossl_kle_aes256ctr_functions[];
extern const OSSL_DISPATCH ossl_kle_aes192ctr_functions[];
extern const OSSL_DISPATCH ossl_kle_aes128ctr_functions[];
extern const OSSL_DISPATCH ossl_kle_aes_skeymgmt_functions[];
extern const OSSL_DISPATCH ossl_kle_store_functions[];

static OSSL_FUNC_provider_gettable_params_fn kle_gettable_params;
static OSSL_FUNC_provider_get_params_fn kle_get_params;
static OSSL_FUNC_provider_query_operation_fn kle_query;

#define ALG(NAMES, FUNC) { NAMES, "provider=kle", FUNC }

static OSSL_FUNC_core_new_error_fn *c_new_error;
static OSSL_FUNC_core_set_error_debug_fn *c_set_error_debug;
static OSSL_FUNC_core_vset_error_fn *c_vset_error;
static OSSL_FUNC_core_set_error_mark_fn *c_set_error_mark;
static OSSL_FUNC_core_clear_last_error_mark_fn *c_clear_last_error_mark;
static OSSL_FUNC_core_pop_error_to_mark_fn *c_pop_error_to_mark;
static OSSL_FUNC_core_count_to_mark_fn *c_count_to_mark;

static const OSSL_PARAM kle_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *kle_gettable_params(void *provctx)
{
    return kle_param_types;
}

static int kle_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL
        && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL KLE (RISC-V Zkl) Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, ossl_prov_is_running()))
        return 0;
    return 1;
}

/* The GCM ones first: kle_query() leaves them out without the Machine. */
#define KLE_NGCM 3
static int kle_have_gcm;

static const OSSL_ALGORITHM kle_ciphers[] = {
    ALG(PROV_NAMES_AES_256_GCM, ossl_kle_aes256gcm_functions),
    ALG(PROV_NAMES_AES_192_GCM, ossl_kle_aes192gcm_functions),
    ALG(PROV_NAMES_AES_128_GCM, ossl_kle_aes128gcm_functions),
    ALG(PROV_NAMES_AES_256_ECB, ossl_kle_aes256ecb_functions),
    ALG(PROV_NAMES_AES_192_ECB, ossl_kle_aes192ecb_functions),
    ALG(PROV_NAMES_AES_128_ECB, ossl_kle_aes128ecb_functions),
    ALG(PROV_NAMES_AES_256_CBC, ossl_kle_aes256cbc_functions),
    ALG(PROV_NAMES_AES_192_CBC, ossl_kle_aes192cbc_functions),
    ALG(PROV_NAMES_AES_128_CBC, ossl_kle_aes128cbc_functions),
    ALG(PROV_NAMES_AES_256_CTR, ossl_kle_aes256ctr_functions),
    ALG(PROV_NAMES_AES_192_CTR, ossl_kle_aes192ctr_functions),
    ALG(PROV_NAMES_AES_128_CTR, ossl_kle_aes128ctr_functions),
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM kle_skeymgmt[] = {
    ALG(PROV_NAMES_AES, ossl_kle_aes_skeymgmt_functions),
    { NULL, NULL, NULL }
};

/* kle: URIs, files holding an SCC. */
static const OSSL_ALGORITHM kle_store[] = {
    ALG("kle", ossl_kle_store_functions),
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *kle_query(void *provctx, int operation_id,
                                        int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_CIPHER:
        return kle_ciphers + (kle_have_gcm ? 0 : KLE_NGCM);
    case OSSL_OP_SKEYMGMT:
        return kle_skeymgmt;
    case OSSL_OP_STORE:
        return kle_store;
    }
    return NULL;
}

static void kle_teardown(void *provctx)
{
    OSSL_LIB_CTX_free(PROV_LIBCTX_OF(provctx));
    ossl_prov_ctx_free(provctx);
}

static const OSSL_DISPATCH kle_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))kle_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))kle_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))kle_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))kle_query },
    OSSL_DISPATCH_END
};

/*
 * Does the kernel report Zkl (hwprobe IMA_EXT_1 bit 6, provisional)?  And
 * V, as kl.exec works on vector registers (AT_HWCAP bit 'V' - 'A').
 */
static int kle_available(void)
{
#ifdef __NR_riscv_hwprobe
    struct {
        int64_t key;
        uint64_t value;
    } pair = { 16, 0 };

    if ((getauxval(AT_HWCAP) & (1UL << ('V' - 'A'))) == 0)
        return 0;
    return syscall(__NR_riscv_hwprobe, &pair, 1, 0, NULL, 0) == 0
        && pair.key == 16 && (pair.value & (1ULL << 6)) != 0;
#else
    return 0;
#endif
}

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    OSSL_LIB_CTX *libctx = NULL;
    const OSSL_DISPATCH *tmp;

    for (tmp = in; tmp->function_id != 0; tmp++) {
        switch (tmp->function_id) {
        case OSSL_FUNC_CORE_NEW_ERROR:
            c_new_error = OSSL_FUNC_core_new_error(tmp);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            c_set_error_debug = OSSL_FUNC_core_set_error_debug(tmp);
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            c_vset_error = OSSL_FUNC_core_vset_error(tmp);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_MARK:
            c_set_error_mark = OSSL_FUNC_core_set_error_mark(tmp);
            break;
        case OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK:
            c_clear_last_error_mark = OSSL_FUNC_core_clear_last_error_mark(tmp);
            break;
        case OSSL_FUNC_CORE_POP_ERROR_TO_MARK:
            c_pop_error_to_mark = OSSL_FUNC_core_pop_error_to_mark(tmp);
            break;
        case OSSL_FUNC_CORE_COUNT_TO_MARK:
            c_count_to_mark = OSSL_FUNC_core_count_to_mark(tmp);
            break;
        }
    }

    if (!kle_available())
        return 0;
    /* kl.size, which only a Zkl hart has: whether to offer AES-GCM. */
    kle_have_gcm = kle_gcm_supported();

    OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT, NULL);

    if ((*provctx = ossl_prov_ctx_new()) == NULL
        || (libctx = OSSL_LIB_CTX_new_child(handle, in)) == NULL) {
        OSSL_LIB_CTX_free(libctx);
        kle_teardown(*provctx);
        *provctx = NULL;
        return 0;
    }
    ossl_prov_ctx_set0_libctx(*provctx, libctx);
    ossl_prov_ctx_set0_handle(*provctx, handle);
    *out = kle_dispatch_table;
    return 1;
}

/* libcrypto ERR functions in terms of upcalls (cf. legacyprov.c). */
void ERR_new(void)
{
    c_new_error(NULL);
}

void ERR_set_debug(const char *file, int line, const char *func)
{
    c_set_error_debug(NULL, file, line, func);
}

void ERR_set_error(int lib, int reason, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    c_vset_error(NULL, ERR_PACK(lib, 0, reason), fmt, args);
    va_end(args);
}

void ERR_vset_error(int lib, int reason, const char *fmt, va_list args)
{
    c_vset_error(NULL, ERR_PACK(lib, 0, reason), fmt, args);
}

int ERR_set_mark(void)
{
    return c_set_error_mark(NULL);
}

int ERR_clear_last_mark(void)
{
    return c_clear_last_error_mark(NULL);
}

int ERR_pop_to_mark(void)
{
    return c_pop_error_to_mark(NULL);
}

int ERR_count_to_mark(void)
{
    return c_count_to_mark != NULL ? c_count_to_mark(NULL) : 0;
}
