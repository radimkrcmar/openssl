/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Tests of AES in RISC-V Zkl (KLE) lockers: the kle provider (raw keys
 * and EVP_SKEY keys that are Sealed Cryptographic Contexts) and the
 * transparent use of lockers by the default provider, AES-GCM included.
 * Needs a Zkl hart.
 * AES-CTR runs on the CTR Machine when the unit has it; with
 * KLE_EXPECT_CTR=0 or 1 in the environment, whether it has is checked too,
 * and KLE_EXPECT_GCM likewise for the AES-GCM Machine, which the kle
 * provider's AES-GCM needs.
 */

#define _GNU_SOURCE             /* sched_setaffinity() */
/* AES_set_encrypt_key() for the software reference */
#include "internal/deprecated.h"

#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/store.h>
#include "crypto/riscv_kle.h"
#include "testutil.h"

#define SKEY_PARAM_KLE_SCC "kle-scc"
#define SKEY_PARAM_KLE_BINDING "kle-binding"

static OSSL_LIB_CTX *libctx;
static OSSL_PROVIDER *prov_default, *prov_kle;

static const char *ciphers[] = {
    "AES-128-ECB", "AES-192-ECB", "AES-256-ECB",
    "AES-128-CBC", "AES-192-CBC", "AES-256-CBC",
    "AES-128-CTR", "AES-192-CTR", "AES-256-CTR",
};

/* One-shot encryption or decryption with a raw key or an EVP_SKEY. */
static int do_crypt(const char *name, const char *propq, const unsigned char *key,
                 EVP_SKEY *skey, const unsigned char *iv, int enc,
                 const unsigned char *in, int inl, unsigned char *out, int *outl)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(libctx, name, propq);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int ok = 0, l1 = 0, l2 = 0;
    size_t ivlen;

    if (!TEST_ptr(c) || !TEST_ptr(ctx))
        goto err;
    ivlen = EVP_CIPHER_get_iv_length(c);
    if (skey != NULL) {
        if (!TEST_true(EVP_CipherInit_SKEY(ctx, c, skey, ivlen ? iv : NULL,
                                           ivlen, enc, NULL)))
            goto err;
    } else if (!TEST_true(EVP_CipherInit_ex2(ctx, c, key, iv, enc, NULL))) {
        goto err;
    }
    if (!TEST_true(EVP_CipherUpdate(ctx, out, &l1, in, inl))
        || !TEST_true(EVP_CipherFinal_ex(ctx, out + l1, &l2)))
        goto err;
    *outl = l1 + l2;
    ok = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
    return ok;
}

/* Number of configured lockers on this hart (of this thread). */
static int lockers_in_use(void)
{
    int i, n = 0;

    for (i = 0; i < KLE_LOCKERS; i++)
        n += kle_getst(i) != KLE_ST_UNCONFIGURED;
    return n;
}

static int test_provider_vs_default(int idx)
{
    unsigned char key[32], iv[16], pt[1000], ct1[1100], ct2[1100], back[1100];
    int l1, l2, l3, inl = 777;
    const char *name = ciphers[idx];

    if (strstr(name, "CTR") == NULL)
        inl = 784;      /* ECB/CBC: whole blocks plus padding */
    if (!TEST_int_eq(RAND_bytes(key, sizeof(key)), 1)
        || !TEST_int_eq(RAND_bytes(iv, sizeof(iv)), 1)
        || !TEST_int_eq(RAND_bytes(pt, sizeof(pt)), 1))
        return 0;

    if (!do_crypt(name, "provider=default", key, NULL, iv, 1, pt, inl, ct1, &l1)
        || !do_crypt(name, "provider=kle", key, NULL, iv, 1, pt, inl, ct2, &l2)
        || !TEST_mem_eq(ct1, l1, ct2, l2)
        || !do_crypt(name, "provider=kle", key, NULL, iv, 0, ct1, l1, back, &l3)
        || !TEST_mem_eq(back, l3, pt, inl))
        return 0;
    return 1;
}

/*
 * The default provider puts raw AES keys in lockers on a Zkl hart: while a
 * context is alive, this thread has one more configured locker.
 */
static int test_default_uses_lockers(void)
{
    static const unsigned char key[16], iv[16];
    EVP_CIPHER *c = EVP_CIPHER_fetch(libctx, "AES-128-CBC", "provider=default");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int before = lockers_in_use(), during, after, ok = 0;

    if (!TEST_ptr(c) || !TEST_ptr(ctx)
        || !TEST_true(EVP_EncryptInit_ex2(ctx, c, key, iv, NULL)))
        goto err;
    during = lockers_in_use();
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
    after = lockers_in_use();
    ok = TEST_int_eq(during, before + 1) && TEST_int_eq(after, before);
err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
    return ok;
}

static int get_scc(const OSSL_PARAM params[], void *arg)
{
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, SKEY_PARAM_KLE_SCC);
    unsigned char *scc = arg;
    const void *d;
    size_t len;

    if (p == NULL || !OSSL_PARAM_get_octet_string_ptr(p, &d, &len) || len > 64)
        return 0;
    memcpy(scc, d, len);
    return 1;
}

static EVP_SKEY *skey_from_scc(const unsigned char *scc, size_t len)
{
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(SKEY_PARAM_KLE_SCC,
                                                  (void *)scc, len);
    params[1] = OSSL_PARAM_construct_end();
    return EVP_SKEY_import(libctx, "AES", "provider=kle",
                           OSSL_SKEYMGMT_SELECT_SECRET_KEY, params);
}

static int test_skey_raw(void)
{
    unsigned char key[32], iv[16], pt[64], ct1[96], ct2[96], scc[64];
    const unsigned char *raw;
    size_t rawlen;
    EVP_SKEY *skey = NULL, *skey2 = NULL;
    int l1, l2, ok = 0;

    if (!TEST_int_eq(RAND_bytes(key, sizeof(key)), 1)
        || !TEST_int_eq(RAND_bytes(iv, sizeof(iv)), 1)
        || !TEST_int_eq(RAND_bytes(pt, sizeof(pt)), 1))
        goto err;
    if (!TEST_ptr(skey = EVP_SKEY_import_raw_key(libctx, "AES", key, 32,
                                                 "provider=kle"))
        /* Only the SCC can come out, never the key. */
        || !TEST_false(EVP_SKEY_get0_raw_key(skey, &raw, &rawlen))
        || !TEST_true(EVP_SKEY_export(skey, OSSL_SKEYMGMT_SELECT_SECRET_KEY,
                                      get_scc, scc))
        || !TEST_mem_ne(scc + 32, 32, key, 32)
        || !do_crypt("AES-256-CBC", "provider=default", key, NULL, iv, 1,
                  pt, sizeof(pt), ct1, &l1)
        || !do_crypt("AES-256-CBC", "provider=kle", NULL, skey, iv, 1,
                  pt, sizeof(pt), ct2, &l2)
        || !TEST_mem_eq(ct1, l1, ct2, l2)
        /* The SCC alone, re-imported, is the same key. */
        || !TEST_ptr(skey2 = skey_from_scc(scc, 64))
        || !do_crypt("AES-256-CBC", "provider=kle", NULL, skey2, iv, 0,
                  ct1, l1, ct2, &l2)
        || !TEST_mem_eq(ct2, l2, pt, sizeof(pt)))
        goto err;
    ok = 1;
err:
    EVP_SKEY_free(skey);
    EVP_SKEY_free(skey2);
    return ok;
}

/* Load a kle: URI; NULL unless it is one AES key of the kle provider. */
static EVP_SKEY *skey_from_uri(const char *uri)
{
    OSSL_STORE_CTX *store;
    OSSL_STORE_INFO *info = NULL;
    EVP_SKEY *skey = NULL;

    if ((store = OSSL_STORE_open_ex(uri, libctx, NULL, NULL, NULL, NULL,
                                    NULL, NULL)) == NULL)
        return NULL;
    if (OSSL_STORE_expect(store, OSSL_STORE_INFO_SKEY)
        && (info = OSSL_STORE_load(store)) != NULL
        && (skey = OSSL_STORE_INFO_get1_SKEY(info)) != NULL
        && (!OSSL_STORE_eof(store)
            || !EVP_SKEY_is_a(skey, "AES")
            || strcmp(EVP_SKEY_get0_provider_name(skey), "kle") != 0)) {
        EVP_SKEY_free(skey);
        skey = NULL;
    }
    OSSL_STORE_INFO_free(info);
    OSSL_STORE_close(store);
    return skey;
}

/*
 * A kle: URI names a file holding an SCC: it loads as that key, of the
 * kle provider, the default provider's file: store notwithstanding.
 */
static int test_skey_store(void)
{
    unsigned char key[32], iv[16], pt[64], ct[96], back[96], scc[80];
    char path[] = "/tmp/kle_test_sccXXXXXX", uri[sizeof(path) + 6];
    EVP_SKEY *skey = NULL, *skey2 = NULL;
    FILE *f = NULL;
    int fd, l, l2, ok = 0;

    if (!TEST_int_eq(RAND_bytes(key, sizeof(key)), 1)
        || !TEST_int_eq(RAND_bytes(iv, sizeof(iv)), 1)
        || !TEST_int_eq(RAND_bytes(pt, sizeof(pt)), 1)
        || !TEST_ptr(skey = EVP_SKEY_import_raw_key(libctx, "AES", key, 32,
                                                    "provider=kle"))
        || !TEST_true(EVP_SKEY_export(skey, OSSL_SKEYMGMT_SELECT_SECRET_KEY,
                                      get_scc, scc))
        || !TEST_int_ge(fd = mkstemp(path), 0)
        || !TEST_ptr(f = fdopen(fd, "wb"))
        || !TEST_size_t_eq(fwrite(scc, 1, 64, f), 64)
        || !TEST_int_eq(fflush(f), 0)
        || !do_crypt("AES-256-CBC", "provider=default", key, NULL, iv, 1,
                     pt, sizeof(pt), ct, &l))
        goto err;

    BIO_snprintf(uri, sizeof(uri), "kle:%s", path);
    if (!TEST_ptr(skey2 = skey_from_uri(uri))
        || !do_crypt("AES-256-CBC", "provider=kle", NULL, skey2, iv, 0,
                     ct, l, back, &l2)
        || !TEST_mem_eq(back, l2, pt, sizeof(pt)))
        goto err;
    EVP_SKEY_free(skey2);
    BIO_snprintf(uri, sizeof(uri), "kle://%s", path);
    if (!TEST_ptr(skey2 = skey_from_uri(uri)))
        goto err;
    EVP_SKEY_free(skey2);
    skey2 = NULL;

    /* No such file, and files that hold no SCC, load nothing. */
    memset(scc + 64, 0, 16);
    if (!TEST_ptr_null(skey_from_uri("kle:/nonexistent/scc"))
        || !TEST_ptr_null(skey_from_uri("kle://localhost/tmp/scc"))
        || !TEST_size_t_eq(fwrite(scc + 64, 1, 8, f), 8)
        || !TEST_int_eq(fflush(f), 0)
        || !TEST_ptr_null(skey_from_uri(uri))
        || !TEST_size_t_eq(fwrite(scc + 64, 1, 16, f), 16)
        || !TEST_int_eq(fflush(f), 0)
        || !TEST_ptr_null(skey_from_uri(uri)))
        goto err;
    ok = 1;
err:
    if (f != NULL) {
        fclose(f);
        unlink(path);
    }
    EVP_SKEY_free(skey);
    EVP_SKEY_free(skey2);
    return ok;
}

static int test_skey_generate_and_tamper(void)
{
    unsigned char iv[16], pt[48], ct[80], back[80], scc[64];
    size_t keylen = 16;
    OSSL_PARAM params[3];
    EVP_SKEY *skey = NULL, *skey2 = NULL;
    EVP_CIPHER *c = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int l, l2, ok = 0;

    if (!TEST_int_eq(RAND_bytes(iv, sizeof(iv)), 1)
        || !TEST_int_eq(RAND_bytes(pt, sizeof(pt)), 1))
        goto err;
    params[0] = OSSL_PARAM_construct_size_t(OSSL_SKEY_PARAM_KEY_LENGTH, &keylen);
    params[1] = OSSL_PARAM_construct_utf8_string(SKEY_PARAM_KLE_BINDING,
                                                 "process", 0);
    params[2] = OSSL_PARAM_construct_end();
    /* A key generated in the KLE unit: no software ever saw it. */
    if (!TEST_ptr(skey = EVP_SKEY_generate(libctx, "AES", "provider=kle",
                                           params))
        || !TEST_true(EVP_SKEY_export(skey, OSSL_SKEYMGMT_SELECT_SECRET_KEY,
                                      get_scc, scc))
        || !do_crypt("AES-128-CTR", "provider=kle", NULL, skey, iv, 1,
                  pt, sizeof(pt), ct, &l)
        || !TEST_mem_ne(ct, l, pt, sizeof(pt))
        || !do_crypt("AES-128-CTR", "provider=kle", NULL, skey, iv, 0,
                  ct, l, back, &l2)
        || !TEST_mem_eq(back, l2, pt, sizeof(pt)))
        goto err;

    /* A tampered SCC is rejected when it is loaded. */
    scc[40] ^= 1;
    if (!TEST_ptr(skey2 = skey_from_scc(scc, 48))
        || !TEST_ptr(c = EVP_CIPHER_fetch(libctx, "AES-128-CTR", "provider=kle"))
        || !TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_false(EVP_CipherInit_SKEY(ctx, c, skey2, iv, 16, 1, NULL)))
        goto err;
    ok = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
    EVP_SKEY_free(skey);
    EVP_SKEY_free(skey2);
    return ok;
}

/*
 * A context set up in one thread and used in another reloads its SCC, and
 * the first thread's locker is cleared once the context is gone.
 */
struct xthread {
    EVP_CIPHER_CTX *ctx;
    const unsigned char *in;
    unsigned char *out;
    int ok;
};

static void *xthread_run(void *arg)
{
    struct xthread *x = arg;
    int l;

    x->ok = lockers_in_use() == 0
        && EVP_CipherUpdate(x->ctx, x->out, &l, x->in, 64) && l == 64;
    return NULL;
}

static int test_cross_thread(void)
{
    unsigned char key[16], iv[16], pt[128], ct[160], ref[160];
    EVP_CIPHER *c = EVP_CIPHER_fetch(libctx, "AES-128-CTR", "provider=kle");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    struct xthread x;
    pthread_t t;
    int before = lockers_in_use(), l, lr, ok = 0;

    if (!TEST_int_eq(RAND_bytes(key, sizeof(key)), 1)
        || !TEST_int_eq(RAND_bytes(iv, sizeof(iv)), 1)
        || !TEST_int_eq(RAND_bytes(pt, sizeof(pt)), 1))
        goto err;
    if (!TEST_ptr(c) || !TEST_ptr(ctx)
        || !do_crypt("AES-128-CTR", "provider=default", key, NULL, iv, 1,
                  pt, sizeof(pt), ref, &lr)
        || !TEST_true(EVP_EncryptInit_ex2(ctx, c, key, iv, NULL))
        || !TEST_true(EVP_EncryptUpdate(ctx, ct, &l, pt, 64)))
        goto err;
    x = (struct xthread){ ctx, pt + 64, ct + 64, 0 };
    if (!TEST_int_eq(pthread_create(&t, NULL, xthread_run, &x), 0)
        || !TEST_int_eq(pthread_join(t, NULL), 0)
        || !TEST_true(x.ok)
        || !TEST_mem_eq(ct, 128, ref, 128))
        goto err;
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
    if (!TEST_int_eq(lockers_in_use(), before))
        goto err;
    ok = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
    return ok;
}

/*
 * A context freed by another thread than the one holding its key: the
 * holder clears that locker on its next use of the provider.
 */
struct xrelease {
    EVP_CIPHER *c;
    EVP_CIPHER_CTX *ctx;
    pthread_barrier_t loaded, freed;
    int ok;
};

static void *xrelease_run(void *arg)
{
    static const unsigned char key[16], key2[16] = { 1 };
    struct xrelease *x = arg;
    EVP_CIPHER_CTX *ctx2 = NULL;
    int base = lockers_in_use(), ok;

    ok = (x->ctx = EVP_CIPHER_CTX_new()) != NULL
        && EVP_EncryptInit_ex2(x->ctx, x->c, key, NULL, NULL)
        && lockers_in_use() == base + 1;
    pthread_barrier_wait(&x->loaded);
    /* The main thread frees x->ctx here. */
    pthread_barrier_wait(&x->freed);
    ok = ok && lockers_in_use() == base + 1     /* posted, not cleared */
        && (ctx2 = EVP_CIPHER_CTX_new()) != NULL
        && EVP_EncryptInit_ex2(ctx2, x->c, key2, NULL, NULL)
        && lockers_in_use() == base + 1;        /* only ctx2's now */
    EVP_CIPHER_CTX_free(ctx2);
    x->ok = ok && lockers_in_use() == base;
    return NULL;
}

static int test_cross_thread_release(void)
{
    struct xrelease x = { 0 };
    pthread_t t;
    int ok = 0;

    if (!TEST_ptr(x.c = EVP_CIPHER_fetch(libctx, "AES-128-ECB",
                                         "provider=kle"))
        || !TEST_int_eq(pthread_barrier_init(&x.loaded, NULL, 2), 0))
        goto err;
    if (!TEST_int_eq(pthread_barrier_init(&x.freed, NULL, 2), 0))
        goto err_loaded;
    if (!TEST_int_eq(pthread_create(&t, NULL, xrelease_run, &x), 0))
        goto err_freed;
    pthread_barrier_wait(&x.loaded);
    EVP_CIPHER_CTX_free(x.ctx);
    pthread_barrier_wait(&x.freed);
    ok = TEST_int_eq(pthread_join(t, NULL), 0) && TEST_true(x.ok);
err_freed:
    pthread_barrier_destroy(&x.freed);
err_loaded:
    pthread_barrier_destroy(&x.loaded);
err:
    EVP_CIPHER_free(x.c);
    return ok;
}

/*
 * Lockers belong to a thread, not to its hart: the kernel switches them
 * with the thread.  Two threads on one hart, the second running while the
 * first waits for it: the second starts without the first's locker, and
 * clearing every locker it finds leaves the first's alone.  Through the
 * library alone, a kernel that lets the threads of a hart share its
 * lockers passes the other tests as often as not, since the library takes
 * only free lockers and loads a cleared key again.  So the lockers are
 * read here directly, and neither thread draws random bytes, whose DRBG
 * would take a locker too.
 */
struct xhart {
    unsigned char key[16], pt[16];
    int start, held, seen, after, ok;
};

/* Pin the calling thread to hart 0. */
static int pin_cpu0(void)
{
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(0, &set);
    return sched_setaffinity(0, sizeof(set), &set) == 0
        && sched_getcpu() == 0;
}

static void *xhart_second(void *arg)
{
    struct xhart *x = arg;
    int i;

    if (!pin_cpu0())
        return NULL;
    x->seen = lockers_in_use();
    for (i = 0; i < KLE_LOCKERS; i++)
        kle_setst(i, KLE_ST_UNCONFIGURED);
    return x;
}

static void *xhart_first(void *arg)
{
    struct xhart *x = arg;
    EVP_CIPHER *c = EVP_CIPHER_fetch(libctx, "AES-128-ECB", "provider=kle");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char ct[16], ref[16];
    AES_KEY ks;
    pthread_t t;
    void *ret = NULL;
    int l, ok;

    ok = c != NULL && ctx != NULL && pin_cpu0();
    x->start = lockers_in_use();
    ok = ok && EVP_EncryptInit_ex2(ctx, c, x->key, NULL, NULL);
    x->held = lockers_in_use();
    /* The second thread runs on this hart while this one waits for it. */
    ok = ok && pthread_create(&t, NULL, xhart_second, x) == 0
        && pthread_join(t, &ret) == 0 && ret == x;
    /* Before the library sees the locker, which it would load again. */
    x->after = lockers_in_use();
    AES_set_encrypt_key(x->key, 128, &ks);
    AES_encrypt(x->pt, ref, &ks);
    OPENSSL_cleanse(&ks, sizeof(ks));
    x->ok = ok && EVP_EncryptUpdate(ctx, ct, &l, x->pt, 16) && l == 16
        && memcmp(ct, ref, 16) == 0;
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
    return NULL;
}

static int test_same_hart(void)
{
    struct xhart x = { 0 };
    pthread_t t;
    int ok;

    if (!TEST_int_eq(RAND_bytes(x.key, 16), 1)
        || !TEST_int_eq(RAND_bytes(x.pt, 16), 1)
        || !TEST_int_eq(pthread_create(&t, NULL, xhart_first, &x), 0)
        || !TEST_int_eq(pthread_join(t, NULL), 0))
        return 0;
    /* Report every check, so that a failure shows what each thread saw. */
    ok = TEST_true(x.ok);
    ok &= TEST_int_eq(x.start, 0);
    ok &= TEST_int_eq(x.held, 1);
    ok &= TEST_int_eq(x.seen, 0);
    ok &= TEST_int_eq(x.after, 1);
    return ok;
}

/* More live contexts than lockers: they evict and reload each other. */
static int test_many_contexts(void)
{
    enum { N = 40 };
    unsigned char key[N][16], iv[16] = { 0 }, pt[32], ct[32], ref[N][48];
    EVP_CIPHER *c = EVP_CIPHER_fetch(libctx, "AES-128-ECB", "provider=kle");
    EVP_CIPHER_CTX *ctx[N] = { 0 };
    int i, round, l, lr, ok = 0;

    if (!TEST_int_eq(RAND_bytes(pt, sizeof(pt)), 1) || !TEST_ptr(c))
        goto err;
    for (i = 0; i < N; i++) {
        if (!TEST_int_eq(RAND_bytes(key[i], 16), 1))
            goto err;
        /* References first: the default provider needs a locker too. */
        if (!do_crypt("AES-128-ECB", "provider=default", key[i], NULL, iv,
                      1, pt, 32, ref[i], &lr))
            goto err;
        if (!TEST_ptr(ctx[i] = EVP_CIPHER_CTX_new())
            || !TEST_true(EVP_EncryptInit_ex2(ctx[i], c, key[i], NULL, NULL))
            || !TEST_true(EVP_CIPHER_CTX_set_padding(ctx[i], 0)))
            goto err;
    }
    for (round = 0; round < 3; round++)
        for (i = 0; i < N; i++) {
            if (!TEST_true(EVP_EncryptUpdate(ctx[i], ct, &l, pt, 32))
                || !TEST_mem_eq(ct, l, ref[i], 32))
                goto err;
        }
    /*
     * Every locker of this thread now holds a kle provider key, which the
     * default provider cannot reclaim: it falls back to software AES.
     */
    for (i = 0; i < 2; i++) {
        unsigned char out[48];
        int lo;

        if (!do_crypt("AES-128-ECB", "provider=default", key[i], NULL, iv,
                      1, pt, 32, out, &lo)
            || !TEST_mem_eq(out, lo, ref[i], 48))
            goto err;
        }
    ok = 1;
err:
    for (i = 0; i < N; i++)
        EVP_CIPHER_CTX_free(ctx[i]);
    EVP_CIPHER_free(c);
    return ok;
}

/*
 * A default provider key that finds no locker it may take when it is used,
 * here in a thread whose lockers the kle provider holds all of, goes on
 * in software AES mid-stream: CTR, and CBC with a decryption key.
 */
struct xfull {
    EVP_CIPHER_CTX *ctx;
    const unsigned char *in;
    unsigned char *out;
    int inl, outl, ok;
};

static void *xfull_run(void *arg)
{
    struct xfull *x = arg;
    EVP_CIPHER *c = EVP_CIPHER_fetch(libctx, "AES-128-ECB", "provider=kle");
    EVP_CIPHER_CTX *held[KLE_LOCKERS] = { 0 };
    unsigned char k[16] = { 0 };
    int i, ok = c != NULL;

    for (i = 0; ok && i < KLE_LOCKERS; i++) {
        k[0] = (unsigned char)i;
        ok = (held[i] = EVP_CIPHER_CTX_new()) != NULL
            && EVP_EncryptInit_ex2(held[i], c, k, NULL, NULL);
    }
    x->ok = ok && lockers_in_use() == KLE_LOCKERS
        && EVP_CipherUpdate(x->ctx, x->out, &x->outl, x->in, x->inl);
    for (i = 0; i < KLE_LOCKERS; i++)
        EVP_CIPHER_CTX_free(held[i]);
    EVP_CIPHER_free(c);
    return NULL;
}

static int test_default_fallback(int idx)
{
    static const char *names[] = { "AES-128-CTR", "AES-256-CBC" };
    const char *name = names[idx];
    int dec = idx == 1;
    unsigned char key[32], iv[16], pt[96], ct[112], out[96];
    EVP_CIPHER *c = EVP_CIPHER_fetch(libctx, name, "provider=default");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    struct xfull x;
    pthread_t t;
    int before, l, lc, ok = 0;

    if (!TEST_int_eq(RAND_bytes(key, sizeof(key)), 1)
        || !TEST_int_eq(RAND_bytes(iv, sizeof(iv)), 1)
        || !TEST_int_eq(RAND_bytes(pt, sizeof(pt)), 1))
        goto err;
    /* Either way ct starts with pt's ciphertext, padded or not. */
    if (!TEST_ptr(c) || !TEST_ptr(ctx)
        || !do_crypt(name, "provider=default", key, NULL, iv, 1,
                     pt, sizeof(pt), ct, &lc))
        goto err;
    before = lockers_in_use();
    if (!TEST_true(EVP_CipherInit_ex2(ctx, c, key, iv, !dec, NULL))
        || !TEST_true(EVP_CIPHER_CTX_set_padding(ctx, 0))
        /* The key is in a locker of this thread, not in software. */
        || !TEST_int_eq(lockers_in_use(), before + 1)
        || !TEST_true(EVP_CipherUpdate(ctx, out, &l, dec ? ct : pt, 40)))
        goto err;
    x = (struct xfull){ ctx, (dec ? ct : pt) + 40, out + l, 56, 0, 0 };
    if (!TEST_int_eq(pthread_create(&t, NULL, xfull_run, &x), 0)
        || !TEST_int_eq(pthread_join(t, NULL), 0)
        || !TEST_true(x.ok)
        || !TEST_mem_eq(out, l + x.outl, dec ? pt : ct, sizeof(pt)))
        goto err;
    ok = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
    return ok;
}

/* ------------------------------------------------------------------ */
/* AES-CTR, checked against software AES independent of the providers  */

static const char *ctr_propq[] = { "provider=default", "provider=kle" };

static void ref_ctr(const unsigned char *key, int keylen,
                    const unsigned char iv[16], const unsigned char *in,
                    size_t len, unsigned char *out)
{
    AES_KEY ks;
    unsigned char ivec[16], ecount[16] = { 0 };
    unsigned int num = 0;

    AES_set_encrypt_key(key, 8 * keylen, &ks);
    memcpy(ivec, iv, 16);
    CRYPTO_ctr128_encrypt(in, out, len, &ks, ivec, ecount, &num,
                          (block128_f)AES_encrypt);
    OPENSSL_cleanse(&ks, sizeof(ks));
}

static EVP_CIPHER_CTX *ctr_ctx(const char *name, const char *propq,
                               const unsigned char *key,
                               const unsigned char *iv)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(libctx, name, propq);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (!TEST_ptr(c) || !TEST_ptr(ctx)
        || !TEST_true(EVP_EncryptInit_ex2(ctx, c, key, iv, NULL))) {
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }
    EVP_CIPHER_free(c);
    return ctx;
}

/* Encrypt len bytes as updates of the given sizes, cycled. */
static int ctr_updates(EVP_CIPHER_CTX *ctx, const unsigned char *in,
                       unsigned char *out, size_t len, const size_t *sizes,
                       size_t nsizes)
{
    size_t i, n;
    int l;

    for (i = 0; len > 0; i++, in += n, out += n, len -= n) {
        n = sizes[i % nsizes] < len ? sizes[i % nsizes] : len;
        if (!TEST_true(EVP_EncryptUpdate(ctx, out, &l, in, (int)n))
            || !TEST_size_t_eq((size_t)l, n))
            return 0;
    }
    return 1;
}

/*
 * The 32-bit counter starts at FFFFFFFE with ones in bytes 8-11, so the
 * stream carries into the upper 96 bits; the second update starts at
 * several offsets around the wrap.
 */
static int test_ctr_wrap(int idx)
{
    static const size_t first[] = { 87, 20, 32, 33 };
    unsigned char key[32], iv[16], pt[87], ct[87], ref[87];
    EVP_CIPHER_CTX *ctx = NULL;
    size_t i;
    int l, ok = 0;

    if (!TEST_int_eq(RAND_bytes(key, sizeof(key)), 1)
        || !TEST_int_eq(RAND_bytes(iv, 8), 1)
        || !TEST_int_eq(RAND_bytes(pt, sizeof(pt)), 1))
        goto err;
    memset(iv + 8, 0xff, 7);
    iv[15] = 0xfe;
    ref_ctr(key, 32, iv, pt, sizeof(pt), ref);
    for (i = 0; i < OSSL_NELEM(first); i++) {
        if (!TEST_ptr(ctx = ctr_ctx("AES-256-CTR", ctr_propq[idx], key, iv))
            || !TEST_true(EVP_EncryptUpdate(ctx, ct, &l, pt, (int)first[i]))
            || !TEST_true(EVP_EncryptUpdate(ctx, ct + first[i], &l,
                                            pt + first[i],
                                            (int)(sizeof(pt) - first[i])))
            || !TEST_mem_eq(ct, sizeof(ct), ref, sizeof(ref)))
            goto err;
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }
    ok = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* Byte-sized updates, then sizes around the block size. */
static int test_ctr_bytewise(int idx)
{
    static const size_t one[] = { 1 };
    static const size_t mixed[] = { 1, 15, 16, 17, 33, 47, 64, 129 };
    unsigned char key[16], iv[16], pt[777], ct[777], ref[777];
    EVP_CIPHER_CTX *ctx = NULL;
    int ok = 0;

    if (!TEST_int_eq(RAND_bytes(key, sizeof(key)), 1)
        || !TEST_int_eq(RAND_bytes(iv, sizeof(iv)), 1)
        || !TEST_int_eq(RAND_bytes(pt, sizeof(pt)), 1))
        goto err;
    ref_ctr(key, 16, iv, pt, sizeof(pt), ref);
    if (!TEST_ptr(ctx = ctr_ctx("AES-128-CTR", ctr_propq[idx], key, iv))
        || !ctr_updates(ctx, pt, ct, 100, one, 1)
        || !ctr_updates(ctx, pt + 100, ct + 100, sizeof(pt) - 100, mixed,
                        OSSL_NELEM(mixed))
        || !TEST_mem_eq(ct, sizeof(ct), ref, sizeof(ref)))
        goto err;
    /* A new IV on the same key, without a new key. */
    iv[3] ^= 0x80;
    ref_ctr(key, 16, iv, pt, sizeof(pt), ref);
    if (!TEST_true(EVP_EncryptInit_ex2(ctx, NULL, NULL, iv, NULL))
        || !ctr_updates(ctx, pt, ct, sizeof(pt), mixed, OSSL_NELEM(mixed))
        || !TEST_mem_eq(ct, sizeof(ct), ref, sizeof(ref)))
        goto err;
    ok = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/*
 * EVP_CIPHER_CTX_copy() in the middle of a block, then enough other
 * contexts of the same provider to evict every locker of this thread: the
 * original and the copy both continue the stream.
 */
static int test_ctr_evict_copy(int idx)
{
    enum { N = 70 };
    unsigned char key[16], iv[16], pt[300], ct[300], ct2[300], ref[300];
    unsigned char k2[16] = { 0 }, buf[16];
    EVP_CIPHER_CTX *ctx = NULL, *dup = NULL, *other[N] = { 0 };
    int i, l, ok = 0;

    if (!TEST_int_eq(RAND_bytes(key, sizeof(key)), 1)
        || !TEST_int_eq(RAND_bytes(iv, sizeof(iv)), 1)
        || !TEST_int_eq(RAND_bytes(pt, sizeof(pt)), 1))
        goto err;
    ref_ctr(key, 16, iv, pt, sizeof(pt), ref);
    if (!TEST_ptr(ctx = ctr_ctx("AES-128-CTR", ctr_propq[idx], key, iv))
        || !TEST_true(EVP_EncryptUpdate(ctx, ct, &l, pt, 100))
        || !TEST_ptr(dup = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_CIPHER_CTX_copy(dup, ctx)))
        goto err;
    for (i = 0; i < N; i++) {
        k2[0] = (unsigned char)i;
        if (!TEST_ptr(other[i] = ctr_ctx("AES-128-CTR", ctr_propq[idx], k2,
                                         iv))
            || !TEST_true(EVP_EncryptUpdate(other[i], buf, &l, pt, 16)))
            goto err;
    }
    memcpy(ct2, ct, 100);
    if (!TEST_true(EVP_EncryptUpdate(ctx, ct + 100, &l, pt + 100, 200))
        || !TEST_true(EVP_EncryptUpdate(dup, ct2 + 100, &l, pt + 100, 200))
        || !TEST_mem_eq(ct, sizeof(ct), ref, sizeof(ref))
        || !TEST_mem_eq(ct2, sizeof(ct2), ref, sizeof(ref)))
        goto err;
    ok = 1;
err:
    for (i = 0; i < N; i++)
        EVP_CIPHER_CTX_free(other[i]);
    EVP_CIPHER_CTX_free(dup);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* Lockers of this thread with the given Machine in the given State. */
static int lockers_with(int machine, int state)
{
    uint64_t m[2];
    int i, n = 0;

    for (i = 0; i < KLE_LOCKERS; i++) {
        kle_getmd(i, m);
        n += KLE_MDH_MACHINE(m[0]) == machine
             && KLE_MDH_STATE(m[0]) == state;
    }
    return n;
}

/*
 * A raw AES-128-CTR key of the default provider goes to the CTR Machine
 * when the unit has it, and is used in Operate; else to the ECB Machine.
 */
static int test_ctr_uses_machine(void)
{
    static const unsigned char key[16], iv[16], pt[32];
    const char *expect = getenv("KLE_EXPECT_CTR");
    int have = kle_ctr_supported();
    int machine = kle_machine(16, have ? KLE_MODE_CTR : KLE_MODE_ECB);
    int state = have ? KLE_ST_OPERATE : KLE_ST_ENCRYPT;
    int before = lockers_with(machine, state), l, ok = 0;
    unsigned char ct[32];
    EVP_CIPHER_CTX *ctx = NULL;

    TEST_info("CTR Machine %s", have ? "present" : "absent");
    if ((expect != NULL && !TEST_int_eq(have, atoi(expect)))
        || !TEST_ptr(ctx = ctr_ctx("AES-128-CTR", "provider=default", key, iv))
        || !TEST_true(EVP_EncryptUpdate(ctx, ct, &l, pt, sizeof(pt)))
        || !TEST_int_eq(lockers_with(machine, state), before + 1))
        goto err;
    ok = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/*
 * Two threads on one hart stream AES-CTR with their own keys, yielding
 * between blocks: the kernel switches their lockers mid-stream, counter
 * included.
 */
struct xpreempt {
    const char *propq;
    unsigned char key[16], iv[16];
    int ok;
};

static void *xpreempt_run(void *arg)
{
    enum { LEN = 16 * 300 };
    struct xpreempt *x = arg;
    unsigned char *pt = OPENSSL_zalloc(3 * LEN), *ct = pt + LEN;
    unsigned char *ref = ct + LEN;
    EVP_CIPHER_CTX *ctx = NULL;
    cpu_set_t set;
    int i, l, ok = pt != NULL;

    CPU_ZERO(&set);
    CPU_SET(0, &set);
    ok = ok && sched_setaffinity(0, sizeof(set), &set) == 0
        && (ctx = ctr_ctx("AES-128-CTR", x->propq, x->key, x->iv)) != NULL;
    if (ok)
        ref_ctr(x->key, 16, x->iv, pt, LEN, ref);
    for (i = 0; ok && i < LEN; i += 16) {
        ok = EVP_EncryptUpdate(ctx, ct + i, &l, pt + i, 16) && l == 16;
        sched_yield();
    }
    x->ok = ok && memcmp(ct, ref, LEN) == 0;
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_free(pt);
    return NULL;
}

static int test_ctr_preempt(int idx)
{
    struct xpreempt x[2];
    pthread_t t[2];
    int i, ok = 1;

    for (i = 0; i < 2; i++) {
        x[i].propq = ctr_propq[idx];
        if (!TEST_int_eq(RAND_bytes(x[i].key, 16), 1)
            || !TEST_int_eq(RAND_bytes(x[i].iv, 16), 1))
            return 0;
        x[i].ok = 0;
    }
    for (i = 0; i < 2; i++)
        if (!TEST_int_eq(pthread_create(&t[i], NULL, xpreempt_run, &x[i]), 0))
            return 0;
    for (i = 0; i < 2; i++)
        ok &= TEST_int_eq(pthread_join(t[i], NULL), 0) & TEST_true(x[i].ok);
    return ok;
}

/*
 * Lockers cleared by other software than the library (here a kl.clear of
 * each by the application): the next update loads the key into a locker
 * again, rather than going on in software, and continues the stream.
 */
static int test_ctr_cleared(int idx)
{
    unsigned char key[16], iv[16], pt[96], ct[96], ref[96];
    EVP_CIPHER_CTX *ctx = NULL;
    int i, l, ok = 0;

    if (!TEST_int_eq(RAND_bytes(key, sizeof(key)), 1)
        || !TEST_int_eq(RAND_bytes(iv, sizeof(iv)), 1)
        || !TEST_int_eq(RAND_bytes(pt, sizeof(pt)), 1))
        goto err;
    ref_ctr(key, 16, iv, pt, sizeof(pt), ref);
    if (!TEST_ptr(ctx = ctr_ctx("AES-128-CTR", ctr_propq[idx], key, iv))
        || !TEST_true(EVP_EncryptUpdate(ctx, ct, &l, pt, 40)))
        goto err;
    for (i = 0; i < KLE_LOCKERS; i++)
        kle_setst(i, KLE_ST_UNCONFIGURED);
    if (!TEST_true(EVP_EncryptUpdate(ctx, ct + 40, &l, pt + 40, 56))
        || !TEST_int_eq(lockers_in_use(), 1)
        || !TEST_mem_eq(ct, sizeof(ct), ref, sizeof(ref)))
        goto err;
    ok = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* ------------------------------------------------------------------ */
/* AES-GCM, checked against CRYPTO_gcm128 on software AES              */

/*
 * The default provider runs GCM's AES on a locker; the kle provider all of
 * GCM on the AES-GCM Machine, if the unit has it.
 */
static const char *gcm_propq[] = { "provider=default", "provider=kle" };

static int gcm_machine(const char *propq)
{
    return strcmp(propq, "provider=kle") == 0;
}

#define GCM_SKIP(propq)                                                 \
    do {                                                                \
        if (gcm_machine(propq) && !kle_gcm_supported())                 \
            return TEST_skip("no AES-GCM Machine");                     \
    } while (0)

/* Any length up to what is left. */
static const size_t whole[] = { (size_t)-1 };

static const char *gcm_name(size_t keylen)
{
    return keylen == 16 ? "AES-128-GCM"
         : keylen == 24 ? "AES-192-GCM" : "AES-256-GCM";
}

static void ref_gcm(const unsigned char *key, size_t keylen,
                    const unsigned char *iv, size_t ivlen,
                    const unsigned char *aad, size_t alen,
                    const unsigned char *in, size_t len, unsigned char *out,
                    unsigned char tag[16])
{
    AES_KEY ks;
    GCM128_CONTEXT *g;

    AES_set_encrypt_key(key, (int)(8 * keylen), &ks);
    g = CRYPTO_gcm128_new(&ks, (block128_f)AES_encrypt);
    CRYPTO_gcm128_setiv(g, iv, ivlen);
    CRYPTO_gcm128_aad(g, aad, alen);
    CRYPTO_gcm128_encrypt(g, in, out, len);
    CRYPTO_gcm128_tag(g, tag, 16);
    CRYPTO_gcm128_release(g);
    OPENSSL_cleanse(&ks, sizeof(ks));
}

/* A GCM context with key and IV of any length, or NULL. */
static EVP_CIPHER_CTX *gcm_ctx(const char *propq, const unsigned char *key,
                               size_t keylen, const unsigned char *iv,
                               size_t ivlen, int enc)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(libctx, gcm_name(keylen), propq);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    OSSL_PARAM p[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, &ivlen),
        OSSL_PARAM_END
    };

    if (!TEST_ptr(c) || !TEST_ptr(ctx)
        || !TEST_true(EVP_CipherInit_ex2(ctx, c, NULL, NULL, enc, p))
        || !TEST_true(EVP_CipherInit_ex2(ctx, NULL, key, iv, enc, NULL))) {
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }
    EVP_CIPHER_free(c);
    return ctx;
}

/*
 * One message on a context that has its key and IV: the AAD and the text
 * in updates of the given sizes (cycled), then the tag, which encryption
 * writes and decryption checks.  0 on any failure, a bad tag included.
 */
static int gcm_message(EVP_CIPHER_CTX *ctx, int enc,
                       const unsigned char *aad, size_t alen,
                       const size_t *asizes, size_t nasizes,
                       const unsigned char *in, size_t len, unsigned char *out,
                       const size_t *sizes, size_t nsizes,
                       unsigned char tag[16])
{
    size_t i, n, done;
    int l;

    if (!enc && !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag))
        return 0;
    for (i = 0, done = 0; done < alen; i++, done += n) {
        n = asizes[i % nasizes] < alen - done ? asizes[i % nasizes]
                                              : alen - done;
        if (!EVP_CipherUpdate(ctx, NULL, &l, aad + done, (int)n))
            return 0;
    }
    for (i = 0, done = 0; done < len; i++, done += n) {
        n = sizes[i % nsizes] < len - done ? sizes[i % nsizes] : len - done;
        if (!EVP_CipherUpdate(ctx, out + done, &l, in + done, (int)n)
            || (size_t)l != n)
            return 0;
    }
    if (!EVP_CipherFinal_ex(ctx, out + len, &l) || l != 0)
        return 0;
    return !enc || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
}

/* Each key length and provider: as the reference, decrypts, a bad tag fails. */
static int test_gcm_vs_ref(int idx)
{
    size_t keylen = 16 + 8 * (idx % 3);
    const char *propq = gcm_propq[idx / 3];
    unsigned char key[32], iv[12], aad[20], pt[777], ct[777], back[777];
    unsigned char ref[777], tag[16], rtag[16];
    EVP_CIPHER_CTX *ctx = NULL;
    int ok = 0;

    GCM_SKIP(propq);
    if (!TEST_int_eq(RAND_bytes(key, sizeof(key)), 1)
        || !TEST_int_eq(RAND_bytes(iv, sizeof(iv)), 1)
        || !TEST_int_eq(RAND_bytes(aad, sizeof(aad)), 1)
        || !TEST_int_eq(RAND_bytes(pt, sizeof(pt)), 1))
        goto err;
    ref_gcm(key, keylen, iv, 12, aad, 20, pt, 777, ref, rtag);
    if (!TEST_ptr(ctx = gcm_ctx(propq, key, keylen, iv, 12, 1))
        || !TEST_true(gcm_message(ctx, 1, aad, 20, whole, 1, pt, 777, ct,
                                  whole, 1, tag))
        || !TEST_mem_eq(ct, sizeof(ct), ref, sizeof(ref))
        || !TEST_mem_eq(tag, 16, rtag, 16))
        goto err;
    EVP_CIPHER_CTX_free(ctx);
    if (!TEST_ptr(ctx = gcm_ctx(propq, key, keylen, iv, 12, 0))
        || !TEST_true(gcm_message(ctx, 0, aad, 20, whole, 1, ct, 777, back,
                                  whole, 1, tag))
        || !TEST_mem_eq(back, sizeof(back), pt, sizeof(pt)))
        goto err;
    /* The same message with a bad tag, on the same context. */
    tag[5] ^= 1;
    if (!TEST_true(EVP_DecryptInit_ex2(ctx, NULL, NULL, iv, NULL))
        || !TEST_false(gcm_message(ctx, 0, aad, 20, whole, 1, ct, 777, back,
                                   whole, 1, tag)))
        goto err;
    ERR_clear_error();
    ok = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/*
 * IVs of 1 to 128 bytes (only 12 makes J0 without GHASH), with AAD and
 * text from empty to several blocks.
 */
static int test_gcm_ivlens(int idx)
{
    static const size_t ivlens[] = { 1, 8, 12, 16, 60, 128 };
    static const size_t alens[] = { 0, 5, 13, 17, 100 };
    static const size_t lens[] = { 0, 1, 15, 16, 17, 100 };
    unsigned char key[16], iv[128], aad[100], pt[100], ct[100], back[100];
    unsigned char ref[100], tag[16], rtag[16];
    EVP_CIPHER_CTX *ctx = NULL;
    size_t i, j, alen;
    int ok = 0;

    GCM_SKIP(gcm_propq[idx]);
    if (!TEST_int_eq(RAND_bytes(key, sizeof(key)), 1)
        || !TEST_int_eq(RAND_bytes(iv, sizeof(iv)), 1)
        || !TEST_int_eq(RAND_bytes(aad, sizeof(aad)), 1)
        || !TEST_int_eq(RAND_bytes(pt, sizeof(pt)), 1))
        goto err;
    for (i = 0; i < OSSL_NELEM(ivlens); i++)
        for (j = 0; j < OSSL_NELEM(lens); j++) {
            alen = alens[(i + j) % OSSL_NELEM(alens)];
            ref_gcm(key, 16, iv, ivlens[i], aad, alen, pt, lens[j], ref, rtag);
            if (!TEST_ptr(ctx = gcm_ctx(gcm_propq[idx], key, 16, iv,
                                        ivlens[i], 1))
                || !TEST_true(gcm_message(ctx, 1, aad, alen, whole, 1, pt,
                                          lens[j], ct, whole, 1, tag))
                || !TEST_mem_eq(ct, lens[j], ref, lens[j])
                || !TEST_mem_eq(tag, 16, rtag, 16))
                goto err;
            EVP_CIPHER_CTX_free(ctx);
            if (!TEST_ptr(ctx = gcm_ctx(gcm_propq[idx], key, 16, iv,
                                        ivlens[i], 0))
                || !TEST_true(gcm_message(ctx, 0, aad, alen, whole, 1, ct,
                                          lens[j], back, whole, 1, tag))
                || !TEST_mem_eq(back, lens[j], pt, lens[j])) {
                TEST_info("IV %zu bytes, AAD %zu, text %zu", ivlens[i], alen,
                          lens[j]);
                goto err;
            }
            EVP_CIPHER_CTX_free(ctx);
            ctx = NULL;
        }
    ok = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/*
 * AAD and text in updates of many sizes, then a second message on the same
 * key under a new IV, as TLS does for each record.  The GCM Machine takes
 * text in whole blocks but the last update.
 */
static int test_gcm_chunked(int idx)
{
    static const size_t asizes[] = { 1, 15, 16, 17, 33 };
    static const size_t mixed[] = { 1, 15, 16, 17, 33, 47, 64, 129 };
    static const size_t blocks[] = { 16, 32, 48, 64, 128 };
    int machine = gcm_machine(gcm_propq[idx]);
    unsigned char key[16], iv[12], aad[300], pt[777], ct[777], ref[777];
    unsigned char tag[16], rtag[16];
    EVP_CIPHER_CTX *ctx = NULL;
    int round, ok = 0;

    GCM_SKIP(gcm_propq[idx]);
    if (!TEST_int_eq(RAND_bytes(key, sizeof(key)), 1)
        || !TEST_int_eq(RAND_bytes(aad, sizeof(aad)), 1)
        || !TEST_int_eq(RAND_bytes(pt, sizeof(pt)), 1))
        goto err;
    for (round = 0; round < 2; round++) {
        if (!TEST_int_eq(RAND_bytes(iv, sizeof(iv)), 1))
            goto err;
        ref_gcm(key, 16, iv, 12, aad, 300, pt, 777, ref, rtag);
        if (round == 0) {
            if (!TEST_ptr(ctx = gcm_ctx(gcm_propq[idx], key, 16, iv, 12, 1)))
                goto err;
        } else if (!TEST_true(EVP_EncryptInit_ex2(ctx, NULL, NULL, iv, NULL))) {
            goto err;
        }
        if (!TEST_true(gcm_message(ctx, 1, aad, 300, asizes,
                                   OSSL_NELEM(asizes), pt, 777, ct,
                                   machine ? blocks : mixed,
                                   machine ? OSSL_NELEM(blocks)
                                           : OSSL_NELEM(mixed), tag))
            || !TEST_mem_eq(ct, sizeof(ct), ref, sizeof(ref))
            || !TEST_mem_eq(tag, 16, rtag, 16))
            goto err;
    }
    ok = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* z = x * y in GF(2^128), in GCM's bit order (SP 800-38D, 6.3). */
static void gf_mul(unsigned char z[16], const unsigned char x[16],
                   const unsigned char y[16])
{
    unsigned char v[16], r[16] = { 0 };
    int i, j, lsb;

    memcpy(v, y, 16);
    for (i = 0; i < 128; i++) {
        if (x[i / 8] & (0x80 >> (i % 8)))
            for (j = 0; j < 16; j++)
                r[j] ^= v[j];
        lsb = v[15] & 1;
        for (j = 15; j > 0; j--)
            v[j] = (unsigned char)(v[j] >> 1 | v[j - 1] << 7);
        v[0] >>= 1;
        if (lsb)
            v[0] ^= 0xe1;
    }
    memcpy(z, r, 16);
}

/* z = x^-1 = x^(2^128 - 2) */
static void gf_inv(unsigned char z[16], const unsigned char x[16])
{
    unsigned char r[16] = { 0x80 };     /* 1 */
    int i;

    for (i = 127; i >= 0; i--) {
        gf_mul(r, r, r);
        if (i > 0)
            gf_mul(r, r, x);
    }
    memcpy(z, r, 16);
}

/*
 * A J0 whose 32-bit counter wraps after two blocks: the text's counter
 * blocks go ...fffffffe, ffffffff, 00000000, with no carry into bytes 0-11
 * (inc32).  A 96-bit IV always starts at 1, so the IV is 16 bytes, solved
 * for J0 = GHASH_H(IV || 0^64 || [128]_64) = ((IV * H) ^ L) * H.  The
 * second update starts at several offsets around the wrap.
 */
static int test_gcm_ctr_wrap(int idx)
{
    static const size_t first[] = { 87, 32, 20, 33 };
    unsigned char key[32], j0[16], h[16], hinv[16], iv[16], cb[16], ks[16];
    unsigned char aad[7], pt[87], ct[87], ref[87], tag[16], rtag[16];
    size_t sizes[2], nfirst = gcm_machine(gcm_propq[idx]) ? 2 : 4;
    AES_KEY aes;
    EVP_CIPHER_CTX *ctx = NULL;
    size_t i;
    int ok = 0;

    GCM_SKIP(gcm_propq[idx]);
    if (!TEST_int_eq(RAND_bytes(key, sizeof(key)), 1)
        || !TEST_int_eq(RAND_bytes(j0, 12), 1)
        || !TEST_int_eq(RAND_bytes(aad, sizeof(aad)), 1)
        || !TEST_int_eq(RAND_bytes(pt, sizeof(pt)), 1))
        goto err;
    memcpy(j0 + 12, "\xff\xff\xff\xfd", 4);
    memset(h, 0, 16);
    AES_set_encrypt_key(key, 256, &aes);
    AES_encrypt(h, h, &aes);
    gf_inv(hinv, h);
    gf_mul(iv, j0, hinv);
    iv[15] ^= 0x80;                     /* L = [0]_64 || [128]_64 */
    gf_mul(iv, iv, hinv);
    /* The first counter block is J0 + 1. */
    memcpy(cb, j0, 16);
    cb[15] = 0xfe;
    AES_encrypt(cb, ks, &aes);
    OPENSSL_cleanse(&aes, sizeof(aes));
    ref_gcm(key, 32, iv, 16, aad, sizeof(aad), pt, sizeof(pt), ref, rtag);
    for (i = 0; i < 16; i++)
        ks[i] ^= pt[i];
    if (!TEST_mem_eq(ref, 16, ks, 16))
        goto err;
    /* Whole blocks first on the GCM Machine. */
    for (i = 0; i < nfirst; i++) {
        sizes[0] = first[i];
        sizes[1] = sizeof(pt);
        if (!TEST_ptr(ctx = gcm_ctx(gcm_propq[idx], key, 32, iv, 16, 1))
            || !TEST_true(gcm_message(ctx, 1, aad, sizeof(aad), whole, 1, pt,
                                      sizeof(pt), ct, sizes, 2, tag))
            || !TEST_mem_eq(ct, sizeof(ct), ref, sizeof(ref))
            || !TEST_mem_eq(tag, 16, rtag, 16))
            goto err;
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }
    ok = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/*
 * A raw AES-128-GCM key of the default provider takes one locker, for
 * encryption whichever the direction: the CTR Machine, used in Operate,
 * when the unit has it, else the ECB Machine in Encrypt.
 */
static int test_gcm_default_machine(void)
{
    unsigned char key[16], iv[12], pt[40], ct[40], back[40], tag[16];
    int have = kle_ctr_supported();
    int machine = kle_machine(16, have ? KLE_MODE_CTR : KLE_MODE_ECB);
    int state = have ? KLE_ST_OPERATE : KLE_ST_ENCRYPT;
    int before = lockers_with(machine, state), i, enc_only = 1, ok = 0;
    EVP_CIPHER_CTX *ec = NULL, *dc = NULL;
    uint64_t m[2];

    if (!TEST_int_eq(RAND_bytes(key, sizeof(key)), 1)
        || !TEST_int_eq(RAND_bytes(iv, sizeof(iv)), 1)
        || !TEST_int_eq(RAND_bytes(pt, sizeof(pt)), 1)
        || !TEST_ptr(ec = gcm_ctx("provider=default", key, 16, iv, 12, 1))
        || !TEST_true(gcm_message(ec, 1, NULL, 0, whole, 1, pt, 40, ct,
                                  whole, 1, tag))
        || !TEST_int_eq(lockers_with(machine, state), before + 1)
        || !TEST_ptr(dc = gcm_ctx("provider=default", key, 16, iv, 12, 0))
        || !TEST_true(gcm_message(dc, 0, NULL, 0, whole, 1, ct, 40, back,
                                  whole, 1, tag))
        || !TEST_mem_eq(back, sizeof(back), pt, sizeof(pt))
        || !TEST_int_eq(lockers_with(machine, state), before + 2))
        goto err;
    for (i = 0; i < KLE_LOCKERS; i++) {
        kle_getmd(i, m);
        if (KLE_MDH_MACHINE(m[0]) == machine && KLE_MDH_STATE(m[0]) == state)
            enc_only &= (m[0] >> 12 & 3) == KLE_POLICY_ENC;
    }
    ok = TEST_true(enc_only);
err:
    EVP_CIPHER_CTX_free(ec);
    EVP_CIPHER_CTX_free(dc);
    return ok;
}

/*
 * EVP_CIPHER_CTX_copy() mid-message, then enough other messages of the
 * same provider to evict every locker of this thread: the original and the
 * copy both finish the message.  On the GCM Machine the message is in the
 * locker, which stays pinned, and the copy takes an SCC of it.
 */
static int test_gcm_evict_copy(int idx)
{
    enum { N = 70 };
    unsigned char key[16], iv[12], aad[20], pt[300], ct[300], ct2[300];
    unsigned char ref[300], tag[16], tag2[16], rtag[16], k2[16] = { 0 };
    unsigned char buf[16];
    EVP_CIPHER_CTX *ctx = NULL, *dup = NULL, *other[N] = { 0 };
    int i, l, ok = 0;

    GCM_SKIP(gcm_propq[idx]);
    if (!TEST_int_eq(RAND_bytes(key, sizeof(key)), 1)
        || !TEST_int_eq(RAND_bytes(iv, sizeof(iv)), 1)
        || !TEST_int_eq(RAND_bytes(aad, sizeof(aad)), 1)
        || !TEST_int_eq(RAND_bytes(pt, sizeof(pt)), 1))
        goto err;
    ref_gcm(key, 16, iv, 12, aad, 20, pt, 300, ref, rtag);
    /* Whole blocks before the copy: the GCM Machine needs that. */
    if (!TEST_ptr(ctx = gcm_ctx(gcm_propq[idx], key, 16, iv, 12, 1))
        || !TEST_true(EVP_EncryptUpdate(ctx, NULL, &l, aad, 20))
        || !TEST_true(EVP_EncryptUpdate(ctx, ct, &l, pt, 96))
        || !TEST_ptr(dup = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_CIPHER_CTX_copy(dup, ctx)))
        goto err;
    for (i = 0; i < N; i++) {
        k2[0] = (unsigned char)i;
        if (!TEST_ptr(other[i] = gcm_ctx(gcm_propq[idx], k2, 16, iv, 12, 1))
            || !TEST_true(gcm_message(other[i], 1, NULL, 0, whole, 1, pt, 16,
                                      buf, whole, 1, tag)))
            goto err;
    }
    memcpy(ct2, ct, 96);
    if (!TEST_true(EVP_EncryptUpdate(ctx, ct + 96, &l, pt + 96, 204))
        || !TEST_true(EVP_EncryptFinal_ex(ctx, buf, &l))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
        || !TEST_true(EVP_EncryptUpdate(dup, ct2 + 96, &l, pt + 96, 204))
        || !TEST_true(EVP_EncryptFinal_ex(dup, buf, &l))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(dup, EVP_CTRL_AEAD_GET_TAG, 16, tag2))
        || !TEST_mem_eq(ct, sizeof(ct), ref, sizeof(ref))
        || !TEST_mem_eq(ct2, sizeof(ct2), ref, sizeof(ref))
        || !TEST_mem_eq(tag, 16, rtag, 16)
        || !TEST_mem_eq(tag2, 16, rtag, 16))
        goto err;
    ok = 1;
err:
    for (i = 0; i < N; i++)
        EVP_CIPHER_CTX_free(other[i]);
    EVP_CIPHER_CTX_free(dup);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/*
 * A default provider GCM key that finds no locker mid-message, in a thread
 * whose lockers the kle provider holds all of, goes on in software AES:
 * GHASH and the counter are in the context already.  idx 1 decrypts.
 */
static int test_gcm_default_fallback(int idx)
{
    int dec = idx == 1;
    unsigned char key[16], iv[12], aad[13], pt[96], ref[96], out[96];
    unsigned char tag[16], rtag[16], buf[16];
    EVP_CIPHER_CTX *ctx = NULL;
    struct xfull x;
    pthread_t t;
    int before, l, ok = 0;

    if (!TEST_int_eq(RAND_bytes(key, sizeof(key)), 1)
        || !TEST_int_eq(RAND_bytes(iv, sizeof(iv)), 1)
        || !TEST_int_eq(RAND_bytes(aad, sizeof(aad)), 1)
        || !TEST_int_eq(RAND_bytes(pt, sizeof(pt)), 1))
        goto err;
    ref_gcm(key, 16, iv, 12, aad, 13, pt, 96, ref, rtag);
    before = lockers_in_use();
    if (!TEST_ptr(ctx = gcm_ctx("provider=default", key, 16, iv, 12, !dec))
        || (dec && !TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                                  16, rtag)))
        || !TEST_true(EVP_CipherUpdate(ctx, NULL, &l, aad, 13))
        /* The key is in a locker of this thread, not in software. */
        || !TEST_int_eq(lockers_in_use(), before + 1)
        || !TEST_true(EVP_CipherUpdate(ctx, out, &l, dec ? ref : pt, 40)))
        goto err;
    x = (struct xfull){ ctx, (dec ? ref : pt) + 40, out + 40, 56, 0, 0 };
    if (!TEST_int_eq(pthread_create(&t, NULL, xfull_run, &x), 0)
        || !TEST_int_eq(pthread_join(t, NULL), 0)
        || !TEST_true(x.ok)
        || !TEST_true(EVP_CipherFinal_ex(ctx, buf, &l))
        || !TEST_mem_eq(out, sizeof(out), dec ? pt : ref, sizeof(out)))
        goto err;
    if (!dec
        && (!TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
            || !TEST_mem_eq(tag, 16, rtag, 16)))
        goto err;
    ok = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/*
 * Two threads on one hart each run a GCM message with their own keys,
 * yielding between blocks: the kernel switches their lockers mid-message.
 */
static void *xpreempt_gcm_run(void *arg)
{
    enum { LEN = 16 * 200 };
    struct xpreempt *x = arg;
    unsigned char *pt = OPENSSL_zalloc(3 * LEN), *ct = pt + LEN;
    unsigned char *ref = ct + LEN, tag[16], rtag[16], buf[16];
    EVP_CIPHER_CTX *ctx = NULL;
    cpu_set_t set;
    int i, l, ok = pt != NULL;

    CPU_ZERO(&set);
    CPU_SET(0, &set);
    ok = ok && sched_setaffinity(0, sizeof(set), &set) == 0
        && (ctx = gcm_ctx(x->propq, x->key, 16, x->iv, 12, 1)) != NULL
        && EVP_EncryptUpdate(ctx, NULL, &l, x->iv, 16);
    if (ok)
        ref_gcm(x->key, 16, x->iv, 12, x->iv, 16, pt, LEN, ref, rtag);
    for (i = 0; ok && i < LEN; i += 16) {
        ok = EVP_EncryptUpdate(ctx, ct + i, &l, pt + i, 16) && l == 16;
        sched_yield();
    }
    x->ok = ok && EVP_EncryptFinal_ex(ctx, buf, &l)
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)
        && memcmp(ct, ref, LEN) == 0 && memcmp(tag, rtag, 16) == 0;
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_free(pt);
    return NULL;
}

static int test_gcm_preempt(int idx)
{
    struct xpreempt x[2];
    pthread_t t[2];
    int i, ok = 1;

    GCM_SKIP(gcm_propq[idx]);
    for (i = 0; i < 2; i++) {
        x[i].propq = gcm_propq[idx];
        if (!TEST_int_eq(RAND_bytes(x[i].key, 16), 1)
            || !TEST_int_eq(RAND_bytes(x[i].iv, 16), 1))
            return 0;
        x[i].ok = 0;
    }
    for (i = 0; i < 2; i++)
        if (!TEST_int_eq(pthread_create(&t[i], NULL, xpreempt_gcm_run, &x[i]),
                         0))
            return 0;
    for (i = 0; i < 2; i++)
        ok &= TEST_int_eq(pthread_join(t[i], NULL), 0) & TEST_true(x[i].ok);
    return ok;
}

/*
 * Lockers cleared mid-message by other software than the library: the
 * default provider loads the key again and finishes the message.  On the
 * GCM Machine the message was in the locker: it fails, with no output,
 * and the next message loads the key again.
 */
static int test_gcm_cleared(int idx)
{
    unsigned char key[16], iv[12], aad[13], pt[96], ct[96], ref[96];
    unsigned char tag[16], rtag[16];
    static const size_t sizes[] = { 48, 48 };
    EVP_CIPHER_CTX *ctx = NULL;
    int i, l, ok = 0;

    GCM_SKIP(gcm_propq[idx]);
    if (!TEST_int_eq(RAND_bytes(key, sizeof(key)), 1)
        || !TEST_int_eq(RAND_bytes(iv, sizeof(iv)), 1)
        || !TEST_int_eq(RAND_bytes(aad, sizeof(aad)), 1)
        || !TEST_int_eq(RAND_bytes(pt, sizeof(pt)), 1))
        goto err;
    ref_gcm(key, 16, iv, 12, aad, 13, pt, 96, ref, rtag);
    if (!TEST_ptr(ctx = gcm_ctx(gcm_propq[idx], key, 16, iv, 12, 1))
        || !TEST_true(EVP_EncryptUpdate(ctx, NULL, &l, aad, 13))
        || !TEST_true(EVP_EncryptUpdate(ctx, ct, &l, pt, (int)sizes[0])))
        goto err;
    for (i = 0; i < KLE_LOCKERS; i++)
        kle_setst(i, KLE_ST_UNCONFIGURED);
    if (gcm_machine(gcm_propq[idx])) {
        memset(ct + sizes[0], 0xa5, sizes[1]);
        if (!TEST_false(EVP_EncryptUpdate(ctx, ct + sizes[0], &l,
                                          pt + sizes[0], (int)sizes[1]))
            || !TEST_char_eq(ct[sizes[0]], 0)
            || !TEST_true(EVP_EncryptInit_ex2(ctx, NULL, NULL, iv, NULL))
            || !TEST_true(gcm_message(ctx, 1, aad, 13, whole, 1, pt, 96, ct,
                                      whole, 1, tag))
            || !TEST_int_eq(lockers_in_use(), 1)
            || !TEST_mem_eq(ct, sizeof(ct), ref, sizeof(ref))
            || !TEST_mem_eq(tag, 16, rtag, 16))
            goto err;
        ERR_clear_error();
        ok = 1;
        goto err;
    }
    if (!TEST_true(EVP_EncryptUpdate(ctx, ct + sizes[0], &l, pt + sizes[0],
                                     (int)sizes[1]))
        || !TEST_true(EVP_EncryptFinal_ex(ctx, ct + 96, &l))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
        || !TEST_int_eq(lockers_in_use(), 1)
        || !TEST_mem_eq(ct, sizeof(ct), ref, sizeof(ref))
        || !TEST_mem_eq(tag, 16, rtag, 16))
        goto err;
    ok = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/*
 * The kle provider's AES-GCM on the AES-GCM Machine: a key for each
 * direction (encrypt-only, decrypt-only), the locker in Success after a
 * message and in Failure after a bad tag, and a next message after either.
 */
static int lockers_with_policy(int machine, int state, int policy)
{
    uint64_t m[2];
    int i, n = 0;

    for (i = 0; i < KLE_LOCKERS; i++) {
        kle_getmd(i, m);
        n += KLE_MDH_MACHINE(m[0]) == machine
             && KLE_MDH_STATE(m[0]) == state
             && (int)(m[0] >> 12 & 3) == policy;
    }
    return n;
}

static int test_gcm_kle_machine(void)
{
    const char *expect = getenv("KLE_EXPECT_GCM");
    int have = kle_gcm_supported(), m128 = kle_machine(16, KLE_MODE_GCM);
    unsigned char key[16], iv[12], aad[13], pt[40], ct[40], back[40];
    unsigned char tag[16], bad[16];
    EVP_CIPHER_CTX *ec = NULL, *dc = NULL;
    uint64_t sz;
    int ok = 0;

    TEST_info("AES-GCM Machine %s", have ? "present" : "absent");
    if (expect != NULL && !TEST_int_eq(have, atoi(expect)))
        return 0;
    if (!have)
        return TEST_skip("no AES-GCM Machine");
    KLE_I_SIZE_MDH(KLE_MDH_LO(kle_machine(32, KLE_MODE_GCM), 3, 0)
                   | (uint64_t)KLE_ST_ENCRYPT << 18, sz);
    if (!TEST_uint64_t_eq(sz, 112)
        || !TEST_int_eq(RAND_bytes(key, sizeof(key)), 1)
        || !TEST_int_eq(RAND_bytes(iv, sizeof(iv)), 1)
        || !TEST_int_eq(RAND_bytes(aad, sizeof(aad)), 1)
        || !TEST_int_eq(RAND_bytes(pt, sizeof(pt)), 1)
        || !TEST_ptr(ec = gcm_ctx("provider=kle", key, 16, iv, 12, 1))
        || !TEST_true(gcm_message(ec, 1, aad, 13, whole, 1, pt, 40, ct,
                                  whole, 1, tag))
        || !TEST_int_eq(lockers_with_policy(m128, KLE_ST_SUCCESS,
                                            KLE_POLICY_ENC), 1)
        || !TEST_ptr(dc = gcm_ctx("provider=kle", key, 16, iv, 12, 0))
        || !TEST_true(gcm_message(dc, 0, aad, 13, whole, 1, ct, 40, back,
                                  whole, 1, tag))
        || !TEST_mem_eq(back, sizeof(back), pt, sizeof(pt))
        || !TEST_int_eq(lockers_with_policy(m128, KLE_ST_SUCCESS,
                                            KLE_POLICY_DEC), 1))
        goto err;
    memcpy(bad, tag, 16);
    bad[0] ^= 0x80;
    if (!TEST_true(EVP_DecryptInit_ex2(dc, NULL, NULL, iv, NULL))
        || !TEST_false(gcm_message(dc, 0, aad, 13, whole, 1, ct, 40, back,
                                   whole, 1, bad))
        || !TEST_int_eq(lockers_with_policy(m128, KLE_ST_FAILURE,
                                            KLE_POLICY_DEC), 1)
        || !TEST_true(EVP_DecryptInit_ex2(dc, NULL, NULL, iv, NULL))
        || !TEST_true(gcm_message(dc, 0, aad, 13, whole, 1, ct, 40, back,
                                  whole, 1, tag)))
        goto err;
    ERR_clear_error();
    ok = 1;
err:
    EVP_CIPHER_CTX_free(ec);
    EVP_CIPHER_CTX_free(dc);
    return ok;
}

/*
 * The GCM Machine must know a partial block is the last one: an update
 * that is not whole blocks ends the text, and more text fails.  So does
 * AAD after text.  A new IV starts a message again; a short tag is not
 * accepted.
 */
static int test_gcm_kle_closed_body(void)
{
    unsigned char key[16], iv[12], pt[64], ct[64], ref[64], tag[16], rtag[16];
    EVP_CIPHER_CTX *ctx = NULL;
    int l, ok = 0;

    if (!kle_gcm_supported())
        return TEST_skip("no AES-GCM Machine");
    if (!TEST_int_eq(RAND_bytes(key, sizeof(key)), 1)
        || !TEST_int_eq(RAND_bytes(iv, sizeof(iv)), 1)
        || !TEST_int_eq(RAND_bytes(pt, sizeof(pt)), 1)
        || !TEST_ptr(ctx = gcm_ctx("provider=kle", key, 16, iv, 12, 1))
        || !TEST_true(EVP_EncryptUpdate(ctx, ct, &l, pt, 20))
        || !TEST_false(EVP_EncryptUpdate(ctx, ct + 20, &l, pt + 20, 16))
        || !TEST_true(EVP_EncryptInit_ex2(ctx, NULL, NULL, iv, NULL))
        || !TEST_true(EVP_EncryptUpdate(ctx, ct, &l, pt, 16))
        || !TEST_false(EVP_EncryptUpdate(ctx, NULL, &l, pt, 16)))
        goto err;
    ERR_clear_error();
    ref_gcm(key, 16, iv, 12, NULL, 0, pt, 64, ref, rtag);
    if (!TEST_true(EVP_EncryptInit_ex2(ctx, NULL, NULL, iv, NULL))
        || !TEST_true(gcm_message(ctx, 1, NULL, 0, whole, 1, pt, 64, ct,
                                  whole, 1, tag))
        || !TEST_mem_eq(ct, sizeof(ct), ref, sizeof(ref))
        || !TEST_mem_eq(tag, 16, rtag, 16))
        goto err;
    EVP_CIPHER_CTX_free(ctx);
    /* A 12-byte tag cannot be checked by the Machine. */
    if (!TEST_ptr(ctx = gcm_ctx("provider=kle", key, 16, iv, 12, 0))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 12,
                                          rtag))
        || !TEST_true(EVP_DecryptUpdate(ctx, pt, &l, ct, 64))
        || !TEST_false(EVP_DecryptFinal_ex(ctx, pt + 64, &l)))
        goto err;
    ERR_clear_error();
    ok = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/*
 * A kle key for decryption, its context then turned to encryption without
 * a new key: refused, without harming the locker, which still decrypts.
 */
static int test_gcm_kle_policy(void)
{
    unsigned char key[16], iv[12], pt[32], ct[32], back[32], tag[16];
    EVP_CIPHER_CTX *ctx = NULL;
    int l, ok = 0;

    if (!kle_gcm_supported())
        return TEST_skip("no AES-GCM Machine");
    if (!TEST_int_eq(RAND_bytes(key, sizeof(key)), 1)
        || !TEST_int_eq(RAND_bytes(iv, sizeof(iv)), 1)
        || !TEST_int_eq(RAND_bytes(pt, sizeof(pt)), 1))
        goto err;
    ref_gcm(key, 16, iv, 12, NULL, 0, pt, 32, ct, tag);
    if (!TEST_ptr(ctx = gcm_ctx("provider=kle", key, 16, iv, 12, 0))
        || !TEST_true(EVP_EncryptInit_ex2(ctx, NULL, NULL, iv, NULL))
        || !TEST_false(EVP_EncryptUpdate(ctx, back, &l, pt, 32))
        || !TEST_true(EVP_DecryptInit_ex2(ctx, NULL, NULL, iv, NULL))
        || !TEST_true(gcm_message(ctx, 0, NULL, 0, whole, 1, ct, 32, back,
                                  whole, 1, tag))
        || !TEST_mem_eq(back, sizeof(back), pt, sizeof(pt)))
        goto err;
    ERR_clear_error();
    ok = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/*
 * The locker of an open message is pinned: in a new thread, 32 kle GCM
 * messages open at once leave no locker for a 33rd key, rather than
 * evicting one of them; all 32 finish, and then the 33rd key loads.
 */
struct xpinned {
    unsigned char key[KLE_LOCKERS + 1][16], iv[12], pt[48];
    unsigned char ref[KLE_LOCKERS][48], rtag[KLE_LOCKERS][16];
    int ok, refused, finished, last;
};

static void *xpinned_run(void *arg)
{
    struct xpinned *x = arg;
    EVP_CIPHER *c = EVP_CIPHER_fetch(libctx, "AES-128-GCM", "provider=kle");
    EVP_CIPHER_CTX *ctx[KLE_LOCKERS + 1] = { 0 };
    unsigned char ct[48], tag[16], buf[16];
    int i, l, ok = c != NULL;

    for (i = 0; ok && i < KLE_LOCKERS; i++)
        ok = (ctx[i] = EVP_CIPHER_CTX_new()) != NULL
            && EVP_EncryptInit_ex2(ctx[i], c, x->key[i], x->iv, NULL)
            && EVP_EncryptUpdate(ctx[i], ct, &l, x->pt, 16);
    x->ok = ok && lockers_in_use() == KLE_LOCKERS;
    ok = ok && (ctx[KLE_LOCKERS] = EVP_CIPHER_CTX_new()) != NULL;
    x->refused = ok && !EVP_EncryptInit_ex2(ctx[KLE_LOCKERS], c,
                                            x->key[KLE_LOCKERS], x->iv, NULL);
    ERR_clear_error();
    for (i = 0; ok && i < KLE_LOCKERS; i++) {
        ok = EVP_EncryptUpdate(ctx[i], ct + 16, &l, x->pt + 16, 32)
            && EVP_EncryptFinal_ex(ctx[i], buf, &l)
            && EVP_CIPHER_CTX_ctrl(ctx[i], EVP_CTRL_AEAD_GET_TAG, 16, tag);
        if (ok && memcmp(ct + 16, x->ref[i] + 16, 32) == 0
            && memcmp(tag, x->rtag[i], 16) == 0)
            x->finished++;
    }
    x->last = ok && EVP_EncryptInit_ex2(ctx[KLE_LOCKERS], c,
                                        x->key[KLE_LOCKERS], x->iv, NULL);
    for (i = 0; i <= KLE_LOCKERS; i++)
        EVP_CIPHER_CTX_free(ctx[i]);
    EVP_CIPHER_free(c);
    return NULL;
}

static int test_gcm_kle_pinned(void)
{
    struct xpinned *x = OPENSSL_zalloc(sizeof(*x));
    pthread_t t;
    int i, ok = 0;

    if (!kle_gcm_supported()) {
        OPENSSL_free(x);
        return TEST_skip("no AES-GCM Machine");
    }
    if (!TEST_ptr(x)
        || !TEST_int_eq(RAND_bytes((unsigned char *)x->key, sizeof(x->key)), 1)
        || !TEST_int_eq(RAND_bytes(x->iv, sizeof(x->iv)), 1)
        || !TEST_int_eq(RAND_bytes(x->pt, sizeof(x->pt)), 1))
        goto err;
    for (i = 0; i < KLE_LOCKERS; i++)
        ref_gcm(x->key[i], 16, x->iv, 12, NULL, 0, x->pt, 48, x->ref[i],
                x->rtag[i]);
    if (!TEST_int_eq(pthread_create(&t, NULL, xpinned_run, x), 0)
        || !TEST_int_eq(pthread_join(t, NULL), 0))
        goto err;
    ok = TEST_true(x->ok);
    ok &= TEST_true(x->refused);
    ok &= TEST_int_eq(x->finished, KLE_LOCKERS);
    ok &= TEST_true(x->last);
err:
    OPENSSL_free(x);
    return ok;
}

/*
 * A kle GCM message started in one thread and continued in another fails
 * there cleanly: its locker is in the first thread.  A new message in the
 * second thread works.
 */
struct xhop {
    EVP_CIPHER_CTX *ctx;
    const unsigned char *iv, *pt, *ref;
    int failed, ok;
};

static void *xhop_run(void *arg)
{
    struct xhop *x = arg;
    unsigned char ct[32], buf[16];
    int l;

    x->failed = !EVP_EncryptUpdate(x->ctx, ct, &l, x->pt + 16, 16);
    ERR_clear_error();
    x->ok = EVP_EncryptInit_ex2(x->ctx, NULL, NULL, x->iv, NULL)
        && EVP_EncryptUpdate(x->ctx, ct, &l, x->pt, 32)
        && EVP_EncryptFinal_ex(x->ctx, buf, &l)
        && memcmp(ct, x->ref, 32) == 0;
    return NULL;
}

static int test_gcm_kle_thread_hop(void)
{
    unsigned char key[16], iv[12], pt[32], ct[32], ref[32], rtag[16];
    EVP_CIPHER_CTX *ctx = NULL;
    struct xhop x;
    pthread_t t;
    int l, ok = 0;

    if (!kle_gcm_supported())
        return TEST_skip("no AES-GCM Machine");
    if (!TEST_int_eq(RAND_bytes(key, sizeof(key)), 1)
        || !TEST_int_eq(RAND_bytes(iv, sizeof(iv)), 1)
        || !TEST_int_eq(RAND_bytes(pt, sizeof(pt)), 1))
        goto err;
    ref_gcm(key, 16, iv, 12, NULL, 0, pt, 32, ref, rtag);
    if (!TEST_ptr(ctx = gcm_ctx("provider=kle", key, 16, iv, 12, 1))
        || !TEST_true(EVP_EncryptUpdate(ctx, ct, &l, pt, 16)))
        goto err;
    x = (struct xhop){ ctx, iv, pt, ref, 0, 0 };
    if (!TEST_int_eq(pthread_create(&t, NULL, xhop_run, &x), 0)
        || !TEST_int_eq(pthread_join(t, NULL), 0))
        goto err;
    ok = TEST_true(x.failed);
    ok &= TEST_true(x.ok);
err:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* TLS 1.2 additional data: sequence number, type, version, length. */
static void tls12_aad(unsigned char aad[13], uint64_t seq, size_t len)
{
    int i;

    for (i = 0; i < 8; i++)
        aad[i] = (unsigned char)(seq >> (56 - 8 * i));
    aad[8] = 23;
    aad[9] = 3;
    aad[10] = 3;
    aad[11] = (unsigned char)(len >> 8);
    aad[12] = (unsigned char)len;
}

/*
 * TLS 1.2 records as libssl makes them: the fixed part of the IV once,
 * then per record the additional data (EVP_CTRL_AEAD_TLS1_AAD) and one
 * in-place update over the explicit IV, which the encrypting context
 * generates, the payload and the tag: the provider's one-shot path.  idx
 * picks the providers that encrypt and decrypt.  A changed byte fails.
 */
static int test_gcm_tls12(int idx)
{
    const char *encq = gcm_propq[idx % OSSL_NELEM(gcm_propq)];
    const char *decq = gcm_propq[idx / OSSL_NELEM(gcm_propq)];
    unsigned char key[16], fixed[4], aad[13], pt[300], rec[8 + 300 + 16];
    EVP_CIPHER *ce = EVP_CIPHER_fetch(libctx, "AES-128-GCM", encq);
    EVP_CIPHER *cd = EVP_CIPHER_fetch(libctx, "AES-128-GCM", decq);
    EVP_CIPHER_CTX *ec = EVP_CIPHER_CTX_new(), *dc = EVP_CIPHER_CTX_new();
    size_t len;
    int seq, l, ok = 0;

    if ((gcm_machine(encq) || gcm_machine(decq)) && !kle_gcm_supported()) {
        ok = TEST_skip("no AES-GCM Machine");
        goto err;
    }
    if (!TEST_ptr(ce) || !TEST_ptr(cd) || !TEST_ptr(ec) || !TEST_ptr(dc)
        || !TEST_int_eq(RAND_bytes(key, sizeof(key)), 1)
        || !TEST_int_eq(RAND_bytes(fixed, sizeof(fixed)), 1)
        || !TEST_int_eq(RAND_bytes(pt, sizeof(pt)), 1)
        || !TEST_true(EVP_CipherInit_ex(ec, ce, NULL, key, NULL, 1))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(ec, EVP_CTRL_GCM_SET_IV_FIXED, 4,
                                          fixed))
        || !TEST_true(EVP_CipherInit_ex(dc, cd, NULL, key, NULL, 0))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(dc, EVP_CTRL_GCM_SET_IV_FIXED, 4,
                                          fixed)))
        goto err;
    for (seq = 0; seq < 4; seq++) {
        len = seq < 3 ? 100 * (size_t)seq + 7 : 64;
        memcpy(rec + 8, pt, len);
        tls12_aad(aad, seq, 8 + len);
        if (!TEST_int_eq(EVP_CIPHER_CTX_ctrl(ec, EVP_CTRL_AEAD_TLS1_AAD, 13,
                                             aad), 16)
            || !TEST_true(EVP_CipherUpdate(ec, rec, &l, rec, (int)len + 24))
            || !TEST_int_eq(l, (int)len + 24))
            goto err;
        if (seq == 3)
            rec[8 + 10] ^= 1;
        tls12_aad(aad, seq, 8 + len + 16);
        if (!TEST_int_eq(EVP_CIPHER_CTX_ctrl(dc, EVP_CTRL_AEAD_TLS1_AAD, 13,
                                             aad), 16))
            goto err;
        if (seq < 3
            && (!TEST_true(EVP_CipherUpdate(dc, rec, &l, rec, (int)len + 24))
                || !TEST_int_eq(l, (int)len)
                || !TEST_mem_eq(rec + 8, len, pt, len)))
            goto err;
        if (seq == 3
            && !TEST_false(EVP_CipherUpdate(dc, rec, &l, rec, (int)len + 24)))
            goto err;
    }
    ERR_clear_error();
    ok = 1;
err:
    EVP_CIPHER_CTX_free(ec);
    EVP_CIPHER_CTX_free(dc);
    EVP_CIPHER_free(ce);
    EVP_CIPHER_free(cd);
    return ok;
}

/*
 * A forked child starts without lockers, but with its parent's contexts.
 * In a new thread, whose lockers are all Unconfigured: a default provider
 * context takes the first one.  After the fork, the child first gives a
 * kle provider key the same locker, then continues the default provider's
 * stream, which must not run on that key.  The parent's stream continues
 * too.
 */
struct xfork {
    unsigned char key[2][16], iv[16];
    int ok;
};

static void *xfork_run(void *arg)
{
    enum { LEN = 48 };
    struct xfork *x = arg;
    unsigned char pt[2 * LEN], ct[2 * LEN], ref[2 * LEN], ref2[LEN];
    EVP_CIPHER_CTX *ctx, *ctx2;
    pid_t pid = -1;
    int l, st, ok;

    memset(pt, 0x5a, sizeof(pt));
    ref_ctr(x->key[0], 16, x->iv, pt, sizeof(pt), ref);
    ref_ctr(x->key[1], 16, x->iv, pt, LEN, ref2);
    ok = (ctx = ctr_ctx("AES-128-CTR", "provider=default", x->key[0],
                        x->iv)) != NULL
        && EVP_EncryptUpdate(ctx, ct, &l, pt, LEN)
        && (pid = fork()) >= 0;
    if (pid == 0) {
        ok = (ctx2 = ctr_ctx("AES-128-CTR", "provider=kle", x->key[1],
                             x->iv)) != NULL
            && EVP_EncryptUpdate(ctx2, ct, &l, pt, LEN)
            && memcmp(ct, ref2, LEN) == 0
            && EVP_EncryptUpdate(ctx, ct + LEN, &l, pt + LEN, LEN)
            && memcmp(ct + LEN, ref + LEN, LEN) == 0;
        _exit(ok ? 0 : 1);
    }
    x->ok = ok
        && EVP_EncryptUpdate(ctx, ct + LEN, &l, pt + LEN, LEN)
        && memcmp(ct, ref, sizeof(ref)) == 0
        && waitpid(pid, &st, 0) == pid && WIFEXITED(st)
        && WEXITSTATUS(st) == 0;
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
}

static int test_fork(void)
{
    struct xfork x = { 0 };
    pthread_t t;

    if (!TEST_int_eq(RAND_bytes(x.key[0], 16), 1)
        || !TEST_int_eq(RAND_bytes(x.key[1], 16), 1)
        || !TEST_int_eq(RAND_bytes(x.iv, 16), 1))
        return 0;
    return TEST_int_eq(pthread_create(&t, NULL, xfork_run, &x), 0)
        && TEST_int_eq(pthread_join(t, NULL), 0)
        && TEST_true(x.ok);
}

/*
 * A locker that other software cleared and another component then took is
 * neither used nor evicted through the old record: nothing in a locker says
 * which key it holds, so the record must go when the locker is taken.  Here
 * the application clears every locker of a fresh thread, and the kle
 * provider takes them all, the one in the record of the default provider's
 * key a too.  Then a, used again, and a new default provider key b find no
 * locker their provider may take: both go on in software, and every kle
 * provider context keeps its key.
 */
struct xstale {
    unsigned char ka[16], kb[16], pt[16];
    int wrong, a_ok, b_ok, ok;
};

/* Does ct hold pt encrypted under the AES-128 key? */
static int xstale_check(const unsigned char *key, const unsigned char *pt,
                        const unsigned char *ct)
{
    unsigned char ref[16];
    AES_KEY ks;
    int ok;

    AES_set_encrypt_key(key, 128, &ks);
    AES_encrypt(pt, ref, &ks);
    ok = memcmp(ct, ref, 16) == 0;
    OPENSSL_cleanse(&ks, sizeof(ks));
    return ok;
}

static void *xstale_run(void *arg)
{
    struct xstale *x = arg;
    EVP_CIPHER *cd = EVP_CIPHER_fetch(libctx, "AES-128-ECB",
                                      "provider=default");
    EVP_CIPHER *ck = EVP_CIPHER_fetch(libctx, "AES-128-ECB", "provider=kle");
    EVP_CIPHER_CTX *a = EVP_CIPHER_CTX_new(), *b = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *held[KLE_LOCKERS] = { 0 };
    unsigned char k[16] = { 0 }, ct[16];
    int i, l, ok;

    /* A default provider key in a locker of this fresh thread. */
    ok = cd != NULL && ck != NULL && a != NULL && b != NULL
        && EVP_EncryptInit_ex2(a, cd, x->ka, NULL, NULL)
        && lockers_in_use() == 1;
    /* The application clears every locker. */
    for (i = 0; i < KLE_LOCKERS; i++)
        kle_setst(i, KLE_ST_UNCONFIGURED);
    /* The kle provider takes them all, the one in a's record too. */
    for (i = 0; ok && i < KLE_LOCKERS; i++) {
        k[0] = (unsigned char)i;
        ok = (held[i] = EVP_CIPHER_CTX_new()) != NULL
            && EVP_EncryptInit_ex2(held[i], ck, k, NULL, NULL);
    }
    ok = ok && lockers_in_use() == KLE_LOCKERS;
    /* a again: its record is gone, so it must not run on a kle key. */
    ok = ok && EVP_EncryptUpdate(a, ct, &l, x->pt, 16) && l == 16;
    x->a_ok = ok && xstale_check(x->ka, x->pt, ct);
    /* A new default provider key: no locker is free or of its provider. */
    ok = ok && EVP_EncryptInit_ex2(b, cd, x->kb, NULL, NULL)
        && EVP_EncryptUpdate(b, ct, &l, x->pt, 16) && l == 16;
    x->b_ok = ok && xstale_check(x->kb, x->pt, ct);
    for (i = 0; ok && i < KLE_LOCKERS; i++) {
        k[0] = (unsigned char)i;
        ok = EVP_EncryptUpdate(held[i], ct, &l, x->pt, 16) && l == 16;
        if (ok && !xstale_check(k, x->pt, ct))
            x->wrong++;
    }
    x->ok = ok && lockers_in_use() == KLE_LOCKERS;
    for (i = 0; i < KLE_LOCKERS; i++)
        EVP_CIPHER_CTX_free(held[i]);
    EVP_CIPHER_CTX_free(a);
    EVP_CIPHER_CTX_free(b);
    EVP_CIPHER_free(cd);
    EVP_CIPHER_free(ck);
    return NULL;
}

static int test_stale_record(void)
{
    struct xstale x = { 0 };
    pthread_t t;
    int ok;

    if (!TEST_int_eq(RAND_bytes(x.ka, 16), 1)
        || !TEST_int_eq(RAND_bytes(x.kb, 16), 1)
        || !TEST_int_eq(RAND_bytes(x.pt, 16), 1)
        || !TEST_int_eq(pthread_create(&t, NULL, xstale_run, &x), 0)
        || !TEST_int_eq(pthread_join(t, NULL), 0)
        || !TEST_true(x.ok))
        return 0;
    /* Report every context that ran on a wrong key. */
    ok = TEST_true(x.a_ok);
    ok &= TEST_true(x.b_ok);
    ok &= TEST_int_eq(x.wrong, 0);
    return ok;
}

/*
 * The library names every locker through klnamedlocker and restores it
 * after every operation (Rule SR9), so a value the application left there
 * survives provisioning, export, import (also a failing one, which clears
 * its locker), State reads, Encrypt and Decrypt, kl.exec, and the CTR
 * Machine's IV, counter and keystream, in both providers, and AES-GCM.
 */
static int test_keeps_named_locker(void)
{
    uint64_t nl;
    int ok;

    KLE_I_SETNL(5);
    ok = test_skey_raw() && test_skey_generate_and_tamper()
         && test_ctr_wrap(0) && test_ctr_wrap(1) && test_gcm_ivlens(0)
         && (!kle_gcm_supported() || test_gcm_ivlens(1));
    KLE_I_GETNL(nl);
    KLE_I_SETNL(KLE_LOCKERS);
    return ok && TEST_uint64_t_eq(nl, 5);
}

int setup_tests(void)
{
    if (!TEST_ptr(libctx = OSSL_LIB_CTX_new())
        || !TEST_ptr(prov_default = OSSL_PROVIDER_load(libctx, "default")))
        return 0;
    prov_kle = OSSL_PROVIDER_load(libctx, "kle");
    if (prov_kle == NULL) {
        TEST_skip("kle provider not available (no Zkl hart?)");
        return 1;
    }
    ADD_ALL_TESTS(test_provider_vs_default, OSSL_NELEM(ciphers));
    ADD_TEST(test_default_uses_lockers);
    ADD_TEST(test_skey_raw);
    ADD_TEST(test_skey_store);
    ADD_TEST(test_skey_generate_and_tamper);
    ADD_TEST(test_cross_thread);
    ADD_TEST(test_cross_thread_release);
    ADD_TEST(test_same_hart);
    ADD_TEST(test_many_contexts);
    ADD_ALL_TESTS(test_default_fallback, 2);
    ADD_ALL_TESTS(test_ctr_wrap, OSSL_NELEM(ctr_propq));
    ADD_ALL_TESTS(test_ctr_bytewise, OSSL_NELEM(ctr_propq));
    ADD_ALL_TESTS(test_ctr_evict_copy, OSSL_NELEM(ctr_propq));
    ADD_TEST(test_ctr_uses_machine);
    ADD_ALL_TESTS(test_ctr_preempt, OSSL_NELEM(ctr_propq));
    ADD_ALL_TESTS(test_ctr_cleared, OSSL_NELEM(ctr_propq));
    ADD_ALL_TESTS(test_gcm_vs_ref, 3 * OSSL_NELEM(gcm_propq));
    ADD_ALL_TESTS(test_gcm_ivlens, OSSL_NELEM(gcm_propq));
    ADD_ALL_TESTS(test_gcm_chunked, OSSL_NELEM(gcm_propq));
    ADD_ALL_TESTS(test_gcm_ctr_wrap, OSSL_NELEM(gcm_propq));
    ADD_TEST(test_gcm_default_machine);
    ADD_ALL_TESTS(test_gcm_evict_copy, OSSL_NELEM(gcm_propq));
    ADD_ALL_TESTS(test_gcm_default_fallback, 2);
    ADD_ALL_TESTS(test_gcm_preempt, OSSL_NELEM(gcm_propq));
    ADD_ALL_TESTS(test_gcm_cleared, OSSL_NELEM(gcm_propq));
    ADD_ALL_TESTS(test_gcm_tls12, OSSL_NELEM(gcm_propq) * OSSL_NELEM(gcm_propq));
    ADD_TEST(test_gcm_kle_machine);
    ADD_TEST(test_gcm_kle_closed_body);
    ADD_TEST(test_gcm_kle_policy);
    ADD_TEST(test_gcm_kle_pinned);
    ADD_TEST(test_gcm_kle_thread_hop);
    ADD_TEST(test_fork);
    ADD_TEST(test_keeps_named_locker);
    ADD_TEST(test_stale_record);
    return 1;
}

void cleanup_tests(void)
{
    OSSL_PROVIDER_unload(prov_kle);
    OSSL_PROVIDER_unload(prov_default);
    OSSL_LIB_CTX_free(libctx);
}
