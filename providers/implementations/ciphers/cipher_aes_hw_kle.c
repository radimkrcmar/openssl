/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * AES-ECB/CBC/CTR on RISC-V Zkl (KLE) cryptographic lockers (prototype).
 *
 * The key schedule area of PROV_AES_CTX holds a KLE_KEY: the Sealed
 * Cryptographic Context of the key and where it is loaded.  In the default
 * provider it also keeps the raw key, for software AES when the key cannot
 * get a locker of the thread that uses it.  ECB runs on the
 * AES-ECB Machine, and CBC is built here from batches of ECB blocks, as the
 * Zkl specification intends for chaining modes.  CTR runs on the AES-CTR
 * Machine, which generates the keystream itself, when the unit has it;
 * otherwise, and for EVP_SKEY keys, which are ECB keys, CTR encrypts counter
 * blocks on the ECB Machine.  This file is compiled into the default
 * provider, which uses it transparently for raw keys, and into the kle
 * provider, which also takes keys that never leave the unit (EVP_SKEY).
 *
 * The default provider also runs AES-GCM here, on the same Machines, with
 * GHASH in software; the kle provider has the AES-GCM Machine for it
 * (cipher_aes_gcm_kle.c).
 */

/* AES_* for the software fallback of the default provider */
#include "internal/deprecated.h"

#include <string.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "cipher_aes.h"
#include "cipher_aes_gcm.h"
#include "crypto/riscv_kle.h"

#ifdef OSSL_RISCV_KLE

KLE_DEFINE_COMPONENT;

#ifndef KLE_PROVIDER
#include <pthread.h>

/*
 * The locker tables of the process, in libcrypto: util/libcrypto.num
 * exports them to the kle provider module.
 */
__thread struct kle_table ossl_kle_table;
struct kle_releases ossl_kle_releases;
static pthread_once_t kle_atfork = PTHREAD_ONCE_INIT;

/*
 * The only thread of a forked child has a copy of the forking thread's
 * table, but no lockers.  Every component takes the Unconfigured lockers
 * it names as free, but software outside the library that configures one
 * would have its key used and evicted through the copied records.
 */
static void kle_atfork_child(void)
{
    memset(&ossl_kle_table, 0, sizeof(ossl_kle_table));
}

static void kle_atfork_init(void)
{
    pthread_atfork(NULL, NULL, kle_atfork_child);
}

uint64_t ossl_kle_next_gen(void)
{
    /* Before the first locker goes into a table. */
    pthread_once(&kle_atfork, kle_atfork_init);
    return __atomic_add_fetch(&ossl_kle_releases.next_gen, 1,
                              __ATOMIC_RELAXED);
}
#endif

/* What lives in the key schedule area of PROV_AES_CTX. */
typedef struct {
    KLE_KEY k;             /* first: the mode functions get a KLE_KEY */
#ifndef KLE_PROVIDER
    unsigned char raw[32];
    size_t rawlen;          /* 0: no raw key, no software fallback */
#endif
} KLE_AES_KEY;

typedef char kle_key_fits[sizeof(KLE_AES_KEY)
                           <= sizeof(((PROV_AES_CTX *)0)->ks) ? 1 : -1];

/* Bytes per CBC kl.exec batch built on the stack. */
#define KLE_BATCH 256

static KLE_AES_KEY *kle_aes_key(PROV_CIPHER_CTX *dat)
{
    return (KLE_AES_KEY *)&((PROV_AES_CTX *)dat)->ks;
}

static KLE_KEY *kle_key(PROV_CIPHER_CTX *dat)
{
    return &kle_aes_key(dat)->k;
}

/* Does the context need a decryption key?  CTR always encrypts. */
static int kle_decrypts(const PROV_CIPHER_CTX *dat)
{
    return !dat->enc && (dat->mode == EVP_CIPH_ECB_MODE
                         || dat->mode == EVP_CIPH_CBC_MODE);
}

/*
 * The mode functions below run only from kle_cipher(), which has put the
 * key into a locker of this thread in the right state, once per call; they
 * cannot report errors.
 */
static int kle_locker(const void *key)
{
    return ((const KLE_KEY *)key)->locker;
}

static void kle_block(const unsigned char in[16], unsigned char out[16],
                       const void *key)
{
    kle_exec(kle_locker(key), in, out, 16);
}

static void kle_ecb(const unsigned char *in, unsigned char *out, size_t len,
                     const void *key, int enc)
{
    kle_exec(kle_locker(key), in, out, len);
}

static void kle_cbc(const unsigned char *in, unsigned char *out, size_t len,
                     const void *key, unsigned char ivec[16], int enc)
{
    int k = kle_locker(key);
    unsigned char buf[KLE_BATCH], prev[16];
    size_t i, n;

    if (enc) {
        /* buf holds plaintext ^ IV: cleansed below like the rest. */
        for (; len >= 16; len -= 16, in += 16, out += 16) {
            for (i = 0; i < 16; i++)
                buf[i] = in[i] ^ ivec[i];
            kle_exec(k, buf, out, 16);
            memcpy(ivec, out, 16);
        }
    } else {
        /* Decryption is parallel: decrypt a batch, then chain. */
        for (; len >= 16; len -= n, in += n, out += n) {
            n = len < KLE_BATCH ? len & ~(size_t)15 : KLE_BATCH;
            memcpy(buf, in, n);
            memcpy(prev, buf + n - 16, 16);
            kle_exec(k, buf, out, n);
            for (i = 0; i < n; i++)
                out[i] ^= i < 16 ? ivec[i] : buf[i - 16];
            memcpy(ivec, prev, 16);
        }
    }
    OPENSSL_cleanse(buf, sizeof(buf));
}

static uint32_t kle_ctr_of(const unsigned char ivec[16])
{
    return (uint32_t)ivec[12] << 24 | ivec[13] << 16 | ivec[14] << 8
           | ivec[15];
}

/*
 * ctr128_f over the ECB Machine: the caller handles carries out of the low
 * 32 bits.  Counter blocks and keystream stay in vector registers.
 */
static void kle_ctr32(const unsigned char *in, unsigned char *out,
                       size_t blocks, const void *key,
                       const unsigned char ivec[16])
{
    kle_ctr_ecb(kle_locker(key), ivec, kle_ctr_of(ivec), in, out, blocks);
}

/*
 * ctr128_f on the CTR Machine.  CRYPTO_ctr128_encrypt_ctr32() fits its
 * shape: it never lets the 32-bit counter wrap within a call, carrying into
 * bytes 0-11 itself, and keeps the bytes left of a partial block, as the
 * Machine works in whole blocks.  The KLE_KEY records what the locker
 * holds, so a contiguous stream costs only the kl.exec; any other IV or
 * counter (a new IV, a copied context, a reload) is set first.  The key is
 * the KLE_KEY in this context, so updating its record is fine.
 */
static void kle_ctr32_machine(const unsigned char *in, unsigned char *out,
                               size_t blocks, const void *key,
                               const unsigned char ivec[16])
{
    KLE_KEY *k = (KLE_KEY *)key;
    uint32_t c = kle_ctr_of(ivec);
    int synced = k->ctr_gen == k->gen;

    if (!synced || memcmp(k->ctr_iv, ivec, 12) != 0) {
        kle_ctr_set_iv(k->locker, ivec);
        memcpy(k->ctr_iv, ivec, 12);
    }
    if (!synced || k->ctr != c)
        kle_ctr_set_ctr(k->locker, c);
    kle_ctr_xor(k->locker, in, out, 16 * blocks);
    k->ctr = c + (uint32_t)blocks;
    k->ctr_gen = k->gen;
}

/* Does the unit have the CTR Machines?  Asked once. */
static int kle_have_ctr(void)
{
    static int have = -1;
    int h = __atomic_load_n(&have, __ATOMIC_RELAXED);

    if (h < 0) {
        h = kle_ctr_supported();
        __atomic_store_n(&have, h, __ATOMIC_RELAXED);
    }
    return h;
}

/*
 * Point the context at its KLE_KEY and the KLE mode functions.  The SCC's
 * Machine decides how CTR runs.
 */
static void kle_setup(PROV_CIPHER_CTX *dat)
{
    KLE_KEY *k = kle_key(dat);
    int dec = kle_decrypts(dat);
    int ctrm = dat->mode == EVP_CIPH_CTR_MODE
               && kle_scc_mode(k->scc) == KLE_MODE_CTR;

    k->state = ctrm ? KLE_ST_OPERATE
               : dec ? KLE_ST_DECRYPT : KLE_ST_ENCRYPT;
    dat->ks = k;
    dat->block = kle_block;
    switch (dat->mode) {
    case EVP_CIPH_ECB_MODE:
        dat->stream.ecb = kle_ecb;
        break;
    case EVP_CIPH_CBC_MODE:
        dat->stream.cbc = kle_cbc;
        break;
    case EVP_CIPH_CTR_MODE:
        dat->stream.ctr = ctrm ? kle_ctr32_machine : kle_ctr32;
        break;
    }
}

#ifndef KLE_PROVIDER
static const PROV_CIPHER_HW *kle_soft_hw(int mode);

/* Software AES in the key schedule area, which then holds an AES_KEY. */
static int kle_soft_initkey(PROV_CIPHER_CTX *dat, const unsigned char *key,
                             size_t keylen)
{
    int dec = kle_decrypts(dat);

    dat->hw = kle_soft_hw(dat->mode);
    return ossl_cipher_set_aes_initkey(dat, key, keylen,
        dec ? AES_set_decrypt_key : AES_set_encrypt_key,
        dec ? AES_decrypt : AES_encrypt, NULL, NULL, NULL);
}

/*
 * The default provider's key found no locker it may take in this thread
 * (the others belong to other components), or its SCC did not import: go
 * on in software AES.  The IV and a partial block are in the context, not
 * in the locker, so a CTR stream continues.
 */
static int kle_to_soft(PROV_CIPHER_CTX *dat)
{
    KLE_AES_KEY *ak = kle_aes_key(dat);
    unsigned char raw[32];
    size_t len = ak->rawlen;
    int ok;

    if (len == 0)
        return 0;
    memcpy(raw, ak->raw, len);
    kle_key_release(&ak->k);
    OPENSSL_cleanse(&((PROV_AES_CTX *)dat)->ks,
                    sizeof(((PROV_AES_CTX *)dat)->ks));
    ok = kle_soft_initkey(dat, raw, len);
    OPENSSL_cleanse(raw, sizeof(raw));
    return ok;
}
#endif

/*
 * Make sure the key is in a locker before the mode code runs, so that a
 * missing locker (all taken by other components of this thread) or an SCC
 * that does not import fails the operation instead of producing zeros, or
 * in CTR mode, the plaintext; the default provider continues in software
 * instead.  This is the only check per call: the mode functions use the
 * locker directly.
 */
static int kle_cipher(PROV_CIPHER_CTX *dat, unsigned char *out,
                       const unsigned char *in, size_t len,
                       int (*cipher)(PROV_CIPHER_CTX *, unsigned char *,
                                     const unsigned char *, size_t))
{
    if (len > 0 && !kle_key_ready(kle_key(dat))) {
#ifndef KLE_PROVIDER
        /* cipher is the generic mode function: it runs on the AES_KEY too. */
        if (kle_to_soft(dat))
            return cipher(dat, out, in, len);
#endif
        ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SETUP_FAILED);
        return 0;
    }
    return cipher(dat, out, in, len);
}

static int kle_cipher_ecb(PROV_CIPHER_CTX *dat, unsigned char *out,
                           const unsigned char *in, size_t len)
{
    return kle_cipher(dat, out, in, len, ossl_cipher_hw_generic_ecb);
}

static int kle_cipher_cbc(PROV_CIPHER_CTX *dat, unsigned char *out,
                           const unsigned char *in, size_t len)
{
    return kle_cipher(dat, out, in, len, ossl_cipher_hw_generic_cbc);
}

static int kle_cipher_ctr(PROV_CIPHER_CTX *dat, unsigned char *out,
                           const unsigned char *in, size_t len)
{
    return kle_cipher(dat, out, in, len, ossl_cipher_hw_generic_ctr);
}

static const PROV_CIPHER_HW *kle_hw(int mode);

/*
 * A raw key: provision it and keep the SCC; the kle provider forgets the
 * key.  The key may only be used for the direction this context needs, and
 * only by this process.  A CTR key goes to the CTR Machine if the unit has
 * it, for encryption only: its keystream serves both directions.
 *
 * Lockers are a per-thread resource shared by every component of the
 * process, and a component can only reclaim its own.  When none is left,
 * here or when the key is used later, the default provider falls back to
 * software AES for this key; the kle provider, which promises that keys
 * live in lockers, fails.
 */
static int kle_initkey(PROV_CIPHER_CTX *dat, const unsigned char *key,
                        size_t keylen)
{
    PROV_AES_CTX *actx = (PROV_AES_CTX *)dat;
    KLE_KEY *k = kle_key(dat);
    int dec = kle_decrypts(dat);
    int mode = dat->mode == EVP_CIPH_CTR_MODE && kle_have_ctr()
               ? KLE_MODE_CTR : KLE_MODE_ECB;

    if (ossl_cipher_hw_aes_is_kle(dat->hw))
        kle_key_release(k);
    /* The previous key's record, or a whole AES_KEY in software fallback. */
    OPENSSL_cleanse(&actx->ks, sizeof(actx->ks));
    k->locker = -1;
    if (kle_key_from_raw(k, key, keylen, mode,
                          dec ? KLE_POLICY_DEC : KLE_POLICY_ENC,
                          KLE_LOC_PROCESS)) {
#ifndef KLE_PROVIDER
        memcpy(kle_aes_key(dat)->raw, key, keylen);
        kle_aes_key(dat)->rawlen = keylen;
#endif
        dat->hw = kle_hw(dat->mode);
        kle_setup(dat);
        return 1;
    }
#ifndef KLE_PROVIDER
    return kle_soft_initkey(dat, key, keylen);
#else
    ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SETUP_FAILED);
    return 0;
#endif
}

int ossl_cipher_aes_kle_set_scc(PROV_CIPHER_CTX *dat,
                                 const unsigned char *scc, size_t len)
{
    KLE_KEY *k = kle_key(dat);

    kle_key_release(k);
    if (!kle_key_from_scc(k, scc, len)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }
    kle_setup(dat);
    /* Load it now, so a bad SCC fails at init rather than silently. */
    if (!kle_key_ready(k)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SETUP_FAILED);
        return 0;
    }
    return 1;
}

static void kle_copyctx(PROV_CIPHER_CTX *dst, const PROV_CIPHER_CTX *src)
{
    PROV_AES_CTX *sctx = (PROV_AES_CTX *)src;
    PROV_AES_CTX *dctx = (PROV_AES_CTX *)dst;

    *dctx = *sctx;
    kle_key_copy((KLE_KEY *)&dctx->ks, (const KLE_KEY *)&sctx->ks);
    dst->ks = &dctx->ks;
}

static const PROV_CIPHER_HW kle_aes_ecb = {
    kle_initkey, kle_cipher_ecb, kle_copyctx
};
static const PROV_CIPHER_HW kle_aes_cbc = {
    kle_initkey, kle_cipher_cbc, kle_copyctx
};
static const PROV_CIPHER_HW kle_aes_ctr = {
    kle_initkey, kle_cipher_ctr, kle_copyctx
};

#ifndef KLE_PROVIDER
static const PROV_CIPHER_HW kle_soft_ecb = {
    kle_initkey, ossl_cipher_hw_generic_ecb, ossl_cipher_aes_copyctx
};
static const PROV_CIPHER_HW kle_soft_cbc = {
    kle_initkey, ossl_cipher_hw_generic_cbc, ossl_cipher_aes_copyctx
};
static const PROV_CIPHER_HW kle_soft_ctr = {
    kle_initkey, ossl_cipher_hw_generic_ctr, ossl_cipher_aes_copyctx
};

static const PROV_CIPHER_HW *kle_soft_hw(int mode)
{
    return mode == EVP_CIPH_ECB_MODE ? &kle_soft_ecb
         : mode == EVP_CIPH_CBC_MODE ? &kle_soft_cbc : &kle_soft_ctr;
}
#endif

static const PROV_CIPHER_HW *kle_hw(int mode)
{
    return ossl_prov_cipher_hw_aes_kle(mode);
}

const PROV_CIPHER_HW *ossl_prov_cipher_hw_aes_kle(int mode)
{
    switch (mode) {
    case EVP_CIPH_ECB_MODE:
        return &kle_aes_ecb;
    case EVP_CIPH_CBC_MODE:
        return &kle_aes_cbc;
    case EVP_CIPH_CTR_MODE:
        return &kle_aes_ctr;
    }
    return NULL;
}

int ossl_cipher_hw_aes_is_kle(const PROV_CIPHER_HW *hw)
{
    return hw == &kle_aes_ecb || hw == &kle_aes_cbc || hw == &kle_aes_ctr;
}

/* Called when a context goes away: clear its locker if this thread has it. */
void ossl_cipher_aes_kle_release(PROV_CIPHER_CTX *dat)
{
    kle_key_release(kle_key(dat));
}

#ifndef KLE_PROVIDER
/*
 * AES-GCM of the default provider.  GCM needs only E_K: the hash subkey
 * H = E_K(0), the tag mask E_K(J0) and the keystream.  So a key takes one
 * locker, for encryption whichever the direction: the CTR Machine, whose
 * counter block is GCM's (a 96-bit IV and a big-endian 32-bit counter that
 * wraps), else the ECB Machine.  GHASH, and so H, stays in software in
 * GCM128_CONTEXT, which the specification accepts: "GCM security is not
 * compromised if H is revealed" (AES-GCM in Zkl-ISA-machines.adoc).
 *
 * All of the GCM state but the AES key is in GCM128_CONTEXT, which reads
 * its block function and key at each call, so a key that finds no locker
 * goes on in software AES even in the middle of a message.
 */
static const PROV_GCM_HW kle_gcm, kle_soft_gcm;

static KLE_AES_KEY *kle_gcm_key(PROV_GCM_CTX *ctx)
{
    return (KLE_AES_KEY *)&((PROV_AES_GCM_CTX *)ctx)->ks;
}

typedef char kle_gcm_key_fits[sizeof(KLE_AES_KEY)
                               <= sizeof(((PROV_AES_GCM_CTX *)0)->ks) ? 1 : -1];

/*
 * block128_f on the CTR Machine: E_K(in) is the keystream of counter block
 * in.  GCM asks for E_K(J0), then runs its stream from J0 + 1, and a
 * partial last block at the counter that follows, so per message this sets
 * the IV and the counter once.  in may be out: it is read first.
 */
static void kle_block_ctrm(const unsigned char in[16], unsigned char out[16],
                            const void *key)
{
    static const unsigned char zero[16];

    kle_ctr32_machine(zero, out, 1, key, in);
}

static int kle_gcm_initkey(PROV_GCM_CTX *ctx, const unsigned char *key,
                            size_t keylen)
{
    PROV_AES_GCM_CTX *actx = (PROV_AES_GCM_CTX *)ctx;
    KLE_AES_KEY *ak = kle_gcm_key(ctx);
    int ctrm = kle_have_ctr();

    if (ctx->hw == &kle_gcm)
        kle_key_release(&ak->k);
    OPENSSL_cleanse(&actx->ks, sizeof(actx->ks));
    ak->k.locker = -1;
    ak->k.state = ctrm ? KLE_ST_OPERATE : KLE_ST_ENCRYPT;
    /* H = E_K(0) comes from the locker: an ECB key enters Encrypt first. */
    if (kle_key_from_raw(&ak->k, key, keylen,
                          ctrm ? KLE_MODE_CTR : KLE_MODE_ECB,
                          KLE_POLICY_ENC, KLE_LOC_PROCESS)
        && kle_key_ready(&ak->k)) {
        memcpy(ak->raw, key, keylen);
        ak->rawlen = keylen;
        ctx->hw = &kle_gcm;
        CRYPTO_gcm128_init(&ctx->gcm, &ak->k,
                           ctrm ? kle_block_ctrm : kle_block);
        ctx->ctr = ctrm ? kle_ctr32_machine : kle_ctr32;
        ctx->key_set = 1;
        return 1;
    }
    kle_key_release(&ak->k);
    ctx->hw = &kle_soft_gcm;
    return ossl_aes_gcm_hw_initkey(ctx, key, keylen, AES_set_encrypt_key,
                                   AES_encrypt, NULL);
}

/* As kle_to_soft(): the AES_KEY replaces the KLE_AES_KEY in ks. */
static int kle_gcm_to_soft(PROV_GCM_CTX *ctx)
{
    PROV_AES_GCM_CTX *actx = (PROV_AES_GCM_CTX *)ctx;
    KLE_AES_KEY *ak = kle_gcm_key(ctx);
    unsigned char raw[32];
    size_t len = ak->rawlen;
    int ok;

    memcpy(raw, ak->raw, len);
    kle_key_release(&ak->k);
    OPENSSL_cleanse(&actx->ks, sizeof(actx->ks));
    ok = AES_set_encrypt_key(raw, (int)(8 * len), &actx->ks.ks) == 0;
    OPENSSL_cleanse(raw, sizeof(raw));
    ctx->gcm.key = &actx->ks.ks;
    ctx->gcm.block = (block128_f)AES_encrypt;
    ctx->ctr = NULL;
    ctx->hw = &kle_soft_gcm;
    return ok;
}

/* The key in a locker of this thread, or the context in software. */
static int kle_gcm_ready(PROV_GCM_CTX *ctx)
{
    if (kle_key_ready(&kle_gcm_key(ctx)->k) || kle_gcm_to_soft(ctx))
        return 1;
    ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SETUP_FAILED);
    return 0;
}

/* E_K(J0): the only use of AES besides the text. */
static int kle_gcm_setiv(PROV_GCM_CTX *ctx, const unsigned char *iv,
                          size_t ivlen)
{
    return kle_gcm_ready(ctx) && ossl_gcm_setiv(ctx, iv, ivlen);
}

static int kle_gcm_cipher_update(PROV_GCM_CTX *ctx, const unsigned char *in,
                                  size_t len, unsigned char *out)
{
    return (len == 0 || kle_gcm_ready(ctx))
        && ossl_generic_aes_gcm_cipher_update(ctx, in, len, out);
}

/* The stream functions are never the Zvkned one that AES_GCM_ASM() wants. */
static const PROV_GCM_HW kle_gcm = {
    kle_gcm_initkey,
    kle_gcm_setiv,
    ossl_gcm_aad_update,
    kle_gcm_cipher_update,
    ossl_gcm_cipher_final,
    ossl_gcm_one_shot
};

/* Keeps kle_gcm_initkey(), so that a new key tries a locker again. */
static const PROV_GCM_HW kle_soft_gcm = {
    kle_gcm_initkey,
    ossl_gcm_setiv,
    ossl_gcm_aad_update,
    ossl_generic_aes_gcm_cipher_update,
    ossl_gcm_cipher_final,
    ossl_gcm_one_shot
};

const PROV_GCM_HW *ossl_prov_aes_hw_gcm_kle(void)
{
    return &kle_gcm;
}

/*
 * A copy of a context (OPENSSL_memdup) must load the key into a locker of
 * its own: through the original's record it would use, and later release,
 * the original's locker.
 */
void ossl_aes_gcm_kle_dup(PROV_GCM_CTX *dst, const PROV_GCM_CTX *src)
{
    if (src->hw == &kle_gcm)
        kle_key_copy(&kle_gcm_key(dst)->k,
                     &kle_gcm_key((PROV_GCM_CTX *)src)->k);
}

void ossl_aes_gcm_kle_release(PROV_GCM_CTX *ctx)
{
    if (ctx->hw == &kle_gcm)
        kle_key_release(&kle_gcm_key(ctx)->k);
}
#endif /* !KLE_PROVIDER */

#endif /* OSSL_RISCV_KLE */
