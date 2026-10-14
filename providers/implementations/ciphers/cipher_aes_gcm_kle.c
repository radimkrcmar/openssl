/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * AES-{128,192,256}-GCM of the kle provider, on the AES-GCM Machine of
 * RISC-V Zkl (KLE) lockers (prototype).  The default provider's AES-GCM on
 * lockers (cipher_aes_hw_kle.c) runs only the AES of GCM in a locker and
 * GHASH in software; here all of GCM runs in the locker: the hash subkey H
 * never leaves the unit, and decryption checks the tag there.  Raw keys
 * only, each for the direction its context first has: the read key of a
 * connection cannot make tags.
 *
 * The Machine must be told that a block is a message's last, partial one
 * before it processes it, and EVP cannot hold output back (an AES-GCM
 * update writes as much as it reads, the final nothing).  So a text update
 * that is not whole blocks ends the message's text, and more text fails.
 * libssl passes each record in one update.  AAD may come in any pieces:
 * what falls short of a block waits in the context.  Decryption takes
 * 16-byte tags only, the one length the Machine compares.
 *
 * A message lives in the locker from its IV to its tag, so the locker is
 * pinned meanwhile: the provider never evicts it, and the kernel saves it
 * with the thread.  If other software clears it, or the context moves to
 * another thread, the message fails; the next IV loads the key again.
 */

#include <string.h>
#include <openssl/proverr.h>
#include "cipher_aes_gcm.h"
#include "prov/ciphercommon_aead.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "crypto/riscv_kle.h"

#ifdef OSSL_RISCV_KLE

typedef struct {
    PROV_GCM_CTX base;          /* first: the generic GCM code's context */
    KLE_KEY k;
    int policy;                 /* KLE_POLICY_ENC or _DEC */
    int st;                     /* the locker's State in a message, else 0 */
    int fresh;                  /* k.scc holds the message: a copy's */
    uint64_t alen, mlen;        /* bytes of AAD and of text so far */
    unsigned char ares[16];     /* AAD short of a block */
    size_t areslen;
} PROV_KLE_GCM_CTX;

static const PROV_GCM_HW kle_gcm_hw;

/* The message ends, or is abandoned: its locker may be evicted again. */
static void kle_gcm_close(PROV_KLE_GCM_CTX *g)
{
    if (g->st != 0 && !g->fresh)
        kle_key_pin(&g->k, 0);
    g->st = 0;
    g->fresh = 0;
    g->areslen = 0;
}

/* The message's locker is not as it left it: fail, and start afresh. */
static int kle_gcm_lost(PROV_KLE_GCM_CTX *g)
{
    kle_gcm_close(g);
    kle_key_release(&g->k);
    ERR_raise_data(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED,
                   "the GCM message's locker was lost");
    return 0;
}

/*
 * The locker of the open message in this thread; a copy made mid-message
 * first imports the message's SCC.  The helpers check its State.
 */
static int kle_gcm_resume(PROV_KLE_GCM_CTX *g)
{
    kle_drain();
    if (g->fresh) {
        g->fresh = 0;
        if (kle_key_load(&g->k) != g->st)
            return 0;
        kle_key_pin(&g->k, 1);
        return 1;
    }
    return kle_key_loaded(&g->k);
}

static int kle_gcm_setkey(PROV_GCM_CTX *ctx, const unsigned char *key,
                           size_t keylen)
{
    PROV_KLE_GCM_CTX *g = (PROV_KLE_GCM_CTX *)ctx;

    kle_gcm_close(g);
    kle_key_release(&g->k);
    g->policy = ctx->enc ? KLE_POLICY_ENC : KLE_POLICY_DEC;
    g->k.state = KLE_ST_READY;
    if (!kle_key_from_raw(&g->k, key, keylen, KLE_MODE_GCM, g->policy,
                           KLE_LOC_PROCESS)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SETUP_FAILED);
        return 0;
    }
    ctx->key_set = 1;
    return 1;
}

/* A new IV starts a message, and abandons one under way. */
static int kle_gcm_setiv(PROV_GCM_CTX *ctx, const unsigned char *iv,
                          size_t ivlen)
{
    PROV_KLE_GCM_CTX *g = (PROV_KLE_GCM_CTX *)ctx;

    if ((g->policy & (ctx->enc ? KLE_POLICY_ENC : KLE_POLICY_DEC)) == 0) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_KEY,
                       "the key was set up for the other direction");
        return 0;
    }
    kle_gcm_close(g);
    if (kle_key_load(&g->k) < 0
        || kle_gcm_start(g->k.locker, iv, ivlen) != KLE_ST_HASH_ABSORB) {
        ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SETUP_FAILED);
        return 0;
    }
    g->st = KLE_ST_HASH_ABSORB;
    g->alen = g->mlen = 0;
    kle_key_pin(&g->k, 1);
    return 1;
}

/* 1, -1 when the AAD is too long, -2 after text (out of order), else 0. */
static int kle_gcm_aad_update(PROV_GCM_CTX *ctx, const unsigned char *aad,
                               size_t len)
{
    PROV_KLE_GCM_CTX *g = (PROV_KLE_GCM_CTX *)ctx;
    size_t n;

    if (g->st != KLE_ST_HASH_ABSORB)
        return g->st != 0 ? -2 : 0;
    if (len > ((uint64_t)1 << 61) - g->alen)
        return -1;
    if (!kle_gcm_resume(g))
        return kle_gcm_lost(g);
    g->alen += len;
    if (g->areslen > 0) {
        n = 16 - g->areslen < len ? 16 - g->areslen : len;
        memcpy(g->ares + g->areslen, aad, n);
        g->areslen += n;
        aad += n;
        len -= n;
        if (g->areslen < 16)
            return 1;
        if (kle_gcm_aad(g->k.locker, g->ares, 16) != KLE_ST_HASH_ABSORB)
            return kle_gcm_lost(g);
        g->areslen = 0;
    }
    n = len & ~(size_t)15;
    if (n > 0 && kle_gcm_aad(g->k.locker, aad, n) != KLE_ST_HASH_ABSORB)
        return kle_gcm_lost(g);
    memcpy(g->ares, aad + n, len - n);
    g->areslen = len - n;
    return 1;
}

static int kle_gcm_cipher_update(PROV_GCM_CTX *ctx, const unsigned char *in,
                                  size_t len, unsigned char *out)
{
    PROV_KLE_GCM_CTX *g = (PROV_KLE_GCM_CTX *)ctx;
    int dec = !ctx->enc;
    int want = len % 16 ? (dec ? KLE_ST_DEC_LAST : KLE_ST_ENC_LAST)
                        : (dec ? KLE_ST_DECRYPT : KLE_ST_ENCRYPT);
    int st;

    if (len == 0)
        return 1;
    if (g->st == KLE_ST_ENC_LAST || g->st == KLE_ST_DEC_LAST) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_UPDATE_CALL_OUT_OF_ORDER,
                       "text after a partial block of the GCM Machine");
        return 0;
    }
    if (g->st == 0)
        return 0;
    /* The Machine's counter limit would make the locker Invalid. */
    if (len > (((uint64_t)1 << 36) - 32) - g->mlen) {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }
    if (!kle_gcm_resume(g))
        return kle_gcm_lost(g);
    st = kle_gcm_text(g->k.locker, g->st, dec, g->ares,
                      g->st == KLE_ST_HASH_ABSORB ? g->areslen : 0,
                      in, out, len);
    if (st != want) {
        OPENSSL_cleanse(out, len);
        return kle_gcm_lost(g);
    }
    g->st = st;
    g->areslen = 0;
    g->mlen += len;
    return 1;
}

/* The tag: made into tag on encryption, compared with tag on decryption. */
static int kle_gcm_cipher_final(PROV_GCM_CTX *ctx, unsigned char *tag)
{
    PROV_KLE_GCM_CTX *g = (PROV_KLE_GCM_CTX *)ctx;
    int dec = !ctx->enc, st, i;
    unsigned char lens[16];

    if (g->st == 0)
        return 0;
    if (dec && ctx->taglen != GCM_TAG_MAX_SIZE) {
        kle_gcm_close(g);
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_TAG,
                       "the GCM Machine checks 16-byte tags only");
        return 0;
    }
    if (!kle_gcm_resume(g))
        return kle_gcm_lost(g);
    /* No text: the Machine still passes through Encrypt or Decrypt. */
    if (g->st == KLE_ST_HASH_ABSORB) {
        st = kle_gcm_text(g->k.locker, g->st, dec, g->ares, g->areslen,
                          NULL, NULL, 0);
        if (st != (dec ? KLE_ST_DECRYPT : KLE_ST_ENCRYPT))
            return kle_gcm_lost(g);
        g->st = st;
    }
    /* The length block: AAD and text lengths in bits, big-endian. */
    for (i = 0; i < 8; i++) {
        lens[i] = (unsigned char)((8 * g->alen) >> (56 - 8 * i));
        lens[8 + i] = (unsigned char)((8 * g->mlen) >> (56 - 8 * i));
    }
    if (dec) {
        st = kle_gcm_verify(g->k.locker, g->st, lens, tag);
        if (st != KLE_ST_SUCCESS && st != KLE_ST_FAILURE)
            return kle_gcm_lost(g);
    } else {
        st = kle_gcm_tag(g->k.locker, g->st, lens, tag);
        if (st != KLE_ST_SUCCESS)
            return kle_gcm_lost(g);
        ctx->taglen = GCM_TAG_MAX_SIZE;
    }
    kle_gcm_close(g);
    return st == KLE_ST_SUCCESS;
}

/* TLS 1.2 records go through ossl_gcm_one_shot(), on the ops above. */
static const PROV_GCM_HW kle_gcm_hw = {
    kle_gcm_setkey,
    kle_gcm_setiv,
    kle_gcm_aad_update,
    kle_gcm_cipher_update,
    kle_gcm_cipher_final,
    ossl_gcm_one_shot
};

static void *kle_aes_gcm_newctx(void *provctx, size_t keybits)
{
    PROV_KLE_GCM_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL) {
        ossl_gcm_initctx(provctx, &ctx->base, keybits, &kle_gcm_hw);
        ctx->k.locker = -1;
    }
    return ctx;
}

/*
 * A copy loads the key into a locker of its own.  Mid-message it takes the
 * message along: an SCC of the original's locker, exported as it is.
 */
static void *kle_aes_gcm_dupctx(void *vctx)
{
    PROV_KLE_GCM_CTX *in = vctx, *ret;

    if (!ossl_prov_is_running())
        return NULL;
    if ((ret = OPENSSL_memdup(in, sizeof(*in))) == NULL)
        return NULL;
    kle_key_copy(&ret->k, &in->k);
    if (in->st != 0 && !in->fresh) {
        if (!kle_key_loaded(&in->k)
            || (ret->k.scc_len = kle_export(in->k.locker, ret->k.scc)) == 0) {
            OPENSSL_clear_free(ret, sizeof(*ret));
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return NULL;
        }
        ret->fresh = 1;
    }
    return ret;
}

static void kle_aes_gcm_freectx(void *vctx)
{
    PROV_KLE_GCM_CTX *ctx = vctx;

    if (ctx == NULL)
        return;
    kle_gcm_close(ctx);
    kle_key_release(&ctx->k);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

/* ossl_kle_aes128gcm_functions */
IMPLEMENT_aead_cipher(kle_aes, gcm, GCM, AEAD_FLAGS, 128, 8, 96);
/* ossl_kle_aes192gcm_functions */
IMPLEMENT_aead_cipher(kle_aes, gcm, GCM, AEAD_FLAGS, 192, 8, 96);
/* ossl_kle_aes256gcm_functions */
IMPLEMENT_aead_cipher(kle_aes, gcm, GCM, AEAD_FLAGS, 256, 8, 96);

#endif /* OSSL_RISCV_KLE */
