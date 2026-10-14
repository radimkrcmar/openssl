/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * RISC-V Zkl (KLE, Cryptographic Lockers) prototype support for AES.
 *
 * A key is held by software only as a Sealed Cryptographic Context (SCC):
 * an AES-ECB, AES-CTR or AES-GCM Cryptographic Context encrypted and
 * authenticated by the KLE unit under its Context Sealing Key.  To use it,
 * the SCC is imported into one of the 32 lockers of the current hart.
 * Lockers are per-hart state, which the OS switches with the thread, so a
 * locker belongs to a thread: every user of a key records which locker of
 * which thread holds it and imports the SCC again whenever it runs on
 * another thread or its locker was reused or cleared.
 *
 * The including components, the default provider and the kle provider
 * module, share one per-thread locker table, which libcrypto keeps.  A
 * locker is free when its State is Unconfigured, whatever the table says,
 * and the component that takes it replaces its record: a locker that other
 * software cleared and another component then took is never used or
 * evicted through the old record.  Each component evicts only lockers it
 * owns.  A thread cannot clear another thread's locker, so a key released
 * elsewhere is posted to the release ring, and the owning thread clears the
 * locker the next time it uses a key.  A forked child starts without
 * lockers, like a new thread, so an atfork handler empties the copy of the
 * table it inherits.
 *
 * A locker number chosen at run time reaches an instruction through
 * klnamedlocker: every instruction that takes a locker may name KLNL, the
 * locker klnamedlocker names, instead of an immediate (Rule GR8 as of the
 * draft of 12 Oct 2026, 9e4dc5b), and kl.load and kl.store act on that
 * locker anyway.  As the specification's management routines do, each
 * operation on a locker saves klnamedlocker, writes the locker's number
 * with kl.setnl, and restores the saved value when done (SR9, SR10), so it
 * needs no 32-way switch of immediates.  A write of klnamedlocker is a
 * change of KLE state, which sets KLS Dirty: every cipher call does, also
 * one that changes no locker, and an OS without per-locker status tracking
 * (Ssklstatus) then exports every locker at the next context switch.
 * Encodings, CSRs and the hwprobe bit are provisional (development draft
 * after Zkl v0.6).
 */

#ifndef OSSL_CRYPTO_RISCV_KLE_H
#define OSSL_CRYPTO_RISCV_KLE_H

#include <openssl/opensslconf.h>

#if defined(__riscv) && __riscv_xlen == 64 && defined(__linux__) \
    && !defined(OPENSSL_NO_KLE)
#define OSSL_RISCV_KLE 1

#include <stdint.h>
#include <string.h>

#define KLE_LOCKERS 32
/* AES-256-GCM: MDH | SIV | 80-byte Content1 (key, J0, tag, start_ctr, ...) */
#define KLE_SCC_MAX 112

#define KLE_ST_UNCONFIGURED 0
#define KLE_ST_READY 1
#define KLE_ST_OPERATE 2       /* CTR */
#define KLE_ST_HASH_ABSORB 2   /* GCM */
#define KLE_ST_HASH_VERIFY 5
#define KLE_ST_ENCRYPT 7
#define KLE_ST_DECRYPT 8
#define KLE_ST_ENC_LAST 9
#define KLE_ST_DEC_LAST 10
#define KLE_ST_ENC_TAG 11
#define KLE_ST_DEC_TAG 12
#define KLE_ST_SUCCESS 46
#define KLE_ST_FAILURE 47
#define KLE_ST_ERROR(st) ((st) >= 48 && (st) <= 55)
#define KLE_CFG_PROVISIONING 56
#define KLE_CFG_EXPORTING 57
#define KLE_CFG_IMPORTING 58
#define KLE_CFG_MANAGEMENT_END 63
/* CTR: sets the counter, not a State; GCM: the State that takes the IV */
#define KLE_SET_AUX_VALUE 13

/* Machine Modes of the AES Types */
#define KLE_MODE_ECB 0
#define KLE_MODE_CTR 1
#define KLE_MODE_GCM 4

/* MDH fields */
#define KLE_MDH_LO(machine, policy, keytype) \
    ((uint64_t)(machine) | (uint64_t)(policy) << 12 | (uint64_t)(keytype) << 28)
#define KLE_MDH_MACHINE(lo) ((int)((lo) & 0xfff))
#define KLE_MDH_STATE(lo) ((int)(((lo) >> 18) & 0x3f))
#define KLE_MDH_HI(usage, locality) \
    ((uint64_t)(usage) | (uint64_t)(locality) << 5)
#define KLE_POLICY_ENC 1
#define KLE_POLICY_DEC 2
/* UsagePolicy: deny VS, HS and M; only U-mode (the process) may use it. */
#define KLE_USAGE_USER_ONLY (2 | 4 | 8)
/* Locality: DevScrt binds to the device, SLocality to the process. */
#define KLE_LOC_DEVICE (3 << 2)
#define KLE_LOC_PROCESS (1 << 8)

/* Encodings, unsigned: funct7 values from 0x40 up shift past INT_MAX. */
#define KLE_SETST(imm, f, r, rs1, rd) \
    ((uint32_t)(imm) << 25 | (uint32_t)(f) << 21 | (uint32_t)(r) << 20 \
     | (uint32_t)(rs1) << 15 | 3u << 12 | (uint32_t)(rd) << 7 | 0x0fu)
#define KLE_R4(f7, rs2, rs1, rd) \
    ((uint32_t)(f7) << 25 | (uint32_t)(rs2) << 20 | (uint32_t)(rs1) << 15 \
     | 4u << 12 | (uint32_t)(rd) << 7 | 0x0fu)
/*
 * KLNL, the locker klnamedlocker names: r = 1 with X0 in the locker field,
 * which is bit 20 of kl.setst and kl.mgmt and funct7 bit 1 of kl.exec,
 * kl.getmd and kl.size.  Every locker operand below is KLNL.
 */
#define KLE_F7_KLNL 0x02
/* kl.load 0(rs1), x0 and kl.store 0(rs1), x0, on the named locker */
#define KLE_LOAD_W(rs1) ((uint32_t)(rs1) << 15 | 7u << 12 | 0x03u)
#define KLE_STORE_W(rs1) ((uint32_t)(rs1) << 15 | 5u << 12 | 0x23u)

/* kl.mgmt KLNL, #imm, a1:a0 (Form D) */
#define KLE_I_MGMT(imm, lo, hi)                                          \
    do {                                                                  \
        register uint64_t _a0 __asm__("a0") = (lo);                       \
        register uint64_t _a1 __asm__("a1") = (hi);                       \
        __asm__ volatile(".4byte %2" ::"r"(_a0), "r"(_a1),                \
            "i"(KLE_SETST(imm, 3, 1, 10, 0)) : "memory");                \
    } while (0)
/*
 * kl.setst KLNL, #imm (Form A): kl.clear (#0), a Machine's State, and
 * kl.mgmt without an MDH
 */
#define KLE_I_SETST(imm) \
    __asm__ volatile(".4byte %0" ::"i"(KLE_SETST(imm, 0, 1, 0, 0)) : "memory")
/* kl.getmd a1:a0, KLNL */
#define KLE_I_GETMD(m)                                                   \
    do {                                                                  \
        register uint64_t _a0 __asm__("a0");                              \
        register uint64_t _a1 __asm__("a1");                              \
        __asm__ volatile(".4byte %2" : "=r"(_a0), "=r"(_a1)               \
            : "i"(KLE_R4(0x68 | KLE_F7_KLNL, 0, 0, 10)));               \
        (m)[0] = _a0;                                                     \
        (m)[1] = _a1;                                                     \
    } while (0)
/* kl.size a0, KLNL (Form A) */
#define KLE_I_SIZE(sz)                                                   \
    do {                                                                  \
        register uint64_t _a0 __asm__("a0");                              \
        __asm__ volatile(".4byte %1" : "=r"(_a0)                          \
            : "i"(KLE_R4(0x04 | KLE_F7_KLNL, 0, 0, 10)));               \
        (sz) = _a0;                                                       \
    } while (0)
#define KLE_I_LOAD(p)                                                    \
    do {                                                                  \
        register const void *_a2 __asm__("a2") = (p);                     \
        __asm__ volatile(".4byte %1" ::"r"(_a2), "i"(KLE_LOAD_W(12)) : "memory"); \
    } while (0)
#define KLE_I_STORE(p)                                                   \
    do {                                                                  \
        register void *_a2 __asm__("a2") = (p);                           \
        __asm__ volatile(".4byte %1" ::"r"(_a2), "i"(KLE_STORE_W(12)) : "memory"); \
    } while (0)
/* kl.getnl a0; kl.setnl a0 (klnamedlocker; 33 and above are ignored) */
#define KLE_I_GETNL(v)                                                   \
    do {                                                                  \
        register uint64_t _a0 __asm__("a0");                              \
        __asm__ volatile(".4byte %1" : "=r"(_a0) : "i"(KLE_R4(0x78, 0, 0, 10))); \
        (v) = _a0;                                                        \
    } while (0)
#define KLE_I_SETNL(v)                                                   \
    do {                                                                  \
        register uint64_t _a0 __asm__("a0") = (v);                        \
        __asm__ volatile(".4byte %1" ::"r"(_a0),                          \
            "i"(KLE_SETST(0, 1, 0, 10, 0) | 1u << 24) : "memory");       \
    } while (0)
/* kl.size a0, a0 (Form B): the size for MDH[63:0], 0 if unsupported */
#define KLE_I_SIZE_MDH(lo, sz)                                           \
    do {                                                                  \
        register uint64_t _a0 __asm__("a0") = (lo);                       \
        __asm__ volatile(".4byte %1" : "+r"(_a0) : "i"(KLE_R4(0x0c, 0, 10, 10))); \
        (sz) = _a0;                                                       \
    } while (0)
/* kl.setst KLNL, #imm, v8 (Form C) with the 16 bytes at p */
#define KLE_I_SETST_V(imm, p)                                            \
    __asm__ volatile(".option push\n.option arch, +v\n"                   \
                     "vsetivli zero, 16, e8, m1, ta, ma\n"                \
                     "vle8.v v8, (%0)\n"                                  \
                     ".4byte %1\n"                                        \
                     ".option pop\n"                                      \
        :: "r"(p), "i"(KLE_SETST(imm, 2, 1, 8, 0))                      \
        : "memory", "v8")
/* kl.setst KLNL, #imm, a0 (Form B) */
#define KLE_I_SETST_X(imm, x)                                            \
    do {                                                                  \
        register uint64_t _a0 __asm__("a0") = (x);                        \
        __asm__ volatile(".4byte %1" ::"r"(_a0),                          \
            "i"(KLE_SETST(imm, 1, 1, 10, 0)) : "memory");                \
    } while (0)
/* CTR: the IV is bytes 0-11 of p (Form C into Operate); the counter */
#define KLE_I_SETIV(p) KLE_I_SETST_V(KLE_ST_OPERATE, p)
#define KLE_I_SETCTR(c) KLE_I_SETST_X(KLE_SET_AUX_VALUE, c)
/* kl.exec KLNL, v8 (Form B, input only) over n bytes (<= VLMAX, e8, m8) */
#define KLE_I_ABSORB(in, n, vl)                                          \
    __asm__ volatile(".option push\n.option arch, +v\n"                   \
                     "vsetvli %0, %1, e8, m8, ta, ma\n"                   \
                     "vle8.v v8, (%2)\n"                                  \
                     ".4byte %3\n"                                        \
                     ".option pop\n"                                      \
        : "=&r"(vl) : "r"((uint64_t)(n)), "r"(in),                        \
        "i"(KLE_R4(0x08 | KLE_F7_KLNL, 8, 0, 0))                         \
        : "memory", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15")
/* kl.exec v8, KLNL (Form C, output only): 16 bytes to out */
#define KLE_I_SQUEEZE(out)                                               \
    __asm__ volatile(".option push\n.option arch, +v\n"                   \
                     "vsetivli zero, 16, e8, m1, ta, ma\n"                \
                     ".4byte %1\n"                                        \
                     "vse8.v v8, (%0)\n"                                  \
                     ".option pop\n"                                      \
        :: "r"(out), "i"(KLE_R4(0x10 | KLE_F7_KLNL, 0, 0, 8))           \
        : "memory", "v8")
/*
 * kl.exec v8, KLNL (Form C) over n bytes (<= VLMAX with e8, m8) of CTR
 * keystream, XORed with in into out: the keystream stays in v8.
 */
#define KLE_I_CTR(in, out, n, vl)                                        \
    __asm__ volatile(".option push\n.option arch, +v\n"                   \
                     "vsetvli %0, %1, e8, m8, ta, ma\n"                   \
                     ".4byte %4\n"                                        \
                     "vle8.v v16, (%2)\n"                                 \
                     "vxor.vv v8, v8, v16\n"                              \
                     "vse8.v v8, (%3)\n"                                  \
                     ".option pop\n"                                      \
        : "=&r"(vl) : "r"((uint64_t)(n)), "r"(in), "r"(out),              \
        "i"(KLE_R4(0x10 | KLE_F7_KLNL, 0, 0, 8))                         \
        : "memory", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", \
          "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23")
/*
 * CTR over the ECB Machine: nb counter blocks built in v8 from the IV
 * (bytes 0-11 of iv) and the big-endian counters c, c + 1, ... (modulo
 * 2^32: no carry into the IV), encrypted in place, XORed with in into
 * out.  4 * nb lanes of e32 with m4: lane 3 of each block gets
 * bswap32(c + block), with the byte swap as an e8 gather (16 * nb <= 256
 * so that the indices fit).
 */
#define KLE_I_CTR_ECB(iv, c, in, out, nb)                                \
    __asm__ volatile(".option push\n.option arch, +v\n"                   \
                     "vsetivli zero, 16, e8, m1, ta, ma\n"                \
                     "vle8.v v16, (%0)\n"                                 \
                     "vsetvli zero, %2, e32, m4, ta, ma\n"                \
                     "vid.v v4\n"                                         \
                     "vand.vi v12, v4, 3\n"                               \
                     "vmseq.vi v0, v12, 3\n"                              \
                     "vsrl.vi v4, v4, 2\n"                                \
                     "vadd.vx v4, v4, %1\n"                               \
                     "vrgather.vv v8, v16, v12\n"                         \
                     "vsetvli zero, %3, e8, m4, ta, ma\n"                 \
                     "vid.v v20\n"                                        \
                     "vxor.vi v20, v20, 3\n"                              \
                     "vrgather.vv v24, v4, v20\n"                         \
                     "vsetvli zero, %2, e32, m4, ta, ma\n"                \
                     "vmerge.vvm v8, v8, v24, v0\n"                       \
                     ".4byte %6\n"                                        \
                     "vsetvli zero, %3, e8, m4, ta, ma\n"                 \
                     "vle8.v v16, (%4)\n"                                 \
                     "vxor.vv v8, v8, v16\n"                              \
                     "vse8.v v8, (%5)\n"                                  \
                     ".option pop\n"                                      \
        :: "r"(iv), "r"((uint64_t)(c)), "r"((uint64_t)(4 * (nb))),        \
        "r"((uint64_t)(16 * (nb))), "r"(in), "r"(out),                    \
        "i"(KLE_R4(KLE_F7_KLNL, 8, 0, 8))                                \
        : "memory", "v0", "v4", "v5", "v6", "v7", "v8", "v9", "v10",      \
          "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19",  \
          "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27")
/* kl.exec v8, KLNL, v8 over n bytes (<= VLMAX with e8, m8), in place. */
#define KLE_I_EXEC(in, out, n, vl)                                       \
    __asm__ volatile(".option push\n.option arch, +v\n"                   \
                     "vsetvli %0, %1, e8, m8, ta, ma\n"                   \
                     "vle8.v v8, (%2)\n"                                  \
                     ".4byte %4\n"                                        \
                     "vse8.v v8, (%3)\n"                                  \
                     ".option pop\n"                                      \
        : "=&r"(vl) : "r"((uint64_t)(n)), "r"(in), "r"(out),              \
        "i"(KLE_R4(KLE_F7_KLNL, 8, 0, 8))                                \
        : "memory", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15")

/*
 * Name locker i as KLNL (Rule SR9): save klnamedlocker and write i, so that
 * kl.load, kl.store and every instruction naming KLNL act on it.
 * kle_nl_pop() restores the saved value (SR10).  A kl.clear of the locker
 * resets klnamedlocker to 32 meanwhile, which changes nothing here.
 */
static inline uint64_t kle_nl_push(int i)
{
    uint64_t saved;

    KLE_I_GETNL(saved);
    KLE_I_SETNL((uint64_t)i);
    return saved;
}

static inline void kle_nl_pop(uint64_t saved)
{
    KLE_I_SETNL(saved);
}

/* State of KLNL; 0 (Unconfigured) if klnamedlocker is 32. */
static inline int kle_nl_getst(void)
{
    uint64_t m[2];

    KLE_I_GETMD(m);
    return KLE_MDH_STATE(m[0]);
}

/* MDH of locker i; zeros for i outside 0..31. */
static inline void kle_getmd(int i, uint64_t m[2])
{
    uint64_t saved;

    m[0] = m[1] = 0;
    if (i < 0 || i >= KLE_LOCKERS)
        return;
    saved = kle_nl_push(i);
    KLE_I_GETMD(m);
    kle_nl_pop(saved);
}

static inline int kle_getst(int i)
{
    uint64_t m[2];

    kle_getmd(i, m);
    return KLE_MDH_STATE(m[0]);
}

/* Set the State of locker i: Unconfigured (kl.clear), Encrypt or Decrypt. */
static inline void kle_setst(int i, int st)
{
    uint64_t saved = kle_nl_push(i);

    switch (st) {
    case KLE_ST_UNCONFIGURED:
        KLE_I_SETST(KLE_ST_UNCONFIGURED);
        break;
    case KLE_ST_ENCRYPT:
        KLE_I_SETST(KLE_ST_ENCRYPT);
        break;
    case KLE_ST_DECRYPT:
        KLE_I_SETST(KLE_ST_DECRYPT);
        break;
    }
    kle_nl_pop(saved);
}

/*
 * Provision locker i from a PI Content (16-byte aligned, zero-padded);
 * returns the State.
 */
static inline int kle_provision(int i, uint64_t lo, uint64_t hi,
                                 const void *content)
{
    uint64_t saved = kle_nl_push(i);
    int st;

    KLE_I_MGMT(KLE_CFG_PROVISIONING, lo, hi);
    KLE_I_LOAD(content);
    KLE_I_SETST(KLE_CFG_MANAGEMENT_END);
    st = kle_nl_getst();
    kle_nl_pop(saved);
    return st;
}

/*
 * Export locker i as an SCC; returns its length (0 on error).  kl.store
 * needs a 16-byte aligned address, so the image goes through the stack.
 */
static inline size_t kle_export(int i, uint8_t scc[KLE_SCC_MAX])
{
    uint8_t img[KLE_SCC_MAX] __attribute__((aligned(16)));
    uint64_t m[2], sz, saved = kle_nl_push(i);

    KLE_I_GETMD(m);
    KLE_I_SIZE(sz);
    if (sz >= 32 && sz <= KLE_SCC_MAX
        && !KLE_ST_ERROR(KLE_MDH_STATE(m[0]))) {
        memcpy(img, m, 16);
        KLE_I_SETST(KLE_CFG_EXPORTING);
        KLE_I_STORE(img + 16);
        KLE_I_MGMT(KLE_CFG_MANAGEMENT_END, m[0], m[1]);
    } else {
        sz = 0;
    }
    kle_nl_pop(saved);
    memcpy(scc, img, (size_t)sz);
    return (size_t)sz;
}

/* Import an SCC into locker i; returns the State. */
static inline int kle_import(int i, const uint8_t *scc)
{
    uint8_t img[KLE_SCC_MAX] __attribute__((aligned(16)));
    uint64_t lo, hi, saved;
    int st;

    memcpy(img, scc, KLE_SCC_MAX);
    memcpy(&lo, img, 8);
    memcpy(&hi, img + 8, 8);
    saved = kle_nl_push(i);
    KLE_I_MGMT(KLE_CFG_IMPORTING, lo, hi);
    KLE_I_LOAD(img + 16);
    KLE_I_MGMT(KLE_CFG_MANAGEMENT_END, lo, hi);
    st = kle_nl_getst();
    kle_nl_pop(saved);
    return st;
}

/* VLMAX in bytes with e8, m8, rounded down to whole AES blocks. */
static inline size_t kle_vlmax(void)
{
    uint64_t vl;

    __asm__ volatile(".option push\n.option arch, +v\n"
                     "vsetvli %0, zero, e8, m8, ta, ma\n"
                     ".option pop\n" : "=r"(vl));
    return (size_t)vl & ~(size_t)15;
}

/*
 * kl.exec on n bytes (a multiple of 16) of locker i, chunked by VLMAX.
 * For VLMAX < AVL < 2 * VLMAX, vsetvli may return any vl from AVL / 2 up,
 * which could split a block, so no chunk asks for more than VLMAX: then
 * vl is exactly the AVL.
 */
static inline void kle_exec(int i, const unsigned char *in,
                             unsigned char *out, size_t n)
{
    size_t max = kle_vlmax(), c;
    uint64_t vl, saved = kle_nl_push(i);

    while (n > 0) {
        c = n < max ? n : max;
        KLE_I_EXEC(in, out, c, vl);
        in += vl;
        out += vl;
        n -= vl;
    }
    kle_nl_pop(saved);
}

/* VLMAX in bytes with e8, m4, capped at 256 for KLE_I_CTR_ECB. */
static inline size_t kle_ctr_ecb_max(void)
{
    size_t max = kle_vlmax() / 2;

    return max < 256 ? max : 256;
}

/* CTR Machine of locker i: IV from bytes 0-11 of ivec, counter c. */
static inline void kle_ctr_set_iv(int i, const unsigned char ivec[16])
{
    uint64_t saved = kle_nl_push(i);

    KLE_I_SETIV(ivec);
    kle_nl_pop(saved);
}

static inline void kle_ctr_set_ctr(int i, uint32_t c)
{
    uint64_t saved = kle_nl_push(i);

    KLE_I_SETCTR(c);
    kle_nl_pop(saved);
}

/* out = in ^ n bytes (a multiple of 16) of keystream of CTR locker i. */
static inline void kle_ctr_xor(int i, const unsigned char *in,
                                unsigned char *out, size_t n)
{
    size_t max = kle_vlmax(), c;
    uint64_t vl, saved = kle_nl_push(i);

    while (n > 0) {
        c = n < max ? n : max;
        KLE_I_CTR(in, out, c, vl);
        in += vl;
        out += vl;
        n -= vl;
    }
    kle_nl_pop(saved);
}

/*
 * out = in ^ AES-CTR keystream of blocks counter blocks from ECB locker i
 * in Encrypt: IV bytes 0-11 of ivec, big-endian counter c (modulo 2^32).
 */
static inline void kle_ctr_ecb(int i, const unsigned char ivec[16],
                                uint32_t c, const unsigned char *in,
                                unsigned char *out, size_t blocks)
{
    size_t max = kle_ctr_ecb_max() / 16, nb;
    uint64_t saved = kle_nl_push(i);

    while (blocks > 0) {
        nb = blocks < max ? blocks : max;
        KLE_I_CTR_ECB(ivec, c, in, out, nb);
        c += (uint32_t)nb;
        in += 16 * nb;
        out += 16 * nb;
        blocks -= nb;
    }
    kle_nl_pop(saved);
}

/* AES Machine for a key length and KLE_MODE_*; -1 if none. */
static inline int kle_machine(size_t keylen, int mode)
{
    switch (keylen) {
    case 16: return 0x000 | mode;
    case 24: return 0x010 | mode;
    case 32: return 0x020 | mode;
    }
    return -1;
}

/* Does the unit implement the AES CTR Machines?  kl.size is 0 if not. */
static inline int kle_ctr_supported(void)
{
    uint64_t sz;

    KLE_I_SIZE_MDH(KLE_MDH_LO(kle_machine(16, KLE_MODE_CTR),
                                KLE_POLICY_ENC, 0), sz);
    return sz != 0;
}

/*
 * Does the unit implement the AES-GCM Machines, with SCCs that fit
 * KLE_SCC_MAX?  kl.size of an MDH in Ready is the SCC's size, 0 if not.
 */
static inline int kle_gcm_supported(void)
{
    uint64_t sz;
    size_t len;

    for (len = 16; len <= 32; len += 8) {
        KLE_I_SIZE_MDH(KLE_MDH_LO(kle_machine(len, KLE_MODE_GCM),
                                    KLE_POLICY_ENC, 0)
                       | (uint64_t)KLE_ST_READY << 18, sz);
        if (sz == 0 || sz > KLE_SCC_MAX)
            return 0;
    }
    return 1;
}

/*
 * The AES-GCM Machine (Zkl-ISA-machines.adoc, AES-GCM) of locker i: one
 * message from its IV to its tag, by the helpers below.  Each checks that
 * the locker is in the State its caller expects before it issues anything,
 * since a Form that a State does not expect is an illegal instruction, and
 * an Unconfigured or Error-State locker gives zeros rather than failing.
 * Each returns the State it leaves, -1 if the locker was not in the
 * expected one.
 */

/* From any Valid State: Ready, Set_Aux_Value and the IV: Hash_Absorb. */
static inline int kle_gcm_start(int i, const unsigned char *iv, size_t ivlen)
{
    size_t max = kle_vlmax(), c;
    uint64_t vl, saved = kle_nl_push(i);
    int st = kle_nl_getst();

    if (st == KLE_ST_UNCONFIGURED || KLE_ST_ERROR(st) || st > KLE_ST_FAILURE) {
        st = -1;
    } else {
        KLE_I_SETST(KLE_ST_READY);
        KLE_I_SETST_X(KLE_SET_AUX_VALUE, 8 * ivlen);
        /* Transfers of whole blocks but the last; its end makes J0. */
        while (ivlen > 0) {
            c = ivlen < max ? ivlen : max;
            KLE_I_ABSORB(iv, c, vl);
            iv += vl;
            ivlen -= vl;
        }
        st = kle_nl_getst();
    }
    kle_nl_pop(saved);
    return st;
}

/* In Hash_Absorb: n bytes of AAD, whole blocks. */
static inline int kle_gcm_aad(int i, const unsigned char *p, size_t n)
{
    size_t max = kle_vlmax(), c;
    uint64_t vl, saved = kle_nl_push(i);
    int st = kle_nl_getst();

    if (st != KLE_ST_HASH_ABSORB) {
        st = -1;
    } else {
        while (n > 0) {
            c = n < max ? n : max;
            KLE_I_ABSORB(p, c, vl);
            p += vl;
            n -= vl;
        }
        st = kle_nl_getst();
    }
    kle_nl_pop(saved);
    return st;
}

/*
 * n bytes of text in from State st: from Hash_Absorb, first the AAD short
 * of a block (npad bytes at pad, zero-padded here) and Encrypt or Decrypt;
 * then whole blocks, then a partial block as the last one (Enc/Dec_Last_
 * Block), whose output the Machine clears above its length.
 */
static inline int kle_gcm_text(int i, int st, int dec, const unsigned char *pad,
                                size_t npad, const unsigned char *in,
                                unsigned char *out, size_t n)
{
    unsigned char blk[16] __attribute__((aligned(16)));
    size_t max = kle_vlmax(), c, r = n % 16;
    uint64_t vl, saved = kle_nl_push(i);
    int cur = kle_nl_getst();

    if (cur != st) {
        cur = -1;
        goto end;
    }
    if (st == KLE_ST_HASH_ABSORB) {
        if (npad > 0) {
            memset(blk, 0, sizeof(blk));
            memcpy(blk, pad, npad);
            KLE_I_ABSORB(blk, 16, vl);
        }
        if (dec)
            KLE_I_SETST(KLE_ST_DECRYPT);
        else
            KLE_I_SETST(KLE_ST_ENCRYPT);
        if ((cur = kle_nl_getst()) != (dec ? KLE_ST_DECRYPT : KLE_ST_ENCRYPT))
            goto end;
    }
    for (n -= r; n > 0; n -= vl, in += vl, out += vl) {
        c = n < max ? n : max;
        KLE_I_EXEC(in, out, c, vl);
    }
    if (r > 0) {
        if (dec)
            KLE_I_SETST_X(KLE_ST_DEC_LAST, 8 * r);
        else
            KLE_I_SETST_X(KLE_ST_ENC_LAST, 8 * r);
        memset(blk, 0, sizeof(blk));
        memcpy(blk, in, r);
        KLE_I_EXEC(blk, blk, 16, vl);
        memcpy(out, blk, r);
        memset(blk, 0, sizeof(blk));
        __asm__ volatile("" ::"r"(blk) : "memory");
    }
    cur = kle_nl_getst();
end:
    kle_nl_pop(saved);
    return cur;
}

/*
 * Encryption from Encrypt or Enc_Last_Block (st): the length block, then
 * the tag into tag: Success.
 */
static inline int kle_gcm_tag(int i, int st, const unsigned char lens[16],
                               unsigned char tag[16])
{
    uint64_t saved = kle_nl_push(i);
    int cur = kle_nl_getst();

    if (cur != st) {
        cur = -1;
    } else {
        KLE_I_SETST_V(KLE_ST_ENC_TAG, lens);
        if ((cur = kle_nl_getst()) == KLE_ST_ENC_TAG) {
            KLE_I_SQUEEZE(tag);
            cur = kle_nl_getst();
        }
    }
    kle_nl_pop(saved);
    return cur;
}

/*
 * Decryption from Decrypt or Dec_Last_Block (st): the length block, then
 * the tag received, which the Machine compares: Success or Failure.
 */
static inline int kle_gcm_verify(int i, int st, const unsigned char lens[16],
                                  const unsigned char tag[16])
{
    uint64_t saved = kle_nl_push(i);
    int cur = kle_nl_getst();

    if (cur != st) {
        cur = -1;
    } else {
        KLE_I_SETST_V(KLE_ST_DEC_TAG, lens);
        if ((cur = kle_nl_getst()) == KLE_ST_DEC_TAG) {
            KLE_I_SETST_V(KLE_ST_HASH_VERIFY, tag);
            cur = kle_nl_getst();
        }
    }
    kle_nl_pop(saved);
    return cur;
}

/* ------------------------------------------------------------------ */
/* Per-thread locker ownership                                        */

/*
 * A user of a key (a cipher context) keeps one KLE_KEY.  The SCC is the
 * key; the remaining fields cache where it is loaded.
 *
 * A CTR Machine key is the SCC exported in Ready.  The IV and counter it
 * operates with are public, so they are never exported: the locker caches
 * them, and ctr_iv and ctr say what it holds as long as ctr_gen is the
 * generation of the current load.  Every load (eviction, another thread, a
 * copied context) starts from the Ready SCC with ctr_gen 0, which no load
 * has.
 */
typedef struct {
    unsigned char scc[KLE_SCC_MAX];
    size_t scc_len;
    int state;              /* KLE_ST_ENCRYPT, _DECRYPT or _OPERATE (CTR) */
    int locker;             /* -1: not loaded */
    const void *thread;     /* identity of the thread that holds it */
    uint64_t gen;
    unsigned char ctr_iv[12];
    uint32_t ctr;
    uint64_t ctr_gen;
} KLE_KEY;

/*
 * The tables shared by the components.  libcrypto defines them and exports
 * them to the kle provider module.  Each component has
 * KLE_DEFINE_COMPONENT in exactly one translation unit: the address of its
 * ossl_kle_component, which no DSO exports, says whose a slot is.
 *
 * Every claim of a locker gets a generation that is unique within the
 * process, so a generation names one load of one key in one thread
 * forever: it cannot match a later load, nor a new thread that reuses an
 * exited thread's storage.
 */
struct kle_slot {
    const KLE_KEY *owner;
    const void *comp;       /* the owner's &ossl_kle_component */
    uint64_t gen;
    int busy;               /* a GCM message is open: not to be evicted */
};

struct kle_table {
    struct kle_slot slot[KLE_LOCKERS];
    uint64_t seen;          /* kle_releases.seq at the last drain */
    int next_victim;
};

/*
 * Generations of lockers released by other threads than their owners.
 * The ring overwrites its oldest entries: a release lost that way, or
 * posted for a thread that has exited, only leaves the locker to be
 * evicted later, as if it was never posted.  0 is an empty entry.
 */
#define KLE_RELEASES 64

struct kle_releases {
    uint64_t gen[KLE_RELEASES];
    uint64_t head;          /* next entry to write */
    uint64_t seq;           /* bumped after each write */
    uint64_t next_gen;      /* last generation handed out */
};

/* Defined in libcrypto's cipher_aes_hw_kle.c, and exported. */
extern __thread struct kle_table ossl_kle_table;
extern struct kle_releases ossl_kle_releases;
/* A new generation; the first call registers the atfork handler. */
uint64_t ossl_kle_next_gen(void);

extern const char ossl_kle_component;
#define KLE_DEFINE_COMPONENT const char ossl_kle_component = 0

static inline int kle_key_loaded(const KLE_KEY *key)
{
    struct kle_table *t = &ossl_kle_table;

    return key->locker >= 0 && key->thread == (const void *)t
        && t->slot[key->locker].owner == key
        && t->slot[key->locker].gen == key->gen;
}

/* Ask the thread that holds generation gen to clear its locker. */
static inline void kle_post_release(uint64_t gen)
{
    struct kle_releases *r = &ossl_kle_releases;
    uint64_t i = __atomic_fetch_add(&r->head, 1, __ATOMIC_RELAXED);

    __atomic_store_n(&r->gen[i % KLE_RELEASES], gen, __ATOMIC_RELAXED);
    __atomic_fetch_add(&r->seq, 1, __ATOMIC_RELEASE);
}

/* Clear this thread's lockers that other threads released. */
static inline void kle_drain(void)
{
    struct kle_table *t = &ossl_kle_table;
    struct kle_releases *r = &ossl_kle_releases;
    uint64_t seq = __atomic_load_n(&r->seq, __ATOMIC_ACQUIRE), g;
    int i, j;

    if (seq == t->seen)
        return;
    t->seen = seq;
    for (j = 0; j < KLE_RELEASES; j++) {
        if ((g = __atomic_load_n(&r->gen[j], __ATOMIC_RELAXED)) == 0)
            continue;
        for (i = 0; i < KLE_LOCKERS; i++) {
            if (t->slot[i].owner != NULL && t->slot[i].gen == g) {
                kle_setst(i, KLE_ST_UNCONFIGURED);
                t->slot[i].owner = NULL;
                /* Unless the entry was overwritten meanwhile. */
                __atomic_compare_exchange_n(&r->gen[j], &g, 0, 0,
                                            __ATOMIC_RELAXED,
                                            __ATOMIC_RELAXED);
                break;
            }
        }
    }
}

/*
 * Take a locker: a free one, else evict one of ours.  An Unconfigured
 * locker is free even when the table names it: other software cleared it,
 * and its record goes, so that its key loads again on its next use.
 */
static inline int kle_alloc(void)
{
    struct kle_table *t = &ossl_kle_table;
    int i;

    kle_drain();
    for (i = 0; i < KLE_LOCKERS; i++)
        if (kle_getst(i) == KLE_ST_UNCONFIGURED) {
            t->slot[i].owner = NULL;
            return i;
        }
    for (i = 0; i < KLE_LOCKERS; i++) {
        int v = (t->next_victim + i) % KLE_LOCKERS;

        if (t->slot[v].owner != NULL && !t->slot[v].busy
            && t->slot[v].comp == &ossl_kle_component) {
            t->next_victim = (v + 1) % KLE_LOCKERS;
            kle_setst(v, KLE_ST_UNCONFIGURED);
            t->slot[v].owner = NULL;
            return v;
        }
    }
    return -1;
}

static inline void kle_claim(KLE_KEY *key, int i)
{
    struct kle_table *t = &ossl_kle_table;

    t->slot[i].owner = key;
    t->slot[i].comp = &ossl_kle_component;
    t->slot[i].gen = ossl_kle_next_gen();
    t->slot[i].busy = 0;
    key->locker = i;
    key->thread = t;
    key->gen = t->slot[i].gen;
    key->ctr_gen = 0;       /* the locker starts from the SCC */
}

/*
 * Release the key's locker: clear it if this thread holds it, else post it
 * to the thread that does.
 */
static inline void kle_key_release(KLE_KEY *key)
{
    kle_drain();
    if (kle_key_loaded(key)) {
        kle_setst(key->locker, KLE_ST_UNCONFIGURED);
        ossl_kle_table.slot[key->locker].owner = NULL;
    } else if (key->locker >= 0 && key->thread != NULL
               && key->thread != (const void *)&ossl_kle_table) {
        kle_post_release(key->gen);
    }
    key->locker = -1;
    key->thread = NULL;
}

/*
 * Make sure the key is in a locker of this thread: import its SCC if not,
 * also when its locker was cleared or is in an Error State (Invalid after
 * a misuse, say).  Returns the locker's State, -1 if no locker or the SCC
 * did not import.
 */
static inline int kle_key_load(KLE_KEY *key)
{
    int i, st;

    kle_drain();
    st = kle_key_loaded(key) ? kle_getst(key->locker)
                              : KLE_ST_UNCONFIGURED;
    if (st == KLE_ST_UNCONFIGURED || KLE_ST_ERROR(st)) {
        /* Cleared by other software (kl.clear, kl.clearall): free the slot. */
        if (kle_key_loaded(key)) {
            if (st != KLE_ST_UNCONFIGURED)
                kle_setst(key->locker, KLE_ST_UNCONFIGURED);
            ossl_kle_table.slot[key->locker].owner = NULL;
        }
        /* If another thread has it loaded, have that thread clear it. */
        kle_key_release(key);
        if ((i = kle_alloc()) < 0)
            return -1;
        st = kle_import(i, key->scc);
        if (KLE_ST_ERROR(st) || st == KLE_ST_UNCONFIGURED) {
            kle_setst(i, KLE_ST_UNCONFIGURED);
            return -1;
        }
        kle_claim(key, i);
    }
    return st;
}

/* A GCM message open (on) or closed: no eviction of its locker meanwhile. */
static inline void kle_key_pin(const KLE_KEY *key, int on)
{
    if (kle_key_loaded(key))
        ossl_kle_table.slot[key->locker].busy = on;
}

/*
 * Make sure the key is in a locker of this thread, in key->state.  A CTR
 * Machine key is ready in Ready or Operate: its user enters Operate, which
 * takes the IV as an operand.
 */
static inline int kle_key_ready(KLE_KEY *key)
{
    int st = kle_key_load(key);

    if (st < 0)
        return 0;
    if (key->state == KLE_ST_OPERATE)
        return st == KLE_ST_READY || st == KLE_ST_OPERATE;
    if (st == key->state)
        return 1;
    /* Enter Encrypt or Decrypt. */
    kle_setst(key->locker, key->state);
    return kle_getst(key->locker) == key->state;
}

static inline void kle_key_copy(KLE_KEY *dst, const KLE_KEY *src)
{
    memcpy(dst->scc, src->scc, sizeof(dst->scc));
    dst->scc_len = src->scc_len;
    dst->state = src->state;
    dst->locker = -1;
    dst->thread = NULL;
    dst->gen = 0;
}

/*
 * Turn a raw AES key into an SCC of the mode's Machine (KLE_MODE_*):
 * provision a locker, export it and keep the locker loaded.  policy is
 * KLE_POLICY_*; locality KLE_LOC_*.  The caller cleanses the raw key.
 */
static inline int kle_key_from_raw(KLE_KEY *key, const unsigned char *raw,
                                    size_t len, int mode, int policy,
                                    int locality)
{
    unsigned char content[32] __attribute__((aligned(16)));
    int machine = kle_machine(len, mode), i, st;

    if (machine < 0)
        return 0;
    if ((i = kle_alloc()) < 0)
        return 0;
    memset(content, 0, sizeof(content));
    memcpy(content, raw, len);
    st = kle_provision(i, KLE_MDH_LO(machine, policy, 0),
                        KLE_MDH_HI(KLE_USAGE_USER_ONLY, locality), content);
    memset(content, 0, sizeof(content));
    __asm__ volatile("" ::"r"(content) : "memory");
    if (st != KLE_ST_READY
        || (key->scc_len = kle_export(i, key->scc)) == 0) {
        kle_setst(i, KLE_ST_UNCONFIGURED);
        return 0;
    }
    kle_claim(key, i);
    return 1;
}

/* Generate a random ECB key inside the unit (all-ones SKID): never seen. */
static inline int kle_key_generate(KLE_KEY *key, size_t len, int policy,
                                    int locality)
{
    unsigned char content[16] __attribute__((aligned(16)));
    int machine = kle_machine(len, KLE_MODE_ECB), i;

    if (machine < 0)
        return 0;
    if ((i = kle_alloc()) < 0)
        return 0;
    memset(content, 0, sizeof(content));
    memset(content, 0xff, 8);
    if (kle_provision(i, KLE_MDH_LO(machine, policy, 1),
                       KLE_MDH_HI(KLE_USAGE_USER_ONLY, locality),
                       content) != KLE_ST_READY
        || (key->scc_len = kle_export(i, key->scc)) == 0) {
        kle_setst(i, KLE_ST_UNCONFIGURED);
        return 0;
    }
    kle_claim(key, i);
    return 1;
}

/* Adopt an SCC handed in by the application; it is checked on first use. */
static inline int kle_key_from_scc(KLE_KEY *key, const unsigned char *scc,
                                    size_t len)
{
    if (len < 32 || len > KLE_SCC_MAX || len % 16)
        return 0;
    memset(key->scc, 0, sizeof(key->scc));
    memcpy(key->scc, scc, len);
    key->scc_len = len;
    key->locker = -1;
    key->thread = NULL;
    return 1;
}

/* KLE_MODE_* of an SCC (from its Machine field). */
static inline int kle_scc_mode(const unsigned char *scc)
{
    return scc[0] & 0xf;
}

/* AES key length in bytes of an ECB SCC (from its Machine field). */
static inline size_t kle_scc_keylen(const unsigned char *scc)
{
    switch (scc[0] | (scc[1] & 0xf) << 8) {
    case 0x000: return 16;
    case 0x010: return 24;
    case 0x020: return 32;
    }
    return 0;
}

#endif /* riscv64 linux */
#endif /* OSSL_CRYPTO_RISCV_KLE_H */
