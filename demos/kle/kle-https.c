/*
 *  Copyright 2023-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License").  You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 */

/*
 * An HTTPS client that shows where its TLS record keys are: in the RISC-V
 * Zkl (KLE) lockers of the thread that runs the connection.  It is
 * demos/guide/tls-client-block.c with an HTTP/1.0 GET, AES-GCM cipher
 * suites, and a census of the thread's lockers after the handshake, after
 * the response and after the connection is freed.
 *
 *   kle-https [--kle] [--tls1.2|--tls1.3] [--suite S] [--CAfile F]
 *             [--port N] [--path P] [--body] [--tamper] [--all] [host]
 *
 * The host defaults to openssl-conference.org.  Without --kle, libssl
 * fetches AES-GCM from the default provider, which puts raw keys into
 * lockers unasked on a Zkl hart, but computes GHASH in software.  --kle
 * loads the kle provider too and prefers it ("?provider=kle"), for AES-GCM
 * on the AES-GCM Machine when the unit has it: all of GCM in the locker.
 * The report goes to stderr; --body writes the response body to stdout.
 *
 * --tamper flips one bit of the first record the server sends after the
 * handshake, on its way from the socket to libssl, so that the record's
 * tag fails, and the census then shows who checked it: with --kle on the
 * AES-GCM Machine, its decrypt-only locker is in Failure.
 *
 * The census reads each locker's metadata (kl.getmd) through the internal
 * header crypto/riscv_kle.h, and which component's locker table owns it,
 * so this demo builds only next to an OpenSSL build tree:
 *
 * Before it connects, the client draws from the public and the private
 * DRBG, so that their lockers exist (the handshake would create them
 * anyway: the default provider's CTR-DRBG runs AES-256 on lockers too),
 * and lists every locker once.  The later censuses list only the lockers
 * whose Machine, State, policy or owner differ from that baseline, and
 * count the rest, so that the connection's own lockers stand out; --all
 * lists every locker each time.
 *
 *   cc -Iinclude -o kle-https demos/kle/kle-https.c -L. -lssl -lcrypto
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include "crypto/riscv_kle.h"

#ifndef OSSL_RISCV_KLE
#error "kle-https needs a riscv64 Linux build of OpenSSL with enable-kle"
#endif

/*
 * AES-128 first: servers that honour the client's order then pick it, and
 * the record keys stand out in the census from the DRBG's AES-256 keys.
 */
static const char *suites13 = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384";
static const char *suites12 = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                              "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384";

/* As the kle provider checks: Zkl (hwprobe IMA_EXT_1 bit 6) and V. */
static int have_kle(void)
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

static const char *machine_name(int m)
{
    static const char *const mode[] = { "ECB", "CTR", "?", "?", "GCM" };
    static char buf[16];

    if (m >> 4 > 2 || (m & 15) >= (int)(sizeof(mode) / sizeof(*mode)))
        snprintf(buf, sizeof(buf), "0x%03x", m);
    else
        snprintf(buf, sizeof(buf), "AES%d_%s", 128 + 64 * (m >> 4), mode[m & 15]);
    return buf;
}

static const char *state_name(int m, int st)
{
    static const char *const names[] = {
        "Unconfigured", "Ready", "Operate", "Hash_Last_Block", "Hash_Finalize",
        "Hash_Verify", "Hash_Output", "Encrypt", "Decrypt", "Enc_Last_Block",
        "Dec_Last_Block", "Enc_Tag_Finalize", "Dec_Tag_Finalize", "Set_Aux_Value"
    };
    static char buf[16];

    if (st == KLE_ST_HASH_ABSORB && (m & 15) == KLE_MODE_GCM)
        return "Hash_Absorb";   /* the number of CTR's Operate */
    if (st < (int)(sizeof(names) / sizeof(*names)))
        return names[st];
    if (st == 46)
        return "Success";
    if (st == 47)
        return "Failure";
    snprintf(buf, sizeof(buf), KLE_ST_ERROR(st) ? "Error %d" : "State %d", st);
    return buf;
}

/* Whose record a locker is: the default provider's (libcrypto) or kle's. */
static const char *owner_name(int i)
{
    const struct kle_slot *s = &ossl_kle_table.slot[i];
    Dl_info info;
    const char *p;

    if (s->owner == NULL)
        return "-";
    if (!dladdr(s->comp, &info) || info.dli_fname == NULL)
        return "?";
    p = strrchr(info.dli_fname, '/');
    p = p != NULL ? p + 1 : info.dli_fname;
    return strncmp(p, "libcrypto", 9) == 0 ? "default provider"
        : strncmp(p, "kle", 3) == 0 ? "kle provider" : p;
}

/* What a census shows of a locker: its MDH's Machine, State and policy. */
struct locker_view {
    int machine, state, policy;
    const char *owner;
};

static int show_all;
static struct locker_view base[KLE_LOCKERS];   /* before the connection */

static void locker_view(int i, struct locker_view *v)
{
    uint64_t m[2];

    kle_getmd(i, m);
    v->machine = KLE_MDH_MACHINE(m[0]);
    v->state = KLE_MDH_STATE(m[0]);
    v->policy = m[0] >> 12 & 3;
    v->owner = owner_name(i);
}

static int same_view(const struct locker_view *a, const struct locker_view *b)
{
    return a->machine == b->machine && a->state == b->state
        && a->policy == b->policy && strcmp(a->owner, b->owner) == 0;
}

static void print_view(int i, const struct locker_view *v)
{
    fprintf(stderr, "  K%-2d %-10s %-16s %-7s %s\n", i,
            machine_name(v->machine), state_name(v->machine, v->state),
            v->policy == 3 ? "enc+dec" : v->policy & 1 ? "enc" : "dec",
            v->owner);
}

/*
 * The lockers of this thread (lockers are hart state the OS switches):
 * all of them with --all, else those that differ from the baseline, and
 * a count of the configured ones that do not.
 */
static void census(const char *when)
{
    struct locker_view v;
    int i, n = 0, unchanged = 0;

    fprintf(stderr, "lockers %s:\n", when);
    for (i = 0; i < KLE_LOCKERS; i++) {
        locker_view(i, &v);
        if (!show_all && same_view(&v, &base[i])) {
            if (v.state != KLE_ST_UNCONFIGURED)
                unchanged++;
            continue;
        }
        if (v.state == KLE_ST_UNCONFIGURED)
            continue;
        print_view(i, &v);
        n++;
    }
    if (n == 0)
        fprintf(stderr, "  none\n");
    if (unchanged > 0)
        fprintf(stderr, "  (%d unchanged since before the connection)\n",
                unchanged);
}

/*
 * The baseline: the lockers before the connection.  A draw from the public
 * and the private DRBG first, so that their lockers, which the handshake
 * would create anyway, are in it and not in what the connection adds.
 */
static int baseline(void)
{
    unsigned char b[1];
    int i;

    if (!RAND_bytes(b, sizeof(b)) || !RAND_priv_bytes(b, sizeof(b)))
        return 0;
    for (i = 0; i < KLE_LOCKERS; i++)
        locker_view(i, &base[i]);
    if (!show_all) {
        fprintf(stderr, "lockers before the connection:\n");
        for (i = 0; i < KLE_LOCKERS; i++)
            if (base[i].state != KLE_ST_UNCONFIGURED)
                print_view(i, &base[i]);
    }
    return 1;
}

/* As demos/guide/tls-client-block.c: the first address that connects. */
static BIO *create_socket_bio(const char *hostname, const char *port)
{
    int sock = -1;
    BIO_ADDRINFO *res;
    const BIO_ADDRINFO *ai = NULL;
    BIO *bio;

    if (!BIO_lookup_ex(hostname, port, BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM,
            0, &res))
        return NULL;
    for (ai = res; ai != NULL; ai = BIO_ADDRINFO_next(ai)) {
        sock = BIO_socket(BIO_ADDRINFO_family(ai), SOCK_STREAM, 0, 0);
        if (sock == -1)
            continue;
        if (!BIO_connect(sock, BIO_ADDRINFO_address(ai), BIO_SOCK_NODELAY)) {
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }
        break;
    }
    BIO_ADDRINFO_free(res);
    if (sock == -1)
        return NULL;
    if ((bio = BIO_new(BIO_s_socket())) == NULL) {
        BIO_closesocket(sock);
        return NULL;
    }
    BIO_set_fd(bio, sock, BIO_CLOSE);
    return bio;
}

/*
 * --tamper: a filter between libssl and the socket.  Once armed, it counts
 * the bytes the server sends down to the one to flip.
 */
static long tamper_at = -1;

static int tamper_read(BIO *b, char *out, size_t len, size_t *done)
{
    int ret = BIO_read_ex(BIO_next(b), out, len, done);

    BIO_clear_retry_flags(b);
    BIO_copy_next_retry(b);
    if (ret && tamper_at >= 0) {
        if ((size_t)tamper_at < *done) {
            out[tamper_at] ^= 1;
            tamper_at = -1;
        } else {
            tamper_at -= (long)*done;
        }
    }
    return ret;
}

static int tamper_write(BIO *b, const char *in, size_t len, size_t *done)
{
    int ret = BIO_write_ex(BIO_next(b), in, len, done);

    BIO_clear_retry_flags(b);
    BIO_copy_next_retry(b);
    return ret;
}

static long tamper_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    return BIO_next(b) != NULL ? BIO_ctrl(BIO_next(b), cmd, num, ptr) : 0;
}

static int tamper_create(BIO *b)
{
    BIO_set_init(b, 1);
    return 1;
}

static BIO *tamper_push(BIO *next, BIO_METHOD **meth)
{
    BIO *b;

    if ((*meth = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_FILTER,
                              "tamper")) == NULL
        || !BIO_meth_set_read_ex(*meth, tamper_read)
        || !BIO_meth_set_write_ex(*meth, tamper_write)
        || !BIO_meth_set_ctrl(*meth, tamper_ctrl)
        || !BIO_meth_set_create(*meth, tamper_create)
        || (b = BIO_new(*meth)) == NULL)
        return NULL;
    return BIO_push(b, next);
}

static void usage(void)
{
    fprintf(stderr, "Usage: kle-https [--kle] [--tls1.2|--tls1.3] [--suite S]"
                    " [--CAfile F]\n"
                    "                 [--port N] [--path P] [--body] [--tamper]"
                    " [--all] [host]\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    const char *host = "openssl-conference.org", *port = "443", *path = "/";
    const char *cafile = NULL, *suite = NULL, *propq = NULL, *eoh;
    int kle = 0, version = 0, body = 0, tamper = 0, res = EXIT_FAILURE, i;
    OSSL_PROVIDER *dflt = NULL, *klep = NULL;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *bio, *tbio;
    BIO_METHOD *tmeth = NULL;
    EVP_CIPHER *ciph = NULL;
    const SSL_CIPHER *c;
    char *req = NULL, *resp = NULL, *p;
    size_t len = 0, cap = 0, n, hlen;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--kle") == 0)
            kle = 1;
        else if (strcmp(argv[i], "--tls1.2") == 0)
            version = TLS1_2_VERSION;
        else if (strcmp(argv[i], "--tls1.3") == 0)
            version = TLS1_3_VERSION;
        else if (strcmp(argv[i], "--body") == 0)
            body = 1;
        else if (strcmp(argv[i], "--tamper") == 0)
            tamper = 1;
        else if (strcmp(argv[i], "--all") == 0)
            show_all = 1;
        else if (i + 1 < argc && strcmp(argv[i], "--suite") == 0)
            suite = argv[++i];
        else if (i + 1 < argc && strcmp(argv[i], "--CAfile") == 0)
            cafile = argv[++i];
        else if (i + 1 < argc && strcmp(argv[i], "--port") == 0)
            port = argv[++i];
        else if (i + 1 < argc && strcmp(argv[i], "--path") == 0)
            path = argv[++i];
        else if (argv[i][0] == '-' || i + 1 != argc)
            usage();
        else
            host = argv[i];
    }
    if (!have_kle()) {
        fprintf(stderr, "This hart has no Zkl (KLE) or no V\n");
        goto end;
    }

    if (kle) {
        /* Explicit loads replace the implicit default provider. */
        if ((dflt = OSSL_PROVIDER_load(NULL, "default")) == NULL
            || (klep = OSSL_PROVIDER_load(NULL, "kle")) == NULL) {
            fprintf(stderr, "Failed to load the kle provider (OPENSSL_MODULES?)\n");
            goto end;
        }
        propq = "?provider=kle";
    }
    if ((ctx = SSL_CTX_new_ex(NULL, propq, TLS_client_method())) == NULL) {
        fprintf(stderr, "Failed to create the SSL_CTX\n");
        goto end;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (!(cafile != NULL ? SSL_CTX_load_verify_file(ctx, cafile)
                         : SSL_CTX_set_default_verify_paths(ctx))) {
        fprintf(stderr, "Failed to set the trusted certificate store\n");
        goto end;
    }
    if (!SSL_CTX_set_min_proto_version(ctx, version ? version : TLS1_2_VERSION)
        || !SSL_CTX_set_max_proto_version(ctx, version)) {
        fprintf(stderr, "Failed to set the TLS protocol version\n");
        goto end;
    }
    /*
     * Only AES-GCM, so that the record keys can go to lockers.  --suite
     * replaces the TLS 1.2 cipher list with --tls1.2, else the TLS 1.3
     * cipher suites.
     */
    if (version == TLS1_2_VERSION)
        i = SSL_CTX_set_cipher_list(ctx, suite != NULL ? suite : suites12);
    else
        i = SSL_CTX_set_ciphersuites(ctx, suite != NULL ? suite : suites13)
            && SSL_CTX_set_cipher_list(ctx, suites12);
    if (!i) {
        fprintf(stderr, "Failed to set the cipher suites\n");
        goto end;
    }

    if ((ssl = SSL_new(ctx)) == NULL) {
        fprintf(stderr, "Failed to create the SSL object\n");
        goto end;
    }
    if (!baseline()) {
        fprintf(stderr, "Failed to draw from the DRBGs\n");
        goto end;
    }
    if ((bio = create_socket_bio(host, port)) == NULL) {
        fprintf(stderr, "Failed to connect to %s:%s\n", host, port);
        goto end;
    }
    if (tamper) {
        if ((tbio = tamper_push(bio, &tmeth)) == NULL) {
            BIO_free(bio);
            goto end;
        }
        bio = tbio;
    }
    SSL_set_bio(ssl, bio, bio);
    if (!SSL_set_tlsext_host_name(ssl, host) || !SSL_set1_dnsname(ssl, host)) {
        fprintf(stderr, "Failed to set the server name\n");
        goto end;
    }
    if (SSL_connect(ssl) < 1) {
        fprintf(stderr, "Failed to connect to the server\n");
        if (SSL_get_verify_result(ssl) != X509_V_OK)
            fprintf(stderr, "Verify error: %s\n",
                X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        goto end;
    }

    c = SSL_get_current_cipher(ssl);
    ciph = EVP_CIPHER_fetch(NULL, OBJ_nid2sn(SSL_CIPHER_get_cipher_nid(c)), propq);
    fprintf(stderr, "%s %s, records by %s from the %s provider\n",
            SSL_get_version(ssl), SSL_CIPHER_get_name(c),
            ciph != NULL ? EVP_CIPHER_get0_name(ciph) : "?",
            ciph != NULL ? OSSL_PROVIDER_get0_name(EVP_CIPHER_get0_provider(ciph))
                         : "?");
    census("after the handshake");
    /*
     * The next record is the server's first under its application traffic
     * key (libssl reads no further than it needs): flip the low bit of its
     * first byte of ciphertext, past the header and, in TLS 1.2, the
     * explicit nonce.
     */
    if (tamper) {
        tamper_at = SSL_version(ssl) == TLS1_2_VERSION ? 5 + 8 : 5;
        fprintf(stderr, "tampering: one bit of the server's next record\n");
    }

    n = strlen(path) + strlen(host) + 64;
    if ((req = malloc(n)) == NULL)
        goto end;
    /* HTTP/1.0: no chunked transfer coding, the server closes. */
    snprintf(req, n, "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: kle-https\r\n\r\n",
             path, host);
    if (!SSL_write_ex(ssl, req, strlen(req), &n)) {
        fprintf(stderr, "Failed to write the HTTP request\n");
        goto end;
    }
    for (;;) {
        if (cap - len < 4096) {
            if ((p = realloc(resp, cap = 2 * cap + 4096)) == NULL)
                goto end;
            resp = p;
        }
        if (!SSL_read_ex(ssl, resp + len, cap - len - 1, &n))
            break;
        len += n;
    }
    /* A clean close_notify; some servers just close after HTTP/1.0. */
    if (SSL_get_error(ssl, 0) != SSL_ERROR_ZERO_RETURN
        && (len == 0 || ERR_GET_REASON(ERR_peek_last_error())
                            != SSL_R_UNEXPECTED_EOF_WHILE_READING)) {
        fprintf(stderr, "Failed reading the response\n");
        census("after the failed read");
        goto end;
    }
    ERR_clear_error();
    resp[len] = '\0';
    census("after the response");

    eoh = strstr(resp, "\r\n\r\n");
    hlen = eoh != NULL ? (size_t)(eoh - resp) + 4 : len;
    p = strstr(resp, "\r\n");
    fprintf(stderr, "%.*s, %zu bytes of body\n",
            (int)(p != NULL ? p - resp : 0), resp, len - hlen);
    if (body)
        fwrite(resp + hlen, 1, len - hlen, stdout);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    ssl = NULL;
    census("after SSL_free");
    res = EXIT_SUCCESS;
end:
    if (res == EXIT_FAILURE)
        ERR_print_errors_fp(stderr);
    free(req);
    free(resp);
    EVP_CIPHER_free(ciph);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    BIO_meth_free(tmeth);
    OSSL_PROVIDER_unload(klep);
    OSSL_PROVIDER_unload(dflt);
    return res;
}
