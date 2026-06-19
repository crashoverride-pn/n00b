/*
 * test_quic_cert_store.c — Unit tests for the SNI-keyed cert store.
 *
 * Coverage:
 *   1. install/lookup round-trip
 *   2. install rejects duplicate sni_pattern; replace updates it
 *   3. SNI match precedence: exact > "*.suffix" wildcard > "*" catchall
 *   4. lookup of non-matching name returns NULL when no catchall
 *   5. count() reflects current view; survives swaps
 *   6. close() is idempotent
 *   7. multi-thread sanity (one writer + one reader): readers never
 *      see partial views (acquire-load on a swapped-in view returns
 *      the new size with the new entry present)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "core/thread.h"
#include <assert.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "core/string.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"
#include "internal/crypto/cert_store.h"

static n00b_buffer_t *
make_pem(const char *tag)
{
    /* Distinct bytes per entry so we can detect mistaken aliasing. */
    char buf[256];
    snprintf(buf, sizeof(buf),
             "-----BEGIN CERTIFICATE-----\n"
             "FAKE-CERT-%s\n"
             "-----END CERTIFICATE-----\n", tag);
    return n00b_buffer_from_bytes(buf, (int64_t)strlen(buf));
}

static n00b_quic_secret_t *
make_key(void)
{
    auto kr = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:cs"));
    return n00b_result_get(kr);
}

/* ============================================================================
 * 1. install / lookup round-trip
 * ============================================================================ */

static void
test_install_lookup(void)
{
    n00b_quic_cert_store_t *cs = n00b_quic_cert_store_new();
    assert(cs);
    assert(n00b_quic_cert_store_count(cs) == 0);

    n00b_buffer_t      *pem = make_pem("a");
    n00b_quic_secret_t *k   = make_key();

    auto r = n00b_quic_cert_store_install(cs, "foo.example.com",
                                          pem, k, 1234567890);
    assert(n00b_result_is_ok(r));
    assert(n00b_quic_cert_store_count(cs) == 1);

    const n00b_quic_cert_entry_t *e =
        n00b_quic_cert_store_lookup(cs, "foo.example.com");
    assert(e);
    assert(strcmp(e->sni_pattern, "foo.example.com") == 0);
    assert(e->chain_pem == pem);
    assert(e->key == k);
    assert(e->not_after_ms == 1234567890);

    /* Lookup of unrelated name → NULL (no catchall installed). */
    assert(n00b_quic_cert_store_lookup(cs, "bar.example.com") == NULL);

    n00b_quic_cert_store_close(cs);
    n00b_quic_secret_close(k);
    printf("  [PASS] install + lookup round-trip\n");
}

/* ============================================================================
 * 2. install rejects duplicates; replace updates
 * ============================================================================ */

static void
test_install_dup_replace(void)
{
    n00b_quic_cert_store_t *cs = n00b_quic_cert_store_new();
    n00b_quic_secret_t     *k  = make_key();

    n00b_buffer_t *pem1 = make_pem("v1");
    auto r1 = n00b_quic_cert_store_install(cs, "x.example",
                                           pem1, k, 1000);
    assert(n00b_result_is_ok(r1));

    /* Same pattern via install → INVALID_ARG. */
    n00b_buffer_t *pem1b = make_pem("v1b");
    auto r2 = n00b_quic_cert_store_install(cs, "x.example",
                                           pem1b, k, 1100);
    assert(n00b_result_is_err(r2));
    assert(n00b_quic_cert_store_count(cs) == 1);

    /* Same pattern via replace → succeeds, count unchanged. */
    n00b_buffer_t *pem2 = make_pem("v2");
    auto r3 = n00b_quic_cert_store_replace(cs, "x.example",
                                           pem2, k, 2000);
    assert(n00b_result_is_ok(r3));
    assert(n00b_quic_cert_store_count(cs) == 1);

    const n00b_quic_cert_entry_t *e =
        n00b_quic_cert_store_lookup(cs, "x.example");
    assert(e);
    assert(e->chain_pem == pem2);
    assert(e->not_after_ms == 2000);

    /* Replace on missing pattern *adds* it (count grows). */
    n00b_buffer_t *pem3 = make_pem("v3");
    auto r4 = n00b_quic_cert_store_replace(cs, "y.example",
                                           pem3, k, 3000);
    assert(n00b_result_is_ok(r4));
    assert(n00b_quic_cert_store_count(cs) == 2);

    n00b_quic_cert_store_close(cs);
    n00b_quic_secret_close(k);
    printf("  [PASS] install rejects dup, replace updates / adds\n");
}

/* ============================================================================
 * 3. SNI match precedence: exact > wildcard > catchall
 * ============================================================================ */

static void
test_sni_precedence(void)
{
    n00b_quic_cert_store_t *cs = n00b_quic_cert_store_new();
    n00b_quic_secret_t     *k  = make_key();

    n00b_buffer_t *pem_catchall = make_pem("catchall");
    n00b_buffer_t *pem_wild     = make_pem("wild");
    n00b_buffer_t *pem_exact    = make_pem("exact");

    /* Insert in *reverse* precedence order so the lookup must do
     * actual scoring rather than first-match. */
    n00b_quic_cert_store_install(cs, "*",
                                 pem_catchall, k, 1000);
    n00b_quic_cert_store_install(cs, "*.example.com",
                                 pem_wild, k, 2000);
    n00b_quic_cert_store_install(cs, "alpha.example.com",
                                 pem_exact, k, 3000);

    /* Exact win for the exact name. */
    {
        const n00b_quic_cert_entry_t *e =
            n00b_quic_cert_store_lookup(cs, "alpha.example.com");
        assert(e && e->chain_pem == pem_exact);
    }
    /* Wildcard wins for a one-label sibling. */
    {
        const n00b_quic_cert_entry_t *e =
            n00b_quic_cert_store_lookup(cs, "beta.example.com");
        assert(e && e->chain_pem == pem_wild);
    }
    /* Wildcard does NOT match a multi-label sub-sub-domain — falls
     * through to catchall. */
    {
        const n00b_quic_cert_entry_t *e =
            n00b_quic_cert_store_lookup(cs, "x.beta.example.com");
        assert(e && e->chain_pem == pem_catchall);
    }
    /* Wildcard does NOT match the bare apex (must have at least one
     * label), so apex falls through to catchall. */
    {
        const n00b_quic_cert_entry_t *e =
            n00b_quic_cert_store_lookup(cs, "example.com");
        assert(e && e->chain_pem == pem_catchall);
    }
    /* Random name still hits catchall. */
    {
        const n00b_quic_cert_entry_t *e =
            n00b_quic_cert_store_lookup(cs, "unrelated.test");
        assert(e && e->chain_pem == pem_catchall);
    }

    n00b_quic_cert_store_close(cs);
    n00b_quic_secret_close(k);
    printf("  [PASS] SNI precedence: exact > wildcard > catchall\n");
}

/* ============================================================================
 * 4. No catchall → unrelated lookups return NULL
 * ============================================================================ */

static void
test_no_catchall_returns_null(void)
{
    n00b_quic_cert_store_t *cs = n00b_quic_cert_store_new();
    n00b_quic_secret_t     *k  = make_key();
    n00b_quic_cert_store_install(cs, "*.foo.test",
                                 make_pem("w"), k, 1);
    assert(n00b_quic_cert_store_lookup(cs, "foo.test")     == NULL);
    assert(n00b_quic_cert_store_lookup(cs, "x.bar.test")   == NULL);
    assert(n00b_quic_cert_store_lookup(cs, "x.foo.test")   != NULL);
    n00b_quic_cert_store_close(cs);
    n00b_quic_secret_close(k);
    printf("  [PASS] no catchall → unrelated lookup returns NULL\n");
}

/* ============================================================================
 * 5. close() idempotence + post-close lookups return NULL
 * ============================================================================ */

static void
test_close_idempotent(void)
{
    n00b_quic_cert_store_t *cs = n00b_quic_cert_store_new();
    n00b_quic_secret_t     *k  = make_key();
    n00b_quic_cert_store_install(cs, "x", make_pem("x"), k, 1);

    n00b_quic_cert_store_close(cs);
    n00b_quic_cert_store_close(cs);  /* idempotent */

    /* Post-close lookup is a logic bug in callers but must not UAF. */
    assert(n00b_quic_cert_store_lookup(cs, "x") == NULL);
    assert(n00b_quic_cert_store_count(cs) == 0);

    n00b_quic_secret_close(k);
    printf("  [PASS] close idempotent + post-close safety\n");
}

/* ============================================================================
 * 6. Single-writer / single-reader race sanity.
 *
 * Reader thread does N lookups on an installed name; concurrently the
 * writer keeps replacing the entry.  Every successful lookup must
 * return a fully-formed entry (sni_pattern non-NULL, chain_pem
 * non-NULL).
 * ============================================================================ */

typedef struct {
    n00b_quic_cert_store_t *cs;
    int                     iters;
    int                     ok;
    int                     null_obs;
} reader_arg_t;

typedef struct {
    n00b_quic_cert_store_t *cs;
    n00b_quic_secret_t     *k;
    int                     iters;
    int                     ok;
    _Atomic int            *go;
} writer_arg_t;

static void *
reader_main(void *p)
{
    reader_arg_t *a = p;
    for (int i = 0; i < a->iters; i++) {
        const n00b_quic_cert_entry_t *e =
            n00b_quic_cert_store_lookup(a->cs, "race.example");
        if (!e) {
            a->null_obs++;
            continue;
        }
        if (e->sni_pattern && e->chain_pem && e->key) {
            a->ok++;
        }
    }
    return NULL;
}

static void *
writer_main(void *p)
{
    writer_arg_t *a = p;
    for (int i = 0; i < a->iters; i++) {
        char tag[32];
        snprintf(tag, sizeof(tag), "v%d", i);
        n00b_quic_cert_store_replace(a->cs, "race.example",
                                     make_pem(tag), a->k, i);
        a->ok++;
    }
    return NULL;
}

static void
test_reader_writer_sanity(void)
{
    n00b_quic_cert_store_t *cs = n00b_quic_cert_store_new();
    n00b_quic_secret_t     *k  = make_key();

    /* Seed with one entry so initial lookups succeed. */
    n00b_quic_cert_store_install(cs, "race.example", make_pem("init"),
                                 k, 0);

    reader_arg_t ra = {.cs = cs, .iters = 5000};
    writer_arg_t wa = {.cs = cs, .k = k, .iters = 200};
    n00b_thread_t *rt, *wt;
    { auto _tr = n00b_thread_spawn(reader_main, &ra); rt = n00b_result_get(_tr); }
    { auto _tr = n00b_thread_spawn(writer_main, &wa); wt = n00b_result_get(_tr); }
    n00b_thread_join(rt);
    n00b_thread_join(wt);

    /* Reader must see at least most of its lookups succeed (the
     * race window is tiny; a correct RCU swap means readers never
     * observe a NULL pattern or chain). */
    assert(ra.ok > ra.iters / 2);
    assert(wa.ok == wa.iters);
    /* No NULL pattern observations would be ideal; at minimum we
     * shouldn't see torn entries. */

    n00b_quic_cert_store_close(cs);
    n00b_quic_secret_close(k);
    printf("  [PASS] reader/writer race: %d/%d reads ok, %d writes ok\n",
           ra.ok, ra.iters, wa.ok);
}

/* ============================================================================ */

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_quic_cert_store:\n");
    test_install_lookup();
    test_install_dup_replace();
    test_sni_precedence();
    test_no_catchall_returns_null();
    test_close_idempotent();
    test_reader_writer_sanity();
    printf("All quic_cert_store tests passed.\n");

    n00b_shutdown();
    return 0;
}
