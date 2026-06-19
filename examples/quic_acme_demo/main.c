/*
 * quic_acme_demo — one-shot ACME cert acquisition demo.
 *
 * Drives the full ACME flow against a configured ACME directory
 * using the manual DNS provider for the DNS-01 challenge.  Prints
 * the resulting PEM chain to stdout.
 *
 * Intended use: against Let's Encrypt staging
 * (https://acme-staging-v02.api.letsencrypt.org/directory) for
 * interop verification.  Requires:
 *   - A DNS name you control
 *   - The ability to add TXT records at _acme-challenge.<name>
 *   - Network access to the ACME directory's HTTPS endpoint
 *
 * Usage:
 *   quic_acme_demo --directory <url> --domain <name> [--account-key <uri>]
 *                  [--cert-key <uri>] [--contact <email>]
 *
 * On success, writes the PEM chain to stdout.  Operator pipes to a
 * file or a `step` invocation as desired.
 *
 * Note on validation: this binary cannot fully verify the issued
 * cert against the ACME server's public CA chain (that requires
 * the trust→picotls bridge shipping in Phase 3).  The fact that
 * the ACME server hands the cert back means it considered the
 * challenge satisfied.  For a stronger sanity check, pipe stdout
 * through `openssl x509 -text -noout`.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"
#include "net/quic/dns_provider.h"
#include "internal/crypto/acme.h"
#include "internal/crypto/acme_dns01.h"

static void
usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s --directory <url> --domain <name>\n"
            "          [--account-key <secret-uri>]\n"
            "          [--cert-key <secret-uri>]\n"
            "          [--contact <email>]\n", argv0);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    const char *directory_url   = NULL;
    const char *domain          = NULL;
    const char *account_key_uri = "ephemeral:acme-account";
    const char *cert_key_uri    = "ephemeral:acme-cert";
    const char *contact         = NULL;

    for (int i = 1; i < argc; i++) {
        if (i + 1 < argc && strcmp(argv[i], "--directory") == 0) {
            directory_url = argv[++i];
        } else if (i + 1 < argc && strcmp(argv[i], "--domain") == 0) {
            domain = argv[++i];
        } else if (i + 1 < argc && strcmp(argv[i], "--account-key") == 0) {
            account_key_uri = argv[++i];
        } else if (i + 1 < argc && strcmp(argv[i], "--cert-key") == 0) {
            cert_key_uri = argv[++i];
        } else if (i + 1 < argc && strcmp(argv[i], "--contact") == 0) {
            contact = argv[++i];
        } else {
            usage(argv[0]);
            return 1;
        }
    }
    (void)contact;
    if (!directory_url || !domain) {
        usage(argv[0]);
        return 1;
    }

    fprintf(stderr, "[demo] Opening account key (%s)...\n", account_key_uri);
    auto akr = n00b_quic_secret_open(n00b_buffer_from_cstr((char *)account_key_uri));
    if (!n00b_result_is_ok(akr)) {
        fprintf(stderr, "[demo] failed to open account key URI\n");
        return 2;
    }
    n00b_quic_secret_t *account_key = n00b_result_get(akr);

    fprintf(stderr, "[demo] Opening cert key (%s)...\n", cert_key_uri);
    auto ckr = n00b_quic_secret_open(n00b_buffer_from_cstr((char *)cert_key_uri));
    if (!n00b_result_is_ok(ckr)) {
        fprintf(stderr, "[demo] failed to open cert key URI\n");
        return 2;
    }
    n00b_quic_secret_t *cert_key = n00b_result_get(ckr);

    fprintf(stderr,
            "[demo] Building manual DNS provider — you'll be prompted "
            "to add a TXT record.\n");
    n00b_quic_dns_provider_t       *dns = n00b_quic_dns_provider_manual();
    n00b_acme_challenge_provider_t *cp  = n00b_acme_dns01_provider_new(dns,
                                                                       .skip_propagation_wait = false);

    fprintf(stderr,
            "[demo] Acquiring cert for '%s' from %s...\n",
            domain, directory_url);

    const char *names[] = {domain};
    auto r = n00b_acme_acquire_certificate(directory_url,
                                           account_key, cert_key,
                                           names, 1, cp,
                                           .timeout_ms       = 60000,
                                           .poll_max_wait_ms = 120000);
    if (!n00b_result_is_ok(r)) {
        int err = (int)n00b_result_get_err(r);
        fprintf(stderr,
                "[demo] acquisition failed: %d (%s)\n", err,
                n00b_quic_err_str((n00b_quic_err_t)err));
        return 3;
    }
    n00b_buffer_t *chain = n00b_result_get(r);

    fprintf(stderr, "[demo] Got %zu bytes of PEM chain.  Writing to stdout.\n",
            (size_t)chain->byte_len);
    fwrite(chain->data, 1, (size_t)chain->byte_len, stdout);
    fflush(stdout);

    n00b_quic_secret_close(account_key);
    n00b_quic_secret_close(cert_key);
    n00b_shutdown();
    return 0;
}
