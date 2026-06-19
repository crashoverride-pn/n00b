# QUIC stack (Phase 1-5) + ACME + Phase-3 auth + RPC + HTTP/3.
#
# This subdir adds picotls-1 / libsecret-1 dependencies to the top-
# level `deps` variable and defines the project-level
# N00B_HAVE_LIBSECRET flag when the Linux secret-service backend is
# available — meson's subdir() inlines this file into the parent
# scope so those modifications are visible to the rest of the build.

n00b_quic_src = files(
    # Phase 1 — core transport.
    'types.c',
    'framer.c',
    'endpoint.c',
    'conn.c',
    'chan.c',
    'rcu.c',
    'lb_cid.c',
    'manifest.c',
    'preflight.c',

    # Phase 2 — DNS providers + DNS-01 challenge driver.
    # (ACME/cert/trust/secret/picotls crypto moved to src/crypto/.)
    'dns_provider_manual.c',
    'dns_cloudflare.c',
    'dns_route53.c',
    'dns_gcp.c',

    # Phase 3 — auth policy + audit. (JWT/RSA/JWKS/OIDC/DPoP/mTLS/JWS
    # moved to src/crypto/ — see src/crypto/meson.build.)
    'auth_policy.c',
    'audit.c',

    # Phase 4 — CBOR + QPACK + RPC + H3 client/server.
    'cbor_encoder.c',
    'cbor_decoder.c',
    'qpack_static.c',
    'qpack_huffman.c',
    'qpack_encoder.c',
    'qpack_decoder.c',
    'rpc_ctx.c',
    'rpc.c',
    'rpc_status.c',
    'h3_frame.c',
    'h3_settings.c',
    'h3_client.c',
    'h3_server.c',

    # Phase 5 — Prometheus metrics + listener.
    'metrics.c',
    'metrics_encode.c',
)

# Secret/keychain/libsecret backends + ACME trust glue + the macOS .m
# Objective-C bridges all moved to src/crypto/ (see src/crypto/meson.build).
# This array is kept (empty) because the top-level still merges it into
# link_whole_libs; the crypto module supplies n00b_crypto_link_whole_libs.
n00b_quic_link_whole_libs = []
