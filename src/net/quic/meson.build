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
    'trust.c',
    'secret.c',
    'endpoint.c',
    'conn.c',
    'chan.c',

    # Phase 2 — ACME / cert provisioner / DNS / SNI routing.
    'acme_tls.c',
    'acme.c',
    'acme_csr.c',
    'cert_provisioner.c',
    'cert_provisioner_static.c',
    'cert_provisioner_acme.c',
    'cert_provisioner_external.c',
    'rcu.c',
    'cert_store.c',
    'sticky_secret.c',
    'lb_cid.c',
    'manifest.c',
    'preflight.c',

    # Phase 2 — DNS providers + DNS-01 challenge.
    'dns_provider_manual.c',
    'dns_cloudflare.c',
    'dns_route53.c',
    'dns_gcp.c',
    'acme_dns01.c',

    # Phase 2 — SNI routing via picotls callbacks.
    'picotls_sni.c',

    # Phase 3 — Trust→picotls verify-cert bridge.
    'picotls_verify.c',
    'picotls_certverify.c',

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

# macOS Keychain bridge — the .m file goes through the system ObjC
# compiler in a separate static library (see top-level meson.build);
# the bridge .c is built into the main libn00b.
if target_os == 'darwin'
    n00b_quic_src += files('secret_keychain_bridge.c')
endif

# Linux libsecret-1 secret provider (URI scheme `libsecret:`).
# Detected via pkg-config; without the dev package the build still
# succeeds and callers requesting `libsecret:...` get
# N00B_QUIC_ERR_NOT_IMPLEMENTED.
libsecret_dep = dependency('libsecret-1', required: false)
have_libsecret = libsecret_dep.found() and target_os == 'linux'
if have_libsecret
    n00b_quic_src += files('secret_libsecret.c')
    deps += libsecret_dep
    add_project_arguments('-DN00B_HAVE_LIBSECRET=1', language: 'c')
endif

# Platform-specific ACME trust glue.  macOS uses .m (separate static
# library, declared below); other Unix uses the Linux C file; anything
# else gets a stub that returns NOT_IMPLEMENTED.
if target_os == 'linux'
    n00b_quic_src += files('acme_trust_linux.c')
elif target_os != 'darwin'
    n00b_quic_src += files('acme_trust_stub.c')
endif

# macOS-only Objective-C bridges: ACME trust verifier (Security.framework
# X.509 chain validation) and Keychain secret provider.  These go through
# the system ObjC compiler — their `.m` files are plain C with the `.m`
# extension purely as a compiler-routing trick.  Same pattern as the
# `n00b_cocoa` block in the top-level meson.build.
#
# The static libs are accumulated into `n00b_quic_link_whole_libs` here;
# the top-level merges that array into `link_whole_libs` after the latter
# is initialized (the order requirement is why this can't just `+=` into
# `link_whole_libs` directly from this subdir).
n00b_quic_link_whole_libs = []
if target_os == 'darwin'
    m_bridge_args = [
        '-g',
        '-Wno-unused-parameter',
        '-Wno-unused-function',
        '-Wno-unknown-pragmas',
        '-fno-omit-frame-pointer',
        '-fPIC',
        '-Wno-atomic-alignment',
        '-DN00B_HOST_OS=' + host_machine.system(),
        '-DN00B_HOST_CPU=' + host_machine.cpu_family(),
    ]
    n00b_quic_link_whole_libs += static_library('n00b_acme_trust_macos',
        ['acme_trust_macos.m'],
        include_directories: incdir,
        dependencies: deps,
        objc_args: m_bridge_args,
        link_args: link_args,
    )
    n00b_quic_link_whole_libs += static_library('n00b_secret_keychain',
        ['secret_keychain.m'],
        include_directories: incdir,
        dependencies: deps,
        objc_args: m_bridge_args,
        link_args: link_args,
    )
endif
