# Consolidated cryptography module (WP-042).
#
# Crypto subsystems gathered from the former src/util/ and src/net/quic/
# trees into one place: encoding-for-crypto (base64/DER/PKCS#7/X.509 walk),
# asymmetric primitives (RSA PKCS#1 v1.5 + PSS), token formats
# (JWT/JWK/JWS, OIDC, DPoP, mTLS), and the PKI/TLS identity layer
# (secrets + keychain backends, X.509 trust/verify, cert store, cert
# provisioner, ACME). The cryptographic hashes (SHA-2) and CSPRNG remain
# foundational primitives in src/core/; QUIC *transport* (framer, conn,
# endpoint, cbor, qpack, h3, dns providers) stays in src/net/quic/.
# Vendored crypto (picotls/cifra/micro-ecc, monocypher) stays under
# subprojects/.
#
# Compile flags come from the consuming library target (incdir + deps), so
# these sources build identically to where they lived before. `deps`,
# `incdir`, and `link_args` are all defined before this subdir() runs.

n00b_crypto_src = files(
    # Encoding used by crypto/PKI.
    'base64.c',
    'der_encode.c',
    'pkcs7.c',
    'x509_walk.c',

    # X.509 parse (WP-042): DER bracketing tokenizer feeding the slay
    # grammar in grammars/x509_der.bnf, + the DER -> parse-tree front door.
    'x509_der_tok.c',
    'x509_parse.c',
    'x509_cert.c',
    'x509_ext.c',
    'x509_verify.c',
    'x509_path.c',

    # Asymmetric — RSA PKCS#1 v1.5 + PSS sign/verify (hand-rolled bignum).
    'rsa_pkcs1.c',

    # Tokens — JWT/JWK verify, JWS encode, OIDC discovery, DPoP, mTLS.
    'jwt.c',
    'jws.c',
    'oidc.c',
    'dpop.c',
    'mtls_token.c',

    # Secrets — handle abstraction + sticky wrapper (platform backends below).
    'secret.c',
    'sticky_secret.c',

    # X.509 trust / verification + picotls verify bridge + SNI routing.
    'trust.c',
    'picotls_sni.c',
    'picotls_verify.c',
    'picotls_certverify.c',

    # Cert store + provisioners.
    'cert_store.c',
    'cert_provisioner.c',
    'cert_provisioner_static.c',
    'cert_provisioner_acme.c',
    'cert_provisioner_external.c',

    # ACME (RFC 8555) client + CSR + DNS-01 challenge driver + TLS-ALPN.
    'acme.c',
    'acme_csr.c',
    'acme_dns01.c',
    'acme_tls.c',
)

# macOS Keychain bridge .c — built into the main libn00b (the .m bridge is
# a separate ObjC static library, below).
if target_os == 'darwin'
    n00b_crypto_src += files('secret_keychain_bridge.c')
endif

# Linux libsecret-1 secret provider (URI scheme `libsecret:`). Detected via
# pkg-config; without the dev package the build still succeeds and callers
# requesting `libsecret:...` get N00B_QUIC_ERR_NOT_IMPLEMENTED.
libsecret_dep = dependency('libsecret-1', required: false)
have_libsecret = libsecret_dep.found() and target_os == 'linux'
if have_libsecret
    n00b_crypto_src += files('secret_libsecret.c')
    deps += libsecret_dep
    add_project_arguments('-DN00B_HAVE_LIBSECRET=1', language: 'c')
endif

# Platform-specific ACME trust glue. macOS uses .m (separate static library,
# below); other Unix uses the Linux C file; anything else gets a stub that
# returns NOT_IMPLEMENTED.
if target_os == 'linux'
    n00b_crypto_src += files('acme_trust_linux.c')
elif target_os != 'darwin'
    n00b_crypto_src += files('acme_trust_stub.c')
endif

# macOS-only Objective-C bridges: ACME trust verifier (Security.framework
# X.509 chain validation) and Keychain secret provider. The `.m` files are
# plain C with the `.m` extension purely as a compiler-routing trick. The
# static libs accumulate into `n00b_crypto_link_whole_libs`; the top-level
# merges that array into `link_whole_libs` after the latter is initialized.
n00b_crypto_link_whole_libs = []
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
    n00b_crypto_link_whole_libs += static_library('n00b_acme_trust_macos',
        ['acme_trust_macos.m'],
        include_directories: incdir,
        dependencies: deps,
        objc_args: m_bridge_args,
        link_args: link_args,
    )
    n00b_crypto_link_whole_libs += static_library('n00b_secret_keychain',
        ['secret_keychain.m'],
        include_directories: incdir,
        dependencies: deps,
        objc_args: m_bridge_args,
        link_args: link_args,
    )
endif
