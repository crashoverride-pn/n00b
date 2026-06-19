# Consolidated cryptography module (WP-042).
#
# Crypto subsystems gathered from the former src/util/ and src/net/quic/
# trees into one place: encoding-for-crypto (base64/DER/PKCS#7/X.509 walk),
# asymmetric primitives (RSA PKCS#1 v1.5 + PSS), and token formats
# (JWT/JWK/JWS, OIDC, DPoP, mTLS). The cryptographic hashes (SHA-2) and
# CSPRNG remain foundational primitives in src/core/. Vendored crypto
# (picotls/cifra/micro-ecc, monocypher) stays under subprojects/.
#
# Compile flags come from the consuming library target (incdir + deps), so
# these sources build identically to where they lived before.

n00b_crypto_src = files(
    # Encoding used by crypto/PKI.
    'base64.c',
    'der_encode.c',
    'pkcs7.c',
    'x509_walk.c',

    # Asymmetric — RSA PKCS#1 v1.5 + PSS sign/verify (hand-rolled bignum).
    'rsa_pkcs1.c',

    # Tokens — JWT/JWK verify, JWS encode, OIDC discovery, DPoP, mTLS.
    'jwt.c',
    'jws.c',
    'oidc.c',
    'dpop.c',
    'mtls_token.c',
)
