# HTTP/1.1 + HTTP/3 client (Phase 6) — URL parser shared by h1+h3,
# request builder, transport, connection pool, Alt-Svc, compression,
# cookies, auth helper.  Most modules depend on the QUIC stack
# (picotls, picoquic, ACME tls shim, etc.) compiled in src/net/quic.

n00b_http_src = files(
    'http_url.c',          # Phase 6 chunk 1 — HTTPS URL parser
    'http_proxy.c',        # HTTP_PROXY / HTTPS_PROXY / NO_PROXY resolution
    'http_h1.c',           # chunk 2 — HTTP/1.1 transport
    'http_h3.c',           # chunk 3 — HTTP/3 round-trip wrapper
    'http_pool.c',         # chunk 4 — connection pool
    'http_client.c',       # chunk 5 — public dispatcher
    'http_alt_svc.c',      # chunk 6 — Alt-Svc cache
    'http_compression.c',  # chunk 8 — Content-Encoding decompression
    'http_cookies.c',      # chunk 9 — RFC 6265-bis cookie jar
    'http_auth.c',         # chunk 10 — Bearer + DPoP + mTLS hooks
    'http_service.c',      # local HTTP/1 service/router
)
