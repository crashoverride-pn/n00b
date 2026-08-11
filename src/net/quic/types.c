#include "n00b.h"
#include "net/quic/quic_types.h"

const char *
n00b_quic_err_str(n00b_quic_err_t err)
{
    switch (err) {
    case N00B_QUIC_OK:                  return "ok";
    case N00B_QUIC_ERR_BIND_FAILED:     return "bind failed";
    case N00B_QUIC_ERR_HANDSHAKE:       return "handshake failure";
    case N00B_QUIC_ERR_TRUST_REJECTED:  return "trust store rejected the peer certificate";
    case N00B_QUIC_ERR_PEER_CLOSED:     return "peer closed connection";
    case N00B_QUIC_ERR_LOCAL_RESET:     return "channel reset locally";
    case N00B_QUIC_ERR_PEER_RESET:      return "channel reset by peer";
    case N00B_QUIC_ERR_FLOW_BLOCKED:    return "flow control window exhausted";
    case N00B_QUIC_ERR_FRAME_TOO_LARGE: return "frame exceeds configured maximum size";
    case N00B_QUIC_ERR_PROTOCOL:        return "protocol violation";
    case N00B_QUIC_ERR_TIMEOUT:         return "operation timed out";
    case N00B_QUIC_ERR_NOT_IMPLEMENTED: return "not implemented on this platform";
    case N00B_QUIC_ERR_INVALID_ARG:     return "invalid argument";
    case N00B_QUIC_ERR_NEED_MORE_DATA:  return "need more data";
    case N00B_QUIC_ERR_BAD_VARINT:      return "malformed varint";
    case N00B_QUIC_ERR_BAD_TYPE:        return "frame type out of allocated range";
    case N00B_QUIC_ERR_NULL_ARG:        return "unexpected null argument";
    case N00B_QUIC_ERR_AUTH_TOKEN_MISSING:   return "auth token missing";
    case N00B_QUIC_ERR_AUTH_TOKEN_INVALID:   return "auth token invalid";
    case N00B_QUIC_ERR_AUTH_TOKEN_EXPIRED:   return "auth token expired";
    case N00B_QUIC_ERR_AUTH_KEY_NOT_FOUND:   return "no JWK matches the token's kid/alg";
    case N00B_QUIC_ERR_AUTH_ALG_REFUSED:     return "JWS alg refused by policy";
    case N00B_QUIC_ERR_AUTH_ISS_MISMATCH:    return "issuer claim mismatch";
    case N00B_QUIC_ERR_AUTH_AUD_MISMATCH:    return "audience claim mismatch";
    case N00B_QUIC_ERR_AUTH_DPOP_FAILED:     return "DPoP proof failed";
    case N00B_QUIC_ERR_AUTH_MTLS_MISMATCH:   return "mTLS-bound token thumbprint mismatch";
    case N00B_QUIC_ERR_AUTH_REPLAY_DETECTED: return "auth replay detected (jti seen)";
    case N00B_QUIC_ERR_PROXY_REJECTED:       return "proxy rejected or did not complete the CONNECT tunnel";
    }
    return "unknown";
}
