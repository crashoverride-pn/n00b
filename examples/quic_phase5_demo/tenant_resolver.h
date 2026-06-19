/**
 * @file tenant_resolver.h
 * @brief Header-based tenant routing for the Phase 5 demo.
 *
 * The demo's verifier resolver reads `X-Tenant: <id>` from the
 * inbound H3 headers and looks up the matching `n00b_jwt_verifier_t`
 * in a per-process tenant table.  Each tenant is bound to one IdP
 * verifier (typically a synthetic IdP in loopback mode, or a real
 * Keycloak / ZITADEL realm in production).
 */
#pragma once

#include "n00b.h"
#include "core/string.h"
#include "crypto/jwt.h"
#include "net/quic/rpc.h"

#define PHASE5_MAX_TENANTS 16

typedef struct {
    const char          *tenant_id;       /**< header value, e.g. "alpha" */
    const char          *idp_id;          /**< manifest auth.idps[].id */
    n00b_jwt_verifier_t *verifier;        /**< verifier for this tenant */
} phase5_tenant_route_t;

typedef struct {
    phase5_tenant_route_t routes[PHASE5_MAX_TENANTS];
    int                   n;
} phase5_tenant_table_t;

extern n00b_jwt_verifier_t *
phase5_tenant_resolver(const char             *idp_id,
                       const n00b_h3_header_t *hdrs,
                       size_t                  n_hdrs,
                       void                   *ctx);
