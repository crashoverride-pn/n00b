/* src/aws/n00b_aws_sts.c — libn00b_aws's STS wrap. Full
 * aws-sdk-sts Smithy-model coverage on top of the Rust shim. See
 * [[project_n00b_aws_via_rust_shim]] in the SKP auto-memory for the
 * architectural context.
 *
 * Per-op pattern:
 *   1. Validate required positional args.
 *   2. Marshal kwargs (including any n00b_list_t collections) into
 *      the shim's repr(C) input shape — usually a stack-allocated
 *      struct + parallel cstring arrays for list inputs.
 *   3. Call the shim (the Tokio runtime blocks on AWS I/O).  No STW
 *      bracketing is needed (WP-001): the GC stop-the-world cycle
 *      preempts a thread blocked in the shim rather than waiting for
 *      it to cooperatively self-park.
 *   4. Translate the shim's repr(C) output into an n00b GC-heap
 *      struct using `n00b_string_from_cstr` / `n00b_alloc`.
 *   5. Call the shim's matching `_free` function to release the
 *      Rust-allocated buffers.
 *
 * Every string field returned to the caller is non-NULL (empty
 * fields surface as `n00b_string_empty()`), so call sites never have
 * to NULL-check inside a returned struct.
 */

#include "n00b.h"
#include "core/string.h"
#include "core/alloc.h"
#include "core/arena.h"
#include "core/stw.h"
#include "adt/list.h"
#include "adt/result.h"

#include "aws/n00b_aws.h"
#include "aws/n00b_aws_config.h"
#include "aws/n00b_aws_sts.h"

#include "n00b_aws_shim_generated.h"
#include "internal/aws/config.h"

/* =========================================================================
 * Config — wraps the Rust SdkConfig handle. The struct layout lives in
 * <internal/aws/config.h> so every libn00b_aws TU shares one definition.
 * ========================================================================= */

static void
finalize_aws_config(void *p)
{
    n00b_aws_config_t *cfg = p;
    if (cfg && cfg->shim) {
        n00b_aws_shim_config_free(cfg->shim);
        cfg->shim = nullptr;
    }
}

n00b_aws_config_t *
n00b_aws_config(n00b_string_t *region) _kargs {
    n00b_string_t    *endpoint_override = nullptr;
    n00b_allocator_t *allocator         = nullptr;
}
{
    const char *region_cstr   = region            ? region->data            : nullptr;
    const char *endpoint_cstr = endpoint_override ? endpoint_override->data : nullptr;

    n00b_aws_shim_config_t *shim;
    {
        shim = n00b_aws_shim_config_new(region_cstr, endpoint_cstr);
    }
    if (!shim) {
        return nullptr;
    }
    n00b_aws_config_t *cfg = n00b_alloc(n00b_aws_config_t,
                                        N00B_ALLOC_OPTS(allocator));
    cfg->shim = shim;
    n00b_add_finalizer(cfg, finalize_aws_config, cfg);
    return cfg;
}

/* =========================================================================
 * Internal helpers
 * ========================================================================= */

/* Copy an owned C string out of the shim's output (NULL-tolerant). */
static n00b_string_t *
cstr_to_n00b(char *p)
{
    return n00b_string_from_cstr(p ? p : "");
}

/* Build an n00b credentials struct from the shim's repr(C). */
static n00b_aws_credentials_t *
credentials_to_n00b(n00b_aws_shim_aws_credentials_t *raw)
{
    if (!raw) {
        return nullptr;
    }
    n00b_aws_credentials_t *out = n00b_alloc(n00b_aws_credentials_t);
    out->access_key_id     = cstr_to_n00b(raw->access_key_id);
    out->secret_access_key = cstr_to_n00b(raw->secret_access_key);
    out->session_token     = cstr_to_n00b(raw->session_token);
    out->expiration_ms     = raw->expiration_ms;
    return out;
}

static n00b_aws_assumed_role_user_t *
assumed_role_user_to_n00b(n00b_aws_shim_assumed_role_user_t *raw)
{
    if (!raw) {
        return nullptr;
    }
    n00b_aws_assumed_role_user_t *out = n00b_alloc(n00b_aws_assumed_role_user_t);
    out->assumed_role_id = cstr_to_n00b(raw->assumed_role_id);
    out->arn             = cstr_to_n00b(raw->arn);
    return out;
}

static n00b_aws_federated_user_t *
federated_user_to_n00b(n00b_aws_shim_federated_user_t *raw)
{
    if (!raw) {
        return nullptr;
    }
    n00b_aws_federated_user_t *out = n00b_alloc(n00b_aws_federated_user_t);
    out->federated_user_id = cstr_to_n00b(raw->federated_user_id);
    out->arn               = cstr_to_n00b(raw->arn);
    return out;
}

/* Flatten an n00b list of n00b_string_t * into a parallel array of
 * `const char *` the shim's repr(C) input structs consume. Result is
 * allocated on the n00b GC heap; the returned array stays valid for
 * the lifetime of the wrap call (the C compiler keeps the local
 * alive across the shim call). */
typedef struct {
    const char **items;
    size_t       count;
} n00b_aws_cstr_array_t;

static n00b_aws_cstr_array_t
list_to_cstr_array(n00b_list_t(n00b_string_t *) *list)
{
    n00b_aws_cstr_array_t out = {.items = nullptr, .count = 0};
    if (!list) {
        return out;
    }
    int len = n00b_list_len(*list);
    if (len <= 0) {
        return out;
    }
    out.count = (size_t)len;
    out.items = n00b_alloc_array(const char *, len);
    for (int i = 0; i < len; i++) {
        n00b_string_t *s = n00b_list_get(*list, i);
        out.items[i] = s ? s->data : "";
    }
    return out;
}

/* =========================================================================
 * GetCallerIdentity
 * ========================================================================= */

n00b_result_t(n00b_aws_sts_identity_t *)
n00b_aws_sts_get_caller_identity(n00b_aws_config_t *cfg)
{
    if (!cfg || !cfg->shim) {
        return n00b_result_err(n00b_aws_sts_identity_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }
    n00b_aws_shim_sts_caller_identity_t *raw = nullptr;
    int rc;
    {
        rc = n00b_aws_shim_sts_get_caller_identity(cfg->shim, &raw);
    }
    if (rc != N00B_AWS_OK || !raw) {
        return n00b_result_err(n00b_aws_sts_identity_t *, rc);
    }
    n00b_aws_sts_identity_t *out = n00b_alloc(n00b_aws_sts_identity_t);
    out->account_id = cstr_to_n00b(raw->account_id);
    out->arn        = cstr_to_n00b(raw->arn);
    out->user_id    = cstr_to_n00b(raw->user_id);
    n00b_aws_shim_sts_caller_identity_free(raw);
    return n00b_result_ok(n00b_aws_sts_identity_t *, out);
}

/* =========================================================================
 * AssumeRole
 * ========================================================================= */

n00b_result_t(n00b_aws_sts_assume_role_result_t *)
n00b_aws_sts_assume_role(n00b_aws_config_t *cfg,
                         n00b_string_t     *role_arn,
                         n00b_string_t     *role_session_name) _kargs {
    int32_t                       duration_seconds  = 0;
    n00b_string_t                *external_id       = nullptr;
    n00b_string_t                *mfa_serial        = nullptr;
    n00b_string_t                *mfa_token         = nullptr;
    n00b_string_t                *policy            = nullptr;
    n00b_string_t                *source_identity   = nullptr;
    n00b_list_t(n00b_string_t *) *policy_arns         = nullptr;
    n00b_list_t(n00b_string_t *) *session_tags        = nullptr;
    n00b_list_t(n00b_string_t *) *session_tag_values  = nullptr;
    n00b_list_t(n00b_string_t *) *transitive_tag_keys = nullptr;
}
{
    if (!cfg || !cfg->shim
        || !role_arn          || role_arn->u8_bytes          == 0
        || !role_session_name || role_session_name->u8_bytes == 0) {
        return n00b_result_err(n00b_aws_sts_assume_role_result_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }

    n00b_aws_cstr_array_t pa = list_to_cstr_array(policy_arns);
    n00b_aws_cstr_array_t tk = list_to_cstr_array(session_tags);
    n00b_aws_cstr_array_t tv = list_to_cstr_array(session_tag_values);
    n00b_aws_cstr_array_t tt = list_to_cstr_array(transitive_tag_keys);

    n00b_aws_shim_sts_assume_role_input_t inp = {
        .role_arn                  = role_arn->data,
        .role_session_name         = role_session_name->data,
        .duration_seconds          = duration_seconds,
        .external_id               = external_id     ? external_id->data     : nullptr,
        .serial_number             = mfa_serial      ? mfa_serial->data      : nullptr,
        .token_code                = mfa_token       ? mfa_token->data       : nullptr,
        .policy                    = policy          ? policy->data          : nullptr,
        .source_identity           = source_identity ? source_identity->data : nullptr,
        .policy_arns               = pa.items,
        .policy_arns_count         = pa.count,
        .session_tag_keys          = tk.items,
        .session_tag_values        = tv.items,
        .session_tags_count        = tk.count < tv.count ? tk.count : tv.count,
        .transitive_tag_keys       = tt.items,
        .transitive_tag_keys_count = tt.count,
    };

    n00b_aws_shim_sts_assume_role_output_t *raw = nullptr;
    int rc;
    {
        rc = n00b_aws_shim_sts_assume_role(cfg->shim, &inp, &raw);
    }
    if (rc != N00B_AWS_OK || !raw) {
        return n00b_result_err(n00b_aws_sts_assume_role_result_t *, rc);
    }
    n00b_aws_sts_assume_role_result_t *out
        = n00b_alloc(n00b_aws_sts_assume_role_result_t);
    out->credentials        = credentials_to_n00b(raw->credentials);
    out->assumed_role_user  = assumed_role_user_to_n00b(raw->assumed_role_user);
    out->packed_policy_size = raw->packed_policy_size;
    out->source_identity    = cstr_to_n00b(raw->source_identity);
    n00b_aws_shim_sts_assume_role_free(raw);
    return n00b_result_ok(n00b_aws_sts_assume_role_result_t *, out);
}

/* =========================================================================
 * AssumeRoleWithWebIdentity (IRSA)
 * ========================================================================= */

n00b_result_t(n00b_aws_sts_web_identity_result_t *)
n00b_aws_sts_assume_role_with_web_identity(n00b_aws_config_t *cfg,
                                           n00b_string_t     *role_arn,
                                           n00b_string_t     *role_session_name,
                                           n00b_string_t     *web_identity_token)
    _kargs {
        n00b_string_t                *provider_id      = nullptr;
        n00b_string_t                *policy           = nullptr;
        int32_t                       duration_seconds = 0;
        n00b_list_t(n00b_string_t *) *policy_arns       = nullptr;
    }
{
    if (!cfg || !cfg->shim
        || !role_arn           || role_arn->u8_bytes           == 0
        || !role_session_name  || role_session_name->u8_bytes  == 0
        || !web_identity_token || web_identity_token->u8_bytes == 0) {
        return n00b_result_err(n00b_aws_sts_web_identity_result_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }

    n00b_aws_cstr_array_t pa = list_to_cstr_array(policy_arns);

    n00b_aws_shim_sts_assume_role_with_web_identity_input_t inp = {
        .role_arn           = role_arn->data,
        .role_session_name  = role_session_name->data,
        .web_identity_token = web_identity_token->data,
        .provider_id        = provider_id ? provider_id->data : nullptr,
        .policy             = policy      ? policy->data      : nullptr,
        .duration_seconds   = duration_seconds,
        .policy_arns        = pa.items,
        .policy_arns_count  = pa.count,
    };

    n00b_aws_shim_sts_assume_role_with_web_identity_output_t *raw = nullptr;
    int rc;
    {
        rc = n00b_aws_shim_sts_assume_role_with_web_identity(cfg->shim, &inp, &raw);
    }
    if (rc != N00B_AWS_OK || !raw) {
        return n00b_result_err(n00b_aws_sts_web_identity_result_t *, rc);
    }
    n00b_aws_sts_web_identity_result_t *out
        = n00b_alloc(n00b_aws_sts_web_identity_result_t);
    out->credentials               = credentials_to_n00b(raw->credentials);
    out->assumed_role_user         = assumed_role_user_to_n00b(raw->assumed_role_user);
    out->subject_from_web_identity = cstr_to_n00b(raw->subject_from_web_identity);
    out->provider                  = cstr_to_n00b(raw->provider);
    out->audience                  = cstr_to_n00b(raw->audience);
    out->source_identity           = cstr_to_n00b(raw->source_identity);
    out->packed_policy_size        = raw->packed_policy_size;
    n00b_aws_shim_sts_assume_role_with_web_identity_free(raw);
    return n00b_result_ok(n00b_aws_sts_web_identity_result_t *, out);
}

/* =========================================================================
 * AssumeRoleWithSAML
 * ========================================================================= */

n00b_result_t(n00b_aws_sts_saml_result_t *)
n00b_aws_sts_assume_role_with_saml(n00b_aws_config_t *cfg,
                                   n00b_string_t     *role_arn,
                                   n00b_string_t     *principal_arn,
                                   n00b_string_t     *saml_assertion)
    _kargs {
        n00b_string_t                *policy           = nullptr;
        int32_t                       duration_seconds = 0;
        n00b_list_t(n00b_string_t *) *policy_arns       = nullptr;
    }
{
    if (!cfg || !cfg->shim
        || !role_arn       || role_arn->u8_bytes       == 0
        || !principal_arn  || principal_arn->u8_bytes  == 0
        || !saml_assertion || saml_assertion->u8_bytes == 0) {
        return n00b_result_err(n00b_aws_sts_saml_result_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }

    n00b_aws_cstr_array_t pa = list_to_cstr_array(policy_arns);

    n00b_aws_shim_sts_assume_role_with_saml_input_t inp = {
        .role_arn          = role_arn->data,
        .principal_arn     = principal_arn->data,
        .saml_assertion    = saml_assertion->data,
        .policy            = policy ? policy->data : nullptr,
        .duration_seconds  = duration_seconds,
        .policy_arns       = pa.items,
        .policy_arns_count = pa.count,
    };

    n00b_aws_shim_sts_assume_role_with_saml_output_t *raw = nullptr;
    int rc;
    {
        rc = n00b_aws_shim_sts_assume_role_with_saml(cfg->shim, &inp, &raw);
    }
    if (rc != N00B_AWS_OK || !raw) {
        return n00b_result_err(n00b_aws_sts_saml_result_t *, rc);
    }
    n00b_aws_sts_saml_result_t *out = n00b_alloc(n00b_aws_sts_saml_result_t);
    out->credentials        = credentials_to_n00b(raw->credentials);
    out->assumed_role_user  = assumed_role_user_to_n00b(raw->assumed_role_user);
    out->packed_policy_size = raw->packed_policy_size;
    out->subject            = cstr_to_n00b(raw->subject);
    out->subject_type       = cstr_to_n00b(raw->subject_type);
    out->issuer             = cstr_to_n00b(raw->issuer);
    out->audience           = cstr_to_n00b(raw->audience);
    out->name_qualifier     = cstr_to_n00b(raw->name_qualifier);
    out->source_identity    = cstr_to_n00b(raw->source_identity);
    n00b_aws_shim_sts_assume_role_with_saml_free(raw);
    return n00b_result_ok(n00b_aws_sts_saml_result_t *, out);
}

/* =========================================================================
 * GetSessionToken
 * ========================================================================= */

n00b_result_t(n00b_aws_credentials_t *)
n00b_aws_sts_get_session_token(n00b_aws_config_t *cfg) _kargs {
    int32_t        duration_seconds = 0;
    n00b_string_t *mfa_serial       = nullptr;
    n00b_string_t *mfa_token        = nullptr;
}
{
    if (!cfg || !cfg->shim) {
        return n00b_result_err(n00b_aws_credentials_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }

    const char *serial = mfa_serial ? mfa_serial->data : nullptr;
    const char *token  = mfa_token  ? mfa_token->data  : nullptr;

    n00b_aws_shim_sts_get_session_token_output_t *raw = nullptr;
    int rc;
    {
        rc = n00b_aws_shim_sts_get_session_token(cfg->shim,
                                                 duration_seconds,
                                                 serial,
                                                 token,
                                                 &raw);
    }
    if (rc != N00B_AWS_OK || !raw) {
        return n00b_result_err(n00b_aws_credentials_t *, rc);
    }
    n00b_aws_credentials_t *out = credentials_to_n00b(raw->credentials);
    n00b_aws_shim_sts_get_session_token_free(raw);
    return n00b_result_ok(n00b_aws_credentials_t *, out);
}

/* =========================================================================
 * GetFederationToken
 * ========================================================================= */

n00b_result_t(n00b_aws_sts_federation_result_t *)
n00b_aws_sts_get_federation_token(n00b_aws_config_t *cfg,
                                  n00b_string_t     *name) _kargs {
    n00b_string_t                *policy           = nullptr;
    int32_t                       duration_seconds = 0;
    n00b_list_t(n00b_string_t *) *policy_arns       = nullptr;
    n00b_list_t(n00b_string_t *) *tag_keys          = nullptr;
    n00b_list_t(n00b_string_t *) *tag_values        = nullptr;
}
{
    if (!cfg || !cfg->shim || !name || name->u8_bytes == 0) {
        return n00b_result_err(n00b_aws_sts_federation_result_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }

    n00b_aws_cstr_array_t pa = list_to_cstr_array(policy_arns);
    n00b_aws_cstr_array_t tk = list_to_cstr_array(tag_keys);
    n00b_aws_cstr_array_t tv = list_to_cstr_array(tag_values);

    n00b_aws_shim_sts_get_federation_token_input_t inp = {
        .name              = name->data,
        .policy            = policy ? policy->data : nullptr,
        .duration_seconds  = duration_seconds,
        .policy_arns       = pa.items,
        .policy_arns_count = pa.count,
        .tag_keys          = tk.items,
        .tag_values        = tv.items,
        .tags_count        = tk.count < tv.count ? tk.count : tv.count,
    };

    n00b_aws_shim_sts_get_federation_token_output_t *raw = nullptr;
    int rc;
    {
        rc = n00b_aws_shim_sts_get_federation_token(cfg->shim, &inp, &raw);
    }
    if (rc != N00B_AWS_OK || !raw) {
        return n00b_result_err(n00b_aws_sts_federation_result_t *, rc);
    }
    n00b_aws_sts_federation_result_t *out
        = n00b_alloc(n00b_aws_sts_federation_result_t);
    out->credentials        = credentials_to_n00b(raw->credentials);
    out->federated_user     = federated_user_to_n00b(raw->federated_user);
    out->packed_policy_size = raw->packed_policy_size;
    n00b_aws_shim_sts_get_federation_token_free(raw);
    return n00b_result_ok(n00b_aws_sts_federation_result_t *, out);
}

/* =========================================================================
 * DecodeAuthorizationMessage
 * ========================================================================= */

n00b_result_t(n00b_string_t *)
n00b_aws_sts_decode_authorization_message(n00b_aws_config_t *cfg,
                                          n00b_string_t     *encoded_message)
{
    if (!cfg || !cfg->shim
        || !encoded_message || encoded_message->u8_bytes == 0) {
        return n00b_result_err(n00b_string_t *, N00B_AWS_ERR_INVALID_ARG);
    }

    n00b_aws_shim_sts_decoded_message_t *raw = nullptr;
    int rc;
    {
        rc = n00b_aws_shim_sts_decode_authorization_message(cfg->shim,
                                                            encoded_message->data,
                                                            &raw);
    }
    if (rc != N00B_AWS_OK || !raw) {
        return n00b_result_err(n00b_string_t *, rc);
    }
    n00b_string_t *out = cstr_to_n00b(raw->decoded_message);
    n00b_aws_shim_sts_decoded_message_free(raw);
    return n00b_result_ok(n00b_string_t *, out);
}

/* =========================================================================
 * GetAccessKeyInfo
 * ========================================================================= */

n00b_result_t(n00b_string_t *)
n00b_aws_sts_get_access_key_info(n00b_aws_config_t *cfg,
                                 n00b_string_t     *access_key_id)
{
    if (!cfg || !cfg->shim
        || !access_key_id || access_key_id->u8_bytes == 0) {
        return n00b_result_err(n00b_string_t *, N00B_AWS_ERR_INVALID_ARG);
    }

    n00b_aws_shim_sts_access_key_info_t *raw = nullptr;
    int rc;
    {
        rc = n00b_aws_shim_sts_get_access_key_info(cfg->shim,
                                                   access_key_id->data,
                                                   &raw);
    }
    if (rc != N00B_AWS_OK || !raw) {
        return n00b_result_err(n00b_string_t *, rc);
    }
    n00b_string_t *out = cstr_to_n00b(raw->account);
    n00b_aws_shim_sts_access_key_info_free(raw);
    return n00b_result_ok(n00b_string_t *, out);
}

const char *
n00b_aws_status_str(n00b_aws_status_t status)
{
    switch (status) {
    case N00B_AWS_OK:                  return "OK";
    case N00B_AWS_ERR_INVALID_ARG:     return "INVALID_ARG";
    case N00B_AWS_ERR_NOT_INITIALIZED: return "NOT_INITIALIZED";
    case N00B_AWS_ERR_NO_CREDENTIALS:  return "NO_CREDENTIALS";
    case N00B_AWS_ERR_AUTHZ:           return "AUTHZ";
    case N00B_AWS_ERR_NOT_FOUND:       return "NOT_FOUND";
    case N00B_AWS_ERR_THROTTLED:       return "THROTTLED";
    case N00B_AWS_ERR_TIMEOUT:         return "TIMEOUT";
    case N00B_AWS_ERR_NETWORK:         return "NETWORK";
    case N00B_AWS_ERR_SERVICE:         return "SERVICE";
    case N00B_AWS_ERR_CLIENT:          return "CLIENT";
    case N00B_AWS_ERR_INTERNAL:        return "INTERNAL";
    }
    return "UNKNOWN";
}
