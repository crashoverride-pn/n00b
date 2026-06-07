/**
 * @file rocs/shard.h
 * @brief Hot shard root and shard lifecycle declarations for rocs.
 *
 * A rocs shard is a marshalable n00b object graph while it is hot and a
 * read-only resident marshal image after seal. The public root layout below is
 * intentionally part of the mapped-image ABI: WP-001 mapped readers consume the
 * scalar prefix directly from sealed bytes and resolve pointer fields through a
 * shard map, never by unmarshaling.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "n00b.h"
#include "adt/dict.h"
#include "adt/list.h"
#include "adt/result.h"
#include "conduit/topic.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/string.h"

typedef struct n00b_json_node n00b_json_node_t;

/**
 * @brief List of shard records.
 *
 * Hot shards store parsed JSON nodes. Sealed shards store the same slots as
 * marshal vaddrs; callers must use rocs mapped/view APIs over sealed images.
 */
typedef n00b_list_t(n00b_json_node_t *) n00b_store_record_list_t;

/**
 * @brief Posting list for a normalized field value.
 *
 * WP-004 populates posting lists. Phase 1 defines the marshalable shape only.
 */
typedef n00b_store_record_list_t n00b_store_posting_list_t;

/**
 * @brief Hash-keyed posting table for one field.
 *
 * Keys are kind-tagged 128-bit hashes of normalized values. Values are posting
 * lists containing the shard's record references.
 */
typedef n00b_dict_t(n00b_uint128_t, n00b_store_posting_list_t *)
    n00b_store_column_t;

/** @brief Field-name to per-field posting table dictionary. */
typedef n00b_dict_t(n00b_string_t *, n00b_store_column_t *)
    n00b_store_columns_t;

/**
 * @brief Linear byte store for retained raw JSON.
 *
 * The default WP-003 backing is inline in the shard marshal image. Future
 * store/VFS work may leave this field null and satisfy spans from separate
 * durable raw-byte storage, but shard records still name raw bytes by offset
 * and length rather than by hot buffer pointers.
 */
typedef struct {
    uint8_t *data;
    uint64_t byte_len;
} n00b_store_raw_blob_t;

/**
 * @brief Per-record span into the shard raw-byte store.
 *
 * The span is scalar-only and therefore safe to expose in sealed images.
 */
typedef struct {
    uint64_t offset;
    uint64_t byte_len;
} n00b_store_raw_span_t;

/** @brief Optional byte-exact raw JSON spans parallel to records. */
typedef n00b_list_t(n00b_store_raw_span_t *) n00b_store_raw_list_t;

/** @brief Per-record accounting overhead used by Phase 2 byte estimates. */
#define N00B_STORE_SHARD_RECORD_OVERHEAD ((uint64_t)sizeof(void *))

/**
 * @brief Mutable shard lifecycle state.
 *
 * The underlying width is fixed because the value is part of the sealed shard
 * root prefix consumed by mapped readers.
 */
typedef enum : uint32_t {
    N00B_SHARD_STATE_OPEN    = 0,
    N00B_SHARD_STATE_SEALED  = 1,
    N00B_SHARD_STATE_DROPPED = 2,
} n00b_shard_state_t;

/**
 * @brief Error domain for hot shard operations.
 */
typedef enum : int32_t {
    N00B_STORE_SHARD_OK          = 0,
    N00B_STORE_SHARD_ERR_ARG     = -1,
    N00B_STORE_SHARD_ERR_STATE   = -2,
    N00B_STORE_SHARD_ERR_MARSHAL = -3,
    N00B_STORE_SHARD_ERR_EVENT   = -4,
} n00b_store_shard_err_t;

/**
 * @brief Shard lifecycle event kind.
 */
typedef enum : int32_t {
    N00B_STORE_LIFECYCLE_SEALED,
    N00B_STORE_LIFECYCLE_DROPPED,
} n00b_store_lifecycle_kind_t;

/**
 * @brief Shard-level lifecycle event payload.
 *
 * Lifecycle events describe shard seal/drop transitions only. They do not carry
 * partition paths, catalog paths, VFS storage handles, retention policy, or
 * per-record live-view payloads.
 */
typedef struct {
    n00b_store_lifecycle_kind_t  kind;
    uint64_t                     shard_id;
    uint64_t                     record_count;
    uint64_t                     byte_size;
    uint64_t                     open_ts;
    uint64_t                     seal_ts;
    n00b_string_t               *drop_reason;
} n00b_store_lifecycle_t;

N00B_CONDUIT_INBOX_IMPL(n00b_store_lifecycle_t);

typedef n00b_conduit_message_t(n00b_store_lifecycle_t)
    n00b_store_lifecycle_msg_t;
typedef n00b_conduit_inbox_t(n00b_store_lifecycle_t)
    n00b_store_lifecycle_inbox_t;
typedef n00b_conduit_topic_t(n00b_store_lifecycle_t)
    n00b_store_lifecycle_topic_t;

/** @brief Pop one shard lifecycle message from an inbox. */
#define n00b_store_lifecycle_inbox_pop(inbox) \
    n00b_conduit_inbox_pop_msg(n00b_store_lifecycle_t, inbox)

/** @brief Check whether a shard lifecycle inbox has queued messages. */
#define n00b_store_lifecycle_inbox_has_messages(inbox) \
    n00b_conduit_inbox_has_msg(n00b_store_lifecycle_t, inbox)

/**
 * @brief Marshalable shard root.
 *
 * Ownership:
 * - `records`, `columns`, optional `retain_raw`, and optional `raw_bytes` are
 *   owned by the shard.
 * - The constructor creates private no-lock containers. Shard mutation is
 *   coordinated at the store/commit boundary, not by embedding locks in this
 *   root graph.
 * - Process-only resources, including conduit lifecycle topics, VFS handles,
 *   residency pins, caches, and service state, must not be stored here because
 *   this root is sealed byte-for-byte into marshal images.
 *
 * Hot-vs-sealed contract:
 * - While `state == N00B_SHARD_STATE_OPEN`, ordinary hot-container APIs may be
 *   used by rocs implementation code.
 * - Once sealed, rocs readers must access the resident image through mapped
 *   views. They must not pass mapped `records` or `columns` internals to
 *   ordinary n00b list/dict APIs and must never unmarshal shard images.
 * - Raw retention is represented as per-record spans into a linear raw byte
 *   store. Mapped readers use the cold-buffer API rather than treating mapped
 *   raw bytes as hot `n00b_buffer_t` objects.
 */
typedef struct n00b_store_shard {
    n00b_store_record_list_t *records;
    n00b_store_columns_t     *columns;
    n00b_store_raw_list_t    *retain_raw;
    n00b_store_raw_blob_t    *raw_bytes;
    n00b_shard_state_t        state;
    uint32_t                  reserved;
    uint64_t                  record_count;
    uint64_t                  byte_estimate;
    uint64_t                  open_ts;
    uint64_t                  seal_ts;
    uint64_t                  shard_id;
} n00b_store_shard_t;

static_assert(sizeof(n00b_store_raw_blob_t) == 16);
static_assert(offsetof(n00b_store_raw_blob_t, data) == 0);
static_assert(offsetof(n00b_store_raw_blob_t, byte_len) == 8);
static_assert(sizeof(n00b_store_raw_span_t) == 16);
static_assert(offsetof(n00b_store_raw_span_t, offset) == 0);
static_assert(offsetof(n00b_store_raw_span_t, byte_len) == 8);

static_assert(sizeof(n00b_store_shard_t) == 80);
static_assert(offsetof(n00b_store_shard_t, records) == 0);
static_assert(offsetof(n00b_store_shard_t, columns) == 8);
static_assert(offsetof(n00b_store_shard_t, retain_raw) == 16);
static_assert(offsetof(n00b_store_shard_t, raw_bytes) == 24);
static_assert(offsetof(n00b_store_shard_t, state) == 32);
static_assert(offsetof(n00b_store_shard_t, reserved) == 36);
static_assert(offsetof(n00b_store_shard_t, record_count) == 40);
static_assert(offsetof(n00b_store_shard_t, byte_estimate) == 48);
static_assert(offsetof(n00b_store_shard_t, open_ts) == 56);
static_assert(offsetof(n00b_store_shard_t, seal_ts) == 64);
static_assert(offsetof(n00b_store_shard_t, shard_id) == 72);

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Static diagnostic string for a shard error code.
 *
 * @param err  A @c N00B_STORE_SHARD_* code, usually from a result error branch.
 * @return A n00b string naming the code, or @c UNKNOWN for an unrecognized
 *         value.
 */
extern n00b_string_t *n00b_store_shard_err_str(n00b_err_t err);

/**
 * @brief Create or retrieve a typed process-side shard lifecycle topic.
 *
 * @param conduit Conduit instance that owns the topic.
 * @param uri     Conduit URI selected by the caller or store/service layer.
 *
 * @return Ok(topic) on success. Returns @c N00B_STORE_SHARD_ERR_EVENT when the
 *         conduit rejects topic creation.
 *
 * The returned topic is process-side state. It must not be stored in
 * @c n00b_store_shard_t or any other marshalable shard graph.
 */
extern n00b_result_t(n00b_store_lifecycle_topic_t *)
n00b_store_lifecycle_topic_get(n00b_conduit_t *conduit,
                               n00b_conduit_uri_t uri);

/**
 * @brief Allocate and initialize a typed lifecycle inbox.
 *
 * @param conduit Conduit instance whose allocator and notification domain own
 *                the inbox.
 *
 * @kw backpressure Inbox backpressure policy; defaults to unbounded.
 * @kw limit        Maximum queue depth for bounded policies; zero means
 *                  unbounded.
 * @kw allocator    Optional inbox allocator. Defaults to the conduit allocator.
 *
 * @return Ok(inbox) on success. Returns @c N00B_STORE_SHARD_ERR_ARG when
 *         @p conduit is null, or @c N00B_STORE_SHARD_ERR_EVENT when inbox
 *         allocation or initialization fails.
 */
extern n00b_result_t(n00b_store_lifecycle_inbox_t *)
n00b_store_lifecycle_inbox_new(n00b_conduit_t *conduit) _kargs
{
    n00b_conduit_backpressure_t backpressure = N00B_CONDUIT_BP_UNBOUNDED;
    uint32_t                    limit        = 0;
    n00b_allocator_t           *allocator    = nullptr;
};

/**
 * @brief Subscribe an inbox to a shard lifecycle topic.
 *
 * @param topic Process-side lifecycle topic returned by
 *              @c n00b_store_lifecycle_topic_get.
 * @param inbox Lifecycle inbox returned by @c n00b_store_lifecycle_inbox_new.
 *
 * @kw operations    Conduit operation mask. Zero defaults to all operations.
 * @kw flags         Conduit subscription flags. Zero uses normal active
 *                   subscription behavior.
 * @kw timeout_ms    Optional subscription timeout in milliseconds. Zero means
 *                   no timeout.
 * @kw backpressure  Subscription backpressure policy; defaults to unbounded.
 * @kw inbox_limit   Subscription inbox limit for bounded policies. Zero means
 *                   unbounded.
 *
 * @return Ok(subscription handle) on success. Returns
 *         @c N00B_STORE_SHARD_ERR_ARG for null required inputs, or
 *         @c N00B_STORE_SHARD_ERR_EVENT when the topic is inactive or the
 *         conduit rejects subscription.
 */
extern n00b_result_t(n00b_conduit_sub_handle_t)
n00b_store_lifecycle_subscribe(n00b_store_lifecycle_topic_t *topic,
                               n00b_store_lifecycle_inbox_t *inbox) _kargs
{
    uint32_t                    operations   = N00B_CONDUIT_OP_ALL;
    uint32_t                    flags        = 0;
    uint32_t                    timeout_ms   = 0;
    n00b_conduit_backpressure_t backpressure = N00B_CONDUIT_BP_UNBOUNDED;
    uint32_t                    inbox_limit  = 0;
};

/**
 * @brief Publish one lifecycle event payload to a lifecycle topic.
 *
 * @param topic Process-side lifecycle topic.
 * @param event Lifecycle payload. The payload is copied into the queued
 *              message; referenced strings remain caller-owned/GC-owned.
 *
 * @return Ok(true) when a message was published, Ok(false) for a null topic,
 *         or @c N00B_STORE_SHARD_ERR_EVENT when a supplied topic is inactive
 *         or cannot accept the event.
 * @post The topic and queued event remain process-side only.
 */
extern n00b_result_t(bool)
n00b_store_lifecycle_publish(n00b_store_lifecycle_topic_t *topic,
                             n00b_store_lifecycle_t        event);

/**
 * @brief Construct an empty open shard root.
 *
 * @kw shard_id   Store-global shard identifier to place in the marshalable root.
 * @kw retain_raw If true, allocate an empty raw-span list parallel to records
 *                 plus an inline raw-byte backing blob. If false, both
 *                 `retain_raw` and `raw_bytes` remain `nullptr`.
 * @kw open_ts    Opening timestamp to place in the marshalable root. A value of
 *                 zero means the caller has not assigned one yet.
 * @kw allocator  Allocator for the shard root and owned hot containers.
 *
 * @return A result containing an owned hot shard root on success.
 *
 * No lifecycle topic is accepted here: topic handles are process-owned conduit
 * resources, not marshalable shard state. Lifecycle seal/drop operations
 * configure and emit through process-side handles.
 */
extern n00b_result_t(n00b_store_shard_t *)
n00b_store_shard_new() _kargs
{
    uint64_t          shard_id  = 0;
    bool              retain_raw = false;
    uint64_t          open_ts   = 0;
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Append one parsed JSON record to an open hot shard.
 *
 * @param shard  Hot shard root returned by @c n00b_store_shard_new.
 * @param record Parsed JSON record to append. The shard retains the pointer.
 *
 * @kw raw Optional byte-exact source buffer for raw retention. If the shard was
 *         constructed with @c .retain_raw = true, this kwarg is required and the
 *         shard appends an independent byte copy to its linear raw-byte store,
 *         recording a scalar span for the record. If raw retention is disabled,
 *         this kwarg is ignored and no raw-retention storage is allocated.
 *
 * @return Ok(ordinal) on success, where ordinal is the zero-based record
 *         position within the shard. Returns @c N00B_STORE_SHARD_ERR_ARG for
 *         null required inputs or accounting overflow, and
 *         @c N00B_STORE_SHARD_ERR_STATE when the shard is not open.
 *
 * @post On success, @c record_count mirrors @c records length and
 *       @c byte_estimate increases by @c N00B_STORE_SHARD_RECORD_OVERHEAD plus
 *       retained raw byte length when raw retention is enabled.
 * @post On error, shard contents and counters are unchanged.
 *
 * Index population is intentionally out of scope for this function; WP-004 owns
 * @c columns contents.
 */
extern n00b_result_t(uint64_t)
n00b_store_shard_append(n00b_store_shard_t *shard,
                        n00b_json_node_t   *record) _kargs
{
    n00b_buffer_t *raw = nullptr;
};

/**
 * @brief Seal an open hot shard into an owned resident-image buffer.
 *
 * @param shard  Open hot shard root returned by @c n00b_store_shard_new.
 *
 * @kw seal_ts      Seal timestamp to store in the marshalable root. A value of
 *                  zero means the caller has not assigned one yet.
 * @kw base_address High 32 bits to place in marshal vaddrs. Zero is valid and
 *                  remains the default.
 * @kw topic        Optional process-side lifecycle topic. When supplied, a
 *                  sealed event is emitted after the shard image is produced.
 * @kw allocator    Allocator for the returned image buffer.
 *
 * @return Ok(buffer) containing the complete marshal v4 payload-front image on
 *         success. Returns @c N00B_STORE_SHARD_ERR_ARG for invalid inputs,
 *         @c N00B_STORE_SHARD_ERR_STATE when the shard is not open, and
 *         @c N00B_STORE_SHARD_ERR_MARSHAL if serialization fails, or
 *         @c N00B_STORE_SHARD_ERR_EVENT when a supplied lifecycle topic is
 *         inactive or cannot be published to.
 *
 * @post On success, @c state becomes @c N00B_SHARD_STATE_SEALED, @c seal_ts is
 *       recorded in the shard root and the returned image, and later mutation
 *       attempts fail with @c N00B_STORE_SHARD_ERR_STATE.
 * @post On marshal failure, @c state and @c seal_ts are restored to their
 *       pre-call values.
 * @post If lifecycle event emission fails, @c state and @c seal_ts are
 *       restored and @c N00B_STORE_SHARD_ERR_EVENT is returned.
 *
 * The returned buffer is process-owned output. It is not stored in the shard
 * root because residency, VFS handles, cache files, and lifecycle topics are
 * process-only resources. rocs readback opens this image through mapped-view
 * APIs and never unmarshals shard images.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_store_shard_seal(n00b_store_shard_t *shard) _kargs
{
    uint64_t                      seal_ts      = 0;
    uint32_t                      base_address = 0;
    n00b_store_lifecycle_topic_t *topic        = nullptr;
    n00b_allocator_t             *allocator    = nullptr;
};

/**
 * @brief Transition a sealed shard to dropped and optionally emit an event.
 *
 * @param shard Sealed hot shard root returned by @c n00b_store_shard_new and
 *              sealed by @c n00b_store_shard_seal.
 *
 * @kw topic       Optional process-side lifecycle topic. When supplied, a
 *                 dropped event is emitted after the state transition.
 * @kw drop_reason Optional human-readable drop reason carried only by dropped
 *                 lifecycle events. The pointer is retained by the queued event
 *                 message but is not copied into the shard root.
 * @kw byte_size   Actual sealed-object byte size when known by the caller.
 *                 Zero defaults to the shard's current byte estimate.
 *
 * @return Ok(true) on success. Returns @c N00B_STORE_SHARD_ERR_ARG for invalid
 *         inputs, @c N00B_STORE_SHARD_ERR_STATE when the shard is not sealed,
 *         and @c N00B_STORE_SHARD_ERR_EVENT when a supplied lifecycle topic is
 *         inactive or cannot be published to.
 *
 * @post On success, @c state becomes @c N00B_SHARD_STATE_DROPPED and later
 *       mutation/seal/drop attempts fail with @c N00B_STORE_SHARD_ERR_STATE.
 * @post On event failure, @c state is restored.
 *
 * This is an in-memory shard lifecycle transition only. Durable retention
 * deletion, VFS paths, catalog generations, and residency policy are store-layer
 * responsibilities in later work plans.
 */
extern n00b_result_t(bool)
n00b_store_shard_drop(n00b_store_shard_t *shard) _kargs
{
    n00b_store_lifecycle_topic_t *topic       = nullptr;
    n00b_string_t                *drop_reason = nullptr;
    uint64_t                      byte_size   = 0;
};

#ifdef __cplusplus
}
#endif
