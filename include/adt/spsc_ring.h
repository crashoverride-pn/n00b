/**
 * @file spsc_ring.h
 * @brief Lock-free single-producer/single-consumer variable-length byte ring.
 *
 * A bounded circular byte buffer carrying variable-length opaque records
 * (length-prefixed). Exactly ONE producer thread and ONE consumer thread; the
 * two coordinate through a pair of monotonic byte counters (head/tail) with
 * release/acquire ordering and NO compare-and-swap. Intended for foreign-thread
 * ingress staging: the producer may be a non-n00b thread (e.g. a libdispatch
 * queue) because @ref n00b_spsc_ring_produce touches no allocator, no lock, and
 * no thread-local state — just a memcpy and two atomic stores.
 *
 * ## Invariant (why the producer never corrupts an in-flight record)
 *
 * `used = head - tail`, `free = cap - used`. The producer only ever writes in
 * `[head, tail + cap)` and, before committing, acquire-loads `tail` and refuses
 * (returns false) if the record would not fit in `free` — so `head` can reach
 * `tail + cap` (full) but never lap it. The consumer reads only in
 * `[tail, head)` and holds `tail` fixed between @ref n00b_spsc_ring_peek and
 * @ref n00b_spsc_ring_pop, so the region it is reading stays "used" and the
 * producer cannot touch it until `pop` release-stores the advanced `tail`.
 * Because head/tail are monotonic (only the derived offset wraps), full
 * (`head-tail==cap`) and empty (`head==tail`) are unambiguous.
 *
 * ## Framing
 *
 * Each record is an 8-byte header (a `uint64_t` length) followed by the
 * payload, and every record start is 8-byte aligned with `cap` a power of two,
 * so `cap - offset` at a record start is always a multiple of 8 (hence >= 8) —
 * the header never straddles the physical end. When a record would not fit
 * contiguously before the end, the producer writes a skip sentinel
 * (@ref N00B_SPSC_RING_SKIP) that consumes the tail gap and restarts the record
 * at offset 0; @ref n00b_spsc_ring_peek advances past skips transparently, so
 * callers only ever see real records as a single contiguous `(ptr, len)`.
 */
#pragma once

#include "n00b.h"
#include "core/atomic.h"

// Header sentinel: this "length" means "skip the rest of the buffer, the record
// restarts at offset 0". A real record length can never collide with it (a
// record must fit in the ring, so len < cap <= UINT64_MAX).
#define N00B_SPSC_RING_SKIP    (~(uint64_t)0)
#define N00B_SPSC_RING_HDR     ((uint64_t)8)

typedef struct n00b_spsc_ring_t {
    uint8_t          *data;    // mmap'd backing (unregistered MAP_ANON, lazy)
    uint64_t          cap;     // power of two; index = counter & (cap - 1)
    _Atomic uint64_t  head;    // producer: total bytes ever committed
    _Atomic uint64_t  tail;    // consumer: total bytes ever reclaimed
    _Atomic uint64_t  drops;   // producer: records refused for lack of space
} n00b_spsc_ring_t;

/**
 * @brief Initialize a ring with at least @p min_cap_bytes of capacity.
 *
 * Rounds capacity up to a power of two and mmaps an unregistered demand-zero
 * region (idle cost is address space, not RSS). Returns false on mmap failure
 * or a zero capacity.
 */
extern bool n00b_spsc_ring_init(n00b_spsc_ring_t *r, uint64_t min_cap_bytes);

/** @brief Release the backing mapping. Not concurrent with produce/consume. */
extern void n00b_spsc_ring_destroy(n00b_spsc_ring_t *r);

/**
 * @brief Producer: append one record. SINGLE producer thread only.
 *
 * Returns true on commit, false if the record does not fit in the currently
 * free space (a drop; @ref n00b_spsc_ring_drops is incremented). @p len must be
 * small enough that a single record fits an empty ring
 * (`N00B_SPSC_RING_HDR + align8(len) <= cap`) — a caller that violates this is
 * a bug and trips a contract check, distinct from the transient full-ring drop.
 */
extern bool n00b_spsc_ring_produce(n00b_spsc_ring_t *r,
                                   const void       *src,
                                   uint32_t          len);

/**
 * @brief Producer: append one record formed by concatenating two segments.
 *
 * Identical contract to @ref n00b_spsc_ring_produce for a record of
 * `hdr_len + body_len` bytes, but writes @p hdr then @p body into the slot
 * with no intermediate buffer — for callers that carry a small fixed prefix
 * (e.g. a source/kind tag) in front of a large opaque payload. The consumer
 * sees the concatenation as one contiguous record.
 */
extern bool n00b_spsc_ring_produce2(n00b_spsc_ring_t *r,
                                    const void       *hdr,
                                    uint32_t          hdr_len,
                                    const void       *body,
                                    uint32_t          body_len);

/**
 * @brief Consumer: view the next record without copying. SINGLE consumer only.
 *
 * On success sets @p out to a contiguous pointer into the ring and @p len to
 * the record length, and returns true; the view stays valid until the next
 * @ref n00b_spsc_ring_pop. Returns false when the ring is empty. Skips are
 * consumed internally, so callers never see them.
 */
extern bool n00b_spsc_ring_peek(n00b_spsc_ring_t *r,
                                const uint8_t   **out,
                                uint32_t         *len);

/** @brief Consumer: advance past the record last returned by peek. */
extern void n00b_spsc_ring_pop(n00b_spsc_ring_t *r);

/** @brief Bytes currently occupied (head - tail). Either thread may call. */
extern uint64_t n00b_spsc_ring_depth(const n00b_spsc_ring_t *r);

/** @brief Total records the producer has refused for lack of space. */
extern uint64_t n00b_spsc_ring_drops(const n00b_spsc_ring_t *r);
