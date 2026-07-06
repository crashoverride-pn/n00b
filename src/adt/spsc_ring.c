#define N00B_USE_INTERNAL_API

#include "n00b.h"
#include "adt/spsc_ring.h"
#include "core/mmaps.h"
#include "util/assert.h" // n00b_require

// 8-byte-aligned record stride keeps every record start on an 8-byte boundary,
// so cap - offset (offset = counter & (cap-1), cap a power of two) is always a
// multiple of 8 at a record start — the header never straddles the end.
static inline uint64_t
spsc_align8(uint64_t n)
{
    return (n + 7u) & ~(uint64_t)7u;
}

// Smallest power of two >= n, with a floor so tiny caps still hold one record
// plus a header. 4 KiB floor mirrors a page; callers pass real capacities.
static inline uint64_t
spsc_pow2_ceil(uint64_t n)
{
    uint64_t p = 4096;
    while (p < n) {
        p <<= 1;
    }
    return p;
}

bool
n00b_spsc_ring_init(n00b_spsc_ring_t *r, uint64_t min_cap_bytes)
{
    if (r == NULL || min_cap_bytes == 0) {
        return false;
    }
    uint64_t cap = spsc_pow2_ceil(min_cap_bytes);

    // Unregistered demand-zero mapping: not GC memory, and the foreign producer
    // thread must never touch the mmap registry. skip_register keeps it out of
    // the interval tree; the ring is a raw byte transport.
    n00b_result_t(void *) m = n00b_mmap(cap, .skip_register = true);
    if (n00b_result_is_err(m)) {
        return false;
    }
    r->data = (uint8_t *)n00b_result_get(m);
    r->cap  = cap;
    atomic_store_explicit(&r->head, 0, memory_order_relaxed);
    atomic_store_explicit(&r->tail, 0, memory_order_relaxed);
    atomic_store_explicit(&r->drops, 0, memory_order_relaxed);
    return true;
}

void
n00b_spsc_ring_destroy(n00b_spsc_ring_t *r)
{
    if (r == NULL || r->data == NULL) {
        return;
    }
    // skip_register mapping has no registry record, so release it directly by
    // (addr, size) rather than the record-removing n00b_munmap.
    n00b_safe_munmap(r->data, r->cap);
    r->data = NULL;
    r->cap  = 0;
}

// Shared reserve+commit for one record built from up to two source segments.
static bool
spsc_produce_iov(n00b_spsc_ring_t *r,
                 const void       *s0,
                 uint32_t          l0,
                 const void       *s1,
                 uint32_t          l1)
{
    if (r == NULL || r->data == NULL) {
        return false;
    }
    uint64_t len = (uint64_t)l0 + (uint64_t)l1;
    if (len == 0) {
        return false;
    }

    uint64_t stride = N00B_SPSC_RING_HDR + spsc_align8(len);
    // A single record must fit an empty ring; a caller asking for more is a bug,
    // not a transient full-ring drop. The staging producer bounds len by the
    // sensor encode-buffer size, so this is provably never hit in that path.
    n00b_require(stride <= r->cap,
                 "n00b_spsc_ring produce: record exceeds ring capacity");

    uint64_t head = atomic_load_explicit(&r->head, memory_order_relaxed);
    uint64_t tail = atomic_load_explicit(&r->tail, memory_order_acquire);
    uint64_t used = head - tail;
    uint64_t off  = head & (r->cap - 1);
    uint64_t to_end = r->cap - off;

    // Total bytes this commit needs, including a wrap skip when the record does
    // not fit contiguously before the physical end (the skip consumes to_end and
    // the record restarts at offset 0).
    uint64_t need = (to_end < stride) ? to_end + stride : stride;
    if (need > r->cap - used) {
        atomic_fetch_add_explicit(&r->drops, 1, memory_order_relaxed);
        return false;
    }

    if (to_end < stride) {
        // Skip sentinel consumes the tail gap; header always fits (to_end >= 8).
        *(uint64_t *)(r->data + off) = N00B_SPSC_RING_SKIP;
        head += to_end;
        off = 0;
    }

    *(uint64_t *)(r->data + off) = len;
    if (l0 != 0) {
        memcpy(r->data + off + N00B_SPSC_RING_HDR, s0, l0);
    }
    if (l1 != 0) {
        memcpy(r->data + off + N00B_SPSC_RING_HDR + l0, s1, l1);
    }

    // Release so the consumer's acquire-load of head observes the header +
    // payload writes before it sees the advanced head.
    atomic_store_explicit(&r->head, head + stride, memory_order_release);
    return true;
}

bool
n00b_spsc_ring_produce(n00b_spsc_ring_t *r, const void *src, uint32_t len)
{
    return spsc_produce_iov(r, src, len, NULL, 0);
}

bool
n00b_spsc_ring_produce2(n00b_spsc_ring_t *r,
                        const void       *hdr,
                        uint32_t          hdr_len,
                        const void       *body,
                        uint32_t          body_len)
{
    return spsc_produce_iov(r, hdr, hdr_len, body, body_len);
}

bool
n00b_spsc_ring_peek(n00b_spsc_ring_t *r, const uint8_t **out, uint32_t *len)
{
    if (r == NULL || r->data == NULL) {
        return false;
    }
    uint64_t tail = atomic_load_explicit(&r->tail, memory_order_relaxed);

    for (;;) {
        uint64_t head = atomic_load_explicit(&r->head, memory_order_acquire);
        if (head == tail) {
            return false; // empty
        }
        uint64_t   off = tail & (r->cap - 1);
        uint64_t   hdr = *(const uint64_t *)(r->data + off);
        if (hdr == N00B_SPSC_RING_SKIP) {
            // Consume the wrap gap and retry from offset 0. The gap is
            // cap - off (matches the producer's to_end skip), keeping the
            // head/tail byte accounting in exact lockstep.
            tail += (r->cap - off);
            atomic_store_explicit(&r->tail, tail, memory_order_release);
            continue;
        }
        if (out != NULL) {
            *out = r->data + off + N00B_SPSC_RING_HDR;
        }
        if (len != NULL) {
            *len = (uint32_t)hdr;
        }
        return true;
    }
}

void
n00b_spsc_ring_pop(n00b_spsc_ring_t *r)
{
    if (r == NULL || r->data == NULL) {
        return;
    }
    uint64_t tail = atomic_load_explicit(&r->tail, memory_order_relaxed);
    uint64_t head = atomic_load_explicit(&r->head, memory_order_acquire);
    if (head == tail) {
        return; // nothing peeked
    }
    uint64_t off = tail & (r->cap - 1);
    uint64_t hdr = *(const uint64_t *)(r->data + off);
    // A skip is transparent to peek, so a well-formed peek/pop pair never lands
    // on one here; guard anyway so a stray pop can't desynchronize accounting.
    if (hdr == N00B_SPSC_RING_SKIP) {
        atomic_store_explicit(&r->tail, tail + (r->cap - off), memory_order_release);
        return;
    }
    uint64_t stride = N00B_SPSC_RING_HDR + spsc_align8(hdr);
    // Release so the producer's acquire-load of tail sees the freed space.
    atomic_store_explicit(&r->tail, tail + stride, memory_order_release);
}

uint64_t
n00b_spsc_ring_depth(const n00b_spsc_ring_t *r)
{
    if (r == NULL) {
        return 0;
    }
    uint64_t head = atomic_load_explicit(&r->head, memory_order_acquire);
    uint64_t tail = atomic_load_explicit(&r->tail, memory_order_acquire);
    return head - tail;
}

uint64_t
n00b_spsc_ring_drops(const n00b_spsc_ring_t *r)
{
    return r == NULL ? 0 : atomic_load_explicit(&r->drops, memory_order_relaxed);
}
