#include "adt/flagset.h"

#include "core/data_lock.h"
#include "util/assert.h"
#include "core/gc_map.h"
#include "core/race_detect.h"

static uint64_t
flagset_words_for_bits(uint64_t bits)
{
    return bits == 0 ? 1 : (bits + 63u) / 64u;
}

static uint64_t
flagset_tail_mask(uint64_t bits)
{
    uint64_t rem = bits & 63u;
    if (rem == 0) {
        return UINT64_MAX;
    }
    return (1ull << rem) - 1ull;
}

static void
flagset_zero_tail(n00b_flagset_t *self)
{
    if (self == nullptr || self->contents == nullptr || self->alloc_wordlen == 0) {
        return;
    }
    self->contents[self->alloc_wordlen - 1] &= flagset_tail_mask(self->num_flags);
}

static void
flagset_resize(n00b_flagset_t *self, uint64_t new_num_flags)
{
    uint64_t new_words = flagset_words_for_bits(new_num_flags);
    if (new_words != self->alloc_wordlen) {
        // The bit array is pure data (membership bits), never pointers, so it
        // MUST be no-scan: otherwise the conservative scan / marshaler reads
        // bitmap words as candidate pointers, which (e.g. when a flagset-backed
        // dense posting list is marshaled at rocs seal) misfires as an
        // unregistered-static-pointer and fails the whole marshal.  The typed
        // (uint64_t) alloc already yields a scalar GC map; .scan_kind=NONE is
        // explicit belt-and-suspenders.
        uint64_t *contents = n00b_alloc_array_with_opts(
            uint64_t,
            new_words,
            &(n00b_alloc_opts_t){.allocator = self->allocator,
                                 .scan_kind = N00B_GC_SCAN_KIND_NONE});
        memset(contents, 0, new_words * sizeof(uint64_t));
        uint64_t copy_words = n00b_min(self->alloc_wordlen, new_words);
        if (copy_words != 0 && self->contents != nullptr) {
            memcpy(contents, self->contents, copy_words * sizeof(uint64_t));
        }
        if (self->contents != nullptr) {
            // The words being dropped keep shadow entries keyed by their
            // addresses. Whatever the allocator hands out next would inherit
            // them and be judged against a history that is not its own.
            n00b_race_scrub_range(
                (uint64_t)(uintptr_t)self->contents,
                (uint64_t)(uintptr_t)(self->contents + self->alloc_wordlen));
            n00b_free(self->contents);
        }
        self->contents      = contents;
        self->alloc_wordlen = new_words;
    }

    // The backing array moves and every reader holds a pointer into the old
    // one, so a resize is a write every concurrent reader has to be ordered
    // against. Tracked on the header rather than the words: the words a resize
    // invalidates no longer exist to be named.
    n00b_race_write(&self->contents, "flagset contents");
    // Written on every resize, including one that keeps the same word count
    // and leaves `contents` alone, so growing 40 bits to 50 moves this and
    // nothing the annotation above covers.
    n00b_race_write(&self->num_flags, "flagset num_flags");

    self->num_flags = new_num_flags;
    flagset_zero_tail(self);
}

static uint64_t
flagset_normalize_index(n00b_flagset_t *self, int64_t index, bool grow)
{
    if (index < 0) {
        index += (int64_t)self->num_flags;
        if (index < 0) {
            n00b_require(false, "negative flagset index is out of bounds");
        }
    }

    uint64_t normalized = (uint64_t)index;
    if (normalized >= self->num_flags && grow) {
        flagset_resize(self, normalized + 1);
    }
    return normalized;
}

n00b_flagset_t *
n00b_flagset_new() _kargs
{
    uint64_t          length    = 64;
    n00b_allocator_t *allocator = nullptr;
    bool              locked    = true;
}
{
    n00b_flagset_t *self = n00b_alloc_with_opts(
        n00b_flagset_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_flagset_init(self,
                      .length = length,
                      .allocator = allocator,
                      .locked = locked);
    return self;
}

void
n00b_flagset_init(n00b_flagset_t *self) _kargs
{
    uint64_t          length    = 64;
    n00b_allocator_t *allocator = nullptr;
    bool              locked    = true;
}
{
    if (self == nullptr) {
        return;
    }
    self->contents      = nullptr;
    self->num_flags     = 0;
    self->alloc_wordlen = 0;
    self->allocator     = allocator;
    self->lock          = locked ? n00b_data_lock_new(.allocator = allocator)
                                 : nullptr;
    flagset_resize(self, length);
}

n00b_flagset_t *
n00b_flagset_copy(const n00b_flagset_t *self)
{
    if (self == nullptr) {
        return nullptr;
    }
    n00b_data_read_lock(self->lock);
    n00b_flagset_t *result =
        n00b_flagset_new(.length = self->num_flags,
                         .allocator = self->allocator);
    memcpy(result->contents,
           self->contents,
           self->alloc_wordlen * sizeof(uint64_t));
    n00b_data_unlock(self->lock);
    return result;
}

n00b_flagset_t *
n00b_flagset_invert(const n00b_flagset_t *self)
{
    n00b_flagset_t *result = n00b_flagset_copy(self);
    if (result == nullptr) {
        return nullptr;
    }

    for (uint64_t i = 0; i < result->alloc_wordlen; i++) {
        result->contents[i] = ~result->contents[i];
    }
    flagset_zero_tail(result);
    return result;
}

static n00b_flagset_t *
flagset_binary_new(const n00b_flagset_t *self, const n00b_flagset_t *with)
{
    if (self == nullptr || with == nullptr) {
        return nullptr;
    }
    return n00b_flagset_new(.length = n00b_max(self->num_flags,
                                               with->num_flags),
                            .allocator = self->allocator);
}

n00b_flagset_t *
n00b_flagset_add(const n00b_flagset_t *self, const n00b_flagset_t *with)
{
    if (self == nullptr || with == nullptr) {
        return nullptr;
    }
    bool same = self == with;
    n00b_data_read_lock(self->lock);
    if (!same) {
        n00b_data_read_lock(with->lock);
    }

    n00b_flagset_t *result = flagset_binary_new(self, with);
    if (result == nullptr) {
        if (!same) {
            n00b_data_unlock(with->lock);
        }
        n00b_data_unlock(self->lock);
        return nullptr;
    }

    uint64_t min_words = n00b_min(self->alloc_wordlen, with->alloc_wordlen);
    for (uint64_t i = 0; i < min_words; i++) {
        result->contents[i] = self->contents[i] | with->contents[i];
    }
    for (uint64_t i = min_words; i < result->alloc_wordlen; i++) {
        result->contents[i] = self->alloc_wordlen > with->alloc_wordlen
                                  ? self->contents[i]
                                  : with->contents[i];
    }
    flagset_zero_tail(result);
    if (!same) {
        n00b_data_unlock(with->lock);
    }
    n00b_data_unlock(self->lock);
    return result;
}

n00b_flagset_t *
n00b_flagset_sub(const n00b_flagset_t *self, const n00b_flagset_t *with)
{
    if (self == nullptr || with == nullptr) {
        return nullptr;
    }
    bool same = self == with;
    n00b_data_read_lock(self->lock);
    if (!same) {
        n00b_data_read_lock(with->lock);
    }

    n00b_flagset_t *result = flagset_binary_new(self, with);
    if (result == nullptr) {
        if (!same) {
            n00b_data_unlock(with->lock);
        }
        n00b_data_unlock(self->lock);
        return nullptr;
    }

    uint64_t min_words = n00b_min(self->alloc_wordlen, with->alloc_wordlen);
    for (uint64_t i = 0; i < min_words; i++) {
        result->contents[i] = self->contents[i] & ~with->contents[i];
    }
    for (uint64_t i = min_words; i < self->alloc_wordlen; i++) {
        result->contents[i] = self->contents[i];
    }
    flagset_zero_tail(result);
    if (!same) {
        n00b_data_unlock(with->lock);
    }
    n00b_data_unlock(self->lock);
    return result;
}

n00b_flagset_t *
n00b_flagset_test(const n00b_flagset_t *self, const n00b_flagset_t *with)
{
    if (self == nullptr || with == nullptr) {
        return nullptr;
    }
    bool same = self == with;
    n00b_data_read_lock(self->lock);
    if (!same) {
        n00b_data_read_lock(with->lock);
    }

    n00b_flagset_t *result = flagset_binary_new(self, with);
    if (result == nullptr) {
        if (!same) {
            n00b_data_unlock(with->lock);
        }
        n00b_data_unlock(self->lock);
        return nullptr;
    }

    uint64_t min_words = n00b_min(self->alloc_wordlen, with->alloc_wordlen);
    for (uint64_t i = 0; i < min_words; i++) {
        result->contents[i] = self->contents[i] & with->contents[i];
    }
    if (!same) {
        n00b_data_unlock(with->lock);
    }
    n00b_data_unlock(self->lock);
    return result;
}

n00b_flagset_t *
n00b_flagset_xor(const n00b_flagset_t *self, const n00b_flagset_t *with)
{
    if (self == nullptr || with == nullptr) {
        return nullptr;
    }
    bool same = self == with;
    n00b_data_read_lock(self->lock);
    if (!same) {
        n00b_data_read_lock(with->lock);
    }

    n00b_flagset_t *result = flagset_binary_new(self, with);
    if (result == nullptr) {
        if (!same) {
            n00b_data_unlock(with->lock);
        }
        n00b_data_unlock(self->lock);
        return nullptr;
    }

    uint64_t min_words = n00b_min(self->alloc_wordlen, with->alloc_wordlen);
    for (uint64_t i = 0; i < min_words; i++) {
        result->contents[i] = self->contents[i] ^ with->contents[i];
    }
    for (uint64_t i = min_words; i < result->alloc_wordlen; i++) {
        result->contents[i] = self->alloc_wordlen > with->alloc_wordlen
                                  ? self->contents[i]
                                  : with->contents[i];
    }
    flagset_zero_tail(result);
    if (!same) {
        n00b_data_unlock(with->lock);
    }
    n00b_data_unlock(self->lock);
    return result;
}

bool
n00b_flagset_eq(const n00b_flagset_t *self, const n00b_flagset_t *other)
{
    if (self == nullptr || other == nullptr) {
        return self == other;
    }

    bool same = self == other;
    n00b_data_read_lock(self->lock);
    if (!same) {
        n00b_data_read_lock(other->lock);
    }
    uint64_t sum       = 0;
    uint64_t low_words = n00b_min(self->alloc_wordlen, other->alloc_wordlen);
    for (uint64_t i = 0; i < low_words; i++) {
        sum |= self->contents[i] ^ other->contents[i];
    }

    const n00b_flagset_t *high = self->alloc_wordlen > other->alloc_wordlen
                                     ? self
                                     : other;
    uint64_t high_words = n00b_max(self->alloc_wordlen, other->alloc_wordlen);
    for (uint64_t i = low_words; i < high_words; i++) {
        sum |= high->contents[i];
    }
    bool result = sum == 0;
    if (!same) {
        n00b_data_unlock(other->lock);
    }
    n00b_data_unlock(self->lock);
    return result;
}

uint64_t
n00b_flagset_len(const n00b_flagset_t *self)
{
    if (self == nullptr) {
        return 0;
    }
    n00b_data_read_lock(self->lock);
    uint64_t result = self->num_flags;
    n00b_data_unlock(self->lock);
    return result;
}

bool
n00b_flagset_index(n00b_flagset_t *self, int64_t index)
{
    if (self == nullptr) {
        return false;
    }

    n00b_data_read_lock(self->lock);
    uint64_t normalized = flagset_normalize_index(self, index, false);
    if (normalized >= self->num_flags) {
        n00b_data_unlock(self->lock);
        return false;
    }
    n00b_race_read(&self->num_flags, "flagset num_flags");
    n00b_race_read(&self->contents, "flagset contents");
    n00b_race_read(&self->contents[normalized >> 6], "flagset word");

    bool result =
        (self->contents[normalized >> 6] & (1ull << (normalized & 63u))) != 0;
    n00b_data_unlock(self->lock);
    return result;
}

void
n00b_flagset_set_index(n00b_flagset_t *self, int64_t index, bool value)
{
    if (self == nullptr) {
        return;
    }

    n00b_data_write_lock(self->lock);
    uint64_t normalized = flagset_normalize_index(self, index, true);
    uint64_t flag       = 1ull << (normalized & 63u);
    uint64_t word       = normalized >> 6;

    n00b_race_write(&self->contents[word], "flagset word");

    if (value) {
        self->contents[word] |= flag;
    }
    else {
        self->contents[word] &= ~flag;
    }
    n00b_data_unlock(self->lock);
}

bool
n00b_flagset_test_and_set_index(n00b_flagset_t *self, int64_t index, bool value)
{
    if (self == nullptr) {
        return false;
    }

    n00b_data_write_lock(self->lock);
    uint64_t normalized = flagset_normalize_index(self, index, true);
    uint64_t flag       = 1ull << (normalized & 63u);
    uint64_t word       = normalized >> 6;

    // The word, not the bit. Setting a bit is a read-modify-write of the whole
    // word, so two threads setting different bits in one word are writing the
    // same location and one of them loses. A set built with .locked = false
    // has no guard to make that safe and nothing else here supplies one.
    n00b_race_write(&self->contents[word], "flagset word");

    bool     old        = (self->contents[word] & flag) != 0;
    if (value) {
        self->contents[word] |= flag;
    }
    else {
        self->contents[word] &= ~flag;
    }
    n00b_data_unlock(self->lock);
    return old;
}

uint64_t
n00b_flagset_count(const n00b_flagset_t *self)
{
    if (self == nullptr) {
        return 0;
    }

    n00b_data_read_lock(self->lock);
    uint64_t count = 0;
    for (uint64_t i = 0; i < self->alloc_wordlen; i++) {
        count += (uint64_t)__builtin_popcountll(self->contents[i]);
    }
    n00b_data_unlock(self->lock);
    return count;
}

bool
n00b_flagset_next_set(const n00b_flagset_t *self,
                      uint64_t              after,
                      uint64_t             *out_index)
{
    if (self == nullptr || out_index == nullptr) {
        return false;
    }

    n00b_data_read_lock(self->lock);
    if (after >= self->num_flags) {
        n00b_data_unlock(self->lock);
        return false;
    }

    uint64_t word_ix = after >> 6;
    uint64_t word    = self->contents[word_ix] & (~0ull << (after & 63u));
    while (true) {
        if (word != 0) {
            uint64_t bit = (uint64_t)__builtin_ctzll(word);
            uint64_t ix  = (word_ix << 6) + bit;
            if (ix >= self->num_flags) {
                n00b_data_unlock(self->lock);
                return false;
            }
            *out_index = ix;
            n00b_data_unlock(self->lock);
            return true;
        }

        word_ix++;
        if (word_ix >= self->alloc_wordlen) {
            n00b_data_unlock(self->lock);
            return false;
        }
        word = self->contents[word_ix];
    }
}
