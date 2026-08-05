#include "n00b.h"
#include "core/hash.h"

#ifdef _WIN32
#include <intrin.h>
#define XXH_NO_PREFETCH
#endif

#define XXH_INLINE_ALL
#include "vendor/xxhash.h"

uint64_t
n00b_xxh3_64bits_raw(const void *data, size_t len)
{
    return XXH3_64bits(data, len);
}

n00b_uint128_t
n00b_xxh3_128bits_raw(const void *data, size_t len)
{
    XXH128_hash_t hv = XXH3_128bits(data, len);
    return ((n00b_uint128_t)hv.high64 << 64) | (n00b_uint128_t)hv.low64;
}
