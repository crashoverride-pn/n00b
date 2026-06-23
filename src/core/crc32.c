// crc32.c — IEEE 802.3 / zlib CRC-32 (reflected, polynomial 0xEDB88320).
//
// D-039: a small, dependency-free core primitive used by the Mach-O SPLIT
// carrier record codec for `slice_digest_crc`. No libc, no allocation. Mirrors
// the standalone structure of src/core/sha256.c.

#include "core/crc32.h"

#define N00B_CRC32_POLY 0xEDB88320u

// Per-byte CRC step over the reflected algorithm. Computing the table-free inner
// loop keeps the primitive allocation-free and table-free; CRC of a slice runs
// once per encode/read pre-check, so the bit-at-a-time form is adequate and has
// no startup/global state.
static inline uint32_t
crc32_byte(uint32_t crc, uint8_t byte)
{
    crc ^= (uint32_t)byte;

    for (uint32_t bit = 0; bit < 8; bit++) {
        uint32_t mask = (uint32_t)-(int32_t)(crc & 1u);
        crc           = (crc >> 1) ^ (N00B_CRC32_POLY & mask);
    }

    return crc;
}

uint32_t
n00b_crc32(const void *data, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t       crc   = 0xFFFFFFFFu;

    for (size_t i = 0; i < len; i++) {
        crc = crc32_byte(crc, bytes[i]);
    }

    return crc ^ 0xFFFFFFFFu;
}
