#pragma once

// CRC-32 (IEEE 802.3 / zlib) — standalone, no dependencies beyond libc
// header-only byte work. Reflected algorithm, polynomial 0xEDB88320 (the
// reflection of 0x04C11DB7), standard initial/final XOR of 0xFFFFFFFF. This is
// the same CRC-32 emitted by zlib's `crc32()` and gzip; e.g. the CRC-32 of the
// ASCII string "123456789" is 0xCBF43926.
//
// D-039: used as the `slice_digest_crc` fast structural pre-check for the Mach-O
// SPLIT carrier's reconstruction records. The bundle-level SHA-256 over the
// reconstructed canonical bytes remains the authoritative integrity gate; this
// CRC is only a cheap pre-check. Mirrors the shape of `core/sha256.h`.

#include <stdint.h>
#include <stddef.h>

/**
 * @brief One-shot IEEE 802.3 / zlib CRC-32 over a byte range.
 *
 * Computes the standard reflected CRC-32 (polynomial 0xEDB88320, initial and
 * final XOR 0xFFFFFFFF) over @p len bytes starting at @p data. Performs no
 * allocation and keeps no state across calls.
 *
 * @param data Pointer to the bytes to hash. May be null iff @p len is 0.
 * @param len  Number of bytes to hash.
 * @return The 32-bit CRC of the input (e.g. `n00b_crc32("123456789", 9)` is
 *         `0xCBF43926`).
 */
uint32_t n00b_crc32(const void *data, size_t len);
