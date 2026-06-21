// GF(2^8) finite-field arithmetic. See include/crypto/gf256.h for the
// API contract. Only the table builder lives out of line; the
// arithmetic ops are static inline in the header.

#include <crypto/gf256.h>

// Carry-less multiply of two field elements, reducing modulo `prim`.
// Used only while building the exp/log tables; the runtime ops use the
// tables instead. Operands are widened to 16 bits so the carry out of
// bit 7 is visible before reduction.
static uint16_t
gf_mul_reduce(uint16_t a, uint16_t b, uint16_t prim)
{
    uint16_t result = 0;

    while (b != 0) {
        if (b & 1) {
            result ^= a;
        }
        b >>= 1;
        a <<= 1;
        if (a & 0x100) {
            a ^= prim;
        }
    }

    return result;
}

void
n00b_gf256_init(n00b_gf256_t *gf) _kargs
{
    uint16_t primitive = 0x11D;
    uint8_t  generator = 2;
}
{
    gf->primitive = primitive;
    gf->generator = generator;

    // Walk the 255 non-zero elements as successive powers of the
    // generator, recording both directions of the mapping. If the
    // generator is primitive, the powers visit every non-zero element
    // exactly once; otherwise the cycle is short and a value repeats.
    // Validate that here (always-on) so a bad (primitive, generator)
    // pair fails loudly instead of producing silently-wrong tables.
    bool     seen[256] = {};
    uint16_t x         = 1;
    for (int i = 0; i < 255; i++) {
        uint8_t e = (uint8_t)x;
        n00b_require(e != 0 && !seen[e],
                     "n00b_gf256_init: generator is not a primitive "
                     "element for this polynomial");
        seen[e]    = true;
        gf->exp[i] = e;
        gf->log[e] = (uint8_t)i;
        x          = gf_mul_reduce(x, generator, primitive);
    }

    // Duplicate the cycle so mul/div can index up to log[a]+log[b]
    // (<= 509) without a modulo.
    for (int i = 255; i < 512; i++) {
        gf->exp[i] = gf->exp[i - 255];
    }

    // log[0] is mathematically undefined; the arithmetic ops never read
    // it (they special-case a zero operand). Pin it to a deterministic
    // value rather than leaving it whatever init order produced.
    gf->log[0] = 0;
}
