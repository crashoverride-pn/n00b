#pragma once

#include "n00b.h"
#include "core/string.h"

/* Resolve a hostname through DNS without using the libc resolver.
 *
 * Returns newline-delimited IP literals in one n00b_string_t. The empty
 * string means no address answers were returned or the lookup failed.
 * The implementation is intentionally synchronous and avoids allocation
 * until the final return string, so it is safe on n00b worker threads.
 */
extern n00b_string_t *n00b_dns_resolve(n00b_string_t *host);
