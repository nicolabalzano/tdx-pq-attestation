#include <stddef.h>
#include <stdint.h>

/*
 * Host-only test stub for the vendored mldsa-native randomized entry points.
 * The TDQE adapter uses deterministic APIs, but the amalgamated upstream
 * source still references randombytes() unless the full library build is
 * split differently.
 */
int randombytes(uint8_t *out, size_t outlen)
{
    size_t i = 0;

    if (NULL == out) {
        return -1;
    }

    for (i = 0; i < outlen; ++i) {
        out[i] = (uint8_t)(0xA5u ^ (uint8_t)i);
    }

    return 0;
}
