#ifndef TESTUTIL_H
#define TESTUTIL_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int t_fail = 0, t_total = 0;
#define CHECK(cond, name) do { t_total++; if (cond) printf("  [ok]   %s\n", name); \
    else { printf("  [FAIL] %s  (%s:%d)\n", name, __FILE__, __LINE__); t_fail++; } } while (0)
#define TEST_DONE() do { printf("%d checks, %d failed\n", t_total, t_fail); return t_fail ? 1 : 0; } while (0)

static __attribute__((unused)) void hex2bin(const char *h, unsigned char *out, size_t *n)
{
    size_t i = 0;
    for (; h[2 * i] && h[2 * i + 1]; i++) { unsigned v; sscanf(h + 2 * i, "%2x", &v); out[i] = (unsigned char)v; }
    if (n) *n = i;
}
#endif
