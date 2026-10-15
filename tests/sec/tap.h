#ifndef SEC_TAP_H
#define SEC_TAP_H

#include <stdio.h>
#include <stdlib.h>

static int tap_tests_run = 0;
static int tap_tests_failed = 0;

#define OK(cond, ...) do { \
    tap_tests_run++; \
    if (cond) { \
        printf("ok %d - ", tap_tests_run); \
        printf(__VA_ARGS__); \
        printf("\n"); \
    } else { \
        tap_tests_failed++; \
        printf("not ok %d - ", tap_tests_run); \
        printf(__VA_ARGS__); \
        printf("\n"); \
    } \
} while(0)

#define DONE() do { \
    printf("1..%d\n", tap_tests_run); \
    exit(tap_tests_failed > 0 ? 1 : 0); \
} while(0)

#endif
