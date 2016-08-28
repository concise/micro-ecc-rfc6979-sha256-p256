#ifndef HMACSHA256_H__
#define HMACSHA256_H__

#include "hmac.h"
#include "sha256.h"

typedef struct {
    hmac_context_t hmac_ctx;
    sha256_context_t sha256_ctx;
    unsigned char ibuf[SHA256_IBLOCK_SIZE];
    unsigned char obuf[SHA256_OUTPUT_SIZE];
} hmacsha256_context_t;

void hmacsha256_init(hmacsha256_context_t *);

void hmacsha256(
    int, const unsigned char *,
    int, const unsigned char *,
    unsigned char *);

#endif
