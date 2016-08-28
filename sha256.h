#ifndef SHA256_H__
#define SHA256_H__

#include <stdint.h>

#define SHA256_IBLOCK_SIZE 64   // input block size in bytes
#define SHA256_OUTPUT_SIZE 32   // output size in bytes

typedef struct {
    uint32_t runninghash[8];    // intermediate hash value (H0 ~ H7)
    uint32_t totalbitlen[2];    // bit length (l) of the input message
    uint8_t buffer[64];         // buffer for unprocessed input message
    uint32_t bufferlen;         // byte length of unprocessed input message
} sha256_context_t;

void sha256_begin(void *ctx);
void sha256_update(void *ctx, int ilen, const uint8_t *input);
void sha256_output(void *ctx, uint8_t *output);

#endif
