//
// This file contains a C99 implementation for "SHA-256" as specified in NIST
// FIPS 180-4 (August 2015) assuming we have uint32_t.  The specification can
// be found here:
//
//      http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
//

#include "sha256.h"

#define SHR(a, b)       (((a) & 0xffffffff) >> (b))
#define ROTR(a, b)      (SHR(a, b) | (((a) << (32 - (b))) & 0xffffffff))
#define Ch(x, y, z)     (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z)    (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define S0(x)           (ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x)           (ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define Q0(x)           (ROTR(x,  7) ^ ROTR(x, 18) ^  SHR(x,  3))
#define Q1(x)           (ROTR(x, 17) ^ ROTR(x, 19) ^  SHR(x, 10))

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void process_one_block(sha256_context_t *ctx, const uint8_t *data)
{
    int i;
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];

    for (i = 0; i <= 15; ++i) {
        m[i] = ((uint32_t) data[i * 4 + 0] << 24)
             | ((uint32_t) data[i * 4 + 1] << 16)
             | ((uint32_t) data[i * 4 + 2] <<  8)
             | ((uint32_t) data[i * 4 + 3] <<  0);
    }
    for (i = 16; i <= 63; ++i) {
        m[i] = Q1(m[i -  2]) + m[i -  7] + Q0(m[i - 15]) + m[i - 16];
    }

    a = ctx->runninghash[0];
    b = ctx->runninghash[1];
    c = ctx->runninghash[2];
    d = ctx->runninghash[3];
    e = ctx->runninghash[4];
    f = ctx->runninghash[5];
    g = ctx->runninghash[6];
    h = ctx->runninghash[7];

    for (i = 0; i <= 63; ++i) {
        t1 = h + S1(e) + Ch(e,f,g) + K[i] + m[i];
        t2 = S0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->runninghash[0] += a;
    ctx->runninghash[1] += b;
    ctx->runninghash[2] += c;
    ctx->runninghash[3] += d;
    ctx->runninghash[4] += e;
    ctx->runninghash[5] += f;
    ctx->runninghash[6] += g;
    ctx->runninghash[7] += h;
}

static void increase_by(uint32_t *biginteger, uint32_t incr)
{
    //          high bits            low bits
    //      +---------------+    +---------------+
    //      | biginteger[0] |    | biginteger[1] |
    //      +---------------+    +---------------+
    //
    uint32_t space = 0xffffffff - biginteger[1];

    biginteger[1] += incr;

    if (incr >= space) {
        biginteger[0] += 1;
    }
}

void sha256_begin(void *_ctx)
{
    sha256_context_t *ctx = _ctx;

    if (!ctx) {
        return;
    }

    ctx->runninghash[0] = 0x6a09e667;
    ctx->runninghash[1] = 0xbb67ae85;
    ctx->runninghash[2] = 0x3c6ef372;
    ctx->runninghash[3] = 0xa54ff53a;
    ctx->runninghash[4] = 0x510e527f;
    ctx->runninghash[5] = 0x9b05688c;
    ctx->runninghash[6] = 0x1f83d9ab;
    ctx->runninghash[7] = 0x5be0cd19;

    ctx->totalbitlen[0] = 0x00000000;
    ctx->totalbitlen[1] = 0x00000000;

    ctx->bufferlen = 0;
}

void sha256_update(void *_ctx, int ilen, const uint8_t *input)
{
    sha256_context_t *ctx = _ctx;
    int i;

    if (!ctx || (ilen > 0 && !input)) {
        return;
    }

    for (i = 0; i < ilen; ++i) {
        ctx->buffer[ctx->bufferlen] = input[i];
        ctx->bufferlen += 1;
        if (ctx->bufferlen == 64) {
            process_one_block(ctx, ctx->buffer);
            increase_by(ctx->totalbitlen, 512);
            ctx->bufferlen = 0;
        }
    }
}

void sha256_output(void *_ctx, uint8_t *output)
{
    const sha256_context_t *ctx = _ctx;
    sha256_context_t ctx_;
    int i;

    if (!ctx || !output) {
        return;
    }

    // Let us use another copy of the context, not polluting the original one
    ctx_ = *ctx;

    // Append one 0x80 byte
    i = (int) ctx_.bufferlen;
    ctx_.buffer[i++] = 0x80;

    // Append some 0x00 bytes... until the last eight bytes
    if (i >= 57) {
        while (i < 64) {
            ctx_.buffer[i++] = 0x00;
        }
        process_one_block(&ctx_, ctx_.buffer);
        i = 0;
    }
    while (i < 56) {
        ctx_.buffer[i++] = 0x00;
    }

    // Append eight bytes representing the message bit length (big-endian)
    increase_by(ctx_.totalbitlen, ctx_.bufferlen * 8);
    ctx_.buffer[56] = (uint8_t) (ctx_.totalbitlen[0] >> 24);
    ctx_.buffer[57] = (uint8_t) (ctx_.totalbitlen[0] >> 16);
    ctx_.buffer[58] = (uint8_t) (ctx_.totalbitlen[0] >>  8);
    ctx_.buffer[59] = (uint8_t) (ctx_.totalbitlen[0] >>  0);
    ctx_.buffer[60] = (uint8_t) (ctx_.totalbitlen[1] >> 24);
    ctx_.buffer[61] = (uint8_t) (ctx_.totalbitlen[1] >> 16);
    ctx_.buffer[62] = (uint8_t) (ctx_.totalbitlen[1] >>  8);
    ctx_.buffer[63] = (uint8_t) (ctx_.totalbitlen[1] >>  0);
    process_one_block(&ctx_, ctx_.buffer);

    // Dump the resulting 32-byte hash value
    for (i = 0; i <= 7; ++i) {
        output[i * 4 + 0] = (uint8_t) (ctx_.runninghash[i] >> 24);
        output[i * 4 + 1] = (uint8_t) (ctx_.runninghash[i] >> 16);
        output[i * 4 + 2] = (uint8_t) (ctx_.runninghash[i] >>  8);
        output[i * 4 + 3] = (uint8_t) (ctx_.runninghash[i] >>  0);
    }
}
