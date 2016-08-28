#include "hmac.h"
#include "hmacsha256.h"

void hmacsha256_init(hmacsha256_context_t *ctx)
{
    if (!ctx) {
        return;
    }

    ctx->hmac_ctx.hash_context   = &ctx->sha256_ctx;
    ctx->hmac_ctx.hash_begin     = &sha256_begin;
    ctx->hmac_ctx.hash_update    = &sha256_update;
    ctx->hmac_ctx.hash_output    = &sha256_output;
    ctx->hmac_ctx.B              = SHA256_IBLOCK_SIZE;
    ctx->hmac_ctx.L              = SHA256_OUTPUT_SIZE;
    ctx->hmac_ctx.workingBufferB = ctx->ibuf;
    ctx->hmac_ctx.workingBufferL = ctx->obuf;
}

void hmacsha256(
    int keylen, const unsigned char *key,
    int msglen, const unsigned char *msg,
    unsigned char *out)
{
    if (!out) {
        return;
    }

    hmacsha256_context_t hmacsha256_ctx;
    hmacsha256_init(&hmacsha256_ctx);
    hmac_begin(&hmacsha256_ctx, keylen, key);
    hmac_update(&hmacsha256_ctx, msglen, msg);
    hmac_output(&hmacsha256_ctx, out);
}
