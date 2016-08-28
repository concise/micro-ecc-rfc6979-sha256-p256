#include "rfc6979sha256p256csprng.h"

void rfc6979sha256p256csprng_init(unsigned char *state, const unsigned char *entropy, int entropy_len)
{
    int i;
    unsigned char *K = state;
    unsigned char *V = state + 32;

    hmacsha256_context_t hmacsha256_ctx;
    hmacsha256_init(&hmacsha256_ctx);

    // K = b'\x00' * 32
    for (i = 0; i < 32; ++i) {
        K[i] = 0x00;
    }

    // V = b'\x01' * 32
    for (i = 0; i < 32; ++i) {
        V[i] = 0x01;
    }

    // K = hmacsha256(K, V + b'\x00' + entropy)
    hmac_begin(&hmacsha256_ctx, 32, K);
    hmac_update(&hmacsha256_ctx, 32, V);
    hmac_update(&hmacsha256_ctx, 1, (const unsigned char *) "\x00");
    hmac_update(&hmacsha256_ctx, entropy_len, entropy);
    hmac_output(&hmacsha256_ctx, K);

    // V = hmacsha256(K, V)
    hmac_begin(&hmacsha256_ctx, 32, K);
    hmac_update(&hmacsha256_ctx, 32, V);
    hmac_output(&hmacsha256_ctx, V);

    // K = hmacsha256(K, V + b'\x01' + entropy)
    hmac_begin(&hmacsha256_ctx, 32, K);
    hmac_update(&hmacsha256_ctx, 32, V);
    hmac_update(&hmacsha256_ctx, 1, (const unsigned char *) "\x01");
    hmac_update(&hmacsha256_ctx, entropy_len, entropy);
    hmac_output(&hmacsha256_ctx, K);

    // V = hmacsha256(K, V)
    hmac_begin(&hmacsha256_ctx, 32, K);
    hmac_update(&hmacsha256_ctx, 32, V);
    hmac_output(&hmacsha256_ctx, V);
}


void rfc6979sha256p256csprng_gen(unsigned char *state, unsigned char *new_private_key)
{
    unsigned char *K = state;
    unsigned char *V = state + 32;

    hmacsha256_context_t hmacsha256_ctx;
    hmacsha256_init(&hmacsha256_ctx);

    // T = hmacsha256(K, V)
    hmac_begin(&hmacsha256_ctx, 32, K);
    hmac_update(&hmacsha256_ctx, 32, V);
    hmac_output(&hmacsha256_ctx, new_private_key);

    // K = hmacsha256(K, V + b'\x00')
    hmac_begin(&hmacsha256_ctx, 32, K);
    hmac_update(&hmacsha256_ctx, 32, V);
    hmac_update(&hmacsha256_ctx, 1, (const unsigned char *) "\x00");
    hmac_output(&hmacsha256_ctx, K);

    // V = hmacsha256(K, V)
    hmac_begin(&hmacsha256_ctx, 32, K);
    hmac_update(&hmacsha256_ctx, 32, V);
    hmac_output(&hmacsha256_ctx, V);

    // XXX In fact, we MUST check if the resulting 256-bit unsigned integer k
    // satisfies 0 < k < n where n is the group order:
    //
    //   ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    //
    // and if the check fails, we have to repeat the generation routine.
    //
    // However the probability of invalid k is less than 2^-32 = 2.33e-10
    // so we can still be 99.9999999% safe even if we omit the check
    // assuming SHA-256 actually works like a pseudo-random function.
}
