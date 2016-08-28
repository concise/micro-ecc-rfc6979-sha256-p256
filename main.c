/*
gcc -Wall main.c uECC.c sha256.c hmac.c hmacsha256.c rfc6979sha256p256csprng.c


1.  SHA256

    const uint8_t msg[5] = "hello";
    uint8_t message_hash[32];
    {
        sha256_context_t ctx;
        sha256_begin(&ctx);
        sha256_update(&ctx, 5, msg);
        sha256_output(&ctx, message_hash);
    }


2.  HMAC-SHA256

    const uint8_t key[3] = "key";
    const uint8_t msg[5] = "hello";
    uint8_t signature[32];
    {
        hmacsha256_context_t ctx;
        hmacsha256_init(&ctx);
        hmac_begin(&ctx, 3, key);
        hmac_update(&ctx, 5, msg);
        hmac_output(&ctx, signature);
    }


3.  RFC6979-SHA256-P256-PRNG

    const uint8_t entropy[64] = "\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x2c\xf2\x4d\xba\x5f\xb0\xa3\x0e\x26\xe8\x3b\x2a\xc5\xb9\xe2\x9e\x1b\x16\x1e\x5c\x1f\xa7\x42\x5e\x73\x04\x33\x62\x93\x8b\x98\x24";
    uint8_t prng_state[64];
    uint8_t new_private_key[32];

    rfc6979sha256p256csprng_init(prng_state, entropy, 64);
    rfc6979sha256p256csprng_gen(prng_state, new_private_key);


4.  RFC6979-SHA256-P256-SIGN

    const uint8_t private_key[32] = "\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61";
    const uint8_t message_hash[32] = "\x2c\xf2\x4d\xba\x5f\xb0\xa3\x0e\x26\xe8\x3b\x2a\xc5\xb9\xe2\x9e\x1b\x16\x1e\x5c\x1f\xa7\x42\x5e\x73\x04\x33\x62\x93\x8b\x98\x24";
    uint8_t signature[64];

    rfc6979sha256p256sign(private_key, message_hash, signature);

*/

#include <stddef.h>
#include <stdint.h>

#include "uECC.h"

/*
#include <stdio.h>
void hexdump(uint8_t *k, int len);
void hexdump(uint8_t *k, int len)
{
    int i;
    for (i = 0; i < len; ++i) {
        printf("%02x", k[i]);
    }
    printf("\n");
}
*/

int main(void)
{
    uint8_t private_key[32] = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
    uint8_t message[5] = "hello";
    uint8_t message_hash[32] = {0};
    uint8_t signature[64] = {0};

    {
        sha256_context_t ctx;
        sha256_begin(&ctx);
        sha256_update(&ctx, sizeof(message), message);
        sha256_output(&ctx, message_hash);
    }

    rfc6979sha256p256sign(private_key, message_hash, signature);

    /*
    printf("private_key = "); hexdump(private_key, 32);
    printf("message_hash = "); hexdump(message_hash, 32);
    printf("signature = \n"); hexdump(signature, 32); hexdump(signature+32, 32);
    */

    return 0;
}
