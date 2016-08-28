#ifndef RFC6979SHA256P256CSPRNG_H__
#define RFC6979SHA256P256CSPRNG_H__

#include "hmacsha256.h"

void rfc6979sha256p256csprng_init(unsigned char *state, const unsigned char *entropy, int entropy_len);
void rfc6979sha256p256csprng_gen(unsigned char *state, unsigned char *new_private_key);

#endif
